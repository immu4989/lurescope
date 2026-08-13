"""Inbox-to-LureProof batch workflow and privacy-boundary tests."""

from __future__ import annotations

import json
import os
from email.message import EmailMessage
from pathlib import Path

import pytest

pytest.importorskip("sklearn")

from lurescope.cli import MAX_BATCH_INPUT_BYTES, _input_messages, main
from lurescope.inbox import INBOX_SCHEMA, INBOX_SUMMARY_SCHEMA, process_inbox
from lurescope.proof import generate_keypair, verify_proof


def _email(subject: str, body: str, sender: str = "sender@example.org") -> bytes:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = "soc@example.org"
    message["Message-ID"] = f"<{subject.casefold().replace(' ', '-')}@example.org>"
    message.set_content(body)
    return message.as_bytes()


def _manifest(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_batch_outputs_minimized_manifest_private_proofs_and_summary(tmp_path):
    sensitive_source = "/mailbox/CEO payroll request.eml"
    secret_subject = "Secret payroll account"
    secret_sender = "chief.executive@example.org"
    raw = _email(
        secret_subject,
        "Urgent: verify your account at http://192.0.2.10/payroll within 24 hours.",
        secret_sender,
    )
    output = tmp_path / "cases"
    run = process_inbox([(sensitive_source, raw)], output)

    assert run.failed_count == 0
    assert run.items[0].source == sensitive_source  # available only to the local caller
    assert run.summary["processed_count"] == 1
    assert run.summary["schema"] == INBOX_SUMMARY_SCHEMA
    assert os.stat(output).st_mode & 0o777 == 0o700

    entries = _manifest(output / "manifest.jsonl")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["schema"] == INBOX_SCHEMA
    assert entry["status"] == "processed"
    assert entry["recommended_action"] in {
        "quarantine_and_review", "hold_and_verify_sender", "continue_normal_controls"
    }
    assert entry["proof"]["artifact_type"] == "statement"
    assert entry["proof"]["signature_count"] == 0
    assert set(entry["resilience"]) == {
        "clean_flagged", "attack_count", "eligible_attack_count",
        "evasion_count", "defense_recovery_count",
    }

    proof_path = output / entry["proof"]["file"]
    assert os.stat(proof_path).st_mode & 0o777 == 0o600
    assert verify_proof(json.loads(proof_path.read_text()))["valid"] is True

    persisted = "\n".join(path.read_text() for path in output.iterdir())
    for secret in (
        sensitive_source, secret_subject, secret_sender, "192.0.2.10", "verify your account"
    ):
        assert secret not in persisted


def test_batch_signed_proofs_authenticate_with_trusted_public_key(tmp_path):
    private_path = tmp_path / "issuer.pem"
    public_path = tmp_path / "issuer.pub.pem"
    generate_keypair(private_path, public_path)
    output = tmp_path / "signed-cases"
    run = process_inbox(
        [("reported.eml", _email("Account alert", "Verify your account within 24 hours."))],
        output,
        signing_key_pem=private_path.read_bytes(),
        issuer="Example SOC",
        nonce="verifier-challenge-123",
    )

    entry = _manifest(output / "manifest.jsonl")[0]
    assert run.summary["proofs_signed"] is True
    assert entry["proof"]["artifact_type"] == "dsse"
    assert entry["proof"]["signature_count"] == 1
    artifact = json.loads((output / entry["proof"]["file"]).read_text())
    verified = verify_proof(
        artifact, public_path.read_bytes(), require_signature=True
    )
    assert verified["valid"] is True
    assert verified["authenticated"] is True


def test_batch_records_safe_error_and_continues(tmp_path):
    output = tmp_path / "partial"
    run = process_inbox([
        ("empty.eml", b"From: empty@example.org\n\n"),
        ("valid.eml", _email("Team notes", "Please review the project notes.")),
    ], output)

    entries = _manifest(output / "manifest.jsonl")
    assert run.failed_count == 1
    assert run.summary["processed_count"] == 1
    assert [entry["status"] for entry in entries] == ["error", "processed"]
    assert entries[0]["error_type"] == "ValueError"
    assert "source" not in entries[0]
    assert "empty.eml" not in (output / "manifest.jsonl").read_text()


def test_batch_refuses_existing_output_and_message_limit(tmp_path):
    existing = tmp_path / "existing"
    existing.mkdir()
    messages = [("one.eml", _email("One", "Project notes"))]
    with pytest.raises(FileExistsError):
        process_inbox(messages, existing)
    with pytest.raises(ValueError, match="configured limit"):
        process_inbox(messages * 2, tmp_path / "too-many", max_messages=1)


def test_cli_batch_limits_are_enforced_before_message_reads(tmp_path, monkeypatch):
    source = tmp_path / "reported"
    source.mkdir()
    for index in range(2):
        (source / f"{index}.eml").write_bytes(_email(str(index), "Project notes"))

    def unexpected_read(*args, **kwargs):
        raise AssertionError("message content was read before the count check")

    monkeypatch.setattr(Path, "open", unexpected_read)
    with pytest.raises(ValueError, match="no files were read"):
        _input_messages([str(source)], recursive=False, max_messages=1)


def test_cli_inbox_applies_configured_message_limit(tmp_path, capsys):
    source = tmp_path / "reported"
    source.mkdir()
    for index in range(2):
        (source / f"{index}.eml").write_bytes(_email(str(index), "Project notes"))

    output = tmp_path / "must-not-exist"
    assert main([
        "inbox", str(source), "--out", str(output), "--max-messages", "1"
    ]) == 2
    assert "no files were read" in capsys.readouterr().err
    assert not output.exists()


def test_cli_batch_has_a_fixed_total_memory_ceiling(tmp_path):
    source = tmp_path / "large.eml"
    source.write_bytes(b"x" * 1024)
    with pytest.raises(ValueError, match="batch limit"):
        _input_messages(
            [str(source)],
            recursive=False,
            max_total_bytes=512,
        )
    assert MAX_BATCH_INPUT_BYTES == 64 * 1024 * 1024


def test_cli_inbox_processes_a_directory(tmp_path, capsys):
    source = tmp_path / "reported"
    source.mkdir()
    (source / "message.eml").write_bytes(
        _email("Payment change", "Please verify the new payment account within 24 hours.")
    )
    output = tmp_path / "cases"

    assert main(["inbox", str(source), "--out", str(output)]) == 0
    captured = capsys.readouterr()
    assert "processed 1/1; failed 0" in captured.out
    assert (output / "manifest.jsonl").is_file()
    assert (output / "summary.json").is_file()


def test_published_inbox_schemas_accept_reference_outputs(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    output = tmp_path / "schema-cases"
    process_inbox([
        ("empty.eml", b"From: empty@example.org\n\n"),
        ("valid.eml", _email("Security alert", "Verify your account within 24 hours.")),
    ], output)
    root = Path(__file__).parents[1]
    event_schema = json.loads((root / "spec/inbox-event-v1.schema.json").read_text())
    summary_schema = json.loads((root / "spec/inbox-summary-v1.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(event_schema)
    for entry in _manifest(output / "manifest.jsonl"):
        validator.validate(entry)
    jsonschema.Draft202012Validator(summary_schema).validate(
        json.loads((output / "summary.json").read_text())
    )
