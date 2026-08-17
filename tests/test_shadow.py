"""Offline Shadow Inbox ingestion, review, reporting, and privacy tests."""

from __future__ import annotations

import json
import mailbox
import os
from email.message import EmailMessage
from pathlib import Path

import pytest

pytest.importorskip("sklearn")

import lurescope.shadow as shadow_module
from lurescope.cli import main
from lurescope.shadow import (
    MAX_SHADOW_INPUT_BYTES,
    append_analyst_label,
    build_shadow_report,
    discover_shadow_messages,
    load_analyst_labels,
    load_shadow_run,
    run_shadow_inbox,
)


def _email(subject: str, body: str, sender: str = "sender@example.org") -> bytes:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = "soc@example.org"
    message["Message-ID"] = f"<{subject.casefold().replace(' ', '-')}@example.org>"
    message.set_content(body)
    return message.as_bytes()


def _manifest(bundle: Path):
    return [
        json.loads(line)
        for line in (bundle / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
    ]


def test_eml_discovery_deduplicates_without_persisting_fingerprints(tmp_path):
    source = tmp_path / "export"
    source.mkdir()
    raw = _email("Payment change", "Verify the new payment account within 24 hours.")
    (source / "first.eml").write_bytes(raw)
    (source / "copy.eml").write_bytes(raw)
    (source / "other.eml").write_bytes(_email("Team notes", "Agenda for tomorrow."))

    discovery = discover_shadow_messages([source])

    assert discovery.candidate_count == 3
    assert discovery.duplicate_count == 1
    assert len(discovery.messages) == 2
    assert discovery.source_type_counts == {"eml": 3}
    assert discovery.unique_source_type_counts == {"eml": 2}


def test_oversized_messages_are_not_deduplicated_by_a_bounded_prefix(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(shadow_module, "MAX_EMAIL_BYTES", 16)
    first = tmp_path / "first.eml"
    second = tmp_path / "second.eml"
    first.write_bytes(b"same-sixteen-byteA-tail")
    second.write_bytes(b"same-sixteen-byteB-tail")

    discovery = discover_shadow_messages([first, second])

    assert discovery.candidate_count == 2
    assert discovery.duplicate_count == 0
    assert len(discovery.messages) == 2


def test_maildir_and_mbox_inputs_are_supported(tmp_path):
    maildir = tmp_path / "Maildir"
    (maildir / "cur").mkdir(parents=True)
    (maildir / "new").mkdir()
    (maildir / "tmp").mkdir()
    (maildir / "new" / "1700000000.local").write_bytes(
        _email("Maildir alert", "Verify your account now.")
    )
    maildir_result = discover_shadow_messages([maildir])
    assert maildir_result.source_type_counts == {"maildir": 1}

    mbox_path = tmp_path / "archive.mbox"
    box = mailbox.mbox(mbox_path, create=True)
    try:
        box.add(mailbox.mboxMessage(_email("First", "Project update.")))
        box.add(mailbox.mboxMessage(_email("Second", "Urgent payment request.")))
        box.flush()
    finally:
        box.close()
    mbox_result = discover_shadow_messages([mbox_path])
    assert mbox_result.candidate_count == 2
    assert mbox_result.source_type_counts == {"mbox": 2}


def test_shadow_limits_fail_before_eml_body_reads(tmp_path, monkeypatch):
    source = tmp_path / "export"
    source.mkdir()
    for index in range(2):
        (source / f"{index}.eml").write_bytes(_email(str(index), "Project notes"))

    def unexpected_read(*args, **kwargs):
        raise AssertionError("message content was read before the count check")

    monkeypatch.setattr(shadow_module.os, "open", unexpected_read)
    with pytest.raises(ValueError, match="no message bodies were read"):
        discover_shadow_messages([source], max_messages=1)


def test_shadow_batch_byte_limit_and_symlinks_are_rejected(tmp_path):
    source = tmp_path / "large.eml"
    source.write_bytes(b"x" * 1024)
    with pytest.raises(ValueError, match="no message bodies were read"):
        discover_shadow_messages([source], max_total_bytes=512)
    assert MAX_SHADOW_INPUT_BYTES == 64 * 1024 * 1024

    linked = tmp_path / "linked.eml"
    linked.symlink_to(source)
    with pytest.raises(ValueError, match="symbolic-link"):
        discover_shadow_messages([linked])


def test_run_creates_private_minimized_bundle_and_valid_schemas(tmp_path):
    sensitive_path = tmp_path / "CEO confidential payroll.eml"
    secret_subject = "Confidential payroll reroute"
    secret_sender = "chief.executive@example.org"
    sensitive_path.write_bytes(_email(
        secret_subject,
        "Urgent: send payment to the new account at hxxps://payroll.example.invalid.",
        secret_sender,
    ))
    bundle = tmp_path / "shadow-pilot"

    run = run_shadow_inbox([sensitive_path], bundle)

    assert run.failed_count == 0
    assert os.stat(bundle).st_mode & 0o777 == 0o700
    expected = {
        "manifest.jsonl", "summary.json", "shadow-run.json", "analyst-labels.jsonl",
        "shadow-report.json", "shadow-report.md",
    }
    assert expected.issubset({path.name for path in bundle.iterdir()})
    for path in bundle.iterdir():
        if path.is_file():
            assert os.stat(path).st_mode & 0o777 == 0o600

    persisted = "\n".join(
        path.read_text(encoding="utf-8") for path in bundle.iterdir() if path.is_file()
    )
    for secret in (
        str(sensitive_path), secret_subject, secret_sender, "payroll.example.invalid",
        "send payment",
    ):
        assert secret not in persisted
    assert "raw_message_hashes" in persisted  # only the explicit exclusion declaration

    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    run_schema = json.loads((root / "spec/shadow-run-v1.schema.json").read_text())
    report_schema = json.loads((root / "spec/shadow-report-v1.schema.json").read_text())
    jsonschema.Draft202012Validator(run_schema).validate(load_shadow_run(bundle))
    jsonschema.Draft202012Validator(report_schema).validate(build_shadow_report(bundle))


def test_labels_are_append_only_latest_wins_and_reports_exclude_uncertain(tmp_path):
    source = tmp_path / "message.eml"
    source.write_bytes(_email("Security alert", "Verify your account within 24 hours."))
    bundle = tmp_path / "pilot"
    run_shadow_inbox([source], bundle)
    entry = _manifest(bundle)[0]
    label = "fraud" if entry["risk_tier"] in {"high", "review"} else "benign"
    first = append_analyst_label(bundle, entry["case_id"], label, "confirmed_external")

    report = build_shadow_report(bundle)
    assert report["analyst_review"]["evaluated_count"] == 1
    expected_cell = "true_positive" if label == "fraud" else "true_negative"
    assert report["analyst_review"]["confusion"][expected_cell] == 1

    second = append_analyst_label(
        bundle, entry["case_id"], "uncertain", "insufficient_evidence"
    )
    events, latest = load_analyst_labels(bundle / "analyst-labels.jsonl")
    assert events == [first, second]
    assert latest[entry["case_id"]] == second
    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    label_schema = json.loads((root / "spec/shadow-label-v1.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(label_schema)
    for event in events:
        validator.validate(event)
    report = build_shadow_report(bundle)
    assert report["analyst_review"]["label_revision_count"] == 2
    assert report["analyst_review"]["evaluated_count"] == 0
    assert report["analyst_review"]["routing_recall"] is None


def test_label_log_rejects_unknown_cases_and_symlinks(tmp_path):
    source = tmp_path / "message.eml"
    source.write_bytes(_email("Team notes", "Project update."))
    bundle = tmp_path / "pilot"
    run_shadow_inbox([source], bundle)

    with pytest.raises(ValueError, match="not a processed case"):
        append_analyst_label(
            bundle, "case-0000000000000000", "benign", "known_legitimate"
        )

    label_path = bundle / "analyst-labels.jsonl"
    label_path.unlink()
    external = tmp_path / "external.jsonl"
    external.write_text("", encoding="utf-8")
    label_path.symlink_to(external)
    case_id = _manifest(bundle)[0]["case_id"]
    with pytest.raises(ValueError, match="symbolic-link"):
        append_analyst_label(bundle, case_id, "benign", "known_legitimate")
    assert external.read_text(encoding="utf-8") == ""


def test_shadow_run_rejects_tampered_bundle_paths(tmp_path):
    source = tmp_path / "message.eml"
    source.write_bytes(_email("Team notes", "Project update."))
    bundle = tmp_path / "pilot"
    run_shadow_inbox([source], bundle)
    run_path = bundle / "shadow-run.json"
    record = json.loads(run_path.read_text(encoding="utf-8"))
    record["manifest"] = "../outside.jsonl"
    run_path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe or unsupported"):
        load_shadow_run(bundle)


def test_labels_and_reports_reject_a_manifest_changed_after_processing(tmp_path):
    source = tmp_path / "message.eml"
    source.write_bytes(_email("Team notes", "Project update."))
    bundle = tmp_path / "pilot"
    run_shadow_inbox([source], bundle)
    case_id = _manifest(bundle)[0]["case_id"]
    with (bundle / "manifest.jsonl").open("a", encoding="utf-8") as stream:
        stream.write("\n")

    with pytest.raises(ValueError, match="summary digest"):
        build_shadow_report(bundle)
    with pytest.raises(ValueError, match="summary digest"):
        append_analyst_label(bundle, case_id, "benign", "known_legitimate")


def test_shadow_cli_run_label_and_report(tmp_path, capsys):
    source = tmp_path / "message.eml"
    source.write_bytes(_email("Account alert", "Verify your account within 24 hours."))
    bundle = tmp_path / "pilot"

    assert main(["shadow", "run", str(source), "--out", str(bundle)]) == 0
    assert "removed 0 duplicate" in capsys.readouterr().out
    case_id = _manifest(bundle)[0]["case_id"]
    assert main([
        "shadow", "label", str(bundle), case_id, "fraud",
        "--reason", "confirmed_external",
    ]) == 0
    assert "refreshed aggregate reports" in capsys.readouterr().out
    assert main(["shadow", "report", str(bundle)]) == 0
    assert "refreshed aggregate reports" in capsys.readouterr().out
