"""Repeated findings remain detailed locally and project to unique proof codes."""

import base64
import copy
import json
from email.message import EmailMessage
from pathlib import Path

import pytest

from lurescope.proof import create_email_proof, generate_keypair, verify_proof
from lurescope.triage import triage_email


def repeated_message(kind):
    message = EmailMessage()
    message["Subject"] = "Private project note"
    message["From"] = "private-sender@example.test"
    urls, filenames = [], []
    if kind in {"ip", "mixed", "many"}:
        urls += [f"http://192.0.2.{i}/private-path" for i in range(1, 41 if kind == "many" else 3)]
    if kind in {"punycode", "mixed"}:
        urls += ["https://xn--bcher-kva.example/private-path", "https://xn--caf-dma.example/private-path"]
    if kind in {"executable", "mixed"}:
        filenames += ["private-one.exe", "private-two.js"]
    if kind in {"archive", "mixed"}:
        filenames += ["private-one.zip", "private-two.tar"]
    message.set_content("Private body notes. " + " ".join(urls))
    for filename in filenames:
        message.add_attachment(b"private-attachment-bytes", maintype="application",
                               subtype="octet-stream", filename=filename)
    return message.as_bytes(), len(urls), len(filenames)


KINDS = ["ip", "punycode", "executable", "archive", "mixed", "many"]


def assert_private(value):
    serialized = json.dumps(value)
    for secret in ("Private project note", "private-sender", "Private body", "private-path",
                   "192.0.2.", "xn--bcher", "private-one", "private-two",
                   "private-attachment-bytes", "private-source.eml"):
        assert secret not in serialized


def test_multiple_ip_links_create_valid_proof_without_losing_triage_findings():
    raw = b"Subject: Project notes\n\nLinks: http://192.0.2.1/ and http://192.0.2.2/"
    triage = triage_email(raw, "heuristic-v0")
    assert [item.code for item in triage.evidence] == ["ip_literal_url", "ip_literal_url"]
    statement = create_email_proof(raw, detector_name="heuristic-v0")
    assert verify_proof(statement)["valid"]
    assessment = statement["predicate"]["assessment"]
    assert assessment["evidence_codes"] == ["ip_literal_url"]
    assert assessment["url_count"] == 2
    assert assessment["risk_tier"] == "review"


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("detector", ["heuristic-v0", "tfidf-logreg"])
def test_projection_preserves_categories_counts_order_risk_and_privacy(kind, detector):
    raw, url_count, attachment_count = repeated_message(kind)
    triage = triage_email(raw, detector)
    codes = [item.code for item in triage.evidence]
    assert len(codes) > len(set(codes))
    assert len({item.detail for item in triage.evidence}) == len(codes)
    statement = create_email_proof(raw, detector_name=detector)
    assert verify_proof(statement)["valid"]
    assessment = statement["predicate"]["assessment"]
    assert assessment["evidence_codes"] == list(dict.fromkeys(codes))
    assert assessment["url_count"] == url_count
    assert assessment["attachment_count"] == attachment_count
    assert assessment["risk_tier"] == triage.risk_tier
    assert assessment["fraud_probability"] == triage.content_probability
    assert assessment["label"] == triage.content_label
    assert_private(statement)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("encoding", ["raw_email", "raw_email_base64"])
def test_api_projects_repeated_findings_without_error(kind, encoding):
    from fastapi.testclient import TestClient

    from lurescope.app import app

    raw, url_count, attachment_count = repeated_message(kind)
    payload = raw.decode() if encoding == "raw_email" else base64.b64encode(raw).decode()
    with TestClient(app) as client:
        response = client.post("/proof/email", json={encoding: payload, "detector": "heuristic-v0"})
    assert response.status_code == 200, response.text
    statement = response.json()
    assert verify_proof(statement)["valid"]
    assessment = statement["predicate"]["assessment"]
    assert assessment["url_count"] == url_count
    assert assessment["attachment_count"] == attachment_count
    assert len(assessment["evidence_codes"]) == len(set(assessment["evidence_codes"]))
    assert_private(statement)


def test_repeated_findings_survive_signed_proof_and_tampering_is_rejected(tmp_path):
    private, public = tmp_path / "issuer.pem", tmp_path / "issuer.pub.pem"
    generate_keypair(private, public)
    raw, _, _ = repeated_message("mixed")
    proof = create_email_proof(
        raw, detector_name="heuristic-v0", signing_key_pem=private.read_bytes(),
    )
    assert verify_proof(proof, public.read_bytes(), require_signature=True)["authenticated"]
    statement = json.loads(base64.b64decode(proof["payload"]))
    assert len(statement["predicate"]["assessment"]["evidence_codes"]) == 4
    assert_private(statement)
    statement["predicate"]["assessment"]["attachment_count"] += 1
    tampered = {**proof, "payload": base64.b64encode(json.dumps(statement).encode()).decode()}
    assert not verify_proof(tampered, public.read_bytes(), require_signature=True)["valid"]


def test_verifiers_still_reject_duplicate_categories_in_supplied_artifacts(tmp_path):
    from lurescope.inbox import process_inbox
    from lurescope.integrations import load_inbox_manifest, render_export

    raw, _, _ = repeated_message("mixed")
    statement = create_email_proof(raw, detector_name="heuristic-v0")
    statement["predicate"]["assessment"]["evidence_codes"].append("ip_literal_url")
    assert not verify_proof(statement)["valid"]
    output = tmp_path / "inbox"
    process_inbox([("private-source.eml", raw)], output, detector_name="heuristic-v0")
    entries = load_inbox_manifest(output / "manifest.jsonl")
    forged = copy.deepcopy(entries)
    forged[0]["assessment"]["evidence_codes"].append("ip_literal_url")
    with pytest.raises(ValueError):
        render_export(forged, "json-array")


def test_inbox_and_all_export_formats_process_repeated_categories_privately(tmp_path):
    from lurescope.inbox import process_inbox
    from lurescope.integrations import EXPORT_FORMATS, load_inbox_manifest, render_export

    output = tmp_path / "inbox"
    messages = [("private-source.eml", repeated_message(kind)[0]) for kind in KINDS]
    run = process_inbox(messages, output, detector_name="heuristic-v0")
    assert run.failed_count == 0 and run.summary["processed_count"] == len(KINDS)
    assert run.summary["risk_counts"] == {"low": 0, "review": 4, "high": 2}
    entries = load_inbox_manifest(output / "manifest.jsonl")
    schema_path = Path(__file__).resolve().parents[1] / "spec/inbox-event-v1.schema.json"
    schema = json.loads(schema_path.read_text())
    import jsonschema

    for entry, kind in zip(entries, KINDS, strict=True):
        jsonschema.validate(entry, schema)
        assert entry["status"] == "processed"
        _, urls, attachments = repeated_message(kind)
        assert entry["assessment"]["url_count"] == urls
        assert entry["assessment"]["attachment_count"] == attachments
        statement = json.loads((output / entry["proof"]["file"]).read_text())
        assert verify_proof(statement)["valid"]
        assert (statement["predicate"]["assessment"]["evidence_codes"]
                == entry["assessment"]["evidence_codes"])
        assert_private(statement)
    for output_format in EXPORT_FORMATS:
        serialized = render_export(entries, output_format).decode()
        assert_private(serialized)
        rows = ([json.loads(line) for line in serialized.splitlines()]
                if output_format in {"splunk-hec", "ecs-9.4"} else json.loads(serialized))
        assert rows
    for artifact in output.iterdir():
        assert_private(artifact.read_text())


def test_cli_proof_handles_multiple_findings(tmp_path, capsys):
    from lurescope.cli import main

    path, output = tmp_path / "private-source.eml", tmp_path / "proof.json"
    path.write_bytes(repeated_message("mixed")[0])
    assert main(["proof", str(path), "--detector", "heuristic-v0", "--out", str(output)]) == 0
    assert "created" in capsys.readouterr().out
    statement = json.loads(output.read_text())
    assert verify_proof(statement)["valid"]
    assert len(statement["predicate"]["assessment"]["evidence_codes"]) == 4
    assert_private(statement)


@pytest.mark.parametrize("body", [
    "Ordinary notes.", "http://192.0.2.1/",
    "https://xn--bcher-kva.example/ and http://192.0.2.1/",
])
def test_already_unique_categories_keep_their_original_order(body):
    import jsonschema

    raw = ("Subject: Notes\n\n" + body).encode()
    triage = triage_email(raw, "heuristic-v0")
    statement = create_email_proof(raw, detector_name="heuristic-v0")
    assert statement["predicate"]["assessment"]["evidence_codes"] == [
        item.code for item in triage.evidence
    ]
    schema_path = Path(__file__).resolve().parents[1] / "spec/lureproof.schema.json"
    jsonschema.validate(statement, json.loads(schema_path.read_text()))


def test_shadow_report_counts_messages_per_category_not_individual_findings(tmp_path):
    from lurescope.shadow import build_shadow_report, run_shadow_inbox

    sources = tmp_path / "source"
    sources.mkdir()
    for kind in ("ip", "many", "mixed"):
        (sources / f"{kind}.eml").write_bytes(repeated_message(kind)[0])
    output = tmp_path / "shadow"
    run_shadow_inbox([sources], output, detector_name="heuristic-v0")
    report = build_shadow_report(output)
    assert report["volume"]["processed_count"] == 3
    assert report["volume"]["failed_count"] == 0
    assert report["evidence"]["code_counts"] == {
        "ip_literal_url": 3, "punycode_url": 1,
        "executable_attachment": 1, "archive_attachment": 1,
    }
    assert_private(report)
