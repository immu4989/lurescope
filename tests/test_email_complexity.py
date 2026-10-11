"""Bound MIME tree construction before extraction, scoring, or proof creation."""

import base64
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from lurescope import service, triage
from lurescope.proof import create_email_proof
from lurescope.triage import (
    MAX_EMAIL_BYTES,
    MAX_EMAIL_DEPTH,
    MAX_EMAIL_PARTS,
    EmailTooComplex,
    parse_email,
)


def nested_message(levels, kind="message/rfc822", newline=b"\n"):
    raw = b"Content-Type: text/plain\n\nNotes"
    for number in range(levels - 1):
        if kind.startswith("multipart/"):
            boundary = f"level-{number}".encode()
            raw = (b"Content-Type: " + kind.encode() + b"; boundary=" + boundary
                   + b"\n\n--" + boundary + b"\n" + raw
                   + b"\n--" + boundary + b"--\n")
        else:
            raw = b"Content-Type: " + kind.encode() + b"\n\n" + raw
    return (b"Subject: Private subject\n" + raw).replace(b"\n", newline)


def wide_message(parts, *, attachment=False, delivery_status=False):
    if delivery_status:
        # Delivery-status uses one child message per header block.
        return (b"Subject: Notes\nContent-Type: message/delivery-status\n\n"
                + b"\n\n".join([b"Reporting-MTA: dns; example.test"] * (parts - 1)))
    child = b"Content-Type: text/plain\n\nNotes"
    if attachment:
        child = b"Content-Disposition: attachment; filename=note.txt\n" + child
    return (b"Subject: Notes\nContent-Type: multipart/mixed; boundary=wide\n\n"
            + b"".join(b"--wide\n" + child + b"\n" for _ in range(parts - 1))
            + b"--wide--\n")


def test_documented_structure_limits():
    assert MAX_EMAIL_DEPTH == 32
    assert MAX_EMAIL_PARTS == 256


@pytest.mark.parametrize("kind", ["message/rfc822", "multipart/mixed", "multipart/digest"])
@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
def test_depth_boundary_includes_root_and_checks_before_descent(kind, newline):
    assert parse_email(nested_message(MAX_EMAIL_DEPTH, kind, newline)).subject == "Private subject"
    raw = nested_message(MAX_EMAIL_DEPTH + 1, kind, newline)
    assert len(raw) < MAX_EMAIL_BYTES
    with pytest.raises(EmailTooComplex, match=f"depth exceeds {MAX_EMAIL_DEPTH}"):
        parse_email(raw)


@pytest.mark.parametrize("options", [{}, {"attachment": True}, {"delivery_status": True}])
def test_part_boundary_includes_root_attachments_and_delivery_status(options):
    assert parse_email(wide_message(MAX_EMAIL_PARTS, **options)).subject == "Notes"
    with pytest.raises(EmailTooComplex, match=f"part count exceeds {MAX_EMAIL_PARTS}"):
        parse_email(wide_message(MAX_EMAIL_PARTS + 1, **options))


def test_factory_stops_before_allocating_part_beyond_limit(monkeypatch):
    created = []
    original = triage._BoundedEmailMessage.__init__

    def tracked(self, *args, **kwargs):
        created.append(self)
        original(self, *args, **kwargs)

    monkeypatch.setattr(triage._BoundedEmailMessage, "__init__", tracked)
    with pytest.raises(EmailTooComplex, match="part count"):
        parse_email(wide_message(MAX_EMAIL_PARTS + 100))
    assert len(created) == MAX_EMAIL_PARTS


def test_depth_limit_stops_before_reading_rejected_child_headers(monkeypatch):
    seen = []
    original = triage._BoundedEmailMessage.set_raw

    def tracked(self, name, value):
        seen.append((name, value))
        return original(self, name, value)

    monkeypatch.setattr(triage._BoundedEmailMessage, "set_raw", tracked)
    raw = (b"Content-Type: message/rfc822\n\n" * MAX_EMAIL_DEPTH
           + b"Subject: Must not parse this child\n\nNotes")
    with pytest.raises(EmailTooComplex, match="depth"):
        parse_email(raw)
    assert all("Must not parse" not in value for _, value in seen)


def test_implicit_digest_messages_count_as_nodes(monkeypatch):
    raw = (b"Subject: Notes\nContent-Type: multipart/digest; boundary=digest\n\n"
           b"--digest\n\nSubject: Inner\n\nNotes\n--digest--\n")
    monkeypatch.setattr(triage, "MAX_EMAIL_PARTS", 3)
    assert parse_email(raw).subject == "Notes"
    monkeypatch.setattr(triage, "MAX_EMAIL_PARTS", 2)
    with pytest.raises(EmailTooComplex, match="part count"):
        parse_email(raw)


def test_limits_apply_inside_attachment_before_body_exclusion():
    raw = (b"Subject: Notes\nContent-Type: multipart/mixed; boundary=outer\n\n"
           b"--outer\nContent-Type: text/plain\n\nReadable outer notes\n"
           b"--outer\nContent-Disposition: attachment; filename=private.eml\n"
           + nested_message(MAX_EMAIL_DEPTH) + b"\n--outer--\n")
    with pytest.raises(EmailTooComplex, match="depth"):
        parse_email(raw)


@pytest.mark.parametrize("operation", [triage.triage_email, create_email_proof])
def test_extreme_depth_is_rejected_without_scoring_or_a_partial_result(monkeypatch, operation):
    raw = nested_message(1200)
    assert len(raw) < 50_000  # Reproduced RecursionError with the unbounded parser.

    def forbidden(*args, **kwargs):
        pytest.fail("over-complex input must not reach the detector")

    monkeypatch.setattr(service, "score", forbidden)
    with pytest.raises(EmailTooComplex, match="depth"):
        operation(raw, "heuristic-v0")


def test_per_message_counters_are_independent_after_failures_and_in_parallel():
    def run(index):
        with pytest.raises(EmailTooComplex):
            parse_email(wide_message(MAX_EMAIL_PARTS + 1))
        return parse_email(wide_message(MAX_EMAIL_PARTS)).subject

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(run, range(8))) == ["Notes"] * 8


@pytest.mark.parametrize("endpoint", ["/triage/email", "/proof/email"])
@pytest.mark.parametrize("as_base64", [False, True])
def test_api_reports_rejected_input_without_a_partial_decision(endpoint, as_base64, monkeypatch):
    from fastapi.testclient import TestClient

    from lurescope.app import app

    def forbidden(*args, **kwargs):
        pytest.fail("rejected mail must not reach the detector")

    monkeypatch.setattr(service, "score", forbidden)
    raw = nested_message(1200)
    payload = ({"raw_email_base64": base64.b64encode(raw).decode()} if as_base64
               else {"raw_email": raw.decode()})
    with TestClient(app) as client:
        response = client.post(endpoint, json={
            **payload, "detector": "heuristic-v0",
        })
    assert response.status_code == 400
    assert set(response.json()) == {"detail"}
    assert "rejected input" in response.json()["detail"]
    assert "Private subject" not in response.text


def test_inbox_records_private_error_and_continues_with_valid_mail(tmp_path):
    from lurescope.inbox import process_inbox

    output = tmp_path / "cases"
    run = process_inbox([
        ("private-path.eml", nested_message(1200)),
        ("good.eml", b"Subject: Notes\n\nOrdinary project notes."),
    ], output, detector_name="heuristic-v0")
    assert run.failed_count == 1
    entries = [json.loads(line) for line in (output / "manifest.jsonl").read_text().splitlines()]
    assert entries[0]["error_type"] == "EmailTooComplex"
    assert "risk_tier" not in entries[0]
    assert entries[1]["status"] == "processed"
    assert len(list(output.glob("*.lureproof.json"))) == 1
    for artifact in output.iterdir():
        assert "Private subject" not in artifact.read_text()
        assert "private-path" not in artifact.read_text()


def test_cli_reports_one_failure_and_continues_batch(tmp_path, capsys):
    from lurescope.cli import main

    bad, good = tmp_path / "bad.eml", tmp_path / "good.eml"
    bad.write_bytes(nested_message(1200))
    good.write_bytes(b"Subject: Notes\n\nOrdinary project notes.")
    assert main(["triage", str(bad), str(good), "--json", "--detector", "heuristic-v0"]) == 1
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert "EmailTooComplex" in rows[0]["error"]
    assert "Private subject" not in rows[0]["error"]
    assert rows[1]["risk_tier"] == "low"
