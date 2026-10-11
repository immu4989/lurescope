"""Unreadable or ambiguous mail cannot receive a silently complete assessment."""

import json
from email.message import EmailMessage

import pytest

from lurescope import service
from lurescope.proof import create_email_proof, verify_proof
from lurescope.triage import parse_email, triage_email


@pytest.mark.parametrize(("headers", "body", "code"), [
    (b"Content-Type: application/pkcs7-mime", b"opaque", "uninspected_body_part"),
    (b"Content-Type: text/calendar", b"opaque", "uninspected_body_part"),
    (b"Content-Type: text/plain; charset=unknown-example", b"notes", "body_decoding_uncertain"),
    (b"Content-Type: text/plain; charset=utf-8", b"notes \xff", "body_decoding_uncertain"),
    (b"Content-Transfer-Encoding: invented", b"notes", "body_decoding_uncertain"),
    (b"Content-Transfer-Encoding: quoted-printable", b"notes =ZZ", "body_decoding_uncertain"),
    (b"Content-Transfer-Encoding: base64", b"bm90ZXM", "mime_parse_defect"),
    (b"Content-Type: multipart/mixed", b"opaque", "mime_parse_defect"),
    (b"Content-Type: text/plain\nContent-Type: text/html", b"notes", "ambiguous_email_headers"),
    (b"Subject: Another subject", b"notes", "ambiguous_email_headers"),
    (b"Content-Type: text/plain; charset=utf-8; charset=ascii", b"notes", "mime_parse_defect"),
    (b"", b"", "no_readable_body"),
])
def test_inspection_gaps_route_low_content_scores_to_review(headers, body, code):
    raw = b"Subject: Project notes\n" + headers + b"\n\n" + body
    result = triage_email(raw, "heuristic-v0")
    assert result.content_label == "benign"
    assert result.risk_tier == "review"
    assert code in {item.code for item in result.evidence}
    evidence = next(item for item in result.evidence if item.code == code)
    assert evidence.severity == "medium"
    assert "not a fraud finding" in evidence.detail


def test_failed_decoding_does_not_guess_or_insert_replacement_characters(monkeypatch):
    seen = []
    original = service.score

    def tracked(text, **kwargs):
        seen.append(text)
        return original(text, **kwargs)

    monkeypatch.setattr(service, "score", tracked)
    result = triage_email(b"Subject: Notes\nContent-Type: text/plain; charset=utf-8\n\n"
                          b"confidential-raw-\xff-payload", "heuristic-v0")
    assert seen == ["Notes"]
    assert result.risk_tier == "review"


def test_readable_part_is_preserved_when_another_body_is_unsupported():
    message = EmailMessage()
    message["Subject"] = "Notes"
    message.set_content("Readable outer notes.")
    message.make_mixed()
    unknown = EmailMessage()
    unknown.set_content(b"private-opaque-payload", maintype="application", subtype="octet-stream")
    message.attach(unknown)
    parsed = parse_email(message.as_bytes())
    assert parsed.body == "Readable outer notes."
    assert parsed.inspection_gaps == ["uninspected_body_part"]
    assert triage_email(message.as_bytes(), "heuristic-v0").risk_tier == "review"


@pytest.mark.parametrize(("html", "differs"), [
    ("<p>Readable outer notes.</p>", False),
    ("<div>Readable  outer\nnotes.</div>", False),
    ("<p>Urgent verify your account within 24 hours.</p>", True),
    ("<p>Readable outer notes.</p><p>Additional content</p>", True),
    ("<p>Readable outer notes.</p><script>Ignored active content</script>", False),
])
def test_html_text_not_represented_in_scored_plain_text_requires_review(html, differs):
    message = EmailMessage()
    message["Subject"] = "Notes"
    message.set_content("Readable outer notes.")
    message.add_alternative(html, subtype="html")
    parsed = parse_email(message.as_bytes())
    assert parsed.body == "Readable outer notes."
    assert ("html_body_differs" in parsed.inspection_gaps) is differs
    result = triage_email(message.as_bytes(), "heuristic-v0")
    assert result.content_label == "benign"
    assert result.risk_tier == ("review" if differs else "low")


def test_only_one_body_representation_does_not_claim_a_disagreement():
    raw = b"Content-Type: text/html\n\n<p>Readable notes.</p>"
    assert parse_email(raw).inspection_gaps == []


@pytest.mark.parametrize("charset", ["utf-8", "iso-8859-1", "windows-1252"])
def test_supported_charsets_remain_readable_without_coverage_warning(charset):
    raw = (f"Subject: Notes\nContent-Type: text/plain; charset={charset}\n"
           "Content-Transfer-Encoding: 8bit\n\n").encode() + "Café project notes.".encode(charset)
    parsed = parse_email(raw)
    assert parsed.body == "Café project notes."
    assert parsed.inspection_gaps == []
    assert triage_email(raw, "heuristic-v0").evidence == []


def test_attachment_payload_defects_are_not_audited_or_decoded(monkeypatch):
    from lurescope import triage

    outer = EmailMessage()
    outer["Subject"] = "Notes"
    outer.set_content("Readable notes.")
    inner = EmailMessage()
    inner.set_content("Private inner body.")
    inner.replace_header("Content-Type", "multipart/mixed")
    outer.add_attachment(inner, filename="inner.eml")
    original = triage._part_text

    def checked(part, gaps):
        assert "Private" not in str(part.get_payload())
        return original(part, gaps)

    monkeypatch.setattr(triage, "_part_text", checked)
    parsed = parse_email(outer.as_bytes())
    assert parsed.body == "Readable notes."
    assert parsed.inspection_gaps == []


def test_proof_binds_review_cues_without_leaking_undecodable_content():
    raw = (b"Subject: private-subject\nContent-Type: text/plain; charset=unknown-example"
           b"\n\nprivate-body")
    proof = create_email_proof(raw, "heuristic-v0", created_at="2026-10-10T12:00:00Z")
    assert verify_proof(proof)["valid"]
    assessment = proof["predicate"]["assessment"]
    assert assessment["label"] == "benign"
    assert assessment["risk_tier"] == "review"
    assert set(assessment["evidence_codes"]) == {"body_decoding_uncertain", "no_readable_body"}
    assert "private-subject" not in json.dumps(proof)
    assert "private-body" not in json.dumps(proof)


def test_unreadable_message_without_subject_still_fails_without_a_decision():
    with pytest.raises(ValueError, match="no subject or readable text"):
        triage_email(b"Content-Type: application/pkcs7-mime\n\nopaque", "heuristic-v0")


def test_api_preserves_coverage_cues():
    from fastapi.testclient import TestClient

    from lurescope.app import app

    with TestClient(app) as client:
        response = client.post("/triage/email", json={
            "raw_email": "Subject: Notes\nContent-Type: application/pkcs7-mime\n\nopaque",
            "detector": "heuristic-v0",
        })
    assert response.status_code == 200
    result = response.json()
    assert result["risk_tier"] == "review"
    assert {item["code"] for item in result["evidence"]} == {
        "no_readable_body", "uninspected_body_part",
    }


def test_inbox_routes_opaque_mail_to_review_and_keeps_payload_private(tmp_path):
    from lurescope.inbox import process_inbox

    output = tmp_path / "cases"
    raw = b"Subject: private-subject\nContent-Type: application/pkcs7-mime\n\nprivate-body"
    run = process_inbox([("private-path.eml", raw)], output, detector_name="heuristic-v0")
    assert run.failed_count == 0
    assert run.summary["risk_counts"] == {"low": 0, "review": 1, "high": 0}
    entry = json.loads((output / "manifest.jsonl").read_text())
    assert entry["recommended_action"] == "hold_and_verify_sender"
    for artifact in output.iterdir():
        serialized = artifact.read_text()
        assert all(secret not in serialized for secret in (
            "private-subject", "private-body", "private-path",
        ))
