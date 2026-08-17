"""Real-world email triage tests with safe, defanged messages."""

from __future__ import annotations

from email.message import EmailMessage

import pytest

pytest.importorskip("sklearn")

from lurescope.triage import EmailTooLarge, parse_email, triage_email


def _message(
    body="Please review the project notes before Thursday.",
    subject="Project review",
    sender="Alex <alex@example.org>",
    reply_to=None,
):
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = "team@example.org"
    message["Message-ID"] = "<safe-1@example.org>"
    if reply_to:
        message["Reply-To"] = reply_to
    message.set_content(body)
    return message


def test_parse_email_extracts_headers_body_urls_without_fetching():
    raw = _message(body="Review https://example.org/notes before Thursday.").as_bytes()
    parsed = parse_email(raw)
    assert parsed.subject == "Project review"
    assert parsed.from_address == "alex@example.org"
    assert parsed.urls == ["https://example.org/notes"]
    assert parsed.attachments == []


def test_html_fallback_ignores_active_content():
    message = EmailMessage()
    message["From"] = "sender@example.org"
    message["To"] = "user@example.org"
    message["Subject"] = "HTML only"
    message.set_content(
        "<html><head><style>secret</style><script>alert(1)</script></head>"
        "<body><p>Visible message</p><a href='https://xn--example-9za.test/login'>"
        "Open portal</a></body></html>",
        subtype="html",
    )
    parsed = parse_email(message.as_bytes())
    assert "Visible message" in parsed.body
    assert "alert" not in parsed.body
    assert "secret" not in parsed.body
    assert parsed.urls == ["https://xn--example-9za.test/login"]


def test_inline_qr_language_routes_review_without_decoding_image_payload():
    message = EmailMessage()
    message["From"] = "benefits@example.org"
    message["To"] = "user@example.org"
    message["Subject"] = "Benefits enrollment"
    message.set_content(
        "<html><body><p>Scan this QR code to continue.</p>"
        "<img src='cid:code' alt='Enrollment QR code'></body></html>",
        subtype="html",
    )

    parsed = parse_email(message.as_bytes())
    assert parsed.inline_image_count == 1
    assert "Enrollment QR code" in parsed.body
    result = triage_email(message.as_bytes())
    assert "qr_lure_cue" in {item.code for item in result.evidence}
    assert result.risk_tier in {"review", "high"}
    detail = next(item.detail for item in result.evidence if item.code == "qr_lure_cue")
    assert "not decoded" in detail


def test_image_dominant_html_is_flagged_for_human_review():
    message = EmailMessage()
    message["From"] = "notices@example.org"
    message["To"] = "user@example.org"
    message["Subject"] = "Notice"
    message.set_content(
        "<html><body><img src='cid:notice' alt='Open notice'></body></html>",
        subtype="html",
    )

    result = triage_email(message.as_bytes())
    assert "image_dominant_html" in {item.code for item in result.evidence}
    assert result.risk_tier in {"review", "high"}


def test_triage_keeps_model_and_context_evidence_separate():
    message = _message(
        body="Urgent: verify your account at http://xn--paypa-4ve.example/login within 24 hours.",
        subject="Final account notice",
        sender="Security <alerts@example.org>",
        reply_to="collect@other.example",
    )
    message["Authentication-Results"] = "mx.example; spf=fail; dkim=fail; dmarc=fail"
    message.add_attachment(b"not executed", maintype="application", subtype="octet-stream",
                           filename="invoice.js")
    result = triage_email(message.as_bytes())
    codes = {item.code for item in result.evidence}
    assert result.risk_tier == "high"
    assert result.content_probability >= 0
    assert {"reply_to_domain_mismatch", "punycode_url", "email_authentication_failed",
            "executable_attachment"} <= codes
    assert result.attachments == ["invoice.js"]


def test_low_risk_email_still_recommends_normal_controls():
    result = triage_email(_message().as_bytes())
    assert result.risk_tier in {"low", "review"}  # content model may be conservative
    assert result.evidence == []
    assert result.recommended_action


def test_oversized_email_fails_before_parsing():
    with pytest.raises(EmailTooLarge):
        parse_email(b"x" * 101, max_bytes=100)


def test_empty_email_fails_closed():
    with pytest.raises(ValueError, match="no subject or readable text"):
        triage_email(b"From: empty@example.org\n\n")
