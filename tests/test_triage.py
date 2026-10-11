"""Real-world email triage tests with safe, defanged messages."""

from __future__ import annotations

from email.message import EmailMessage

import pytest

pytest.importorskip("sklearn")

from lurescope.triage import EmailTooLarge, parse_email, triage_email


def test_triage_files_uses_bounded_regular_intake(tmp_path, monkeypatch):
    from lurescope import triage

    source = tmp_path / "valid.eml"
    raw = b"Subject: Team notes\n\nPlease review the notes."
    source.write_bytes(raw)
    calls = []
    monkeypatch.setattr(triage, "triage_email", lambda data, **kw: calls.append((data, kw)))
    assert triage.triage_files([source], detector_name="keyword") == [None]
    assert calls == [(raw, {"detector_name": "keyword"})]
    calls.clear()
    alias = tmp_path / "alias.eml"
    alias.symlink_to(source)
    with pytest.raises(ValueError, match="regular non-symlink"):
        triage.triage_files([alias])
    monkeypatch.setattr(triage, "MAX_EMAIL_BYTES", len(raw) - 1)
    with pytest.raises(ValueError, match="bounded size"):
        triage.triage_files([source])
    assert calls == []


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


@pytest.mark.parametrize("disposition", ["attachment", "inline", None])
def test_embedded_message_never_contributes_body_or_nested_filenames(disposition, monkeypatch):
    from lurescope import triage

    outer = _message(body="Outer notes only.")
    inner = _message(body="Private attachment https://example.org/private")
    inner.add_attachment(b"not executed", maintype="application", subtype="octet-stream",
                         filename="nested.js")
    outer.add_attachment(inner, filename="forwarded.eml")
    embedded = outer.get_payload()[-1]
    del embedded["Content-Disposition"]
    if disposition:
        embedded.add_header("Content-Disposition", disposition, filename="forwarded.eml")
    original = triage._part_text
    decoded = []

    def checked(part, gaps):
        result = original(part, gaps)
        decoded.append(result)
        assert "Private attachment" not in result
        return result

    monkeypatch.setattr(triage, "_part_text", checked)
    parsed = parse_email(outer.as_bytes())
    assert parsed.body == "Outer notes only."
    assert parsed.urls == []
    assert parsed.attachments == (["forwarded.eml"] if disposition else [])
    assert len(decoded) == 1


@pytest.mark.parametrize("multipart", [False, True])
@pytest.mark.parametrize("disposition", ["attachment", "inline", None])
def test_named_parts_are_not_scored_even_without_attachment_disposition(multipart, disposition):
    outer = _message(body="Outer notes only.")
    part = EmailMessage()
    part.set_content("<a href='https://example.org/private'>Hidden</a><img src='cid:x'>",
                     subtype="html")
    if multipart:
        part.make_mixed()
    part.set_param("name", "attached.html")
    if disposition:
        part["Content-Disposition"] = disposition
    outer.make_mixed()
    outer.attach(part)
    parsed = parse_email(outer.as_bytes())
    assert parsed.body == "Outer notes only."
    assert parsed.urls == []
    assert parsed.inline_image_count == 0
    assert parsed.html_visible_text_length == 0
    assert parsed.attachments == ["attached.html"]


def test_regular_nested_multipart_body_is_still_readable():
    outer = _message(body="Outer notes only.")
    outer.add_alternative("<p>Outer notes only.</p>", subtype="html")
    outer.make_mixed()
    parsed = parse_email(outer.as_bytes())
    assert parsed.body == "Outer notes only."
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


@pytest.mark.parametrize("url", ["http://[broken", "http://[not-an-ip]/", "http:///missing-host"])
def test_malformed_links_route_to_review_instead_of_crashing_or_disappearing(url):
    raw = _message(body=f"Project notes {url} and https://127.0.0.1/notes").as_bytes()
    result = triage_email(raw, "heuristic-v0")
    codes = {item.code for item in result.evidence}
    assert {"malformed_url", "ip_literal_url"} <= codes
    assert result.risk_tier in {"review", "high"}
    detail = next(item.detail for item in result.evidence if item.code == "malformed_url")
    assert "1 extracted link" in detail
    assert url not in detail


def test_oversized_email_fails_before_parsing():
    with pytest.raises(EmailTooLarge):
        parse_email(b"x" * 101, max_bytes=100)


def test_empty_email_fails_closed():
    with pytest.raises(ValueError, match="no subject or readable text"):
        triage_email(b"From: empty@example.org\n\n")


def test_long_readable_text_fails_before_scoring_or_creating_partial_proof(monkeypatch):
    from lurescope import service
    from lurescope.proof import create_email_proof
    from lurescope.triage import MAX_SCORE_TEXT

    def unexpected_score(*args, **kwargs):
        pytest.fail("over-limit email reached the detector")

    monkeypatch.setattr(service, "score", unexpected_score)
    raw = _message(body="ordinary notes " * MAX_SCORE_TEXT).as_bytes()
    for operation in (triage_email, create_email_proof):
        with pytest.raises(ValueError, match="scoring limit"):
            operation(raw)


def test_exact_text_budget_scores_the_complete_message(monkeypatch):
    from lurescope import service
    from lurescope.triage import MAX_SCORE_TEXT

    original = service.score
    seen = []

    def tracked(text, **kwargs):
        seen.append(text)
        return original(text, **kwargs)

    monkeypatch.setattr(service, "score", tracked)
    text = "a" * MAX_SCORE_TEXT
    result = triage_email(b"Content-Type: text/plain\r\n\r\n" + text.encode(), "heuristic-v0")
    assert seen == [text]
    assert result.threshold == .5
