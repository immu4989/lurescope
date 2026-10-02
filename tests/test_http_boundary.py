"""Exercise real ASGI chunking separately from HTTP client header handling."""

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from lurescope.app import app
from lurescope.http_boundary import MAX_REQUEST_BODY_BYTES, RequestBodyLimit


def exercise(messages, *, headers=(), maximum=8, scope_type="http"):
    received = []
    sent = []
    pending = iter(messages)

    async def receive():
        return next(pending)

    async def send(message):
        sent.append(message)

    async def downstream(scope, receive, send):
        received.append(scope)
        if scope["type"] == "http":
            received.append(await receive())

    asyncio.run(RequestBodyLimit(downstream, maximum)(
        {"type": scope_type, "headers": list(headers)}, receive, send,
    ))
    return received, sent


def chunk(body, more=False):
    return {"type": "http.request", "body": body, "more_body": more}


@pytest.mark.parametrize("headers", [[], [(b"Content-Length", b"8")]])
def test_exact_limit_passes_and_reassembles_chunks(headers):
    received, sent = exercise([chunk(b"123", True), chunk(b"", True), chunk(b"45678")],
                              headers=headers)
    assert received[1] == chunk(b"12345678")
    assert sent == []


@pytest.mark.parametrize("headers", [[], [(b"content-length", b"1")]])
def test_streamed_or_underdeclared_overflow_never_reaches_application(headers):
    received, sent = exercise([chunk(b"1234", True), chunk(b"56789")], headers=headers)
    assert not received
    assert sent[0]["status"] == 413


@pytest.mark.parametrize("headers,status", [
    ([(b"content-length", b"9")], 413),
    ([(b"content-length", b"-1")], 400),
    ([(b"content-length", b"1.0")], 400),
    ([(b"content-length", b"+1")], 400),
    ([(b"content-length", b"")], 400),
    ([(b"content-length", b"9" * 10000)], 400),
    ([(b"content-length", b"1"), (b"Content-Length", b"1")], 400),
    ([(b"content-encoding", b"gzip")], 415),
    ([(b"content-encoding", b"br")], 415),
])
def test_invalid_headers_reject_without_reading_body(headers, status):
    received, sent = exercise([], headers=headers)
    assert not received
    assert sent[0]["status"] == status


def test_declared_length_must_equal_actual_bytes():
    received, sent = exercise([chunk(b"one")], headers=[(b"content-length", b"4")])
    assert not received
    assert sent[0]["status"] == 400


def test_identity_content_encoding_is_allowed():
    received, sent = exercise([chunk(b'"one"')], headers=[(b"content-encoding", b"identity")])
    assert received[1]["body"] == b'"one"'
    assert not sent


def test_disconnected_partial_body_never_reaches_route():
    received, sent = exercise([chunk(b"one", True), {"type": "http.disconnect"}])
    assert not received and not sent


def test_lifespan_is_passed_through_without_body_processing():
    received, sent = exercise([], scope_type="lifespan")
    assert received[0]["type"] == "lifespan"
    assert not sent


@pytest.mark.parametrize("bad", [True, False, 0, -1, 1.5, "8"])
def test_invalid_limits_rejected(bad):
    with pytest.raises(ValueError):
        RequestBodyLimit(None, bad)


@pytest.mark.parametrize("endpoint", ["/score", "/attack", "/triage/email", "/proof/email",
                                      "/proof/verify", "/unknown"])
def test_application_rejects_oversize_before_routing(endpoint):
    response = TestClient(app).post(endpoint, content=b"x",
                                    headers={"Content-Length": str(MAX_REQUEST_BODY_BYTES + 1)})
    assert response.status_code == 413
    assert response.json() == {"detail": "request body exceeds the application byte limit"}


@pytest.mark.parametrize("payload", [
    {"text": {"PRIVATE_EMAIL_CONTENT": "secret"}},
    {"text": "PRIVATE_EMAIL_CONTENT" * 2000},
    {"text": "hello", "threshold": "PRIVATE_EMAIL_CONTENT"},
])
def test_validation_errors_do_not_echo_submitted_values(payload, monkeypatch):
    monkeypatch.delenv("LURESCOPE_PUBLIC_MODE", raising=False)
    monkeypatch.delenv("LURESCOPE_API_KEY_SCRYPT", raising=False)
    response = TestClient(app).post("/score", json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "request validation failed"}
    assert "PRIVATE_EMAIL_CONTENT" not in response.text


def test_malformed_json_error_is_redacted():
    response = TestClient(app).post("/score", content=b'{"PRIVATE_EMAIL_CONTENT": broken}',
                                    headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert json.loads(response.text) == {"detail": "request validation failed"}


@pytest.mark.parametrize("content_type", [None, "application/json", "application/example+json"])
@pytest.mark.parametrize("payload", [
    b'{"text":"hello", "threshold":0.1, "threshold":0.9}',
    b'{"text":"hello", "threshold":NaN}',
    b'{"text":"hello", "threshold":1e999}',
    b'{"proof":{"PRIVATE_SENTINEL":1,"PRIVATE_SENTINEL":2}}',
    b'{"proof":' + b'[' * 130 + b'0' + b']' * 130 + b'}',
])
def test_ambiguous_json_rejected_before_framework_decoding(payload, content_type):
    headers = {"Content-Type": content_type} if content_type else {}
    response = TestClient(app).post("/score", content=payload, headers=headers)
    assert response.status_code == 422
    assert response.json() == {"detail": "request validation failed"}


@pytest.mark.parametrize("endpoint,payload", [
    ("/score", {"text": "hello", "threshold": True}),
    ("/score", {"text": "hello", "threshold": "0.5"}),
    ("/score", {"text": "hello", "detetor": "typo"}),
    ("/attack", {"text": "hello", "attack": "homoglyph", "threshold": False}),
    ("/proof/verify", {"proof": {}, "require_signature": "false"}),
    ("/proof/verify", {"proof": {}, "require_signature": 0}),
    ("/proof/verify", {"proof": {}, "public_key_pem": "\ud800"}),
    ("/score", {"text": "\ud800"}),
    ("/score", {"text": "hello", "detector": "x" * 513}),
])
def test_request_controls_are_strict_and_unknown_fields_rejected(endpoint, payload, monkeypatch):
    monkeypatch.delenv("LURESCOPE_PUBLIC_MODE", raising=False)
    monkeypatch.delenv("LURESCOPE_API_KEY_SCRYPT", raising=False)
    response = TestClient(app).post(endpoint, content=json.dumps(payload).encode(),
                                    headers={"Content-Type": "application/json"})
    assert response.status_code == 422


def test_explicit_text_and_email_limits_override_identifier_default():
    from lurescope.models import EmailTriageRequest, ScoreRequest

    assert len(ScoreRequest(text="x" * 20000, threshold=0).text) == 20000
    assert ScoreRequest(text="ok", threshold=1).threshold == 1.
    assert len(EmailTriageRequest(raw_email="x" * 30000).raw_email) == 30000


def test_email_base64_bound_checks_decoded_bytes_not_just_encoded_length():
    import base64

    from pydantic import ValidationError

    from lurescope.models import MAX_EMAIL_INPUT_BYTES, EmailTriageRequest
    from lurescope.triage import MAX_EMAIL_BYTES

    assert MAX_EMAIL_INPUT_BYTES == MAX_EMAIL_BYTES
    maximum = b"a" * MAX_EMAIL_BYTES
    request = EmailTriageRequest(raw_email_base64=base64.b64encode(maximum).decode())
    assert request.email_bytes() == maximum
    with pytest.raises(ValidationError):
        EmailTriageRequest(raw_email_base64=base64.b64encode(maximum + b"a").decode())
    # Legacy Unicode text is bounded by its actual UTF-8 bytes too.
    with pytest.raises(ValidationError):
        EmailTriageRequest(raw_email="é" * (MAX_EMAIL_BYTES // 2 + 1))
