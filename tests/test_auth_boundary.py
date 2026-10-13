"""Bound unauthenticated work without weakening key verification or accepting ambiguity."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from lurescope import security
from lurescope.app import app

KEY = "synthetic-client-key-" + "k" * 32


def verifier(i=0):
    return security.ApiKeyVerifier(1 << 14, 8, 1, bytes([i]) * 16, bytes([i]) * 32)


@pytest.mark.parametrize("headers", [
    [(b"authorization", f"Bearer {KEY}".encode()), (b"authorization", b"Bearer second")],
    [(b"authorization", f"Bearer {KEY}".encode()), (b"Authorization", f"Bearer {KEY}".encode())],
    [(b"x-api-key", KEY.encode()), (b"X-API-Key", KEY.encode())],
    [(b"authorization", b""), (b"x-api-key", KEY.encode())],
    [(b"authorization", f"Bearer {KEY}".encode()), (b"x-api-key", b"")],
    [(b"authorization", f"Bearer {KEY}\n".encode())],
    [(b"x-api-key", b"k" * 513)],
    [(b"x-api-key", b"short")],
    [(b"x-api-key", KEY.encode() + b",other")],
    [(b"x-api-key", b"\xff" * 32)],
])
def test_credential_syntax_is_unambiguous_and_bounded(headers):
    request = Request({"type": "http", "headers": headers})
    assert security._presented_key(request) is None


@pytest.mark.parametrize("token", [
    "x" * 513, "short", "é" * 32, KEY + ",other", KEY + "\x00", None, True,
])
def test_invalid_tokens_do_not_reach_scrypt(monkeypatch, token):
    calls = []
    monkeypatch.setattr(security, "_derive_api_key", lambda *a: calls.append(True) or bytes(32))
    assert security._credential_identity(token, (verifier(),)) is None
    assert calls == []


@pytest.mark.parametrize("headers", [
    [("Authorization", f"Bearer {KEY}"), ("Authorization", f"Bearer {KEY}")],
    [("X-API-Key", KEY), ("X-API-Key", KEY)],
    [("Authorization", "Bearer " + "k" * 513)],
])
def test_real_api_rejects_ambiguous_credentials_without_derivation(monkeypatch, headers):
    monkeypatch.setenv("LURESCOPE_PUBLIC_MODE", "true")
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT", verifier().serialize())
    calls = []
    monkeypatch.setattr(security, "_derive_api_key", lambda *a: calls.append(True) or bytes(32))
    response = TestClient(app).post("/proof/verify", json={"proof": {}}, headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "a valid API key is required"}
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert calls == []


def test_third_concurrent_verification_is_rejected_without_queueing(monkeypatch):
    started, release = threading.Event(), threading.Event()
    lock = threading.Lock()
    calls = []

    def slow_derive(*args):
        with lock:
            calls.append(True)
            current = len(calls)
            if current == 2:
                started.set()
        if current <= 2:
            assert release.wait(5), "test did not release authentication worker"
        return bytes(32)

    monkeypatch.setattr(security, "_derive_api_key", slow_derive)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(security._credential_identity, KEY, (verifier(),)) for _ in range(2)]
        try:
            assert started.wait(5)
            with pytest.raises(HTTPException) as exc:
                security._credential_identity(KEY, (verifier(),))
            assert exc.value.status_code == 503
            assert exc.value.headers == {"Retry-After": "1"}
            assert len(calls) == 2
        finally:
            release.set()
        assert [f.result(timeout=5) for f in futures] == [bytes(32).hex()] * 2
    assert security._credential_identity(KEY, (verifier(),)) == bytes(32).hex()


def test_key_ring_is_bounded_before_parsing(monkeypatch):
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT",
                       ",".join(verifier(i).serialize() for i in range(9)))
    with pytest.raises(ValueError):
        security.SecuritySettings.from_env()


@pytest.mark.parametrize("bad", [None, "x" * 257,
    "scrypt$16384$8$1$" + "00" * 17 + "$" + "00" * 32])
def test_verifier_parser_requires_bounded_canonical_work_material(bad):
    with pytest.raises(ValueError):
        security.ApiKeyVerifier.parse(bad)


@pytest.mark.parametrize("token", [
    "x" * 31, "x" * 513, KEY + " ", "é" * 32, KEY + ",other", None, True,
])
def test_creation_cannot_mint_credentials_the_service_will_reject(monkeypatch, token):
    monkeypatch.setattr(security, "_derive_api_key",
                        lambda *a: pytest.fail("derived invalid token"))
    with pytest.raises(ValueError):
        security.create_api_key_verifier(token)


@pytest.mark.parametrize("length", [32, 512])
def test_real_scrypt_roundtrip_at_token_bounds(length):
    key = "k" * length
    encoded = security.create_api_key_verifier(key, salt=b"s" * 16)
    expected = security.ApiKeyVerifier.parse(encoded)
    assert security._credential_identity(key, (expected,)) == expected.digest.hex()
    assert security._credential_identity("z" * length, (expected,)) is None


@pytest.mark.parametrize("headers", [
    [(b"authorization", f"Bearer {KEY}".encode())],
    [(b"Authorization", f"bearer {KEY}".encode())],
    [(b"x-api-key", KEY.encode())],
    [(b"authorization", f"Bearer {KEY}".encode()), (b"x-api-key", KEY.encode())],
])
def test_supported_header_forms_remain_valid(headers):
    assert security._presented_key(Request({"type": "http", "headers": headers})) == KEY


def test_disagreeing_channels_cannot_choose_one_credential():
    headers = [(b"authorization", f"Bearer {KEY}".encode()), (b"x-api-key", b"z" * 43)]
    assert security._presented_key(Request({"type": "http", "headers": headers})) is None


def test_all_rotation_verifiers_are_checked_even_after_match(monkeypatch):
    candidates = tuple(verifier(i) for i in range(8))
    seen = []

    def derive(token, candidate):
        seen.append(candidate)
        return candidates[0].digest

    monkeypatch.setattr(security, "_derive_api_key", derive)
    assert security._credential_identity(KEY, candidates) == candidates[0].digest.hex()
    assert seen == list(candidates)


@pytest.mark.parametrize("failure", [ValueError, OSError, MemoryError, RuntimeError])
def test_capacity_released_when_derivation_raises(monkeypatch, failure):
    calls = []

    def derive(*args):
        calls.append(True)
        raise failure("synthetic-private-diagnostic")

    monkeypatch.setattr(security, "_derive_api_key", derive)
    for _ in range(4):
        with pytest.raises(failure):
            security._credential_identity(KEY, (verifier(),))
    assert len(calls) == 4
    monkeypatch.setattr(security, "_derive_api_key", lambda *a: bytes(32))
    assert security._credential_identity(KEY, (verifier(),)) == bytes(32).hex()


def test_capacity_released_for_nonmatching_keys(monkeypatch):
    monkeypatch.setattr(security, "_derive_api_key", lambda *a: b"x" * 32)
    for _ in range(5):
        assert security._credential_identity(KEY, (verifier(),)) is None


def test_authentication_saturation_is_redacted_and_does_not_block_health(monkeypatch, caplog):
    monkeypatch.setenv("LURESCOPE_PUBLIC_MODE", "true")
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT", verifier().serialize())
    slots = threading.BoundedSemaphore(2)
    monkeypatch.setattr(security, "_KEY_CHECK_SLOTS", slots)
    monkeypatch.setattr(security, "_derive_api_key", lambda *a: pytest.fail("saturated KDF"))
    with slots, slots, TestClient(app) as client:
        response = client.post("/proof/verify", json={"proof": {"private": "PRIVATE_BODY"}},
                               headers={"Authorization": f"Bearer {KEY}"})
        assert response.status_code == 503
        assert response.json() == {"detail": "authentication capacity temporarily unavailable"}
        assert response.headers["Retry-After"] == "1"
        assert client.get("/health").status_code == 200
        assert client.post("/proof/verify", json={"proof": {}}).status_code == 401
    assert KEY not in caplog.text and "PRIVATE_BODY" not in caplog.text


@pytest.mark.parametrize("failure", [ValueError, OSError, MemoryError])
def test_known_kdf_failures_are_redacted_service_errors(monkeypatch, failure, caplog):
    monkeypatch.setenv("LURESCOPE_PUBLIC_MODE", "true")
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT", verifier().serialize())

    def fail(*args):
        raise failure("PRIVATE_AUTH_DIAGNOSTIC")

    monkeypatch.setattr(security, "_derive_api_key", fail)
    response = TestClient(app).post("/proof/verify", json={"proof": {}}, headers={"X-API-Key": KEY})
    assert response.status_code == 503
    assert response.json() == {"detail": "authentication temporarily unavailable"}
    assert "PRIVATE_AUTH_DIAGNOSTIC" not in response.text + caplog.text


@pytest.mark.parametrize("raw", ["x" * 2057, ",", verifier().serialize() + ",",
                               verifier().serialize() + "," + verifier().serialize()])
def test_invalid_keyring_fails_closed_without_disclosing_verifiers(monkeypatch, raw):
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT", raw)
    monkeypatch.setenv("LURESCOPE_PUBLIC_MODE", "true")
    with pytest.raises(ValueError):
        security.SecuritySettings.from_env()
    response = TestClient(app).get("/health")
    assert response.status_code == 503
    assert response.json() == {"detail": "deployment security is misconfigured"}


def test_key_rotation_takes_effect_without_positive_authentication_cache(monkeypatch):
    first = security.create_api_key_verifier(KEY, b"a" * 16)
    second_key = "second-synthetic-client-key-" + "z" * 32
    second = security.create_api_key_verifier(second_key, b"b" * 16)
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT", first + "," + second)
    before = security.SecuritySettings.from_env().api_key_verifiers
    assert security._credential_identity(KEY, before)
    assert security._credential_identity(second_key, before)
    monkeypatch.setenv("LURESCOPE_API_KEY_SCRYPT", second)
    after = security.SecuritySettings.from_env().api_key_verifiers
    assert security._credential_identity(KEY, after) is None
    assert security._credential_identity(second_key, after)


def test_local_unrestricted_routes_do_not_use_key_derivation(monkeypatch):
    monkeypatch.delenv("LURESCOPE_PUBLIC_MODE", raising=False)
    monkeypatch.delenv("LURESCOPE_API_KEY_SCRYPT", raising=False)
    monkeypatch.setattr(security, "_derive_api_key",
                        lambda *a: pytest.fail("unexpected local auth"))
    assert TestClient(app).post("/proof/verify", json={"proof": {}}).status_code == 200
