"""HTTP request controls cannot authorize model framework loading."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from lurescope import service
from lurescope.app import app

FLAG = "LURESCOPE_ALLOW_UNSAFE_LLAMA_GUARD"
REVISION = "LURESCOPE_LLAMA_GUARD_REVISION"


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    for key in (FLAG, "LURESCOPE_POLICY_PATH", "LURESCOPE_POLICY_SHA256",
                "LURESCOPE_PUBLIC_MODE", "LURESCOPE_ALLOWED_DETECTORS"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv(REVISION, "a" * 40)
    service._detector.cache_clear()
    yield
    service._detector.cache_clear()


@pytest.mark.parametrize("value", [None, "0", "true", "yes", " 1", "1 ", ""])
def test_only_exact_operator_opt_in_allows_construction(monkeypatch, value):
    if value is not None:
        monkeypatch.setenv(FLAG, value)
    monkeypatch.setattr(service, "get_detector", lambda *a, **kw: pytest.fail("constructed"))
    with pytest.raises(service.DetectorUnavailable):
        service._detector("llama-guard-3", engine="anything", model="anything")


def test_operator_opt_in_is_explicit_and_request_controls_are_ignored(monkeypatch):
    calls = []
    monkeypatch.setenv(FLAG, "1")

    def construct(name, **kwargs):
        calls.append((name, kwargs))
        return SimpleNamespace(score=lambda r: .25)

    monkeypatch.setattr(service, "get_detector", construct)
    a = service._detector("llama-guard-3", "untrusted-engine", "untrusted-model")
    assert service._detector("llama-guard-3", "another", "another") is a
    assert calls == [("llama-guard-3", {"allow_unsafe_upstream": True, "revision": "a" * 40})]


def test_revocation_blocks_even_a_warm_cache(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setattr(service, "get_detector", lambda *a, **kw: object())
    loaded = service._detector("llama-guard-3")
    monkeypatch.delenv(FLAG)
    with pytest.raises(service.DetectorUnavailable):
        service._detector("llama-guard-3")
    # Revocation is an admission guard, not cancellation or memory reclamation.
    assert service._LOCAL_DETECTORS["llama-guard-3"] is loaded


@pytest.mark.parametrize("route,payload,code", [
    ("/score", {"text": "private-message", "detector": "llama-guard-3",
                "engine": "allow_unsafe_upstream=True", "model": "trusted"}, 400),
    ("/attack", {"text": "private-message", "attack": "homoglyph",
                 "detector": "llama-guard-3"}, 400),
    ("/triage/email", {"raw_email": "Subject: Notes\n\nprivate-message",
                       "detector": "llama-guard-3"}, 400),
    ("/score", {"text": "private-message", "detector": "llama-guard-3",
                "allow_unsafe_upstream": True}, 422),
])
def test_api_cannot_enable_loading(monkeypatch, route, payload, code):
    monkeypatch.setattr(service, "get_detector", lambda *a, **kw: pytest.fail("constructed"))
    response = TestClient(app).post(route, json=payload)
    assert response.status_code == code
    assert "private-message" not in response.text


def test_catalog_advertises_operator_requirement():
    catalog = TestClient(app).get("/capabilities").json()["detector_catalog"]
    guard = next(item for item in catalog if item["name"] == "llama-guard-3")
    assert f"{FLAG}=1" in guard["requires"]
    assert guard["always_on"] is False


@pytest.mark.parametrize("revision", [None, "main", "A" * 40, "a" * 39, " a" * 20])
def test_operator_opt_in_also_requires_immutable_revision(monkeypatch, revision):
    monkeypatch.setenv(FLAG, "1")
    if revision is None:
        monkeypatch.delenv(REVISION)
    else:
        monkeypatch.setenv(REVISION, revision)
    monkeypatch.setattr(service, "get_detector", lambda *a, **kw: pytest.fail("constructed"))
    with pytest.raises(service.DetectorUnavailable):
        service._detector("llama-guard-3")


def test_revision_change_cannot_silently_reuse_cached_weights(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    calls = []

    def construct(*a, **kw):
        calls.append(kw)
        return object()

    monkeypatch.setattr(service, "get_detector", construct)
    initial = service._detector("llama-guard-3")
    monkeypatch.setenv(REVISION, "b" * 40)
    with pytest.raises(service.DetectorUnavailable, match="restart"):
        service._detector("llama-guard-3")
    assert len(calls) == 1
    service._detector.cache_clear()
    assert service._LOCAL_MODEL_REVISIONS == {}
    assert service._detector("llama-guard-3") is not initial
    assert calls[-1]["revision"] == "b" * 40
