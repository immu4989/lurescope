"""Provenance-only detector outputs cannot become fraud decisions or proofs."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from lurescope import service
from lurescope.app import app


@pytest.fixture(autouse=True)
def local_mode(monkeypatch):
    for name in ("LURESCOPE_PUBLIC_MODE", "LURESCOPE_API_KEY_SCRYPT",
                 "LURESCOPE_ALLOWED_DETECTORS", "LURESCOPE_ALLOWED_ATTACKS"):
        monkeypatch.delenv(name, raising=False)
    service._detector.cache_clear()
    yield
    service._detector.cache_clear()


@pytest.mark.parametrize("path,payload", [
    ("/score", {"text": "synthetic"}),
    ("/attack", {"text": "synthetic", "attack": "homoglyph"}),
    ("/triage/email", {"raw_email": "Subject: Notes\n\nSynthetic notes"}),
    ("/proof/email", {"raw_email": "Subject: Notes\n\nSynthetic notes"}),
])
def test_provenance_detector_is_not_loaded_by_fraud_routes(monkeypatch, path, payload):
    calls = []

    def construct(*args, **kwargs):
        calls.append(True)
        return SimpleNamespace(name="binoculars", task="provenance", score=lambda r: .99)

    monkeypatch.setattr(service, "get_detector", construct)
    response = TestClient(app).post(path, json={**payload, "detector": "binoculars"})
    assert response.status_code == 400
    assert calls == []
    assert "fraud_probability" not in response.json()
    assert "predicate" not in response.json()


def test_capabilities_explain_provenance_only_boundary():
    catalog = TestClient(app).get("/capabilities").json()["detector_catalog"]
    entry = next(item for item in catalog if item["name"] == "binoculars")
    assert "provenance" in entry["kind"]
    assert "disabled" in entry["requires"]
    assert not entry["always_on"]
