"""Upstream moderation failures cannot produce fraud decisions or proofs."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from lurescope import service
from lurescope.app import app


@pytest.fixture(autouse=True)
def local_mode(monkeypatch):
    for name in ("LURESCOPE_PUBLIC_MODE", "LURESCOPE_API_KEY_SCRYPT",
                 "LURESCOPE_ALLOWED_DETECTORS", "LURESCOPE_ALLOWED_ATTACKS",
                 "LURESCOPE_PROVIDER_DAILY_LIMIT", "LURESCOPE_POLICY_PATH"):
        monkeypatch.delenv(name, raising=False)
    service._detector.cache_clear()
    yield
    service._detector.cache_clear()


@pytest.mark.parametrize("path,payload", [
    ("/score", {"text": "Synthetic notes"}),
    ("/attack", {"text": "Synthetic notes", "attack": "homoglyph"}),
    ("/triage/email", {"raw_email": "Subject: Notes\n\nSynthetic notes"}),
])
def test_moderation_runtime_failure_has_no_decision(monkeypatch, path, payload):
    scored = []

    def failed_score(record):
        scored.append(True)
        # The adapter's malformed-response exception is a RuntimeError subtype.
        # No dependency on unreleased companion parsing APIs is needed here.
        raise RuntimeError("SYNTHETIC_PRIVATE_PROVIDER_DIAGNOSTIC")

    monkeypatch.setattr(service, "get_detector",
                        lambda *a, **kw: SimpleNamespace(score=failed_score))
    response = TestClient(app).post(path, json={**payload, "detector": "openai-moderation"})
    assert response.status_code == 502
    assert len(scored) == 1
    assert "SYNTHETIC_PRIVATE" not in response.text
    assert "fraud_probability" not in response.json()
    assert "evaded" not in response.json()


def test_proof_rejects_moderation_before_construction(monkeypatch):
    constructed = []
    monkeypatch.setattr(service, "get_detector", lambda *a, **kw: constructed.append(True))
    response = TestClient(app).post("/proof/email", json={
        "raw_email": "Subject: Notes\n\nSynthetic notes", "detector": "openai-moderation",
    })
    assert response.status_code == 400
    assert constructed == []
    assert "predicate" not in response.json()


@pytest.mark.parametrize("path,payload", [
    ("/score", {"text": "Synthetic notes"}),
    ("/attack", {"text": "Synthetic notes", "attack": "homoglyph"}),
    ("/triage/email", {"raw_email": "Subject: Notes\n\nSynthetic notes"}),
])
def test_paired_source_moderation_parser_and_valid_zero_recovery(monkeypatch, path, payload):
    from lurebench.detectors import moderation

    if not hasattr(moderation, "ModerationResponseError"):
        pytest.skip("paired parser regression requires source-branch LureBench")
    scores = dict.fromkeys(moderation.CATEGORIES, 0.)
    scores["violence"] = float("nan")
    upstream = SimpleNamespace(moderations=SimpleNamespace(create=lambda **kwargs: {
        "results": [{"flagged": False, "category_scores": scores}],
    }))
    detector = moderation.OpenAIModerationDetector(client=upstream)
    monkeypatch.setattr(service, "get_detector", lambda *args, **kwargs: detector)
    request = {**payload, "detector": "openai-moderation"}
    client = TestClient(app)
    rejected = client.post(path, json=request)
    assert rejected.status_code == 502
    assert set(rejected.json()) == {"detail"}
    scores["violence"] = 0.
    assert client.post(path, json=request).status_code == 200
