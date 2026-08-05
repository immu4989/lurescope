import json

import pytest

pytest.importorskip("sklearn")

from lurescope import service
from lurescope.policy import load_policy


def _write_policy(path, **overrides):
    payload = {
        "schema_version": 1,
        "policy_id": "tfidf-validated-v1",
        "detector": "tfidf-logreg",
        "task": "fraud",
        "threshold": 0.99,
        "objective": "target_fpr",
        "target_fpr": 0.01,
        "validation_records": 100,
        "validation_sha256": "a" * 64,
        "created_at": "2026-08-05T00:00:00+00:00",
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_service_uses_configured_policy_when_threshold_omitted(tmp_path, monkeypatch):
    path = tmp_path / "policy.json"
    _write_policy(path)
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    result = service.score("Please verify your account immediately")
    assert result.threshold == 0.99
    assert result.policy_id == "tfidf-validated-v1"
    assert result.threshold_source == "validated_policy"


def test_explicit_threshold_overrides_policy(tmp_path, monkeypatch):
    path = tmp_path / "policy.json"
    _write_policy(path)
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    result = service.score("Please verify your account immediately", threshold=0.2)
    assert result.threshold == 0.2
    assert result.policy_id is None
    assert result.threshold_source == "request"


def test_policy_rejects_missing_validation_provenance(tmp_path):
    path = tmp_path / "policy.json"
    _write_policy(path, validation_sha256="bad")
    with pytest.raises(ValueError):
        load_policy(str(path))
