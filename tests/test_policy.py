import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

pytest.importorskip("sklearn")

from lurebench.calibration import binomial_cdf, clopper_pearson_upper

from lurescope import service
from lurescope.app import app
from lurescope.cli import main
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


def _write_risk_controlled_policy(path, **overrides):
    target = 0.01
    confidence = 0.95
    negatives = 400
    false_positives = 0
    payload = {
        "schema_version": 2,
        "policy_id": "tfidf-risk-controlled-v2",
        "detector": "tfidf-logreg",
        "task": "fraud",
        "threshold": 0.11,
        "objective": "risk_controlled_fpr",
        "target_fpr": target,
        "validation_records": 500,
        "validation_sha256": "a" * 64,
        "evaluation_sha256": "b" * 64,
        "validation_true_positives": 100,
        "validation_recall": 1.0,
        "created_at": "2026-08-09T12:00:00+00:00",
        "risk_control": {
            "method": "learn_then_test_fixed_sequence_exact_binomial_v1",
            "risk": "false_positive_rate",
            "confidence": confidence,
            "validation_negatives": negatives,
            "false_positives": false_positives,
            "empirical_fpr": 0.0,
            "upper_confidence_bound": clopper_pearson_upper(
                false_positives, negatives, confidence
            ),
            "hypothesis_p_value": binomial_cdf(false_positives, negatives, target),
            "threshold_grid_size": 101,
        },
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


def test_legacy_v1_policy_without_timestamp_remains_compatible(tmp_path):
    path = tmp_path / "policy-v1.json"
    _write_policy(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.pop("created_at")
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_policy(str(path)).schema_version == 1


def test_risk_controlled_policy_v2_is_accepted(tmp_path):
    path = tmp_path / "policy-v2.json"
    _write_risk_controlled_policy(path)
    policy = load_policy(str(path))
    assert policy.schema_version == 2
    assert policy.risk_control is not None
    assert policy.risk_control.upper_confidence_bound <= policy.target_fpr
    schema_path = Path(__file__).parents[1] / "spec" / "decision-policy-v2.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(path.read_text(encoding="utf-8")))


def test_risk_controlled_policy_rejects_forged_bound(tmp_path):
    path = tmp_path / "policy-v2.json"
    _write_risk_controlled_policy(
        path,
        risk_control={
            "method": "learn_then_test_fixed_sequence_exact_binomial_v1",
            "risk": "false_positive_rate",
            "confidence": 0.95,
            "validation_negatives": 400,
            "false_positives": 0,
            "empirical_fpr": 0.0,
            "upper_confidence_bound": 0.0001,
            "hypothesis_p_value": binomial_cdf(0, 400, 0.01),
            "threshold_grid_size": 101,
        },
    )
    with pytest.raises(ValueError, match="upper bound is inconsistent"):
        load_policy(str(path))


def test_policy_cli_validates_and_reports_assurance(tmp_path, capsys):
    path = tmp_path / "policy-v2.json"
    _write_risk_controlled_policy(path)
    assert main(["policy", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["assurance_status"] == "finite_sample_fpr_control"
    assert output["risk_control"]["upper_confidence_bound"] <= output["target_fpr"]


def test_policy_endpoint_exposes_configured_assurance(tmp_path, monkeypatch):
    path = tmp_path / "policy-v2.json"
    _write_risk_controlled_policy(path)
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    response = TestClient(app).get("/policy")
    assert response.status_code == 200
    payload = response.json()
    assert payload["assurance_status"] == "finite_sample_fpr_control"
    assert payload["validation_recall"] == 1.0
    assert payload["risk_control"]["upper_confidence_bound"] <= payload["target_fpr"]


def test_policy_path_cache_does_not_hide_replacement(tmp_path):
    path = tmp_path / "policy.json"
    _write_policy(path, threshold=.4)
    assert load_policy(str(path)).threshold == .4
    _write_policy(path, threshold=.8)
    assert load_policy(str(path)).threshold == .8
    path.write_text("not JSON")
    with pytest.raises(ValueError):
        load_policy(str(path))


def test_optional_pin_checked_against_current_bytes(tmp_path, monkeypatch):
    import hashlib

    from lurescope.policy import configured_policy

    path = tmp_path / "policy.json"
    _write_policy(path)
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    monkeypatch.setenv("LURESCOPE_POLICY_SHA256", pin)
    assert configured_policy().threshold == .99
    _write_policy(path, threshold=.1)
    with pytest.raises(ValueError, match="digest mismatch"):
        configured_policy()
    monkeypatch.delenv("LURESCOPE_POLICY_PATH")
    with pytest.raises(ValueError, match="requires"):
        configured_policy()


def test_duplicate_policy_fields_and_oversize_rejected(tmp_path):
    from lurescope.policy import MAX_POLICY_BYTES

    path = tmp_path / "policy.json"
    _write_policy(path)
    raw = path.read_text()
    path.write_text(raw[:-1] + ', "threshold": 0.0}')
    with pytest.raises(ValueError, match="duplicate"):
        load_policy(str(path))
    path.write_bytes(b" " * (MAX_POLICY_BYTES + 1))
    with pytest.raises(ValueError, match="bounded size"):
        load_policy(str(path))


def test_policy_rejects_symlink_and_excessive_validation_work(tmp_path, monkeypatch):
    import lurescope.policy as module

    path = tmp_path / "policy.json"
    _write_policy(path)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="regular"):
        load_policy(str(link))
    _write_risk_controlled_policy(path, validation_records=10_000_001)
    monkeypatch.setattr(module, "binomial_cdf", lambda *a: pytest.fail("expensive work"))
    with pytest.raises(ValueError, match="provenance"):
        load_policy(str(path))


def test_risk_control_threshold_must_be_on_declared_grid(tmp_path):
    path = tmp_path / "policy.json"
    _write_risk_controlled_policy(path, threshold=.115)
    with pytest.raises(ValueError, match="declared grid"):
        load_policy(str(path))


@pytest.mark.parametrize("value", [True, "1", 10 ** 400, float("nan"), float("inf")])
def test_malformed_policy_probability_rejected(tmp_path, value):
    path = tmp_path / "policy.json"
    _write_policy(path, threshold=value)
    with pytest.raises(ValueError):
        load_policy(str(path))


@pytest.mark.parametrize("value", [True, "0.5", -.1, 1.1, float("nan"), float("inf")])
def test_service_rejects_bad_threshold_before_detector_work(monkeypatch, value):
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("detector constructed"))
    with pytest.raises(ValueError, match="threshold"):
        service.score("example", threshold=value)
    with pytest.raises(ValueError, match="threshold"):
        service.attack("example", "homoglyph", threshold=value)
