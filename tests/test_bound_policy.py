"""Exact portable calibration, deployment mismatch rejection, and honest status."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from lurebench import calibration as producer
from lurebench.schema import Lure, save_jsonl

from lurescope import calibrate, service
from lurescope.app import app
from lurescope.cli import main
from lurescope.policy import load_policy, policy_status
from lurescope.portable_tfidf import PortableTfidfDetector, detector_binding


@pytest.fixture(autouse=True)
def clean_policy(monkeypatch):
    monkeypatch.delenv("LURESCOPE_POLICY_PATH", raising=False)
    monkeypatch.delenv("LURESCOPE_POLICY_SHA256", raising=False)
    service._detector.cache_clear()
    yield
    service._detector.cache_clear()


def bound_policy(path, *, objective="max_mcc", changes=None):
    if not hasattr(producer, "DetectorBinding"):
        pytest.skip("paired binding producer requires source-branch LureBench")
    binding = detector_binding(service._detector("tfidf-logreg"))
    binding.update(changes or {})
    policy, _ = producer.build_policy("tfidf-logreg", "fraud", [str(i) for i in range(401)],
        [0] * 400 + [1], [.1] * 400 + [.9], objective, .01,
        detector_binding=producer.DetectorBinding(**binding))
    policy.save(str(path))
    return policy


@pytest.mark.parametrize("objective", ["max_mcc", "target_fpr", "risk_controlled_fpr"])
def test_producer_consumer_schema_and_status(tmp_path, monkeypatch, capsys, objective):
    path = tmp_path / "bound.json"
    policy = bound_policy(path, objective=objective)
    loaded = load_policy(str(path))
    assert loaded.policy_id == policy.policy_id
    schema_path = Path(__file__).parents[1] / "spec/decision-policy-v3.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(path.read_text()))
    assert policy_status(loaded)["detector_binding_status"] == "not_checked"
    assert not policy_status(loaded)["detector_configuration_verified"]
    assert main(["policy", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["detector_binding_status"] == "not_checked"
    assert main(["policy", str(path), "--check-deployment"]) == 0
    assert json.loads(capsys.readouterr().out)["detector_configuration_verified"] is True
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    payload = TestClient(app).get("/policy").json()
    assert payload["detector_binding_status"] == "match"
    assert payload["detector_configuration_verified"] is True
    result = service.score("Ordinary synthetic notes")
    assert result.policy_id == policy.policy_id
    assert result.threshold == policy.threshold


@pytest.mark.parametrize("field", ["artifact_sha256", "implementation_sha256", "runtime_sha256"])
def test_mismatched_configuration_stops_before_scoring(tmp_path, monkeypatch, capsys, field):
    path = tmp_path / "different.json"
    bound_policy(path, changes={field: "f" * 64})
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    monkeypatch.setattr(PortableTfidfDetector, "score", lambda *a: pytest.fail("scoring invoked"))
    with pytest.raises(RuntimeError, match="does not match"):
        service.score("private-message")
    assert main(["policy", str(path), "--check-deployment"]) == 1
    status = json.loads(capsys.readouterr().out)
    assert status["detector_binding_status"] == "mismatch"
    client = TestClient(app)
    assert client.get("/policy").json()["detector_configuration_verified"] is False
    for route, payload in [("/score", {"text": "private-message"}),
                           ("/triage/email", {"raw_email": "Subject: Notes\n\nprivate-message"})]:
        response = client.post(route, json=payload)
        assert response.status_code == 502
        assert "private-message" not in response.text


@pytest.mark.parametrize("field,value", [
    ("threshold", .3), ("validation_records", 500), ("policy_id", "wrong"),
    ("evaluation_sha256", "f" * 64), ("validation_sha256", "f" * 64),
])
def test_tampered_evidence_rejected_by_both_loaders(tmp_path, field, value):
    path = tmp_path / "bound.json"
    bound_policy(path)
    payload = json.loads(path.read_text())
    payload[field] = value
    path.write_text(json.dumps(payload))
    for loader in (load_policy, producer.DecisionPolicy.load):
        with pytest.raises(ValueError):
            loader(str(path))


@pytest.mark.parametrize("changes", [
    {"detector_binding": None}, {"detector_binding": {}},
    {"detector_binding": {"profile": "unknown"}}, {"schema_version": 1},
    {"created_at": ""}, {"evaluation_sha256": None},
])
def test_malformed_bound_policies_fail(tmp_path, changes):
    path = tmp_path / "bound.json"
    bound_policy(path)
    payload = json.loads(path.read_text())
    payload.update(changes)
    path.write_text(json.dumps(payload))
    for loader in (load_policy, producer.DecisionPolicy.load):
        with pytest.raises(ValueError):
            loader(str(path))


def test_explicit_threshold_does_not_inherit_mismatched_policy(tmp_path, monkeypatch):
    path = tmp_path / "different.json"
    bound_policy(path, changes={"artifact_sha256": "f" * 64})
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    result = service.score("Synthetic notes", threshold=.4)
    assert result.policy_id is None
    assert result.threshold_source == "request"
    assert result.threshold == .4
    other = service.score("Synthetic notes", detector_name="heuristic-v0")
    assert other.policy_id is None
    assert other.threshold_source == "default"


def test_policy_endpoint_redacts_invalid_configuration(tmp_path, monkeypatch):
    path = tmp_path / "private-path.json"
    path.write_text("private-contents")
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    response = TestClient(app).get("/policy")
    assert response.status_code == 503
    assert "private" not in response.text


def test_portable_binding_uses_exact_bytes_not_joblib_source(tmp_path):
    raw = Path(service._DEFAULT_TFIDF).read_bytes()
    path = tmp_path / "portable.json"
    path.write_bytes(raw)
    a = PortableTfidfDetector(path, expected_sha256=hashlib.sha256(raw).hexdigest())
    payload = json.loads(raw)
    payload["intercept"] += .001
    changed = json.dumps(payload).encode()
    path.write_bytes(changed)
    b = PortableTfidfDetector(path, expected_sha256=hashlib.sha256(changed).hexdigest())
    assert a.source_sha256 == b.source_sha256
    assert detector_binding(a) != detector_binding(b)
    assert detector_binding(a)["artifact_sha256"] == hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="exact portable"):
        detector_binding(SimpleNamespace(artifact_sha256=a.artifact_sha256))


def test_portable_configuration_is_immutable():
    detector = service._detector("tfidf-logreg")
    for name, value in [("artifact_sha256", "f" * 64), ("_intercept", 0), ("_sealed", False)]:
        with pytest.raises(AttributeError):
            setattr(detector, name, value)
        with pytest.raises(AttributeError):
            delattr(detector, name)
    with pytest.raises(TypeError):
        detector._features["new"] = (0, 1., 1.)


@pytest.mark.parametrize("objective", ["max_mcc", "target_fpr", "risk_controlled_fpr"])
def test_offline_calibration_uses_actual_portable_scores(tmp_path, monkeypatch, objective):
    if not hasattr(producer, "DetectorBinding"):
        pytest.skip("paired binding producer requires source-branch LureBench")
    records = [Lure("a", "ordinary weekly notes", 0, "human", "benign"),
               Lure("b", "urgent verify your password account", 1, "human", "phishing")]
    if objective == "risk_controlled_fpr":
        records.extend(Lure(f"extra-{i}", f"synthetic project notes {i}", 0, "human", "benign")
                       for i in range(399))
    source, target = tmp_path / "validation.jsonl", tmp_path / "policy.json"
    save_jsonl(records, source)
    # Calibration must not borrow a configured policy or its threshold.
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(tmp_path / "nonexistent.json"))
    assert main(["calibrate", "-d", str(source), "-o", str(target),
                 "--objective", objective, "--target-fpr", ".01"]) == 0
    loaded = load_policy(str(target))
    detector = service._detector("tfidf-logreg")
    labels, scores = [r.label for r in records], [detector.score(r) for r in records]
    if objective == "risk_controlled_fpr":
        expected = producer.select_risk_controlled_threshold(labels, scores, .01)[0]
    else:
        expected = producer.select_threshold(labels, scores, objective, .01)[0]
    assert loaded.threshold == expected
    assert loaded.schema_version == 3
    assert loaded.detector_binding.artifact_sha256 == detector.artifact_sha256
    assert service.policy_status_for_deployment(loaded)["detector_configuration_verified"]


@pytest.mark.parametrize("args", [["--bins", "0"], ["--confidence", "nan"],
                                  ["--objective", "target_fpr"]])
def test_calibration_invalid_controls_do_not_read_or_construct(tmp_path, monkeypatch, args):
    monkeypatch.setattr(calibrate, "load_jsonl", lambda *a: pytest.fail("dataset read"))
    monkeypatch.setattr(calibrate, "PortableTfidfDetector",
                        lambda *a, **k: pytest.fail("constructed"))
    target = tmp_path / "policy.json"
    target.write_text("existing")
    assert main(["calibrate", "-d", "unused", "-o", str(target), *args]) == 2
    assert target.read_text() == "existing"


def test_binding_mismatch_blocks_proof_creation(tmp_path, monkeypatch):
    from lurescope.proof import create_email_proof

    path = tmp_path / "different.json"
    bound_policy(path, changes={"runtime_sha256": "f" * 64})
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    with pytest.raises(RuntimeError, match="does not match"):
        create_email_proof(b"Subject: Notes\n\nSynthetic notes.")


def test_legacy_policy_cannot_claim_deployment_verification(tmp_path, capsys):
    path = tmp_path / "policy.json"
    policy = bound_policy(path)
    legacy = replace(policy, schema_version=1, detector_binding=None, evaluation_sha256=None)
    legacy.save(str(path))
    assert main(["policy", str(path), "--check-deployment"]) == 1
    assert json.loads(capsys.readouterr().out)["detector_binding_status"] == "legacy_unbound"


def test_risk_numeric_serialization_preserves_semantic_identity(tmp_path):
    path = tmp_path / "bound.json"
    policy = bound_policy(path, objective="risk_controlled_fpr")
    payload = json.loads(path.read_text())
    payload["risk_control"]["empirical_fpr"] = 0
    payload["validation_recall"] = 1
    path.write_text(json.dumps(payload))
    assert load_policy(str(path)).policy_id == policy.policy_id


def test_vendored_v3_schema_matches_compatible_producer():
    if not hasattr(producer, "DetectorBinding"):
        pytest.skip("paired schema verification requires source-branch LureBench")
    package = Path(producer.__file__).parent
    source = package / "spec/decision-policy-v3.schema.json"
    if not source.is_file():
        source = package.parent / "spec/decision-policy-v3.schema.json"
    consumer = Path(__file__).parents[1] / "spec/decision-policy-v3.schema.json"
    assert consumer.read_bytes() == source.read_bytes()


def test_configuration_is_rechecked_before_result_publication(tmp_path, monkeypatch):
    path = tmp_path / "bound.json"
    bound_policy(path)
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    original = detector_binding(service._detector("tfidf-logreg"))
    calls = []

    def changed(detector):
        calls.append(True)
        return original if len(calls) == 1 else {**original, "runtime_sha256": "f" * 64}

    monkeypatch.setattr(service, "detector_binding", changed)
    with pytest.raises(RuntimeError, match="does not match"):
        service.score("Ordinary synthetic notes")
    assert len(calls) == 2


@pytest.mark.parametrize("mode", ["too_small", "related_negatives"])
def test_bound_calibration_population_preflight(tmp_path, monkeypatch, mode):
    if not hasattr(producer, "DetectorBinding"):
        pytest.skip("paired binding producer requires source-branch LureBench")
    count = 1 if mode == "too_small" else 400
    records = [Lure(str(i), f"Synthetic notes {i}", 0, "human", "benign",
                    meta={"family_id": "one-family"}) for i in range(count)]
    records.append(Lure("p", "synthetic positive", 1, "human", "phishing"))
    source, output = tmp_path / "records.jsonl", tmp_path / "out.json"
    save_jsonl(records, source)
    monkeypatch.setattr(calibrate, "PortableTfidfDetector",
                        lambda *a, **k: pytest.fail("constructed"))
    assert main(["calibrate", "-d", str(source), "-o", str(output),
                 "--objective", "risk_controlled_fpr", "--target-fpr", ".01"]) == 2
    assert not output.exists()
