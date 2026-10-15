"""Operator-controlled admission is independent of client scoring options."""

import hashlib
import importlib
import json

import pytest
from fastapi.testclient import TestClient
from lurebench import calibration as producer

from lurescope import service
from lurescope.app import app
from lurescope.cli import main
from lurescope.portable_tfidf import detector_binding
from lurescope.proof import create_email_proof


@pytest.fixture(autouse=True)
def clean_configuration(monkeypatch):
    for key in ("LURESCOPE_POLICY_ENFORCEMENT", "LURESCOPE_POLICY_PATH",
                "LURESCOPE_POLICY_SHA256", "LURESCOPE_PUBLIC_MODE",
                "LURESCOPE_API_KEY_SCRYPT", "LURESCOPE_API_KEY_SCRYPT_PREVIOUS",
                "LURESCOPE_ALLOWED_DETECTORS"):
        monkeypatch.delenv(key, raising=False)
    clear = service._detector.cache_clear
    clear()
    yield
    clear()


def deploy(tmp_path, monkeypatch, *, objective="max_mcc", bound=True, changes=None):
    if not hasattr(producer, "DetectorBinding"):
        pytest.skip("requires paired source-branch LureBench")
    binding = detector_binding(service._detector("tfidf-logreg"))
    binding.update(changes or {})
    policy, _ = producer.build_policy("tfidf-logreg", "fraud", [str(i) for i in range(401)],
        [0] * 400 + [1], [.1] * 400 + [.9], objective, .01,
        detector_binding=producer.DetectorBinding(**binding) if bound else None)
    path = tmp_path / "private-reviewed-policy.json"
    policy.save(str(path))
    monkeypatch.setenv("LURESCOPE_POLICY_PATH", str(path))
    monkeypatch.setenv("LURESCOPE_POLICY_SHA256", hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setenv("LURESCOPE_POLICY_ENFORCEMENT", "bound")
    return path, policy


@pytest.mark.parametrize("mode", ["", "true", "BOUND", " bound", "bound ", "unknown"])
def test_invalid_mode_fails_before_constructor(monkeypatch, mode):
    monkeypatch.setenv("LURESCOPE_POLICY_ENFORCEMENT", mode)
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    with pytest.raises(RuntimeError):
        service.score("private-message")


@pytest.mark.parametrize("mode", ["bound", "risk_controlled_bound"])
def test_missing_policy_fails_before_constructor(monkeypatch, mode):
    monkeypatch.setenv("LURESCOPE_POLICY_ENFORCEMENT", mode)
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    with pytest.raises(RuntimeError):
        service.score("private-message")


@pytest.mark.parametrize("case", ["pin_missing", "pin_wrong", "legacy", "corrupt", "missing"])
def test_invalid_policy_or_trust_fails_before_constructor(tmp_path, monkeypatch, case):
    path, _ = deploy(tmp_path, monkeypatch, bound=case != "legacy")
    if case == "pin_missing":
        monkeypatch.delenv("LURESCOPE_POLICY_SHA256")
    elif case == "pin_wrong":
        monkeypatch.setenv("LURESCOPE_POLICY_SHA256", "f" * 64)
    elif case == "corrupt":
        path.write_text("private-invalid-material")
    elif case == "missing":
        path.unlink()
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    with pytest.raises(RuntimeError):
        service.score("private-message")


@pytest.mark.parametrize("options", [
    {"threshold": .5}, {"threshold": 1.0}, {"detector_name": "heuristic-v0"},
    {"detector_name": "llm-judge"}, {"engine": "ignored"}, {"model": "ignored"},
])
def test_request_cannot_bypass_required_policy(tmp_path, monkeypatch, options):
    deploy(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    with pytest.raises(RuntimeError):
        service.score("private-message", **options)


@pytest.mark.parametrize("mode,objective", [
    ("bound", "max_mcc"), ("bound", "target_fpr"),
    ("bound", "risk_controlled_fpr"), ("risk_controlled_bound", "risk_controlled_fpr"),
])
def test_approved_policy_scores_and_is_ready(tmp_path, monkeypatch, mode, objective, capsys):
    _, policy = deploy(tmp_path, monkeypatch, objective=objective)
    monkeypatch.setenv("LURESCOPE_POLICY_ENFORCEMENT", mode)
    result = service.score("Ordinary synthetic notes")
    assert result.policy_id == policy.policy_id
    assert result.threshold_source == "validated_policy"
    response = TestClient(app).get("/policy/readiness")
    assert response.status_code == 200
    assert response.json()["ready"] is True
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["enforcement"] == mode
    assert response.json()["policy_id"] == policy.policy_id
    assert main(["policy", "--check-readiness"]) == 0
    assert json.loads(capsys.readouterr().out) == response.json()


def test_stronger_mode_rejects_empirical_policy(tmp_path, monkeypatch):
    deploy(tmp_path, monkeypatch)
    monkeypatch.setenv("LURESCOPE_POLICY_ENFORCEMENT", "risk_controlled_bound")
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    with pytest.raises(RuntimeError):
        service.score("private-message")
    response = TestClient(app).get("/policy/readiness")
    assert response.status_code == 503
    assert response.json()["reason"] == "risk_control_required"


@pytest.mark.parametrize("route,payload", [
    ("/score", {"text": "private-message", "threshold": .5}),
    ("/triage/email", {"raw_email": "Subject: Note\n\nprivate-message", "threshold": .5}),
    ("/proof/email", {"raw_email": "Subject: Note\n\nprivate-message"}),
    ("/attack", {"text": "private-message", "attack": "homoglyph"}),
])
def test_http_bypasses_rejected_without_inference(tmp_path, monkeypatch, route, payload):
    deploy(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    monkeypatch.setattr(importlib.import_module("lurescope.app"), "enforce_request_policy",
                        lambda **kw: pytest.fail("provider quota admission invoked"))
    response = TestClient(app).post(route, json=payload)
    assert response.status_code == 403
    assert "private" not in response.text


def test_exploration_disabled_before_provider_or_proof_work(tmp_path, monkeypatch):
    deploy(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    with pytest.raises(RuntimeError):
        service.attack("private-message", "llm-paraphrase", engine="provider")
    with pytest.raises(RuntimeError):
        create_email_proof(b"Subject: Note\n\nprivate-message")


def test_readiness_mismatch_and_configuration_errors_are_redacted(tmp_path, monkeypatch):
    path, _ = deploy(tmp_path, monkeypatch, changes={"runtime_sha256": "f" * 64})
    response = TestClient(app).get("/policy/readiness")
    assert response.status_code == 503
    assert response.json()["reason"] == "detector_mismatch"
    assert "private" not in response.text
    path.write_text("private-corrupt-material")
    client = TestClient(app)
    assert client.get("/policy/readiness").status_code == 503
    response = client.post("/score", json={"text": "private-message"})
    assert response.status_code == 503
    assert "private" not in response.text


def test_unconfigured_demo_remains_live_but_not_enforced_ready(capsys):
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    response = client.get("/policy/readiness")
    assert response.status_code == 503
    assert response.json()["reason"] == "enforcement_disabled"
    assert response.headers["cache-control"] == "no-store"
    assert main(["policy", "--check-readiness"]) == 1
    assert json.loads(capsys.readouterr().out) == response.json()
    assert service.score("notes", threshold=.8).threshold_source == "request"


def test_mode_change_applies_with_warm_model(tmp_path, monkeypatch):
    deploy(tmp_path, monkeypatch)
    assert service.score("notes").policy_id
    monkeypatch.delenv("LURESCOPE_POLICY_SHA256")
    with pytest.raises(RuntimeError):
        service.score("notes")


def test_readiness_does_not_predict(tmp_path, monkeypatch):
    deploy(tmp_path, monkeypatch)
    from lurescope.portable_tfidf import PortableTfidfDetector

    monkeypatch.setattr(PortableTfidfDetector, "score", lambda *a: pytest.fail("predicted"))
    assert TestClient(app).get("/policy/readiness").status_code == 200


@pytest.mark.parametrize("args", [["ignored.json", "--check-readiness"],
                                 ["--check-readiness", "--check-deployment"]])
def test_readiness_checks_configuration_not_arbitrary_file(args):
    with pytest.raises(SystemExit) as exc:
        main(["policy", *args])
    assert exc.value.code == 2


def test_readiness_security_failure_matches_cli(tmp_path, monkeypatch, capsys):
    deploy(tmp_path, monkeypatch)
    monkeypatch.setenv("LURESCOPE_PUBLIC_MODE", "true")
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    response = TestClient(app).get("/policy/readiness")
    assert response.status_code == 503
    assert response.json()["reason"] == "security_misconfigured"
    assert main(["policy", "--check-readiness"]) == 1
    assert json.loads(capsys.readouterr().out) == response.json()


def test_policy_replacement_cannot_downgrade_warm_worker(tmp_path, monkeypatch):
    path, _ = deploy(tmp_path, monkeypatch)
    assert service.score("notes").policy_id
    legacy, _ = producer.build_policy("tfidf-logreg", "fraud", ["b", "f"],
                                      [0, 1], [.1, .9], "max_mcc")
    legacy.save(str(path))
    with pytest.raises(RuntimeError):
        service.score("notes")
    # Even administrative approval of new bytes cannot remove the schema floor.
    monkeypatch.setenv("LURESCOPE_POLICY_SHA256", hashlib.sha256(path.read_bytes()).hexdigest())
    with pytest.raises(RuntimeError):
        service.score("notes")
    assert TestClient(app).get("/policy/readiness").json()["reason"] == "bound_policy_required"


def test_equal_threshold_is_still_a_forbidden_override(tmp_path, monkeypatch):
    _, policy = deploy(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError):
        service.score("notes", threshold=policy.threshold)


def test_triage_uses_the_approved_policy(tmp_path, monkeypatch):
    _, policy = deploy(tmp_path, monkeypatch, objective="risk_controlled_fpr")
    monkeypatch.setenv("LURESCOPE_POLICY_ENFORCEMENT", "risk_controlled_bound")
    response = TestClient(app).post("/triage/email", json={"raw_email": "Subject: Notes\n\nhello"})
    assert response.status_code == 200
    assert response.json()["policy_id"] == policy.policy_id


def test_existing_proof_verification_is_not_an_inference_bypass(monkeypatch):
    proof = create_email_proof(b"Subject: Notes\n\nhello")
    monkeypatch.setenv("LURESCOPE_POLICY_ENFORCEMENT", "bound")
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    response = TestClient(app).post("/proof/verify", json={"proof": proof})
    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_proof_batch_preflight_rejects_before_creating_outputs(tmp_path, monkeypatch):
    from lurescope.inbox import process_inbox

    monkeypatch.setenv("LURESCOPE_POLICY_ENFORCEMENT", "bound")
    output = tmp_path / "no-proof-output"
    with pytest.raises(RuntimeError):
        process_inbox([("synthetic.eml", b"Subject: Notes\n\nhello")], output)
    assert not output.exists()


def test_readiness_rejects_conflicting_detector_allowlist(tmp_path, monkeypatch, capsys):
    deploy(tmp_path, monkeypatch)
    monkeypatch.setenv("LURESCOPE_ALLOWED_DETECTORS", "heuristic-v0")
    monkeypatch.setattr(service, "_detector", lambda *a: pytest.fail("constructed detector"))
    response = TestClient(app).get("/policy/readiness")
    assert response.status_code == 503
    assert response.json()["reason"] == "detector_not_allowed"
    assert main(["policy", "--check-readiness"]) == 1
    assert json.loads(capsys.readouterr().out) == response.json()
