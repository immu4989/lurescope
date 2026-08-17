"""Pre-registration, statistical correctness, and fail-closed Pilot Gate tests."""

from __future__ import annotations

import json
import math
import os
from email.message import EmailMessage
from pathlib import Path

import pytest

pytest.importorskip("sklearn")

import lurescope.pilot as pilot_module
from lurescope.cli import main
from lurescope.pilot import (
    build_pilot_gate,
    create_pilot_plan,
    detector_artifact_sha256,
    load_pilot_plan,
    pilot_plan_sha256,
)


def _create_plan(path: Path, **overrides):
    values = {
        "plan_id": "soc-pilot-001",
        "min_processed_count": 400,
        "min_fraud_labels": 100,
        "min_benign_labels": 300,
        "max_uncertain_rate": 0.0,
        "max_processing_failure_rate": 0.0,
        "min_routing_recall_lower_bound": 0.97,
        "max_routing_false_positive_rate_upper_bound": 0.01,
        "max_routed_rate": 0.25,
        "max_routed_count": 100,
        "confidence": 0.95,
    }
    values.update(overrides)
    return create_pilot_plan(path, **values)


def _report(
    *,
    processed: int = 400,
    failed: int = 0,
    fraud: int = 100,
    benign: int = 300,
    uncertain: int = 0,
    latest: int = 400,
    true_positive: int = 100,
    false_positive: int = 0,
    true_negative: int = 300,
    false_negative: int = 0,
    routed: int = 100,
):
    return {
        "volume": {"processed_count": processed, "failed_count": failed},
        "routing": {"routed_count": routed},
        "analyst_review": {
            "latest_label_count": latest,
            "label_counts": {
                "fraud": fraud,
                "benign": benign,
                "uncertain": uncertain,
            },
            "confusion": {
                "true_positive": true_positive,
                "false_positive": false_positive,
                "true_negative": true_negative,
                "false_negative": false_negative,
            },
        },
    }


def _fake_bundle(tmp_path: Path, monkeypatch, report=None) -> Path:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.jsonl").write_text("minimized manifest\n", encoding="utf-8")
    (bundle / "analyst-labels.jsonl").write_text("aggregate labels\n", encoding="utf-8")
    monkeypatch.setattr(
        pilot_module,
        "load_shadow_run",
        lambda unused: {
            "generated_at": "2099-01-01T00:00:00+00:00",
            "manifest": "manifest.jsonl",
            "labels": "analyst-labels.jsonl",
        },
    )
    monkeypatch.setattr(
        pilot_module, "build_shadow_report", lambda unused: report or _report()
    )
    monkeypatch.setattr(
        pilot_module,
        "load_inbox_manifest",
        lambda unused: [{
            "status": "processed",
            "assessment": {
                "detector": "tfidf-logreg",
                "detector_artifact_sha256": detector_artifact_sha256("tfidf-logreg"),
                "threshold": 0.5,
                "policy_id": None,
            },
        }],
    )
    monkeypatch.setattr(
        pilot_module, "load_analyst_labels", lambda unused: ([], {})
    )
    return bundle


def _email(subject: str, body: str) -> bytes:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = "sender@example.org"
    message["To"] = "soc@example.org"
    message.set_content(body)
    return message.as_bytes()


def test_plan_is_strict_private_non_overwriting_and_schema_valid(tmp_path):
    path = tmp_path / "pilot-plan.json"
    plan = _create_plan(path)

    assert load_pilot_plan(path) == plan
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert len(pilot_plan_sha256(path)) == 64
    with pytest.raises(FileExistsError):
        _create_plan(path)
    with pytest.raises(ValueError):
        _create_plan(tmp_path / "nan.json", confidence=float("nan"))

    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    schema = json.loads((root / "spec/pilot-plan-v1.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(plan)

    tampered = dict(plan)
    tampered["unexpected_free_text"] = "copied message body"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="allowlist"):
        load_pilot_plan(path)


def test_exact_bounds_and_pre_registered_gate_pass(tmp_path, monkeypatch):
    plan_path = tmp_path / "pilot-plan.json"
    _create_plan(plan_path)
    bundle = _fake_bundle(tmp_path, monkeypatch)

    gate = build_pilot_gate(bundle, plan_path)

    expected_recall_lower = math.pow(0.05, 1 / 100)
    expected_fpr_upper = 1 - math.pow(0.05, 1 / 300)
    assert gate["verdict"] == "pass"
    assert gate["failed_checks"] == []
    assert gate["metrics"]["routing_recall_lower_bound"] == pytest.approx(
        expected_recall_lower, abs=1e-11
    )
    assert gate["metrics"]["routing_false_positive_rate_upper_bound"] == pytest.approx(
        expected_fpr_upper, abs=1e-11
    )
    assert gate["plan_binding"]["sha256"] == pilot_plan_sha256(plan_path)
    assert len(gate["run_binding"]["manifest_sha256"]) == 64

    jsonschema = pytest.importorskip("jsonschema")
    root = Path(__file__).parents[1]
    schema = json.loads((root / "spec/pilot-gate-v1.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(gate)


def test_gate_distinguishes_insufficient_evidence_from_performance_failure(
    tmp_path, monkeypatch
):
    plan_path = tmp_path / "pilot-plan.json"
    _create_plan(plan_path)
    incomplete = _report(
        latest=399,
        fraud=99,
        uncertain=0,
        true_positive=99,
        false_negative=0,
    )
    bundle = _fake_bundle(tmp_path, monkeypatch, incomplete)

    gate = build_pilot_gate(bundle, plan_path)
    assert gate["verdict"] == "insufficient_evidence"
    assert set(gate["failed_checks"]) == {"fraud_label_count", "label_coverage"}
    assert all(
        item["status"] == "not_evaluable"
        for item in gate["checks"]
        if item["group"] == "acceptance"
    )

    failed = _report(
        true_positive=99,
        false_negative=1,
        routed=99,
    )
    monkeypatch.setattr(pilot_module, "build_shadow_report", lambda unused: failed)
    gate = build_pilot_gate(bundle, plan_path)
    assert gate["verdict"] == "fail"
    assert gate["failed_checks"] == ["routing_recall_lower_bound"]


def test_plan_created_after_run_is_rejected(tmp_path, monkeypatch):
    plan_path = tmp_path / "pilot-plan.json"
    plan = _create_plan(plan_path)
    plan["created_at"] = "2100-01-01T00:00:00+00:00"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    bundle = _fake_bundle(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="created before"):
        build_pilot_gate(bundle, plan_path)


def test_gate_rejects_unregistered_control_and_pre_run_labels(tmp_path, monkeypatch):
    plan_path = tmp_path / "pilot-plan.json"
    _create_plan(plan_path)
    bundle = _fake_bundle(tmp_path, monkeypatch)
    monkeypatch.setattr(
        pilot_module,
        "load_inbox_manifest",
        lambda unused: [{
            "status": "processed",
            "assessment": {
                "detector": "tfidf-logreg",
                "detector_artifact_sha256": detector_artifact_sha256("tfidf-logreg"),
                "threshold": 0.6,
                "policy_id": None,
            },
        }],
    )
    with pytest.raises(ValueError, match="does not match"):
        build_pilot_gate(bundle, plan_path)

    monkeypatch.setattr(
        pilot_module,
        "load_inbox_manifest",
        lambda unused: [{
            "status": "processed",
            "assessment": {
                "detector": "tfidf-logreg",
                "detector_artifact_sha256": detector_artifact_sha256("tfidf-logreg"),
                "threshold": 0.5,
                "policy_id": None,
            },
        }],
    )
    monkeypatch.setattr(
        pilot_module,
        "load_analyst_labels",
        lambda unused: ([{"labeled_at": "2098-12-31T23:59:59+00:00"}], {}),
    )
    with pytest.raises(ValueError, match="cannot predate"):
        build_pilot_gate(bundle, plan_path)


def test_gate_rejects_inputs_changed_during_evaluation(tmp_path, monkeypatch):
    plan_path = tmp_path / "pilot-plan.json"
    _create_plan(plan_path)
    bundle = _fake_bundle(tmp_path, monkeypatch)

    def change_plan_during_report(unused):
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["acceptance"]["max_routed_count"] = 101
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        return _report()

    monkeypatch.setattr(pilot_module, "build_shadow_report", change_plan_during_report)
    with pytest.raises(ValueError, match="changed during"):
        build_pilot_gate(bundle, plan_path)


def test_cli_plan_then_unlabeled_gate_fails_closed_and_writes_private_artifacts(
    tmp_path, capsys
):
    plan_path = tmp_path / "pilot-plan.json"
    assert main([
        "shadow",
        "plan",
        "--out",
        str(plan_path),
        "--plan-id",
        "integration-pilot",
        "--min-processed",
        "2",
        "--min-fraud-labels",
        "1",
        "--min-benign-labels",
        "1",
        "--max-uncertain-rate",
        "0",
        "--max-failure-rate",
        "0",
        "--min-recall-lower",
        "0.1",
        "--max-fpr-upper",
        "0.99",
        "--max-routed-rate",
        "1",
        "--max-routed-count",
        "2",
    ]) == 0
    assert "sha256:" in capsys.readouterr().out

    first = tmp_path / "first.eml"
    second = tmp_path / "second.eml"
    first.write_bytes(_email("Account alert", "Verify your account immediately."))
    second.write_bytes(_email("Team agenda", "Agenda for the project meeting."))
    bundle = tmp_path / "pilot"
    assert main([
        "shadow", "run", str(first), str(second), "--out", str(bundle),
        "--threshold", "0.5",
    ]) == 0
    capsys.readouterr()

    assert main(["shadow", "gate", str(bundle), "--plan", str(plan_path)]) == 1
    assert "insufficient_evidence" in capsys.readouterr().out
    for name in ("pilot-gate.json", "pilot-gate.md"):
        assert os.stat(bundle / name).st_mode & 0o777 == 0o600
    assert (bundle / "pilot-plan.json").read_bytes() == plan_path.read_bytes()
    assert os.stat(bundle / "pilot-plan.json").st_mode & 0o777 == 0o600
    gate = json.loads((bundle / "pilot-gate.json").read_text(encoding="utf-8"))
    assert gate["privacy"] == {
        "aggregate_only": True,
        "contains_case_identifiers": False,
        "contains_message_content": False,
    }
    persisted = json.dumps(gate)
    assert "case-" not in persisted
    assert "Verify your account" not in persisted

    prior_labels_digest = gate["run_binding"]["labels_sha256"]
    first_entry = json.loads(
        (bundle / "manifest.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert main([
        "shadow",
        "label",
        str(bundle),
        first_entry["case_id"],
        "fraud",
        "--reason",
        "confirmed_external",
    ]) == 0
    assert "and Pilot Gate" in capsys.readouterr().out
    refreshed = json.loads((bundle / "pilot-gate.json").read_text(encoding="utf-8"))
    assert refreshed["run_binding"]["labels_sha256"] != prior_labels_digest
    assert refreshed["verdict"] == "insufficient_evidence"
