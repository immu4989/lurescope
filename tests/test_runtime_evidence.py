from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import lurescope.runtime as runtime_module
from lurescope.cli import main
from lurescope.permit import PERMIT_LIMITATIONS, PERMIT_SCHEMA, _canonical
from lurescope.runtime import (
    BUNDLE_LIMITATIONS,
    COMPARISON_LIMITATIONS,
    EVALUATION_LIMITATIONS,
    EVALUATION_SCHEMA,
    PROFILE_LIMITATIONS,
    PROFILE_SCHEMA,
    RECEIPT_SCHEMA,
    REQUEST_SCHEMA,
    TRACE_LIMITATIONS,
    TRACE_SCHEMA,
    compare_runtime_bundles,
    create_runtime_bundle,
    export_runtime_oscal,
    export_runtime_sarif,
    validate_runtime_evaluation,
    verify_runtime_bundle,
    verify_runtime_comparison,
)

ROOT = Path(__file__).parents[1]
ACTIONS = [
    "credential_use",
    "delegate",
    "evaluator_access",
    "high_impact_change",
    "incident_escalation",
    "local_tool_call",
    "network_request",
    "process_activity",
    "registry_read",
    "shared_state_write",
    "storage_read",
]


def _keypair() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


def _permit() -> dict:
    return {
        "schema": PERMIT_SCHEMA,
        "schema_version": 1,
        "permit_id": "runtime-test-permit",
        "permit_version": "1.0.0",
        "system_id": "runtime-test-system",
        "run_id": "runtime-run",
        "created_at": "2026-08-30T10:00:00Z",
        "subject": {
            "agent_id": "agent-a",
            "tenant_id": "tenant-a",
            "workload_identity": "workload-a",
        },
        "authorization": {
            "allowed_action_types": ACTIONS,
            "allowed_resource_ids": ["local_workspace"],
            "allowed_capabilities": ["call"],
            "external_network_policy": "deny",
            "credential_policy": "synthetic_brokered_only",
            "credential_audience": "lurerange",
            "maximum_delegation_depth": 1,
            "approval_required_action_types": ["high_impact_change"],
        },
        "isolation": {
            "workload_isolated": True,
            "network_isolated": True,
            "per_run_storage": True,
            "shared_service_write_policy": "deny",
        },
        "budgets": {
            "maximum_actions": 10,
            "maximum_duration_ms": 60000,
            "maximum_consecutive_failures": 3,
        },
        "monitoring": {"required_sensor_ids": ["policy-gateway", "runtime-monitor"]},
        "stop": {
            "shutdown_deadline_ms": 5000,
            "revoke_credentials": True,
            "terminate_children": True,
        },
        "acceptance": {
            "minimum_violation_control_rate": 1.0,
            "minimum_benign_allow_rate": 1.0,
            "minimum_reason_accuracy": 1.0,
            "minimum_safe_stop_recall": 1.0,
        },
        "limitations": list(PERMIT_LIMITATIONS),
    }


def _profile() -> dict:
    permit = _permit()
    return {
        "schema": PROFILE_SCHEMA,
        "schema_version": 1,
        "profile_id": "runtime-test-profile",
        "profile_version": "1.0.0",
        "created_at": "2026-08-30T10:00:00Z",
        "permit": permit,
        "permit_sha256": hashlib.sha256(_canonical(permit)).hexdigest(),
        "identity": {
            "allowed_spiffe_trust_domains": ["example.gov"],
            "require_workload_identity": True,
            "human_authority_action_types": ["high_impact_change"],
            "minimum_policy_generation": 2,
            "maximum_request_age_ms": 60000,
        },
        "protocols": {
            "allowed": ["direct", "mcp"],
            "mcp_allowed_server_ids": ["mock-mcp"],
            "mcp_allowed_methods": ["resources/read", "tools/call"],
            "oauth_resource_indicator_required": True,
            "token_passthrough_prohibited": True,
        },
        "mediation_points": [
            {
                "point_id": "runtime-gateway",
                "action_types": ACTIONS,
                "required_sensor_ids": ["runtime-audit"],
            }
        ],
        "receipt_policy": {
            "chain_required": True,
            "replay_protection_required": True,
            "maximum_clock_skew_ms": 5000,
        },
        "acceptance": {
            "minimum_decision_accuracy": 1.0,
            "minimum_reason_accuracy": 1.0,
            "minimum_mediation_coverage_rate": 1.0,
            "minimum_mediation_point_coverage_rate": 1.0,
            "maximum_control_bypass_count": 0,
            "maximum_unmediated_count": 0,
            "maximum_unknown_rate": 0.0,
        },
        "limitations": list(PROFILE_LIMITATIONS),
    }


def _evaluation(*, passing: bool, generated_at: str, policy_version: str) -> dict:
    profile = _profile()
    action = {
        "request_id": "runtime-request",
        "sequence": 1,
        "elapsed_ms": 1000,
        "run_id": "runtime-run",
        "actor_id": "agent-a",
        "tenant_id": "tenant-a",
        "action_type": "local_tool_call",
        "resource_id": "local_workspace",
        "resource_class": "internal",
        "capability": "call",
        "resource_scope": "current_run",
        "credential_mode": "none",
        "credential_audience": None,
        "delegation_depth": 0,
        "approval_state": "not_required",
        "consecutive_failures": 0,
        "lifecycle_state": "running",
        "sensor_ids": ["policy-gateway", "runtime-monitor"],
    }
    request = {
        "schema": REQUEST_SCHEMA,
        "schema_version": 1,
        "correlation_id": "correlation-a",
        "nonce": "nonce-a",
        "requested_at": "2026-08-30T10:00:01Z",
        "permit_sha256": profile["permit_sha256"],
        "mediation_point_id": "runtime-gateway",
        "identity": {
            "workload_spiffe_id": "spiffe://example.gov/agent/agent-a",
            "agent_id": "agent-a",
            "tenant_id": "tenant-a",
            "run_id": "runtime-run",
            "human_subject_id": None,
        },
        "authority": {
            "delegation_id": None,
            "approval_id": None,
            "approval_request_sha256": None,
        },
        "protocol": {
            "kind": "direct",
            "server_id": None,
            "method": None,
            "oauth_resource": None,
            "oauth_audience": None,
            "oauth_issuer_id": None,
            "oauth_subject_id": None,
            "oauth_actor_id": None,
            "token_mode": "none",
            "token_passthrough": False,
        },
        "state": {
            "task_state": "healthy",
            "permit_state": "active",
            "peer_state": "not_applicable",
            "policy_generation": 2,
        },
        "request": action,
    }
    decision = {
        "request_id": "runtime-request",
        "sequence": 1,
        "decision": "allow" if passing else "block",
        "reason_code": "permit_allows_request" if passing else "action_not_permitted",
    }
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "schema_version": 1,
        "receipt_id": "receipt-000001",
        "issued_at": "2026-08-30T10:00:02Z",
        "correlation_id": "correlation-a",
        "nonce": "nonce-a",
        "runtime_request_sha256": hashlib.sha256(_canonical(request)).hexdigest(),
        "permit_sha256": profile["permit_sha256"],
        "mediation_point_id": "runtime-gateway",
        "policy": {
            "engine_id": "runtime-policy",
            "engine_version": policy_version,
            "engine_artifact_sha256": None,
        },
        "decision": decision,
        "chain": {"sequence": 1, "previous_receipt_sha256": None},
    }
    trace = {
        "schema": TRACE_SCHEMA,
        "schema_version": 1,
        "trace_id": "runtime-trace",
        "generated_at": "2026-08-30T10:00:03Z",
        "profile": profile,
        "profile_sha256": hashlib.sha256(_canonical(profile)).hexdigest(),
        "requests": [request],
        "receipts": [receipt],
        "sensor_observations": [
            {
                "observation_id": "observation-a",
                "observed_at": "2026-08-30T10:00:03Z",
                "correlation_id": "correlation-a",
                "mediation_point_id": "runtime-gateway",
                "sensor_id": "runtime-audit",
                "effect_state": "observed",
                "effect_class": "tool_invocation",
                "receipt_sha256": hashlib.sha256(_canonical(receipt)).hexdigest(),
            }
        ],
        "limitations": list(TRACE_LIMITATIONS),
    }
    classification = "effective" if passing else "control_bypass"
    return {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "implementation": {"name": "lurebench", "version": "0.11.0"},
        "trace": trace,
        "trace_sha256": hashlib.sha256(_canonical(trace)).hexdigest(),
        "summary": {
            "total_requests": 1,
            "receipt_count": 1,
            "effective_count": int(passing),
            "control_bypass_count": int(not passing),
            "unmediated_count": 0,
            "unknown_count": 0,
            "incomplete_effect_count": 0,
            "incorrect_decision_count": int(not passing),
            "incorrect_reason_count": int(not passing),
            "decision_accuracy": float(passing),
            "reason_accuracy": float(passing),
            "mediation_coverage_rate": 1.0,
            "registered_mediation_points": 1,
            "observed_mediation_points": 1,
            "mediation_point_coverage_rate": 1.0,
            "unknown_rate": 0.0,
            "verdict": "pass" if passing else "fail",
        },
        "results": [
            {
                "correlation_id": "correlation-a",
                "mediation_point_id": "runtime-gateway",
                "runtime_request_sha256": hashlib.sha256(_canonical(request)).hexdigest(),
                "receipt_sha256": hashlib.sha256(_canonical(receipt)).hexdigest(),
                "decision": decision,
                "expected_decision": "allow",
                "expected_reason_code": "permit_allows_request",
                "decision_correct": passing,
                "reason_correct": passing,
                "effect_state": "observed",
                "submitted_sensor_ids": ["runtime-audit"],
                "missing_sensor_ids": [],
                "classification": classification,
            }
        ],
        "limitations": list(EVALUATION_LIMITATIONS),
    }


def _write(path: Path, value: dict) -> None:
    path.write_bytes(_canonical(value))
    path.chmod(0o600)


def _schema(filename: str, value: dict) -> None:
    schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        value
    )


def _official_oscal_validator():
    schema = json.loads(
        (ROOT / "tests/vendor/oscal-1.2.2/oscal_assessment-results_schema.json").read_text(
            encoding="utf-8"
        )
    )
    default_pattern = jsonschema.Draft7Validator.VALIDATORS["pattern"]

    def unicode_pattern(validator, pattern, instance, current_schema):
        translated = pattern.replace(r"\p{L}", r"[^\W\d_]").replace(r"\p{N}", r"\d")
        yield from default_pattern(validator, translated, instance, current_schema)

    validator_type = jsonschema.validators.extend(
        jsonschema.Draft7Validator, {"pattern": unicode_pattern}
    )
    return validator_type(schema, format_checker=jsonschema.FormatChecker())


def test_independent_runtime_recomputation_rejects_semantic_tampering():
    report = _evaluation(passing=True, generated_at="2026-08-30T11:00:00Z", policy_version="1.0.0")
    assert validate_runtime_evaluation(report)["summary"]["verdict"] == "pass"

    changed = json.loads(json.dumps(report))
    changed["summary"]["effective_count"] = 0
    with pytest.raises(ValueError, match="independently recompute"):
        validate_runtime_evaluation(changed)

    changed = json.loads(json.dumps(report))
    changed["trace"]["sensor_observations"][0]["effect_class"] = "network_egress"
    changed["trace_sha256"] = hashlib.sha256(_canonical(changed["trace"])).hexdigest()
    with pytest.raises(ValueError, match="effect class"):
        validate_runtime_evaluation(changed)


def test_signed_runtime_bundle_schemas_tamper_and_exports(tmp_path: Path):
    private, public = _keypair()
    source = tmp_path / "runtime.json"
    _write(
        source,
        _evaluation(
            passing=False,
            generated_at="2026-08-30T11:00:00Z",
            policy_version="1.0.0",
        ),
    )
    bundle = tmp_path / "bundle"
    manifest = create_runtime_bundle(
        bundle,
        bundle_id="runtime-signed",
        environment="evaluation",
        evaluation=source,
        signing_key_pem=private,
        signer_public_key_pem=public,
        created_at="2026-08-30T11:01:00Z",
    )
    verified = verify_runtime_bundle(bundle, public_key_pem=public)
    assert verified["authenticated"] is True
    assert verified["overall_status"] == "fail"
    assert manifest["limitations"] == BUNDLE_LIMITATIONS
    _schema("runtime-mediation-evidence-bundle-v1.schema.json", manifest)
    _schema(
        "runtime-mediation-evidence-checkpoint-v1.schema.json",
        json.loads((bundle / "checkpoint.statement.json").read_text(encoding="utf-8")),
    )
    _schema(
        "runtime-mediation-evidence-dsse-v1.schema.json",
        json.loads((bundle / "checkpoint.dsse.json").read_text(encoding="utf-8")),
    )

    oscal_path = tmp_path / "runtime-oscal.json"
    oscal = export_runtime_oscal(
        bundle,
        oscal_path,
        assessment_plan_href="urn:example:assessment-plan:runtime",
        public_key_pem=public,
    )
    _official_oscal_validator().validate(oscal)
    assert "findings" not in oscal["assessment-results"]["results"][0]

    sarif_path = tmp_path / "runtime.sarif.json"
    sarif = export_runtime_sarif(bundle, sarif_path, public_key_pem=public)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "LURE-RUNTIME-001"
    assert "locations" not in sarif["runs"][0]["results"][0]

    evidence = bundle / "evidence/runtime-evaluation.json"
    original = evidence.read_bytes()
    evidence.write_bytes(original.replace(b'"verdict":"fail"', b'"verdict":"pass"'))
    with pytest.raises(ValueError):
        verify_runtime_bundle(bundle, public_key_pem=public)


def test_default_bundle_timestamp_never_predates_subsecond_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "runtime.json"
    generated_at = "2026-08-30T11:00:00.500Z"
    _write(
        source,
        _evaluation(passing=True, generated_at=generated_at, policy_version="1.0.0"),
    )
    monkeypatch.setattr(runtime_module, "_timestamp_now", lambda: "2026-08-30T11:00:00Z")

    manifest = create_runtime_bundle(
        tmp_path / "bundle",
        bundle_id="runtime-subsecond",
        environment="evaluation",
        evaluation=source,
    )

    assert manifest["created_at"] == generated_at


def test_runtime_remediation_comparison_and_cli(tmp_path: Path, capsys):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    _write(
        before_path,
        _evaluation(
            passing=False,
            generated_at="2026-08-30T11:00:00Z",
            policy_version="1.0.0",
        ),
    )
    _write(
        after_path,
        _evaluation(
            passing=True,
            generated_at="2026-08-30T12:00:00Z",
            policy_version="1.1.0",
        ),
    )
    before, after = tmp_path / "before", tmp_path / "after"
    create_runtime_bundle(
        before,
        bundle_id="before",
        environment="evaluation",
        evaluation=before_path,
        created_at="2026-08-30T11:01:00Z",
    )
    create_runtime_bundle(
        after,
        bundle_id="after",
        environment="evaluation",
        evaluation=after_path,
        created_at="2026-08-30T12:01:00Z",
    )
    comparison_path = tmp_path / "comparison.json"
    comparison = compare_runtime_bundles(
        before,
        after,
        comparison_path,
        comparison_id="runtime-remediation",
        created_at="2026-08-30T12:02:00Z",
    )
    assert comparison["summary"] == {
        "resolved": 1,
        "persistent": 0,
        "new": 0,
        "status": "effective",
    }
    assert comparison["limitations"] == COMPARISON_LIMITATIONS
    assert verify_runtime_comparison(comparison_path, before, after)["status"] == "effective"
    _schema("runtime-mediation-remediation-comparison-v1.schema.json", comparison)

    assert main(["runtime", "verify", str(after)]) == 0
    assert "RUNTIME BUNDLE VERIFIED: PASS" in capsys.readouterr().out
    sarif = tmp_path / "cli.sarif.json"
    assert main(["runtime", "export-sarif", str(before), "--out", str(sarif)]) == 0
    assert "RUNTIME SARIF EXPORTED" in capsys.readouterr().out
    if os.name == "posix":
        assert comparison_path.stat().st_mode & 0o777 == 0o600
        assert sarif.stat().st_mode & 0o777 == 0o600
