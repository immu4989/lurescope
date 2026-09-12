"""Fail-closed deployment gate for independently verified LureMandate evidence."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from . import __version__
from .mandate import _instant, validate_mandate_verification
from .mandate_auth import validate_authenticated_mandate_verification
from .mandate_otel import validate_mandate_otel_projection
from .mandate_otel_auth import validate_authenticated_mandate_otel_projection
from .permit import (
    _canonical,
    _digest,
    _exact,
    _id,
    _read,
    _sha256,
    _strict,
    _timestamp,
    _timestamp_now,
    _write_new,
)

KEY_POLICY_SCHEMA = "https://github.com/immu4989/lurescope/spec/luremandate-approver-key-policy/v1"
GATE_SCHEMA = "https://github.com/immu4989/lurescope/spec/luremandate-deployment-gate/v1"
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_APPROVERS = 65_536

CHECK_IDS = [
    "semantic_verification_recomputed",
    "authenticated_approval_evidence_recomputed",
    "body_free_telemetry_projection_recomputed",
    "telemetry_source_signature_authenticated",
    "exact_plan_run_and_evaluation_binding",
    "preregistered_approver_key_policy",
    "externally_pinned_approver_keys",
    "deployment_engine_identity_matches_policy",
    "run_freshness_matches_policy",
    "transaction_authority_acceptance_met",
]
LIMITATIONS = [
    "gate_reconciles_submitted_semantic_approval_signature_and_receiver_signed_body_free_telemetry_evidence_only",
    "approver_key_policy_is_caller_supplied_and_requires_separately_governed_authorization",
    "key_fingerprints_do_not_prove_identity_proofing_hardware_backing_key_custody_or_revocation",
    "receiver_signature_does_not_prove_telemetry_completeness_clock_sync_delivery_or_non_bypassable_instrumentation",
    "effect_observations_sensor_identity_and_complete_runtime_mediation_remain_external_claims",
    "impact_units_roles_thresholds_and_legal_authority_require_organization_specific_governance",
    "a_pass_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
]
INTERPRETATION = (
    "Pass means an independently reproduced transaction-authority evaluation, authenticated "
    "P-256 approval statements, and an independently reconstructed body-free telemetry export "
    "authenticated by an externally pinned receiver key "
    "bind the same exact plan, run, and producer evaluation. Every approval key fingerprint "
    "matches a preregistered caller-supplied policy, and the run matches caller-supplied engine, "
    "receiver-instance, and freshness policy. It does not establish trusted identity proofing, "
    "key custody, trusted time, telemetry completeness, effect-sensor authenticity, complete "
    "mediation, legal authority, compliance, safety, or deployment authorization."
)


def _read_source(path: Path, label: str, maximum: int = MAX_SOURCE_BYTES) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.parent.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    size = target.stat().st_size
    if not 1 <= size <= maximum:
        raise ValueError(f"{label} exceeds its bounded size")
    return target.read_bytes()


def _load_source(
    path: Path,
    label: str,
    validator: Callable[[Any], Dict[str, Any]],
    maximum: int = MAX_SOURCE_BYTES,
) -> Tuple[bytes, Dict[str, Any]]:
    payload = _read_source(path, label, maximum)
    return payload, validator(_strict(payload, label))


def validate_approver_key_policy(value: Any) -> Dict[str, Any]:
    policy = _exact(
        value,
        "LureMandate approver-key policy",
        (
            "schema",
            "schema_version",
            "policy_id",
            "created_at",
            "campaign_id",
            "environment",
            "approver_keys",
        ),
    )
    if policy["schema"] != KEY_POLICY_SCHEMA or policy["schema_version"] != 1:
        raise ValueError("unsupported LureMandate approver-key policy schema")
    _id(policy["policy_id"], "approver-key policy id")
    _timestamp(policy["created_at"], "approver-key policy created_at")
    _id(policy["campaign_id"], "approver-key policy campaign_id")
    environment = _exact(
        policy["environment"], "approver-key policy environment", ("environment_id", "tenant_id")
    )
    _id(environment["environment_id"], "approver-key policy environment_id")
    _id(environment["tenant_id"], "approver-key policy tenant_id")
    records = policy["approver_keys"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_APPROVERS:
        raise ValueError("approver-key policy keys must be a nonempty bounded array")
    approver_ids: list[str] = []
    fingerprints: list[str] = []
    for index, item in enumerate(records):
        record = _exact(
            item,
            f"approver_keys[{index}]",
            ("approver_id", "public_key_sha256"),
        )
        approver_ids.append(_id(record["approver_id"], "approver key approver_id"))
        fingerprints.append(_digest(record["public_key_sha256"], "approver key fingerprint"))
    if approver_ids != sorted(approver_ids) or len(approver_ids) != len(set(approver_ids)):
        raise ValueError("approver-key policy IDs must be sorted and unique")
    if len(fingerprints) != len(set(fingerprints)):
        raise ValueError("approver-key policy must assign one distinct key to each approver")
    return dict(policy)


def load_approver_key_policy(path: Path) -> Dict[str, Any]:
    payload = _read_source(Path(path), "LureMandate approver-key policy", 4 * 1024 * 1024)
    return validate_approver_key_policy(_strict(payload, "LureMandate approver-key policy"))


def _gate_value(
    semantic: Mapping[str, Any],
    authenticated: Mapping[str, Any],
    projection: Mapping[str, Any],
    authenticated_projection: Mapping[str, Any],
    key_policy: Mapping[str, Any],
    *,
    semantic_sha256: str,
    authenticated_sha256: str,
    projection_sha256: str,
    authenticated_projection_sha256: str,
    key_policy_sha256: str,
    gate_id: str,
    created_at: str,
    producer_version: str,
    minimum_run_started_at: str,
    expected_engine_id: str,
    expected_engine_version: str,
    expected_engine_artifact_sha256: str,
    expected_receiver_instance_id: str,
    expected_receiver_key_id: str,
) -> Dict[str, Any]:
    _id(gate_id, "LureMandate deployment gate id")
    _timestamp(created_at, "LureMandate deployment gate created_at")
    _id(producer_version, "LureMandate deployment gate producer version")
    minimum_run = _timestamp(minimum_run_started_at, "minimum run started_at")
    engine_id = _id(expected_engine_id, "expected engine id")
    engine_version = _id(expected_engine_version, "expected engine version")
    engine_artifact = _digest(expected_engine_artifact_sha256, "expected engine artifact digest")
    receiver_instance = _id(expected_receiver_instance_id, "expected receiver instance id")
    receiver_key_id = _digest(expected_receiver_key_id, "expected receiver key ID")
    for digest, field in (
        (semantic_sha256, "semantic verification source digest"),
        (authenticated_sha256, "authenticated verification source digest"),
        (projection_sha256, "telemetry projection source digest"),
        (authenticated_projection_sha256, "authenticated telemetry source digest"),
        (key_policy_sha256, "approver-key policy source digest"),
    ):
        _digest(digest, field)

    evaluation = semantic["producer_evaluation"]
    plan = evaluation["plan"]
    run = evaluation["run"]
    export = projection["inputs"]["otel_log_export"]
    receiver = export["receiver"]
    latest_source_time = max(
        _instant(semantic["verified_at"], "semantic verified_at"),
        _instant(authenticated["verified_at"], "authenticated verified_at"),
        _instant(projection["generated_at"], "projection generated_at"),
        _instant(authenticated_projection["verified_at"], "telemetry authentication time"),
    )
    if _instant(created_at, "gate created_at") < latest_source_time:
        raise ValueError("LureMandate deployment gate predates its source evidence")

    if semantic["documents"] != authenticated["documents"]:
        raise ValueError("semantic and authenticated evidence do not bind exact source bytes")
    if authenticated["producer_evaluation"] != evaluation:
        raise ValueError("semantic and authenticated evidence bind different evaluations")
    if projection["inputs"]["mandate_plan"] != plan or projection["run"] != run:
        raise ValueError("telemetry and verification evidence do not bind the same plan and run")
    if (
        projection["run_sha256"] != evaluation["run_sha256"]
        or projection["inputs"]["mandate_plan_sha256"] != evaluation["plan_sha256"]
    ):
        raise ValueError("telemetry and verification evidence digests do not match")
    if (
        authenticated_projection["projection"] != projection
        or authenticated_projection["documents"]["projection"]["document_sha256"]
        != projection_sha256
    ):
        raise ValueError(
            "authenticated telemetry evidence does not bind the exact projection bytes"
        )
    if authenticated_projection["summary"][
        "telemetry_source_authenticated"
    ] is not True or not secrets.compare_digest(
        authenticated_projection["summary"]["receiver_public_key_sha256"], receiver_key_id
    ):
        raise ValueError("telemetry receiver signature differs from external key policy")

    if (
        key_policy["campaign_id"] != plan["campaign_id"]
        or key_policy["environment"] != plan["environment"]
    ):
        raise ValueError("approver-key policy does not bind the evaluated campaign environment")
    if _instant(key_policy["created_at"], "key policy created_at") > _instant(
        plan["created_at"], "plan created_at"
    ):
        raise ValueError("approver-key policy was not preregistered before the plan")
    pinned_keys = key_policy["approver_keys"]
    authenticated_keys = sorted(
        (
            {
                "approver_id": item["approver_id"],
                "public_key_sha256": item["public_key_sha256"],
            }
            for item in authenticated["public_keys"]
        ),
        key=lambda item: item["approver_id"],
    )
    if pinned_keys != authenticated_keys:
        raise ValueError("authenticated approval keys differ from the external key policy")

    expected_engine = {
        "engine_id": engine_id,
        "engine_version": engine_version,
        "engine_artifact_sha256": engine_artifact,
    }
    if run["engine"] != expected_engine:
        raise ValueError("LureMandate run engine differs from external deployment policy")
    expected_receiver = {
        "name": engine_id,
        "instance_id": receiver_instance,
        "version": engine_version,
        "artifact_sha256": engine_artifact,
    }
    if receiver != expected_receiver:
        raise ValueError("telemetry receiver differs from external deployment policy")
    if _instant(run["started_at"], "run started_at") < _instant(
        minimum_run, "minimum run started_at"
    ):
        raise ValueError("LureMandate run predates external freshness policy")

    semantic_status = semantic["summary"]["verdict"]
    authentication_status = (
        "pass"
        if authenticated["summary"]["verdict"] == "pass"
        and authenticated["summary"]["approval_authentication_complete"] is True
        and authenticated["summary"]["transaction_authority_evidence_authenticated"] is True
        else "fail"
    )
    authority_status = (
        "pass"
        if semantic["summary"]["transaction_authority_verified"] is True
        and authentication_status == "pass"
        else "fail"
    )
    checks = [
        {"check_id": "semantic_verification_recomputed", "status": semantic_status},
        {
            "check_id": "authenticated_approval_evidence_recomputed",
            "status": authentication_status,
        },
        {"check_id": "body_free_telemetry_projection_recomputed", "status": "pass"},
        {"check_id": "telemetry_source_signature_authenticated", "status": "pass"},
        {"check_id": "exact_plan_run_and_evaluation_binding", "status": "pass"},
        {"check_id": "preregistered_approver_key_policy", "status": "pass"},
        {"check_id": "externally_pinned_approver_keys", "status": "pass"},
        {"check_id": "deployment_engine_identity_matches_policy", "status": "pass"},
        {"check_id": "run_freshness_matches_policy", "status": "pass"},
        {"check_id": "transaction_authority_acceptance_met", "status": authority_status},
    ]
    if [item["check_id"] for item in checks] != CHECK_IDS:
        raise RuntimeError("LureMandate deployment gate check order is inconsistent")
    overall_status = "pass" if all(item["status"] == "pass" for item in checks) else "fail"
    documents = semantic["documents"]
    return {
        "schema": GATE_SCHEMA,
        "schema_version": 1,
        "gate_id": gate_id,
        "created_at": created_at,
        "producer": {"name": "lurescope", "version": producer_version},
        "campaign": {
            "campaign_id": plan["campaign_id"],
            "environment": dict(plan["environment"]),
            "run_id": run["run_id"],
        },
        "policy": {
            "approver_key_policy_id": key_policy["policy_id"],
            "approver_key_policy_sha256": key_policy_sha256,
            "minimum_run_started_at": minimum_run,
            "expected_engine_id": engine_id,
            "expected_engine_version": engine_version,
            "expected_engine_artifact_sha256": engine_artifact,
            "expected_receiver_instance_id": receiver_instance,
            "expected_receiver_key_id": receiver_key_id,
        },
        "contract": {
            "plan_sha256": evaluation["plan_sha256"],
            "run_sha256": evaluation["run_sha256"],
            "evaluation_sha256": _sha256(_canonical(evaluation)),
            "plan_document_sha256": documents["plan"]["document_sha256"],
            "run_document_sha256": documents["run"]["document_sha256"],
            "evaluation_document_sha256": documents["evaluation"]["document_sha256"],
            "engine": dict(run["engine"]),
            "receiver": dict(receiver),
        },
        "sources": {
            "semantic_verification": {
                "sha256": semantic_sha256,
                "verification_id": semantic["verification_id"],
                "verified_at": semantic["verified_at"],
                "verdict": semantic_status,
            },
            "authenticated_verification": {
                "sha256": authenticated_sha256,
                "verification_id": authenticated["verification_id"],
                "verified_at": authenticated["verified_at"],
                "verdict": authenticated["summary"]["verdict"],
                "authenticated_approval_count": authenticated["summary"][
                    "authenticated_approval_count"
                ],
                "approver_key_count": authenticated["summary"]["approver_key_count"],
            },
            "otel_projection": {
                "sha256": projection_sha256,
                "generated_at": projection["generated_at"],
                "source_export_sha256": projection["inputs"]["otel_log_export_sha256"],
                "record_count": len(export["records"]),
            },
            "authenticated_otel_projection": {
                "sha256": authenticated_projection_sha256,
                "verification_id": authenticated_projection["verification_id"],
                "verified_at": authenticated_projection["verified_at"],
                "receiver_public_key_sha256": authenticated_projection["summary"][
                    "receiver_public_key_sha256"
                ],
            },
        },
        "checks": checks,
        "overall_status": overall_status,
        "limitations": list(LIMITATIONS),
        "interpretation_boundary": INTERPRETATION,
    }


def _sources(
    semantic_verification: Path,
    authenticated_verification: Path,
    otel_projection: Path,
    authenticated_otel_projection: Path,
    approver_key_policy: Path,
) -> Tuple[
    bytes,
    Dict[str, Any],
    bytes,
    Dict[str, Any],
    bytes,
    Dict[str, Any],
    bytes,
    Dict[str, Any],
    bytes,
    Dict[str, Any],
]:
    semantic_payload, semantic = _load_source(
        semantic_verification,
        "LureMandate semantic verification",
        validate_mandate_verification,
    )
    authenticated_payload, authenticated = _load_source(
        authenticated_verification,
        "LureMandate authenticated verification",
        validate_authenticated_mandate_verification,
    )
    projection_payload, projection = _load_source(
        otel_projection,
        "LureMandate OpenTelemetry projection",
        validate_mandate_otel_projection,
        8 * 1024 * 1024,
    )
    authenticated_projection_payload, authenticated_projection = _load_source(
        authenticated_otel_projection,
        "authenticated LureMandate OpenTelemetry projection",
        validate_authenticated_mandate_otel_projection,
        16 * 1024 * 1024,
    )
    policy_payload, policy = _load_source(
        approver_key_policy,
        "LureMandate approver-key policy",
        validate_approver_key_policy,
        4 * 1024 * 1024,
    )
    return (
        semantic_payload,
        semantic,
        authenticated_payload,
        authenticated,
        projection_payload,
        projection,
        authenticated_projection_payload,
        authenticated_projection,
        policy_payload,
        policy,
    )


def create_mandate_deployment_gate(
    semantic_verification: Path,
    authenticated_verification: Path,
    otel_projection: Path,
    authenticated_otel_projection: Path,
    approver_key_policy: Path,
    output: Path,
    *,
    gate_id: str,
    minimum_run_started_at: str,
    expected_engine_id: str,
    expected_engine_version: str,
    expected_engine_artifact_sha256: str,
    expected_receiver_instance_id: str,
    expected_receiver_key_id: str,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    (
        semantic_payload,
        semantic,
        authenticated_payload,
        authenticated,
        projection_payload,
        projection,
        authenticated_projection_payload,
        authenticated_projection,
        policy_payload,
        policy,
    ) = _sources(
        Path(semantic_verification),
        Path(authenticated_verification),
        Path(otel_projection),
        Path(authenticated_otel_projection),
        Path(approver_key_policy),
    )
    source_times = [
        semantic["verified_at"],
        authenticated["verified_at"],
        projection["generated_at"],
        authenticated_projection["verified_at"],
    ]
    latest = max(source_times, key=lambda value: _instant(value, "source time"))
    current = _timestamp_now()
    effective_created_at = created_at or (
        latest if _instant(current, "current time") < _instant(latest, "latest source") else current
    )
    result = _gate_value(
        semantic,
        authenticated,
        projection,
        authenticated_projection,
        policy,
        semantic_sha256=_sha256(semantic_payload),
        authenticated_sha256=_sha256(authenticated_payload),
        projection_sha256=_sha256(projection_payload),
        authenticated_projection_sha256=_sha256(authenticated_projection_payload),
        key_policy_sha256=_sha256(policy_payload),
        gate_id=gate_id,
        created_at=effective_created_at,
        producer_version=__version__,
        minimum_run_started_at=minimum_run_started_at,
        expected_engine_id=expected_engine_id,
        expected_engine_version=expected_engine_version,
        expected_engine_artifact_sha256=expected_engine_artifact_sha256,
        expected_receiver_instance_id=expected_receiver_instance_id,
        expected_receiver_key_id=expected_receiver_key_id,
    )
    payload = _canonical(result)
    if len(payload) > 4 * 1024 * 1024:
        raise ValueError("LureMandate deployment gate exceeds the report size limit")
    _write_new(Path(output), payload)
    return result


def verify_mandate_deployment_gate(
    gate: Path,
    semantic_verification: Path,
    authenticated_verification: Path,
    otel_projection: Path,
    authenticated_otel_projection: Path,
    approver_key_policy: Path,
    *,
    minimum_run_started_at: str,
    expected_engine_id: str,
    expected_engine_version: str,
    expected_engine_artifact_sha256: str,
    expected_receiver_instance_id: str,
    expected_receiver_key_id: str,
) -> Dict[str, Any]:
    gate_payload = _read(Path(gate), private=True)
    reviewed = _exact(
        _strict(gate_payload, "LureMandate deployment gate"),
        "LureMandate deployment gate",
        (
            "schema",
            "schema_version",
            "gate_id",
            "created_at",
            "producer",
            "campaign",
            "policy",
            "contract",
            "sources",
            "checks",
            "overall_status",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if reviewed["schema"] != GATE_SCHEMA or reviewed["schema_version"] != 1:
        raise ValueError("unsupported LureMandate deployment gate schema")
    producer = _exact(reviewed["producer"], "deployment gate producer", ("name", "version"))
    if producer["name"] != "lurescope":
        raise ValueError("LureMandate deployment gate producer is unsupported")
    (
        semantic_payload,
        semantic,
        authenticated_payload,
        authenticated,
        projection_payload,
        projection,
        authenticated_projection_payload,
        authenticated_projection,
        policy_payload,
        policy,
    ) = _sources(
        Path(semantic_verification),
        Path(authenticated_verification),
        Path(otel_projection),
        Path(authenticated_otel_projection),
        Path(approver_key_policy),
    )
    expected = _gate_value(
        semantic,
        authenticated,
        projection,
        authenticated_projection,
        policy,
        semantic_sha256=_sha256(semantic_payload),
        authenticated_sha256=_sha256(authenticated_payload),
        projection_sha256=_sha256(projection_payload),
        authenticated_projection_sha256=_sha256(authenticated_projection_payload),
        key_policy_sha256=_sha256(policy_payload),
        gate_id=reviewed["gate_id"],
        created_at=reviewed["created_at"],
        producer_version=producer["version"],
        minimum_run_started_at=minimum_run_started_at,
        expected_engine_id=expected_engine_id,
        expected_engine_version=expected_engine_version,
        expected_engine_artifact_sha256=expected_engine_artifact_sha256,
        expected_receiver_instance_id=expected_receiver_instance_id,
        expected_receiver_key_id=expected_receiver_key_id,
    )
    if reviewed != expected or not secrets.compare_digest(gate_payload, _canonical(expected)):
        raise ValueError("LureMandate deployment gate does not independently reproduce")
    return {
        "valid": True,
        "gate_id": expected["gate_id"],
        "gate_sha256": _sha256(gate_payload),
        "overall_status": expected["overall_status"],
        "contract": expected["contract"],
        "checks": expected["checks"],
        "limitations": list(LIMITATIONS),
        "interpretation_boundary": INTERPRETATION,
    }
