"""Cross-artifact deployment gate for operational LureRevoke evidence."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .permit import (
    _canonical,
    _digest,
    _exact,
    _id,
    _integer,
    _read,
    _sha256,
    _strict,
    _timestamp,
    _timestamp_now,
    _write_new,
)
from .revocation import _time, verify_revocation_bundle
from .revocation_otel import load_otel_revocation_projection
from .revocation_topology import load_revocation_topology_audit

GATE_SCHEMA = "https://github.com/immu4989/lurescope/spec/lurerevoke-deployment-gate/v1"
GATE_LIMITATIONS = [
    "gate_reconciles_declared_topology_telemetry_projection_and_signed_evaluation_only",
    "a_pass_does_not_prove_topology_discovery_telemetry_completeness_clock_sync_or_enforcement",
    "source_signature_authenticates_a_key_not_a_receiver_node_operator_or_organization",
    "external_policy_values_are_caller_supplied_and_require_separately_governed_authorization",
    "topology_preregistration_uses_declared_timestamps_and_requires_external_clock_assurance",
    "gate_does_not_establish_causality_interoperability_compliance_or_deployment_authorization",
]
GATE_INTERPRETATION = (
    "Pass means a complete declared topology based on a runtime profile dated no later than the "
    "run, an independently recomputed body-free telemetry projection, and an authenticated passing "
    "revocation evaluation bind the same exact plan, run, system, and receiver contract while "
    "satisfying caller-supplied deployment identity, freshness, and deadline policy. It does not "
    "authenticate that policy or establish trusted time, observation completeness, deployment, "
    "causality, or enforcement authenticity."
)


def _trusted_bundle(path: Path, *, public_key_pem: bytes, expected_key_id: str) -> Dict[str, Any]:
    expected = _digest(expected_key_id, "expected revocation bundle key id")
    verified = verify_revocation_bundle(Path(path), public_key_pem=public_key_pem)
    if len(verified["key_ids"]) != 1 or not secrets.compare_digest(
        verified["key_ids"][0], expected
    ):
        raise ValueError("revocation bundle signer does not match the pinned expected key id")
    return verified


def _require_probe_phase_coverage(plan: Mapping[str, Any]) -> None:
    deadline = plan["acceptance"]["maximum_convergence_ms"]
    events = {item["event_id"]: item for item in plan["events"]}
    event_subjects = {item["subject"]["id"] for item in events.values()}
    required = {
        (event_id, node["node_id"], phase)
        for event_id in events
        for node in plan["nodes"]
        for phase in ("pre_event", "propagation_window", "post_deadline", "unrelated_subject")
    }
    observed = set()
    for probe in plan["probes"]:
        event = events[probe["event_id"]]
        if probe["subject_id"] not in event_subjects:
            phase = "unrelated_subject"
        elif probe["subject_id"] != event["subject"]["id"]:
            continue
        elif probe["attempted_at_ms"] < event["occurred_at_ms"]:
            phase = "pre_event"
        elif probe["attempted_at_ms"] >= event["occurred_at_ms"] + deadline:
            phase = "post_deadline"
        else:
            phase = "propagation_window"
        observed.add((probe["event_id"], probe["node_id"], phase))
    if required - observed:
        raise ValueError("deployment gate plan lacks full probe-phase coverage at every node")


def _require_strict_acceptance(plan: Mapping[str, Any]) -> None:
    acceptance = plan["acceptance"]
    required = {
        "maximum_deadline_miss_count": 0,
        "maximum_post_deadline_allow_count": 0,
        "maximum_collateral_block_count": 0,
        "minimum_delivery_coverage_rate": 1.0,
        "minimum_revoked_block_recall": 1.0,
        "minimum_pre_event_allow_rate": 1.0,
        "minimum_signal_disposition_accuracy": 1.0,
    }
    if any(acceptance[field] != expected for field, expected in required.items()):
        raise ValueError("deployment gate plan weakens strict revocation acceptance thresholds")


def _gate_value(
    topology: Mapping[str, Any],
    projection: Mapping[str, Any],
    verified_bundle: Mapping[str, Any],
    *,
    gate_id: str,
    created_at: str,
    producer_version: str,
    maximum_allowed_convergence_ms: int,
    minimum_run_generated_at: str,
    expected_system_id: str,
    expected_environment: str,
    expected_receiver_name: str,
    expected_receiver_artifact_sha256: str,
) -> Dict[str, Any]:
    _id(gate_id, "revocation deployment gate id")
    _id(producer_version, "revocation deployment gate producer version")
    _timestamp(created_at, "revocation deployment gate created_at")
    policy_deadline = _integer(
        maximum_allowed_convergence_ms,
        "maximum allowed convergence milliseconds",
        1,
        600_000,
    )
    policy_minimum_run_time = _timestamp(
        minimum_run_generated_at, "minimum allowed revocation run timestamp"
    )
    policy_system = _id(expected_system_id, "expected deployment system id")
    if expected_environment not in {"development", "evaluation", "staging", "production"}:
        raise ValueError("expected deployment environment is unsupported")
    policy_receiver = _id(expected_receiver_name, "expected receiver name")
    policy_artifact = _digest(
        expected_receiver_artifact_sha256, "expected receiver artifact digest"
    )
    report = verified_bundle["report"]
    if not verified_bundle["authenticated"] or len(verified_bundle["key_ids"]) != 1:
        raise ValueError("revocation deployment gate requires one authenticated bundle signer")
    latest_source_time = max(
        _time(topology["generated_at"]),
        _time(projection["generated_at"]),
        _time(report["generated_at"]),
    )
    if _time(created_at) < latest_source_time:
        raise ValueError("revocation deployment gate predates source evidence")

    topology_plan = topology["inputs"]["revocation_plan"]
    projection_plan = projection["inputs"]["revocation_plan"]
    plan_digests = {
        topology["inputs"]["revocation_plan_sha256"],
        projection["inputs"]["revocation_plan_sha256"],
        report["plan_sha256"],
    }
    if (
        len(plan_digests) != 1
        or topology_plan != projection_plan
        or projection_plan != report["plan"]
    ):
        raise ValueError("deployment gate sources do not bind the same exact revocation plan")
    if projection["run_sha256"] != report["run_sha256"] or projection["run"] != report["run"]:
        raise ValueError("deployment gate telemetry and evidence do not bind the same exact run")
    system_ids = {
        topology_plan["system_id"],
        projection_plan["system_id"],
        report["plan"]["system_id"],
        verified_bundle["system_id"],
    }
    if len(system_ids) != 1:
        raise ValueError("deployment gate sources name different systems")
    receiver = projection["run"]["implementation"]
    if receiver != report["run"]["implementation"]:
        raise ValueError("deployment gate sources name different receiver implementations")
    if (
        report["plan"]["system_id"] != policy_system
        or verified_bundle["environment"] != expected_environment
        or receiver["name"] != policy_receiver
        or receiver["artifact_sha256"] is None
        or not secrets.compare_digest(receiver["artifact_sha256"], policy_artifact)
    ):
        raise ValueError("deployment gate source identity differs from external policy")
    profile_created_at = topology["inputs"]["runtime_profile"]["created_at"]
    if _time(profile_created_at) > _time(projection["run"]["generated_at"]):
        raise ValueError("deployment gate runtime topology was not preregistered before the run")
    _require_probe_phase_coverage(report["plan"])
    _require_strict_acceptance(report["plan"])
    declared_deadline = report["plan"]["acceptance"]["maximum_convergence_ms"]
    if declared_deadline > policy_deadline:
        raise ValueError("deployment gate convergence deadline exceeds external policy")
    if _time(report["run"]["generated_at"]) < _time(policy_minimum_run_time):
        raise ValueError("deployment gate revocation run predates external freshness policy")

    topology_status = topology["summary"]["verdict"]
    evidence_status = verified_bundle["overall_status"]
    checks = [
        {"check_id": "declared_topology_complete", "status": topology_status},
        {"check_id": "runtime_topology_preregistered", "status": "pass"},
        {"check_id": "probe_phase_coverage_complete", "status": "pass"},
        {"check_id": "strict_acceptance_thresholds", "status": "pass"},
        {"check_id": "convergence_deadline_within_policy", "status": "pass"},
        {"check_id": "run_freshness_matches_policy", "status": "pass"},
        {"check_id": "deployment_identity_matches_policy", "status": "pass"},
        {"check_id": "telemetry_projection_recomputed", "status": "pass"},
        {"check_id": "source_bundle_authenticated", "status": "pass"},
        {"check_id": "revocation_acceptance_met", "status": evidence_status},
    ]
    overall_status = "pass" if all(item["status"] == "pass" for item in checks) else "fail"
    return {
        "schema": GATE_SCHEMA,
        "schema_version": 1,
        "gate_id": gate_id,
        "created_at": created_at,
        "producer": {"name": "lurescope", "version": producer_version},
        "system": {
            "system_id": report["plan"]["system_id"],
            "environment": verified_bundle["environment"],
        },
        "policy": {
            "maximum_allowed_convergence_ms": policy_deadline,
            "declared_convergence_ms": declared_deadline,
            "minimum_run_generated_at": policy_minimum_run_time,
            "expected_system_id": policy_system,
            "expected_environment": expected_environment,
            "expected_receiver_name": policy_receiver,
            "expected_receiver_artifact_sha256": policy_artifact,
        },
        "contract": {
            "plan_sha256": report["plan_sha256"],
            "run_sha256": report["run_sha256"],
            "receiver": dict(receiver),
        },
        "sources": {
            "topology_audit": {
                "sha256": _sha256(_canonical(topology)),
                "verdict": topology_status,
                "covered_mediation_point_count": topology["summary"][
                    "covered_mediation_point_count"
                ],
                "required_mediation_point_count": topology["summary"][
                    "required_mediation_point_count"
                ],
            },
            "otel_projection": {
                "sha256": _sha256(_canonical(projection)),
                "source_export_sha256": projection["inputs"]["otel_log_export_sha256"],
                "record_count": len(projection["inputs"]["otel_log_export"]["records"]),
            },
            "revocation_evidence": {
                "manifest_sha256": verified_bundle["manifest_sha256"],
                "checkpoint_sha256": verified_bundle["statement_sha256"],
                "signer_key_id": verified_bundle["key_ids"][0],
                "overall_status": evidence_status,
            },
        },
        "checks": checks,
        "overall_status": overall_status,
        "limitations": list(GATE_LIMITATIONS),
        "interpretation_boundary": GATE_INTERPRETATION,
    }


def create_revocation_deployment_gate(
    topology_audit: Path,
    otel_projection: Path,
    revocation_bundle: Path,
    output: Path,
    *,
    gate_id: str,
    bundle_public_key_pem: bytes,
    expected_bundle_key_id: str,
    maximum_allowed_convergence_ms: int,
    minimum_run_generated_at: str,
    expected_system_id: str,
    expected_environment: str,
    expected_receiver_name: str,
    expected_receiver_artifact_sha256: str,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    topology = load_revocation_topology_audit(Path(topology_audit))
    projection = load_otel_revocation_projection(Path(otel_projection))
    bundle = _trusted_bundle(
        Path(revocation_bundle),
        public_key_pem=bundle_public_key_pem,
        expected_key_id=expected_bundle_key_id,
    )
    source_times = [
        topology["generated_at"],
        projection["generated_at"],
        bundle["report"]["generated_at"],
    ]
    latest = max(source_times, key=_time)
    current = _timestamp_now()
    gate = _gate_value(
        topology,
        projection,
        bundle,
        gate_id=gate_id,
        created_at=created_at or (latest if _time(current) < _time(latest) else current),
        producer_version=__version__,
        maximum_allowed_convergence_ms=maximum_allowed_convergence_ms,
        minimum_run_generated_at=minimum_run_generated_at,
        expected_system_id=expected_system_id,
        expected_environment=expected_environment,
        expected_receiver_name=expected_receiver_name,
        expected_receiver_artifact_sha256=expected_receiver_artifact_sha256,
    )
    _write_new(Path(output), _canonical(gate))
    return gate


def verify_revocation_deployment_gate(
    gate: Path,
    topology_audit: Path,
    otel_projection: Path,
    revocation_bundle: Path,
    *,
    bundle_public_key_pem: bytes,
    expected_bundle_key_id: str,
    maximum_allowed_convergence_ms: int,
    minimum_run_generated_at: str,
    expected_system_id: str,
    expected_environment: str,
    expected_receiver_name: str,
    expected_receiver_artifact_sha256: str,
) -> Dict[str, Any]:
    raw = _read(Path(gate), private=True)
    value = _strict(raw, "revocation deployment gate")
    reviewed = _exact(
        value,
        "revocation deployment gate",
        (
            "schema",
            "schema_version",
            "gate_id",
            "created_at",
            "producer",
            "system",
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
        raise ValueError("unsupported revocation deployment-gate schema")
    producer = _exact(reviewed["producer"], "deployment gate producer", ("name", "version"))
    if producer["name"] != "lurescope":
        raise ValueError("revocation deployment gate producer is unsupported")
    expected = _gate_value(
        load_revocation_topology_audit(Path(topology_audit)),
        load_otel_revocation_projection(Path(otel_projection)),
        _trusted_bundle(
            Path(revocation_bundle),
            public_key_pem=bundle_public_key_pem,
            expected_key_id=expected_bundle_key_id,
        ),
        gate_id=reviewed["gate_id"],
        created_at=reviewed["created_at"],
        producer_version=producer["version"],
        maximum_allowed_convergence_ms=maximum_allowed_convergence_ms,
        minimum_run_generated_at=minimum_run_generated_at,
        expected_system_id=expected_system_id,
        expected_environment=expected_environment,
        expected_receiver_name=expected_receiver_name,
        expected_receiver_artifact_sha256=expected_receiver_artifact_sha256,
    )
    if reviewed != expected or raw != _canonical(expected):
        raise ValueError("revocation deployment gate does not independently recompute")
    return {
        "valid": True,
        "authenticated_source_bundle": True,
        "gate_id": expected["gate_id"],
        "overall_status": expected["overall_status"],
        "contract": expected["contract"],
        "checks": expected["checks"],
        "limitations": list(GATE_LIMITATIONS),
        "interpretation_boundary": GATE_INTERPRETATION,
    }
