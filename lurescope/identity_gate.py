"""Cross-artifact deployment gate for operational LureIdentity evidence."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .artifact import load_artifact_verification
from .identity import _event_cut, _time, verify_identity_bundle
from .identity_campaign import load_identity_campaign_verification
from .identity_otel import load_identity_otel_projection
from .identity_topology import load_identity_topology_audit
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

GATE_SCHEMA = "https://github.com/immu4989/lurescope/spec/lureidentity-deployment-gate/v1"
GATE_LIMITATIONS = [
    "gate_reconciles_identity_and_artifact_compiler_proofs_declared_topology_body_free_telemetry_and_signed_lifecycle_evidence_only",
    "a_pass_does_not_prove_topology_discovery_telemetry_completeness_event_authenticity_clock_sync_or_enforcement",
    "trust_domain_membership_does_not_prove_svid_issuance_validation_or_possession",
    "source_signature_authenticates_a_key_not_a_directory_receiver_operator_or_organization",
    "external_policy_values_are_caller_supplied_and_require_separately_governed_authorization",
    "artifact_hash_provenance_and_ai_bom_equality_do_not_prove_content_safety_or_builder_trust",
    "gate_does_not_establish_scim_interoperability_compliance_or_deployment_authorization",
]
GATE_INTERPRETATION = (
    "Pass means independently recompiled identity and artifact campaigns, a complete declared "
    "runtime topology with allowed workload trust domains based on a runtime profile dated no "
    "later than the run, an independently recomputed body-free telemetry projection, and an "
    "authenticated identity-lifecycle evaluation bind the same exact identity plan and run; the "
    "declared workload-to-model, image, policy, AI-BOM, and SLSA provenance observations also "
    "match their reviewed plan. All sources satisfy caller-supplied deployment identity, "
    "freshness, probe-coverage, and convergence policy. It does not establish trusted discovery, "
    "time, event origin, SVID possession, artifact safety, builder trust, observation "
    "completeness, deployment, or enforcement authenticity."
)


def _trusted_bundle(path: Path, *, public_key_pem: bytes, expected_key_id: str) -> Dict[str, Any]:
    expected = _digest(expected_key_id, "expected identity bundle key id")
    verified = verify_identity_bundle(Path(path), public_key_pem=public_key_pem)
    if len(verified["key_ids"]) != 1 or not secrets.compare_digest(
        verified["key_ids"][0], expected
    ):
        raise ValueError("identity bundle signer does not match the pinned expected key id")
    return verified


def _require_probe_phase_coverage(plan: Mapping[str, Any]) -> None:
    deadline = plan["acceptance"]["maximum_convergence_ms"]
    required = set()
    for event in plan["events"]:
        for node in plan["nodes"]:
            for authorization in _event_cut(plan, event):
                for phase in ("pre_event", "propagation_window", "post_deadline"):
                    required.add((event["event_id"], node["node_id"], authorization, phase))
    events = {item["event_id"]: item for item in plan["events"]}
    observed = set()
    for probe in plan["probes"]:
        event = events[probe["event_id"]]
        authorization = (probe["actor_id"], probe["resource_id"], probe["action"])
        if authorization not in _event_cut(plan, event):
            continue
        phase = (
            "pre_event"
            if probe["attempted_at_ms"] < event["occurred_at_ms"]
            else "post_deadline"
            if probe["attempted_at_ms"] >= event["occurred_at_ms"] + deadline
            else "propagation_window"
        )
        observed.add((probe["event_id"], probe["node_id"], authorization, phase))
    if required - observed:
        raise ValueError(
            "identity deployment gate requires pre/window/post cut probes at every node"
        )


def _require_strict_acceptance(plan: Mapping[str, Any]) -> None:
    acceptance = plan["acceptance"]
    required = {
        "maximum_deadline_miss_count": 0,
        "maximum_post_deadline_stale_allow_count": 0,
        "maximum_collateral_block_count": 0,
        "minimum_delivery_coverage_rate": 1.0,
        "minimum_cut_recall": 1.0,
        "minimum_pre_event_allow_rate": 1.0,
        "minimum_preserved_allow_rate": 1.0,
        "minimum_signal_disposition_accuracy": 1.0,
    }
    if any(acceptance[field] != expected for field, expected in required.items()):
        raise ValueError("identity deployment gate requires strict lifecycle acceptance thresholds")


def _gate_value(
    campaign_verification: Mapping[str, Any],
    artifact_verification: Mapping[str, Any],
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
    _id(gate_id, "identity deployment gate id")
    _id(producer_version, "identity deployment gate producer version")
    _timestamp(created_at, "identity deployment gate created_at")
    policy_deadline = _integer(
        maximum_allowed_convergence_ms,
        "maximum allowed convergence milliseconds",
        1,
        600_000,
    )
    policy_minimum_run_time = _timestamp(
        minimum_run_generated_at, "minimum allowed identity run timestamp"
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
        raise ValueError("identity deployment gate requires one authenticated bundle signer")
    latest_source_time = max(
        _time(campaign_verification["verified_at"]),
        _time(artifact_verification["verified_at"]),
        _time(topology["generated_at"]),
        _time(projection["generated_at"]),
        _time(report["generated_at"]),
    )
    if _time(created_at) < latest_source_time:
        raise ValueError("identity deployment gate predates source evidence")

    topology_plan = topology["inputs"]["identity_plan"]
    projection_plan = projection["inputs"]["identity_plan"]
    if artifact_verification["identity_campaign_verification"] != campaign_verification:
        raise ValueError(
            "identity deployment gate artifact evidence does not bind the exact campaign proof"
        )
    plan_digests = {
        campaign_verification["derived_plan_sha256"],
        artifact_verification["digests"]["identity_plan_sha256"],
        topology["inputs"]["identity_plan_sha256"],
        projection["inputs"]["identity_plan_sha256"],
        report["plan_sha256"],
    }
    if (
        len(plan_digests) != 1
        or topology_plan != projection_plan
        or projection_plan != report["plan"]
    ):
        raise ValueError("identity deployment gate sources do not bind the same exact plan")
    if projection["run_sha256"] != report["run_sha256"] or projection["run"] != report["run"]:
        raise ValueError(
            "identity deployment gate telemetry and evidence do not bind the same exact run"
        )
    system_ids = {
        topology_plan["system_id"],
        projection_plan["system_id"],
        report["plan"]["system_id"],
        artifact_verification["artifact_plan"]["system_id"],
        verified_bundle["system_id"],
    }
    if len(system_ids) != 1:
        raise ValueError("identity deployment gate sources name different systems")
    receiver = projection["run"]["implementation"]
    if receiver != report["run"]["implementation"]:
        raise ValueError("identity deployment gate sources name different receiver implementations")
    if (
        report["plan"]["system_id"] != policy_system
        or verified_bundle["environment"] != expected_environment
        or receiver["name"] != policy_receiver
        or receiver["artifact_sha256"] is None
        or not secrets.compare_digest(receiver["artifact_sha256"], policy_artifact)
    ):
        raise ValueError("identity deployment gate source identity differs from external policy")
    profile_created_at = topology["inputs"]["runtime_profile"]["created_at"]
    if _time(profile_created_at) > _time(projection["run"]["generated_at"]):
        raise ValueError("identity deployment gate runtime profile was not preregistered")
    _require_probe_phase_coverage(report["plan"])
    _require_strict_acceptance(report["plan"])
    declared_deadline = report["plan"]["acceptance"]["maximum_convergence_ms"]
    if declared_deadline > policy_deadline:
        raise ValueError("identity deployment gate convergence deadline exceeds external policy")
    if _time(report["run"]["generated_at"]) < _time(policy_minimum_run_time):
        raise ValueError("identity deployment gate run predates external freshness policy")

    topology_status = topology["summary"]["verdict"]
    trust_status = (
        "pass" if topology["summary"]["untrusted_workload_identity_count"] == 0 else "fail"
    )
    evidence_status = verified_bundle["overall_status"]
    artifact_status = artifact_verification["overall_status"]
    checks = [
        {"check_id": "campaign_compilation_recomputed", "status": "pass"},
        {"check_id": "declared_enforcement_topology_complete", "status": topology_status},
        {"check_id": "workload_trust_domains_covered", "status": trust_status},
        {"check_id": "workload_artifact_authorization_met", "status": artifact_status},
        {"check_id": "runtime_profile_preregistered", "status": "pass"},
        {"check_id": "cut_probe_phase_coverage_complete", "status": "pass"},
        {"check_id": "strict_acceptance_thresholds", "status": "pass"},
        {"check_id": "convergence_deadline_within_policy", "status": "pass"},
        {"check_id": "run_freshness_matches_policy", "status": "pass"},
        {"check_id": "deployment_identity_matches_policy", "status": "pass"},
        {"check_id": "telemetry_projection_recomputed", "status": "pass"},
        {"check_id": "source_bundle_authenticated", "status": "pass"},
        {"check_id": "identity_lifecycle_acceptance_met", "status": evidence_status},
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
            "campaign_sha256": campaign_verification["campaign_sha256"],
            "plan_sha256": report["plan_sha256"],
            "run_sha256": report["run_sha256"],
            "runtime_profile_sha256": topology["inputs"]["runtime_profile_sha256"],
            "artifact_campaign_sha256": artifact_verification["digests"][
                "artifact_campaign_sha256"
            ],
            "artifact_plan_sha256": artifact_verification["digests"]["artifact_plan_sha256"],
            "artifact_observation_sha256": artifact_verification["digests"]["observation_sha256"],
            "artifact_evaluation_sha256": artifact_verification["digests"]["evaluation_sha256"],
            "receiver": dict(receiver),
        },
        "sources": {
            "campaign_verification": {
                "sha256": _sha256(_canonical(campaign_verification)),
                "verified_at": campaign_verification["verified_at"],
                "event_count": campaign_verification["summary"]["event_count"],
                "probe_count": campaign_verification["summary"]["probe_count"],
            },
            "artifact_verification": {
                "sha256": _sha256(_canonical(artifact_verification)),
                "verified_at": artifact_verification["verified_at"],
                "active_workload_count": artifact_verification["summary"]["active_workload_count"],
                "deployment_count": artifact_verification["summary"]["deployment_count"],
                "artifact_binding_count": artifact_verification["summary"][
                    "artifact_binding_count"
                ],
                "provenance_binding_count": artifact_verification["summary"][
                    "provenance_binding_count"
                ],
                "ai_bom_binding_count": artifact_verification["summary"]["ai_bom_binding_count"],
                "overall_status": artifact_status,
            },
            "topology_audit": {
                "sha256": _sha256(_canonical(topology)),
                "verdict": topology_status,
                "covered_enforcement_point_count": topology["summary"][
                    "covered_enforcement_point_count"
                ],
                "required_enforcement_point_count": topology["summary"][
                    "required_enforcement_point_count"
                ],
                "trusted_workload_identity_count": topology["summary"][
                    "trusted_workload_identity_count"
                ],
                "workload_identity_count": topology["summary"]["workload_identity_count"],
            },
            "otel_projection": {
                "sha256": _sha256(_canonical(projection)),
                "source_export_sha256": projection["inputs"]["otel_log_export_sha256"],
                "record_count": len(projection["inputs"]["otel_log_export"]["records"]),
            },
            "identity_evidence": {
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


def create_identity_deployment_gate(
    campaign_verification: Path,
    artifact_verification: Path,
    topology_audit: Path,
    otel_projection: Path,
    identity_bundle: Path,
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
    campaign_proof = load_identity_campaign_verification(Path(campaign_verification))
    artifact_proof = load_artifact_verification(Path(artifact_verification))
    topology = load_identity_topology_audit(Path(topology_audit))
    projection = load_identity_otel_projection(Path(otel_projection))
    bundle = _trusted_bundle(
        Path(identity_bundle),
        public_key_pem=bundle_public_key_pem,
        expected_key_id=expected_bundle_key_id,
    )
    latest = max(
        (
            campaign_proof["verified_at"],
            artifact_proof["verified_at"],
            topology["generated_at"],
            projection["generated_at"],
            bundle["report"]["generated_at"],
        ),
        key=_time,
    )
    current = _timestamp_now()
    gate = _gate_value(
        campaign_proof,
        artifact_proof,
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


def verify_identity_deployment_gate(
    gate: Path,
    campaign_verification: Path,
    artifact_verification: Path,
    topology_audit: Path,
    otel_projection: Path,
    identity_bundle: Path,
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
    value = _strict(raw, "identity deployment gate")
    reviewed = _exact(
        value,
        "identity deployment gate",
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
        raise ValueError("unsupported identity deployment-gate schema")
    producer = _exact(reviewed["producer"], "identity gate producer", ("name", "version"))
    if producer["name"] != "lurescope":
        raise ValueError("identity deployment gate producer is unsupported")
    expected = _gate_value(
        load_identity_campaign_verification(Path(campaign_verification)),
        load_artifact_verification(Path(artifact_verification)),
        load_identity_topology_audit(Path(topology_audit)),
        load_identity_otel_projection(Path(otel_projection)),
        _trusted_bundle(
            Path(identity_bundle),
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
        raise ValueError("identity deployment gate does not independently recompute")
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
