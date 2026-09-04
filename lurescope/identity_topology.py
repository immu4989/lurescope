"""Independent verifier for LureIdentity/LurePermit declared-topology audits."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from .identity import _time, _validate_plan
from .permit import _canonical, _exact, _id, _read, _sha256, _strict, _timestamp
from .runtime import validate_runtime_profile
from .spiffe import parse_spiffe_id

TOPOLOGY_AUDIT_SCHEMA = (
    "https://github.com/immu4989/lurebench/spec/lureidentity-topology-audit/v1"
)
TOPOLOGY_LIMITATIONS = [
    "audit_compares_declared_identity_nodes_to_declared_runtime_mediation_points_only",
    "spiffe_trust_domain_membership_does_not_prove_svid_issuance_validation_or_possession",
    "a_pass_does_not_prove_discovery_completeness_reachability_event_delivery_or_enforcement",
    "replica_count_is_reported_but_no_fault_domain_independence_is_inferred",
    "audit_executes_no_discovery_directory_workload_probe_access_action_or_enforcement",
]


def _topology_value(
    plan: Mapping[str, Any],
    profile: Mapping[str, Any],
    generated_at: str,
    producer_version: str,
) -> Dict[str, Any]:
    reviewed_plan = _validate_plan(plan)
    reviewed_profile = validate_runtime_profile(profile)
    _timestamp(generated_at, "identity topology audit generated_at")
    _id(producer_version, "identity topology audit implementation.version")
    if _time(generated_at) < max(
        _time(reviewed_plan["created_at"]), _time(reviewed_profile["created_at"])
    ):
        raise ValueError("identity topology audit predates its plan or runtime profile")
    if reviewed_plan["system_id"] != reviewed_profile["permit"]["system_id"]:
        raise ValueError("identity topology audit inputs name different systems")

    mappings: dict[str, list[str]] = {}
    for node in reviewed_plan["nodes"]:
        mappings.setdefault(node["enforcement_point_id"], []).append(node["node_id"])
    profile_points = {
        item["point_id"]: item for item in reviewed_profile["mediation_points"]
    }
    results = []
    for point_id in sorted(profile_points):
        point = profile_points[point_id]
        node_ids = sorted(mappings.get(point_id, []))
        results.append(
            {
                "enforcement_point_id": point_id,
                "action_types": sorted(point["action_types"]),
                "required_sensor_ids": sorted(point["required_sensor_ids"]),
                "node_ids": node_ids,
                "replica_count": len(node_ids),
                "covered": bool(node_ids),
            }
        )
    unmapped = sorted(
        (
            {
                "node_id": node["node_id"],
                "enforcement_point_id": node["enforcement_point_id"],
            }
            for node in reviewed_plan["nodes"]
            if node["enforcement_point_id"] not in profile_points
        ),
        key=lambda item: (item["enforcement_point_id"], item["node_id"]),
    )
    missing = [item["enforcement_point_id"] for item in results if not item["covered"]]
    allowed_domains = set(
        reviewed_profile["identity"]["allowed_spiffe_trust_domains"]
    )
    workload_identities = []
    for principal in sorted(
        (
            item
            for item in reviewed_plan["principals"]
            if item["kind"] == "workload"
        ),
        key=lambda item: item["principal_id"],
    ):
        _, domain = parse_spiffe_id(
            principal["spiffe_id"], "workload principal SPIFFE ID", require_path=True
        )
        workload_identities.append(
            {
                "principal_id": principal["principal_id"],
                "spiffe_id": principal["spiffe_id"],
                "trust_domain": domain,
                "trusted": domain in allowed_domains,
            }
        )
    untrusted = [
        item["principal_id"] for item in workload_identities if not item["trusted"]
    ]
    covered_count = len(results) - len(missing)
    trusted_count = len(workload_identities) - len(untrusted)
    return {
        "schema": TOPOLOGY_AUDIT_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "implementation": {"name": "lurebench", "version": producer_version},
        "inputs": {
            "identity_plan": reviewed_plan,
            "identity_plan_sha256": _sha256(_canonical(reviewed_plan)),
            "runtime_profile": reviewed_profile,
            "runtime_profile_sha256": _sha256(_canonical(reviewed_profile)),
        },
        "results": results,
        "missing_enforcement_point_ids": missing,
        "unmapped_nodes": unmapped,
        "workload_identities": workload_identities,
        "untrusted_workload_principal_ids": untrusted,
        "summary": {
            "required_enforcement_point_count": len(results),
            "covered_enforcement_point_count": covered_count,
            "missing_enforcement_point_count": len(missing),
            "unmapped_node_count": len(unmapped),
            "enforcement_point_coverage_rate": covered_count / len(results),
            "workload_identity_count": len(workload_identities),
            "trusted_workload_identity_count": trusted_count,
            "untrusted_workload_identity_count": len(untrusted),
            "workload_trust_domain_coverage_rate": trusted_count / len(workload_identities),
            "verdict": (
                "pass" if not missing and not unmapped and not untrusted else "fail"
            ),
        },
        "limitations": list(TOPOLOGY_LIMITATIONS),
    }


def validate_identity_topology_audit(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "identity topology audit",
        (
            "schema",
            "schema_version",
            "generated_at",
            "implementation",
            "inputs",
            "results",
            "missing_enforcement_point_ids",
            "unmapped_nodes",
            "workload_identities",
            "untrusted_workload_principal_ids",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != TOPOLOGY_AUDIT_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported identity topology audit schema")
    implementation = report.get("implementation")
    if (
        not isinstance(implementation, dict)
        or set(implementation) != {"name", "version"}
        or implementation.get("name") != "lurebench"
    ):
        raise ValueError("identity topology audit producer must be lurebench")
    inputs = report.get("inputs")
    if not isinstance(inputs, dict):
        raise ValueError("identity topology audit inputs must be an object")
    expected = _topology_value(
        inputs.get("identity_plan"),
        inputs.get("runtime_profile"),
        report.get("generated_at"),
        implementation.get("version"),
    )
    if report != expected:
        raise ValueError("identity topology audit does not independently recompute")
    return dict(report)


def load_identity_topology_audit(path: Path) -> Dict[str, Any]:
    raw = _read(Path(path), private=True)
    report = validate_identity_topology_audit(_strict(raw, "identity topology audit"))
    if raw != _canonical(report):
        raise ValueError("identity topology audit must use canonical JSON")
    return report
