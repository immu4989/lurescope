"""Independent verifier for LureRevoke/LurePermit declared-topology audits."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from .permit import _canonical, _exact, _id, _read, _sha256, _strict, _timestamp
from .revocation import _time, _validate_plan
from .runtime import validate_runtime_profile

TOPOLOGY_AUDIT_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerevoke-topology-audit/v1"
TOPOLOGY_LIMITATIONS = [
    "audit_compares_declared_plan_nodes_to_declared_runtime_mediation_points_only",
    "a_pass_does_not_prove_discovery_completeness_reachability_or_signal_delivery",
    "replica_count_is_reported_but_no_fault_domain_independence_is_inferred",
    "audit_executes_no_discovery_probe_signal_access_action_or_enforcement",
]


def _topology_value(
    plan: Mapping[str, Any],
    profile: Mapping[str, Any],
    generated_at: str,
    producer_version: str,
) -> Dict[str, Any]:
    reviewed_plan = _validate_plan(plan)
    reviewed_profile = validate_runtime_profile(profile)
    _timestamp(generated_at, "topology audit generated_at")
    _id(producer_version, "topology audit implementation.version")
    if _time(generated_at) < max(
        _time(reviewed_plan["created_at"]), _time(reviewed_profile["created_at"])
    ):
        raise ValueError("topology audit predates its plan or runtime profile")
    if reviewed_plan["system_id"] != reviewed_profile["permit"]["system_id"]:
        raise ValueError("topology audit inputs name different systems")
    mappings: dict[str, list[str]] = {}
    for node in reviewed_plan["nodes"]:
        mappings.setdefault(node["mediation_point_id"], []).append(node["node_id"])
    profile_points = {item["point_id"]: item for item in reviewed_profile["mediation_points"]}
    results = []
    for point_id in sorted(profile_points):
        point = profile_points[point_id]
        nodes = sorted(mappings.get(point_id, []))
        results.append(
            {
                "mediation_point_id": point_id,
                "action_types": sorted(point["action_types"]),
                "required_sensor_ids": sorted(point["required_sensor_ids"]),
                "node_ids": nodes,
                "replica_count": len(nodes),
                "covered": bool(nodes),
            }
        )
    unmapped = sorted(
        (
            {"node_id": item["node_id"], "mediation_point_id": item["mediation_point_id"]}
            for item in reviewed_plan["nodes"]
            if item["mediation_point_id"] not in profile_points
        ),
        key=lambda item: (item["mediation_point_id"], item["node_id"]),
    )
    missing = [item["mediation_point_id"] for item in results if not item["covered"]]
    covered = len(results) - len(missing)
    return {
        "schema": TOPOLOGY_AUDIT_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "implementation": {"name": "lurebench", "version": producer_version},
        "inputs": {
            "revocation_plan": reviewed_plan,
            "revocation_plan_sha256": _sha256(_canonical(reviewed_plan)),
            "runtime_profile": reviewed_profile,
            "runtime_profile_sha256": _sha256(_canonical(reviewed_profile)),
        },
        "results": results,
        "missing_mediation_point_ids": missing,
        "unmapped_nodes": unmapped,
        "summary": {
            "required_mediation_point_count": len(results),
            "covered_mediation_point_count": covered,
            "missing_mediation_point_count": len(missing),
            "unmapped_node_count": len(unmapped),
            "mediation_point_coverage_rate": covered / len(results),
            "verdict": "pass" if not missing and not unmapped else "fail",
        },
        "limitations": list(TOPOLOGY_LIMITATIONS),
    }


def validate_revocation_topology_audit(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "revocation topology audit",
        (
            "schema",
            "schema_version",
            "generated_at",
            "implementation",
            "inputs",
            "results",
            "missing_mediation_point_ids",
            "unmapped_nodes",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != TOPOLOGY_AUDIT_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported revocation topology audit schema")
    implementation = report.get("implementation")
    if (
        not isinstance(implementation, dict)
        or set(implementation) != {"name", "version"}
        or implementation.get("name") != "lurebench"
    ):
        raise ValueError("revocation topology audit producer must be lurebench")
    inputs = report.get("inputs")
    if not isinstance(inputs, dict):
        raise ValueError("revocation topology audit inputs must be an object")
    expected = _topology_value(
        inputs.get("revocation_plan"),
        inputs.get("runtime_profile"),
        report.get("generated_at"),
        implementation.get("version"),
    )
    if report != expected:
        raise ValueError("revocation topology audit does not independently recompute")
    return dict(report)


def load_revocation_topology_audit(path: Path) -> Dict[str, Any]:
    raw = _read(Path(path), private=True)
    report = validate_revocation_topology_audit(_strict(raw, "revocation topology audit"))
    if raw != _canonical(report):
        raise ValueError("revocation topology audit must use canonical JSON")
    return report
