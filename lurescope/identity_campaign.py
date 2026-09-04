"""Independent verification of LureIdentity campaign compilation.

This module intentionally imports no LureBench code.  It derives the expected
plan from an embedded campaign, validates that plan with LureScope's independent
identity verifier, and can bind the result in a self-contained verification
artifact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .identity import (
    EVENT_TYPES,
    MAX_EDGES,
    MAX_EVENTS,
    MAX_GRANTS,
    MAX_NODES,
    MAX_PRINCIPALS,
    MAX_PROBES,
    PLAN_LIMITATIONS,
    PLAN_SCHEMA,
    Authorization,
    _adjacency,
    _authorizations,
    _descendants,
    _event_material,
    _event_state,
    _nullable_id,
    _validate_plan,
)
from .permit import (
    _canonical,
    _digest,
    _exact,
    _id,
    _integer,
    _rate,
    _read,
    _sha256,
    _strict,
    _timestamp,
    _timestamp_now,
    _write_new,
)

CAMPAIGN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-campaign-v1"
VERIFICATION_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/lureidentity-campaign-verification/v1"
)
CAMPAIGN_LIMITATIONS = [
    "synthetic_projected_identity_metadata_only_no_credentials_tokens_or_raw_directory_payloads",
    "campaign_composition_derives_graph_cuts_and_controls_but_does_not_discover_topology",
    "every_unchanged_baseline_actor_outside_each_event_cone_is_used_as_a_collateral_control",
    "composition_generates_probes_but_does_not_deliver_events_or_execute_access_requests",
    "finite_declared_graph_coverage_does_not_prove_complete_mediation_compliance_or_containment",
]
VERIFICATION_LIMITATIONS = [
    "verification_is_an_independent_local_reimplementation_and_imports_no_lurebench_code",
    "a_pass_confirms_compiler_semantics_only_for_the_exact_embedded_declared_campaign",
    "source_event_digests_are_commitments_not_event_directory_or_identity_authentication",
    "verification_does_not_discover_topology_execute_probes_or_prove_complete_mediation",
]
CHECK_NAMES = [
    "campaign_contract_valid",
    "plan_contract_valid",
    "base_contract_bound",
    "event_sequence_derived",
    "authorization_cut_recomputed",
    "collateral_controls_exhaustive",
    "probe_matrix_recomputed",
    "probe_budget_enforced",
    "exact_plan_reconciled",
]


def _enum(value: Any, field: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} is unsupported")
    return value


def _bounded_list(value: Any, field: str, minimum: int, maximum: int) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{field} must be a bounded array")
    return value


def _campaign_header(value: Any) -> Dict[str, Any]:
    campaign = _exact(
        value,
        "identity campaign",
        (
            "schema",
            "schema_version",
            "campaign_id",
            "created_at",
            "system_id",
            "directory",
            "principals",
            "authority_edges",
            "grants",
            "nodes",
            "events",
            "acceptance",
            "probe_schedule",
            "limitations",
        ),
    )
    if campaign["schema"] != CAMPAIGN_SCHEMA or campaign["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity campaign schema")
    _id(campaign["campaign_id"], "campaign.campaign_id")
    _timestamp(campaign["created_at"], "campaign.created_at")
    _id(campaign["system_id"], "campaign.system_id")
    directory = _exact(
        campaign["directory"],
        "campaign.directory",
        ("issuer_id", "tenant_id", "profile", "authentication_boundary"),
    )
    _id(directory["issuer_id"], "campaign.directory.issuer_id")
    _id(directory["tenant_id"], "campaign.directory.tenant_id")
    if (
        directory["profile"] != "ietf-scim-rfc7643-lifecycle-metadata-projection"
        or directory["authentication_boundary"]
        != "externally_authenticated_and_authorized"
    ):
        raise ValueError("identity campaign directory contract is unsupported")
    _bounded_list(campaign["principals"], "campaign.principals", 1, MAX_PRINCIPALS)
    _bounded_list(campaign["authority_edges"], "campaign.authority_edges", 0, MAX_EDGES)
    _bounded_list(campaign["grants"], "campaign.grants", 1, MAX_GRANTS)
    _bounded_list(campaign["nodes"], "campaign.nodes", 1, MAX_NODES)
    _bounded_list(campaign["events"], "campaign.events", 1, MAX_EVENTS)
    if campaign["limitations"] != CAMPAIGN_LIMITATIONS:
        raise ValueError("identity campaign limitations are invalid")
    return dict(campaign)


def _acceptance(value: Any) -> Dict[str, Any]:
    acceptance = _exact(
        value,
        "campaign.acceptance",
        (
            "maximum_convergence_ms",
            "maximum_deadline_miss_count",
            "maximum_post_deadline_stale_allow_count",
            "maximum_collateral_block_count",
            "minimum_delivery_coverage_rate",
            "minimum_cut_recall",
            "minimum_pre_event_allow_rate",
            "minimum_preserved_allow_rate",
            "minimum_signal_disposition_accuracy",
        ),
    )
    _integer(acceptance["maximum_convergence_ms"], "maximum_convergence_ms", 1, 600_000)
    for field in (
        "maximum_deadline_miss_count",
        "maximum_post_deadline_stale_allow_count",
        "maximum_collateral_block_count",
    ):
        _integer(acceptance[field], field, 0, MAX_PROBES)
    for field in (
        "minimum_delivery_coverage_rate",
        "minimum_cut_recall",
        "minimum_pre_event_allow_rate",
        "minimum_preserved_allow_rate",
        "minimum_signal_disposition_accuracy",
    ):
        _rate(acceptance[field], field)
    return dict(acceptance)


def _schedule(value: Any, deadline: int) -> Dict[str, Any]:
    schedule = _exact(
        value,
        "campaign.probe_schedule",
        ("pre_event_offset_ms", "propagation_probe_offset_ms", "post_deadline_offset_ms"),
    )
    _integer(schedule["pre_event_offset_ms"], "pre_event_offset_ms", 1, 600_000)
    propagation = _integer(
        schedule["propagation_probe_offset_ms"],
        "propagation_probe_offset_ms",
        1,
        600_000,
    )
    _integer(schedule["post_deadline_offset_ms"], "post_deadline_offset_ms", 1, 600_000)
    if propagation >= deadline:
        raise ValueError("propagation probe offset must be shorter than the convergence deadline")
    return dict(schedule)


def _source_event(value: Any, index: int) -> Dict[str, Any]:
    event = _exact(
        value,
        f"campaign.events[{index}]",
        (
            "event_id",
            "occurred_at_ms",
            "event_type",
            "target_principal_id",
            "target_edge_id",
            "source_event_sha256",
        ),
    )
    _id(event["event_id"], "campaign event id")
    _integer(event["occurred_at_ms"], "campaign event occurrence", 1, 86_400_000)
    _enum(event["event_type"], "campaign event type", EVENT_TYPES)
    _nullable_id(event["target_principal_id"], "campaign event target principal")
    _nullable_id(event["target_edge_id"], "campaign event target edge")
    _digest(event["source_event_sha256"], "campaign source event digest")
    return dict(event)


def _cone(
    event: Mapping[str, Any],
    principals: Mapping[str, Mapping[str, Any]],
    edges: Mapping[str, Mapping[str, Any]],
    adjacency: Mapping[str, list[str]],
) -> set[str]:
    event_type = event["event_type"]
    principal_id = event["target_principal_id"]
    edge_id = event["target_edge_id"]
    if event_type == "scim_user_deactivated":
        if (
            principal_id not in principals
            or principals[principal_id].get("kind") != "human"
            or edge_id is not None
        ):
            raise ValueError("SCIM user deactivation must target one human principal")
        return _descendants(adjacency, principal_id)
    if event_type == "workload_retired":
        if (
            principal_id not in principals
            or principals[principal_id].get("kind") != "workload"
            or edge_id is not None
        ):
            raise ValueError("workload retirement must target one workload principal")
        return _descendants(adjacency, principal_id)
    relationship = (
        "member_of" if event_type == "scim_group_membership_removed" else "delegates_to"
    )
    if (
        principal_id is not None
        or edge_id not in edges
        or edges[edge_id].get("relationship") != relationship
    ):
        raise ValueError("edge lifecycle event targets an incompatible authority edge")
    return _descendants(adjacency, edges[edge_id]["target_id"])


def _actor_set(authorizations: set[Authorization], actor_id: str) -> set[Authorization]:
    return {item for item in authorizations if item[0] == actor_id}


def derive_identity_campaign_plan(value: Any) -> Dict[str, Any]:
    """Reimplement the compiler and return its exact expected plan."""

    try:
        campaign = _campaign_header(value)
        acceptance = _acceptance(campaign["acceptance"])
        deadline = acceptance["maximum_convergence_ms"]
        schedule = _schedule(campaign["probe_schedule"], deadline)
        principals = {
            item["principal_id"]: item
            for item in campaign["principals"]
            if isinstance(item, dict) and "principal_id" in item
        }
        edges = {
            item["edge_id"]: item
            for item in campaign["authority_edges"]
            if isinstance(item, dict) and "edge_id" in item
        }
        if len(principals) != len(campaign["principals"]):
            raise ValueError("identity campaign principal identifiers must be unique")
        if len(edges) != len(campaign["authority_edges"]):
            raise ValueError("identity campaign edge identifiers must be unique")
        adjacency = _adjacency(principals, list(edges.values()))
        baseline = _authorizations(principals, list(edges.values()), campaign["grants"])
        if not baseline:
            raise ValueError("identity campaign must produce baseline authorization")
        source_events = [
            _source_event(item, index)
            for index, item in enumerate(campaign["events"])
        ]
        occurrences = [item["occurred_at_ms"] for item in source_events]
        if occurrences != sorted(set(occurrences)):
            raise ValueError("identity campaign event times must increase strictly")
        if schedule["pre_event_offset_ms"] > occurrences[0]:
            raise ValueError("pre-event probe offset precedes the campaign clock origin")

        plan: Dict[str, Any] = {
            "schema": PLAN_SCHEMA,
            "schema_version": 1,
            "plan_id": campaign["campaign_id"],
            "created_at": campaign["created_at"],
            "system_id": campaign["system_id"],
            "directory": dict(campaign["directory"]),
            "principals": [dict(item) for item in campaign["principals"]],
            "authority_edges": [dict(item) for item in campaign["authority_edges"]],
            "grants": [dict(item) for item in campaign["grants"]],
            "nodes": [dict(item) for item in campaign["nodes"]],
            "events": [],
            "probes": [],
            "acceptance": acceptance,
            "limitations": list(PLAN_LIMITATIONS),
        }
        matrices: list[tuple[Dict[str, Any], list[Authorization], list[Authorization]]] = []
        expected_probe_count = 0
        for event_number, source in enumerate(source_events, start=1):
            event = {
                **source,
                "sequence": event_number,
                "required_cut_actor_ids": ["placeholder"],
                "required_preserve_actor_ids": ["placeholder"],
            }
            before, after = _event_state(plan, event)
            cut = sorted(before - after)
            if not cut:
                raise ValueError("every identity campaign event must cut authorization")
            cut_actors = sorted({item[0] for item in cut})
            if any(_actor_set(after, actor_id) for actor_id in cut_actors):
                raise ValueError("identity campaign event partially deauthorizes an actor")
            dependency_cone = _cone(source, principals, edges, adjacency)
            preserve_actors = sorted(
                actor_id
                for actor_id in {item[0] for item in before}
                if actor_id not in dependency_cone
                and _actor_set(before, actor_id) == _actor_set(after, actor_id)
            )
            if not preserve_actors:
                raise ValueError("identity campaign event lacks an unrelated authorized control")
            preserve = sorted(item for item in before if item[0] in preserve_actors)
            event["required_cut_actor_ids"] = cut_actors
            event["required_preserve_actor_ids"] = preserve_actors
            event["event_sha256"] = _sha256(_canonical(_event_material(event)))
            plan["events"].append(event)
            matrices.append((event, cut, preserve))
            expected_probe_count += len(plan["nodes"]) * (3 * len(cut) + len(preserve))
        if expected_probe_count > MAX_PROBES:
            raise ValueError("identity campaign exceeds the bounded probe budget")

        probes = []
        for event_number, (event, cut, preserve) in enumerate(matrices, start=1):
            occurred = event["occurred_at_ms"]
            times = {
                "pre": occurred - schedule["pre_event_offset_ms"],
                "window": occurred + schedule["propagation_probe_offset_ms"],
                "post": occurred + deadline + schedule["post_deadline_offset_ms"],
            }
            if times["post"] > 86_400_000:
                raise ValueError("identity campaign probe schedule exceeds its relative clock")
            for node_number, node in enumerate(plan["nodes"], start=1):
                for auth_number, authorization in enumerate(cut, start=1):
                    actor_id, resource_id, action = authorization
                    for phase in ("pre", "window", "post"):
                        probes.append(
                            {
                                "probe_id": (
                                    f"e{event_number:03d}-n{node_number:03d}-"
                                    f"c{auth_number:04d}-{phase}"
                                ),
                                "event_id": event["event_id"],
                                "node_id": node["node_id"],
                                "attempted_at_ms": times[phase],
                                "actor_id": actor_id,
                                "resource_id": resource_id,
                                "action": action,
                            }
                        )
                for auth_number, authorization in enumerate(preserve, start=1):
                    actor_id, resource_id, action = authorization
                    probes.append(
                        {
                            "probe_id": (
                                f"e{event_number:03d}-n{node_number:03d}-"
                                f"p{auth_number:04d}-post"
                            ),
                            "event_id": event["event_id"],
                            "node_id": node["node_id"],
                            "attempted_at_ms": times["post"],
                            "actor_id": actor_id,
                            "resource_id": resource_id,
                            "action": action,
                        }
                    )
        if len(probes) != expected_probe_count:
            raise RuntimeError("identity campaign probe count did not reconcile")
        plan["probes"] = probes
        return _validate_plan(plan)
    except (KeyError, TypeError) as exc:
        raise ValueError("identity campaign contains malformed graph metadata") from exc


def _summary(plan: Mapping[str, Any]) -> Dict[str, int]:
    cut_authorizations = 0
    preserved_authorizations = 0
    for event in plan["events"]:
        before, after = _event_state(plan, event)
        cut_authorizations += len(before - after)
        preserved_authorizations += len(
            [item for item in before if item[0] in event["required_preserve_actor_ids"]]
        )
    return {
        "principal_count": len(plan["principals"]),
        "authority_edge_count": len(plan["authority_edges"]),
        "grant_count": len(plan["grants"]),
        "event_count": len(plan["events"]),
        "node_count": len(plan["nodes"]),
        "cut_authorization_count": cut_authorizations,
        "preserved_authorization_count": preserved_authorizations,
        "probe_count": len(plan["probes"]),
    }


def _verification_value(campaign: Any, verified_at: str) -> Dict[str, Any]:
    _timestamp(verified_at, "verification.verified_at")
    expected_plan = derive_identity_campaign_plan(campaign)
    return {
        "schema": VERIFICATION_SCHEMA,
        "schema_version": 1,
        "verified_at": verified_at,
        "campaign": campaign,
        "campaign_sha256": _sha256(_canonical(campaign)),
        "derived_plan_sha256": _sha256(_canonical(expected_plan)),
        "summary": _summary(expected_plan),
        "checks": [{"check": name, "status": "pass"} for name in CHECK_NAMES],
        "overall_status": "pass",
        "limitations": list(VERIFICATION_LIMITATIONS),
    }


def create_identity_campaign_verification(
    campaign_path: Path,
    plan_path: Path,
    output_path: Optional[Path] = None,
    *,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    campaign = _strict(_read(Path(campaign_path)), "identity campaign")
    plan = _strict(_read(Path(plan_path)), "identity plan")
    expected = derive_identity_campaign_plan(campaign)
    reviewed = _validate_plan(plan)
    if reviewed != expected:
        raise ValueError("identity plan is not the exact independently derived campaign plan")
    result = _verification_value(campaign, verified_at or _timestamp_now())
    if output_path is not None:
        _write_new(Path(output_path), _canonical(result))
    return result


def validate_identity_campaign_verification(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "identity campaign verification",
        (
            "schema",
            "schema_version",
            "verified_at",
            "campaign",
            "campaign_sha256",
            "derived_plan_sha256",
            "summary",
            "checks",
            "overall_status",
            "limitations",
        ),
    )
    if report["schema"] != VERIFICATION_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported identity campaign verification schema")
    expected = _verification_value(report["campaign"], report["verified_at"])
    if report != expected:
        raise ValueError("identity campaign verification does not independently recompute")
    return dict(report)


def load_identity_campaign_verification(path: Path) -> Dict[str, Any]:
    value = _strict(_read(Path(path)), "identity campaign verification")
    return validate_identity_campaign_verification(value)
