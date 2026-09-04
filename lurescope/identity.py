"""Independent evidence verification for LureIdentity lifecycle closure."""

from __future__ import annotations

import math
import os
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from . import __version__
from .boundary import (
    _private_key,
    _private_key_id,
    _sign_statement,
    _verify_envelope,
    public_key_id,
)
from .permit import (
    STATEMENT_TYPE,
    _canonical,
    _digest,
    _exact,
    _id,
    _integer,
    _portable_id,
    _rate,
    _read,
    _sha256,
    _strict,
    _timestamp,
    _timestamp_now,
    _write_new,
)
from .spiffe import parse_spiffe_id

PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-plan-v1"
RUN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-run-v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-evaluation-v1"
BUNDLE_SCHEMA = "https://github.com/immu4989/lurescope/spec/lureidentity-evidence-bundle/v1"
CHECKPOINT_PREDICATE = (
    "https://github.com/immu4989/lurescope/spec/lureidentity-evidence-checkpoint/v1"
)

MAX_PRINCIPALS = 128
MAX_EDGES = 256
MAX_GRANTS = 256
MAX_NODES = 64
MAX_EVENTS = 64
MAX_PROBES = 8192
PRINCIPAL_KINDS = {"agent", "group", "human", "workload"}
RELATIONSHIPS = {"delegates_to", "member_of", "runs_as"}
EVENT_TYPES = {
    "delegation_revoked",
    "scim_group_membership_removed",
    "scim_user_deactivated",
    "workload_retired",
}
ACTIONS = {"administer", "credential_use", "invoke", "read", "write"}
DISPOSITIONS = {"applied", "duplicate", "invalid"}
DECISIONS = {"allow", "block"}
REASONS = {
    "authority_active",
    "authority_path_cut",
    "authority_preserved",
    "lifecycle_event_pending",
}

PLAN_LIMITATIONS = [
    "synthetic_identity_and_authorization_metadata_only_no_credentials_tokens_or_payloads",
    "scim_fields_are_a_lifecycle_projection_not_scim_http_patch_or_endpoint_conformance",
    "event_authentication_delivery_clock_quality_and_complete_mediation_are_external_controls",
    "finite_graph_closure_results_do_not_prove_zero_trust_compliance_or_system_containment",
]
RUN_LIMITATIONS = [
    "observations_are_claimed_receiver_metadata_not_proof_of_event_or_enforcement_authenticity",
    "reference_run_is_offline_and_contacts_no_directory_agent_workload_or_policy_engine",
    "invalid_and_duplicate_events_are_synthetic_and_contain_no_reusable_security_material",
]
EVALUATION_LIMITATIONS = [
    "authority_closure_and_metrics_are_recomputed_from_embedded_plan_and_run_metadata",
    "a_graph_cut_covers_only_preregistered_principals_edges_grants_nodes_and_probes",
    "passing_does_not_establish_identity_proofing_event_authenticity_or_complete_mediation",
    "evaluation_is_not_certification_authorization_or_a_claim_of_scim_interoperability",
]
BUNDLE_LIMITATIONS = [
    "plan_run_graph_closure_dispositions_decisions_and_metrics_are_independently_recomputed",
    "a_signature_authenticates_a_key_not_a_directory_human_agent_workload_or_organization",
    "submitted_graph_and_observations_do_not_prove_complete_authority_or_mediation_coverage",
    "passing_is_not_scim_interoperability_zero_trust_compliance_or_deployment_authorization",
]
INTERPRETATION = (
    "LureScope independently recomputed the declared identity authority graph, lifecycle cuts, "
    "event delivery, convergence, dispositions, and access outcomes and bound their exact bytes. "
    "This is evidence integrity, not proof of identity, directory, clock, observation, or "
    "enforcement authenticity."
)

MANIFEST_FILE = "bundle.json"
EVIDENCE_DIRECTORY = "evidence"
EVALUATION_FILE = "identity-evaluation.json"
STATEMENT_FILE = "checkpoint.statement.json"
DSSE_FILE = "checkpoint.dsse.json"

Authorization = tuple[str, str, str]


def _enum(value: Any, field: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} is unsupported")
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean")
    return value


def _nullable_id(value: Any, field: str) -> Optional[str]:
    return None if value is None else _id(value, field)


def _ids(values: Any, field: str, maximum: int) -> list[str]:
    if not isinstance(values, list) or not 1 <= len(values) <= maximum:
        raise ValueError(f"{field} must be a non-empty bounded array")
    normalized = [_id(value, f"{field}[{index}]") for index, value in enumerate(values)]
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field} contains duplicate identifiers")
    return normalized


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _now_not_before(reference: str) -> str:
    current = _timestamp_now()
    return reference if _time(current) < _time(reference) else current


def _event_material(event: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: event[key] for key in event if key != "event_sha256"}


def _adjacency(
    principals: Mapping[str, Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
) -> dict[str, list[str]]:
    result = {principal_id: [] for principal_id in principals}
    for edge in edges:
        result[edge["source_id"]].append(edge["target_id"])
    for targets in result.values():
        targets.sort()
    return result


def _assert_acyclic(adjacency: Mapping[str, Sequence[str]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(principal_id: str) -> None:
        if principal_id in visiting:
            raise ValueError("identity authority graph must be acyclic")
        if principal_id in visited:
            return
        visiting.add(principal_id)
        for target_id in adjacency[principal_id]:
            visit(target_id)
        visiting.remove(principal_id)
        visited.add(principal_id)

    for principal_id in sorted(adjacency):
        visit(principal_id)


def _descendants(adjacency: Mapping[str, Sequence[str]], start_id: str) -> set[str]:
    result: set[str] = set()
    pending = [start_id]
    while pending:
        principal_id = pending.pop()
        if principal_id in result:
            continue
        result.add(principal_id)
        pending.extend(adjacency[principal_id])
    return result


def _authorizations(
    principals: Mapping[str, Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    grants: Sequence[Mapping[str, Any]],
) -> set[Authorization]:
    active = {
        principal_id
        for principal_id, principal in principals.items()
        if principal["active"] is True
    }
    active_edges = [
        edge
        for edge in edges
        if edge["source_id"] in active and edge["target_id"] in active
    ]
    adjacency = _adjacency(principals, active_edges)
    result: set[Authorization] = set()
    for grant in grants:
        if grant["principal_id"] in active:
            for actor_id in _descendants(adjacency, grant["principal_id"]):
                if actor_id in active:
                    result.add((actor_id, grant["resource_id"], grant["action"]))
    return result


def _event_state(
    plan: Mapping[str, Any], event: Mapping[str, Any]
) -> tuple[set[Authorization], set[Authorization]]:
    principals = {item["principal_id"]: dict(item) for item in plan["principals"]}
    edges = [dict(item) for item in plan["authority_edges"]]
    baseline = _authorizations(principals, edges, plan["grants"])
    if event["event_type"] in {"scim_user_deactivated", "workload_retired"}:
        principals[event["target_principal_id"]]["active"] = False
    else:
        edges = [edge for edge in edges if edge["edge_id"] != event["target_edge_id"]]
    return baseline, _authorizations(principals, edges, plan["grants"])


def _event_cut(plan: Mapping[str, Any], event: Mapping[str, Any]) -> set[Authorization]:
    before, after = _event_state(plan, event)
    return before - after


def _validate_relationship(
    edge: Mapping[str, Any], principals: Mapping[str, Mapping[str, Any]], field: str
) -> None:
    source_kind = principals[edge["source_id"]]["kind"]
    target_kind = principals[edge["target_id"]]["kind"]
    relationship = edge["relationship"]
    valid = (
        relationship == "member_of"
        and source_kind == "group"
        and target_kind == "human"
        or relationship == "delegates_to"
        and source_kind in {"human", "agent"}
        and target_kind == "agent"
        or relationship == "runs_as"
        and source_kind == "agent"
        and target_kind == "workload"
    )
    if not valid:
        raise ValueError(f"{field} has incompatible principal kinds")


def _validate_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "identity plan",
        (
            "schema",
            "schema_version",
            "plan_id",
            "created_at",
            "system_id",
            "directory",
            "principals",
            "authority_edges",
            "grants",
            "nodes",
            "events",
            "probes",
            "acceptance",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity plan schema")
    _id(plan["plan_id"], "plan.plan_id")
    _id(plan["system_id"], "plan.system_id")
    _timestamp(plan["created_at"], "plan.created_at")
    directory = _exact(
        plan["directory"],
        "plan.directory",
        ("issuer_id", "tenant_id", "profile", "authentication_boundary"),
    )
    _id(directory["issuer_id"], "directory.issuer_id")
    _id(directory["tenant_id"], "directory.tenant_id")
    if (
        directory["profile"] != "ietf-scim-rfc7643-lifecycle-metadata-projection"
        or directory["authentication_boundary"] != "externally_authenticated_and_authorized"
    ):
        raise ValueError("identity directory contract is unsupported")

    if not isinstance(plan["principals"], list) or not 1 <= len(
        plan["principals"]
    ) <= MAX_PRINCIPALS:
        raise ValueError("identity principals must be a non-empty bounded array")
    principals: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(plan["principals"]):
        principal = _exact(
            item,
            f"plan.principals[{index}]",
            ("principal_id", "kind", "active", "spiffe_id"),
        )
        principal_id = _id(principal["principal_id"], "principal.principal_id")
        if principal_id in principals:
            raise ValueError("identity plan contains duplicate principals")
        kind = _enum(principal["kind"], "principal.kind", PRINCIPAL_KINDS)
        _boolean(principal["active"], "principal.active")
        if kind == "workload":
            try:
                parse_spiffe_id(
                    principal["spiffe_id"], "principal.spiffe_id", require_path=True
                )
            except ValueError as exc:
                raise ValueError(
                    "workload principal requires a canonical SPIFFE ID"
                ) from exc
        elif principal["spiffe_id"] is not None:
            raise ValueError("only workload principals may declare a SPIFFE ID")
        principals[principal_id] = principal

    if not isinstance(plan["authority_edges"], list) or len(
        plan["authority_edges"]
    ) > MAX_EDGES:
        raise ValueError("identity authority edges must be a bounded array")
    edges: dict[str, Mapping[str, Any]] = {}
    edge_pairs: set[tuple[str, str, str]] = set()
    for index, item in enumerate(plan["authority_edges"]):
        edge = _exact(
            item,
            f"plan.authority_edges[{index}]",
            ("edge_id", "source_id", "target_id", "relationship"),
        )
        edge_id = _id(edge["edge_id"], "authority edge id")
        source_id = _id(edge["source_id"], "authority edge source")
        target_id = _id(edge["target_id"], "authority edge target")
        _enum(edge["relationship"], "authority edge relationship", RELATIONSHIPS)
        if edge_id in edges:
            raise ValueError("identity plan contains duplicate edge identifiers")
        if source_id not in principals or target_id not in principals or source_id == target_id:
            raise ValueError("authority edge references an unknown or identical principal")
        pair = (source_id, target_id, edge["relationship"])
        if pair in edge_pairs:
            raise ValueError("identity plan contains a duplicate relationship")
        edge_pairs.add(pair)
        _validate_relationship(edge, principals, f"plan.authority_edges[{index}]")
        edges[edge_id] = edge
    adjacency = _adjacency(principals, list(edges.values()))
    _assert_acyclic(adjacency)

    if not isinstance(plan["grants"], list) or not 1 <= len(plan["grants"]) <= MAX_GRANTS:
        raise ValueError("identity grants must be a non-empty bounded array")
    grants: list[Mapping[str, Any]] = []
    grant_ids: set[str] = set()
    grant_tuples: set[tuple[str, str, str]] = set()
    for index, item in enumerate(plan["grants"]):
        grant = _exact(
            item,
            f"plan.grants[{index}]",
            ("grant_id", "principal_id", "resource_id", "action"),
        )
        grant_id = _id(grant["grant_id"], "grant id")
        principal_id = _id(grant["principal_id"], "grant principal")
        resource_id = _id(grant["resource_id"], "grant resource")
        action = _enum(grant["action"], "grant action", ACTIONS)
        if grant_id in grant_ids:
            raise ValueError("identity plan contains duplicate grant identifiers")
        if principal_id not in principals:
            raise ValueError("identity grant references an unknown principal")
        grant_tuple = (principal_id, resource_id, action)
        if grant_tuple in grant_tuples:
            raise ValueError("identity plan contains duplicate authority")
        grant_ids.add(grant_id)
        grant_tuples.add(grant_tuple)
        grants.append(grant)

    if not isinstance(plan["nodes"], list) or not 1 <= len(plan["nodes"]) <= MAX_NODES:
        raise ValueError("identity nodes must be a non-empty bounded array")
    node_ids = []
    for index, item in enumerate(plan["nodes"]):
        node = _exact(item, f"plan.nodes[{index}]", ("node_id", "enforcement_point_id"))
        node_ids.append(_id(node["node_id"], "node.node_id"))
        _id(node["enforcement_point_id"], "node.enforcement_point_id")
    if len(set(node_ids)) != len(node_ids):
        raise ValueError("identity plan contains duplicate node identifiers")

    if not isinstance(plan["events"], list) or not 1 <= len(plan["events"]) <= MAX_EVENTS:
        raise ValueError("identity events must be a non-empty bounded array")
    events: dict[str, Mapping[str, Any]] = {}
    sequences: set[int] = set()
    for index, item in enumerate(plan["events"]):
        event = _exact(
            item,
            f"plan.events[{index}]",
            (
                "event_id",
                "sequence",
                "occurred_at_ms",
                "event_type",
                "target_principal_id",
                "target_edge_id",
                "required_cut_actor_ids",
                "required_preserve_actor_ids",
                "source_event_sha256",
                "event_sha256",
            ),
        )
        event_id = _id(event["event_id"], "event.event_id")
        sequence = _integer(event["sequence"], "event.sequence", 1, 1_000_000)
        if event_id in events or sequence in sequences:
            raise ValueError("identity plan contains duplicate event identity or sequence")
        sequences.add(sequence)
        _integer(event["occurred_at_ms"], "event.occurred_at_ms", 1, 86_400_000)
        event_type = _enum(event["event_type"], "event.event_type", EVENT_TYPES)
        target_principal_id = _nullable_id(
            event["target_principal_id"], "event.target_principal_id"
        )
        target_edge_id = _nullable_id(event["target_edge_id"], "event.target_edge_id")
        cut_ids = _ids(event["required_cut_actor_ids"], "required cut actors", MAX_PRINCIPALS)
        preserve_ids = _ids(
            event["required_preserve_actor_ids"], "required preserve actors", MAX_PRINCIPALS
        )
        if set(cut_ids) & set(preserve_ids):
            raise ValueError("identity cut and preserve actors must be disjoint")
        if any(actor_id not in principals for actor_id in cut_ids + preserve_ids):
            raise ValueError("identity event references an unknown cut or preserve actor")
        if event_type == "scim_user_deactivated":
            if (
                target_principal_id not in principals
                or principals[target_principal_id]["kind"] != "human"
                or target_edge_id is not None
            ):
                raise ValueError("SCIM user deactivation must target one human principal")
            cone = _descendants(adjacency, target_principal_id)
        elif event_type == "workload_retired":
            if (
                target_principal_id not in principals
                or principals[target_principal_id]["kind"] != "workload"
                or target_edge_id is not None
            ):
                raise ValueError("workload retirement must target one workload principal")
            cone = _descendants(adjacency, target_principal_id)
        else:
            relationship = (
                "member_of" if event_type == "scim_group_membership_removed" else "delegates_to"
            )
            if (
                target_principal_id is not None
                or target_edge_id not in edges
                or edges[target_edge_id]["relationship"] != relationship
            ):
                raise ValueError("edge lifecycle event targets an incompatible authority edge")
            cone = _descendants(adjacency, edges[target_edge_id]["target_id"])
        if not set(cut_ids) <= cone:
            raise ValueError("identity cut actors must be in the event dependency cone")
        if set(preserve_ids) & cone:
            raise ValueError("identity preserve actors must be outside the event dependency cone")
        _digest(event["source_event_sha256"], "event.source_event_sha256")
        _digest(event["event_sha256"], "event.event_sha256")
        if event["event_sha256"] != _sha256(_canonical(_event_material(event))):
            raise ValueError("identity event digest does not reconcile")
        events[event_id] = event
    if sorted(sequences) != list(range(1, len(sequences) + 1)):
        raise ValueError("identity event sequences must be contiguous from one")

    baseline = _authorizations(principals, list(edges.values()), grants)
    event_states: dict[str, tuple[set[Authorization], set[Authorization]]] = {}
    for event_id, event in events.items():
        before, after = _event_state(plan, event)
        event_states[event_id] = (before, after)
        if before != baseline or not before - after:
            raise ValueError("each identity event must cut at least one authorization")
        if {item[0] for item in before - after} != set(event["required_cut_actor_ids"]):
            raise ValueError("identity cut actors do not exactly cover the authorization cut")
        for actor_id in event["required_cut_actor_ids"]:
            actor_before = {item for item in before if item[0] == actor_id}
            actor_after = {item for item in after if item[0] == actor_id}
            if not actor_before or actor_after:
                raise ValueError("required identity actor did not lose every authorization")
        for actor_id in event["required_preserve_actor_ids"]:
            actor_before = {item for item in before if item[0] == actor_id}
            actor_after = {item for item in after if item[0] == actor_id}
            if not actor_before or actor_before != actor_after:
                raise ValueError("preserved identity actor did not retain every authorization")

    acceptance = _exact(
        plan["acceptance"],
        "plan.acceptance",
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
    deadline = _integer(
        acceptance["maximum_convergence_ms"], "maximum_convergence_ms", 1, 600_000
    )
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

    if not isinstance(plan["probes"], list) or not 1 <= len(plan["probes"]) <= MAX_PROBES:
        raise ValueError("identity probes must be a non-empty bounded array")
    probe_ids: set[str] = set()
    probe_index: set[tuple[str, str, Authorization, str]] = set()
    for index, item in enumerate(plan["probes"]):
        probe = _exact(
            item,
            f"plan.probes[{index}]",
            (
                "probe_id",
                "event_id",
                "node_id",
                "attempted_at_ms",
                "actor_id",
                "resource_id",
                "action",
            ),
        )
        probe_id = _id(probe["probe_id"], "probe.probe_id")
        if probe_id in probe_ids:
            raise ValueError("identity plan contains duplicate probe identifiers")
        probe_ids.add(probe_id)
        if probe["event_id"] not in events or probe["node_id"] not in node_ids:
            raise ValueError("identity probe references an unknown event or node")
        _integer(probe["attempted_at_ms"], "probe.attempted_at_ms", 0, 86_400_000)
        authorization = (
            _id(probe["actor_id"], "probe.actor_id"),
            _id(probe["resource_id"], "probe.resource_id"),
            _enum(probe["action"], "probe.action", ACTIONS),
        )
        if authorization not in baseline:
            raise ValueError("every identity probe must be allowed by the baseline graph")
        event = events[probe["event_id"]]
        attempted = probe["attempted_at_ms"]
        phase = (
            "pre"
            if attempted < event["occurred_at_ms"]
            else "post"
            if attempted >= event["occurred_at_ms"] + deadline
            else "window"
        )
        key = (probe["event_id"], probe["node_id"], authorization, phase)
        if key in probe_index:
            raise ValueError("identity plan contains a duplicate authorization phase")
        probe_index.add(key)

    for event_id, event in events.items():
        before, after = event_states[event_id]
        required_cut = {
            item for item in before - after if item[0] in event["required_cut_actor_ids"]
        }
        required_preserve = {
            item for item in before if item[0] in event["required_preserve_actor_ids"]
        }
        for node_id in node_ids:
            for authorization in required_cut:
                if (event_id, node_id, authorization, "pre") not in probe_index:
                    raise ValueError("identity plan omits a required pre-event cut probe")
                if (event_id, node_id, authorization, "post") not in probe_index:
                    raise ValueError("identity plan omits a required post-deadline cut probe")
            for authorization in required_preserve:
                if (event_id, node_id, authorization, "post") not in probe_index:
                    raise ValueError("identity plan omits a required preservation probe")
    if plan["limitations"] != PLAN_LIMITATIONS:
        raise ValueError("identity plan limitations are invalid")
    return dict(plan)


def _validate_run(value: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    run = _exact(
        value,
        "identity run",
        (
            "schema",
            "schema_version",
            "run_id",
            "generated_at",
            "implementation",
            "plan_sha256",
            "event_observations",
            "access_observations",
            "limitations",
        ),
    )
    if run["schema"] != RUN_SCHEMA or run["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity run schema")
    _id(run["run_id"], "run.run_id")
    _timestamp(run["generated_at"], "run.generated_at")
    if _time(run["generated_at"]) < _time(plan["created_at"]):
        raise ValueError("identity run predates its plan")
    implementation = _exact(
        run["implementation"], "run.implementation", ("name", "version", "artifact_sha256")
    )
    _id(implementation["name"], "run.implementation.name")
    _id(implementation["version"], "run.implementation.version")
    if implementation["artifact_sha256"] is not None:
        _digest(implementation["artifact_sha256"], "run.implementation.artifact_sha256")
    _digest(run["plan_sha256"], "run.plan_sha256")
    if run["plan_sha256"] != _sha256(_canonical(plan)):
        raise ValueError("identity run plan digest does not reconcile")
    event_ids = {event["event_id"] for event in plan["events"]}
    node_ids = {node["node_id"] for node in plan["nodes"]}
    observations = run["event_observations"]
    if not isinstance(observations, list) or len(observations) > MAX_EVENTS * MAX_NODES * 4:
        raise ValueError("identity event observations must be a bounded array")
    observation_ids = []
    for index, item in enumerate(observations):
        observation = _exact(
            item,
            f"run.event_observations[{index}]",
            (
                "observation_id",
                "event_id",
                "node_id",
                "received_at_ms",
                "event_sha256",
                "disposition",
            ),
        )
        observation_ids.append(_id(observation["observation_id"], "observation.observation_id"))
        if observation["event_id"] not in event_ids or observation["node_id"] not in node_ids:
            raise ValueError("identity event observation references an unknown event or node")
        _integer(observation["received_at_ms"], "observation.received_at_ms", 0, 86_400_000)
        _digest(observation["event_sha256"], "observation.event_sha256")
        _enum(observation["disposition"], "observation.disposition", DISPOSITIONS)
    if len(set(observation_ids)) != len(observation_ids):
        raise ValueError("identity run contains duplicate event observations")
    probe_ids = {probe["probe_id"] for probe in plan["probes"]}
    access = run["access_observations"]
    if not isinstance(access, list) or len(access) != len(probe_ids):
        raise ValueError("identity run must contain exactly one decision per probe")
    submitted_ids = []
    for index, item in enumerate(access):
        observation = _exact(
            item,
            f"run.access_observations[{index}]",
            ("probe_id", "decision", "reason_code"),
        )
        submitted_ids.append(_id(observation["probe_id"], "access observation probe id"))
        _enum(observation["decision"], "access decision", DECISIONS)
        _enum(observation["reason_code"], "access reason", REASONS)
    if set(submitted_ids) != probe_ids or len(set(submitted_ids)) != len(probe_ids):
        raise ValueError("identity access observations do not exactly cover plan probes")
    if run["limitations"] != RUN_LIMITATIONS:
        raise ValueError("identity run limitations are invalid")
    return dict(run)


def _expected_dispositions(
    plan: Mapping[str, Any], observations: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, str], dict[tuple[str, str], int]]:
    events = {event["event_id"]: event for event in plan["events"]}
    seen: set[tuple[str, str]] = set()
    expected: dict[str, str] = {}
    applied: dict[tuple[str, str], int] = {}
    for observation in sorted(
        observations, key=lambda item: (item["received_at_ms"], item["observation_id"])
    ):
        event = events[observation["event_id"]]
        key = (observation["event_id"], observation["node_id"])
        valid = (
            observation["event_sha256"] == event["event_sha256"]
            and observation["received_at_ms"] >= event["occurred_at_ms"]
        )
        if not valid:
            disposition = "invalid"
        elif key in seen:
            disposition = "duplicate"
        else:
            disposition = "applied"
            seen.add(key)
            applied[key] = observation["received_at_ms"]
        expected[observation["observation_id"]] = disposition
    return expected, applied


def _expected_probe(
    plan: Mapping[str, Any],
    probe: Mapping[str, Any],
    event: Mapping[str, Any],
    applied_at: Optional[int],
) -> tuple[str, str, str]:
    authorization = (probe["actor_id"], probe["resource_id"], probe["action"])
    if authorization not in _event_cut(plan, event):
        return "allow", "authority_preserved", "unrelated_control"
    attempted = probe["attempted_at_ms"]
    if attempted < event["occurred_at_ms"]:
        return "allow", "authority_active", "pre_event"
    deadline_at = event["occurred_at_ms"] + plan["acceptance"]["maximum_convergence_ms"]
    if attempted >= deadline_at:
        return "block", "authority_path_cut", "post_deadline"
    if applied_at is not None and attempted >= applied_at:
        return "block", "authority_path_cut", "cut_effective"
    return "allow", "lifecycle_event_pending", "propagation_window"


def _authorization_value(authorization: Authorization) -> Dict[str, str]:
    return {
        "actor_id": authorization[0],
        "resource_id": authorization[1],
        "action": authorization[2],
    }


def _evaluation_value(value: Mapping[str, Any]) -> Dict[str, Any]:
    generated_at = value["generated_at"]
    _timestamp(generated_at, "evaluation.generated_at")
    plan = _validate_plan(value["plan"])
    run = _validate_run(value["run"], plan)
    if _time(generated_at) < _time(run["generated_at"]):
        raise ValueError("identity evaluation predates its run")
    expected_dispositions, applied = _expected_dispositions(plan, run["event_observations"])
    events = {event["event_id"]: event for event in plan["events"]}
    submitted = {item["probe_id"]: item for item in run["access_observations"]}
    deadline = plan["acceptance"]["maximum_convergence_ms"]
    convergence_values = []
    delivery_results = []
    deadline_misses = 0
    for event in plan["events"]:
        for node in plan["nodes"]:
            received = applied.get((event["event_id"], node["node_id"]))
            convergence = None if received is None else received - event["occurred_at_ms"]
            deadline_met = convergence is not None and convergence <= deadline
            if convergence is not None:
                convergence_values.append(convergence)
            deadline_misses += int(not deadline_met)
            delivery_results.append(
                {
                    "event_id": event["event_id"],
                    "node_id": node["node_id"],
                    "applied_at_ms": received,
                    "convergence_ms": convergence,
                    "deadline_met": deadline_met,
                }
            )

    event_results = []
    affected_count = 0
    for event in plan["events"]:
        affected = sorted(_event_cut(plan, event))
        affected_count += len(affected)
        event_results.append(
            {
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "affected_authorization_count": len(affected),
                "affected_authorizations": [_authorization_value(item) for item in affected],
            }
        )

    probe_results = []
    cut_total = cut_correct = 0
    pre_total = pre_correct = 0
    preserve_total = preserve_correct = 0
    stale_allows = collateral_blocks = 0
    incorrect_decisions = incorrect_reasons = 0
    for probe in plan["probes"]:
        event = events[probe["event_id"]]
        expected_decision, expected_reason, phase = _expected_probe(
            plan,
            probe,
            event,
            applied.get((probe["event_id"], probe["node_id"])),
        )
        actual = submitted[probe["probe_id"]]
        decision_correct = actual["decision"] == expected_decision
        reason_correct = actual["reason_code"] == expected_reason
        incorrect_decisions += int(not decision_correct)
        incorrect_reasons += int(not reason_correct)
        if expected_decision == "block":
            cut_total += 1
            cut_correct += int(actual["decision"] == "block")
        if phase == "pre_event":
            pre_total += 1
            pre_correct += int(actual["decision"] == "allow")
        if phase == "unrelated_control":
            preserve_total += 1
            preserve_correct += int(actual["decision"] == "allow")
            collateral_blocks += int(actual["decision"] == "block")
        if phase == "post_deadline" and actual["decision"] == "allow":
            stale_allows += 1
        classification = (
            "correct"
            if decision_correct and reason_correct
            else "stale_authorization"
            if expected_decision == "block" and actual["decision"] == "allow"
            else "collateral_denial"
            if phase == "unrelated_control" and actual["decision"] == "block"
            else "premature_denial"
            if expected_decision == "allow" and actual["decision"] == "block"
            else "wrong_reason"
        )
        probe_results.append(
            {
                "probe_id": probe["probe_id"],
                "event_id": probe["event_id"],
                "node_id": probe["node_id"],
                "actor_id": probe["actor_id"],
                "resource_id": probe["resource_id"],
                "action": probe["action"],
                "phase": phase,
                "expected_decision": expected_decision,
                "submitted_decision": actual["decision"],
                "expected_reason_code": expected_reason,
                "submitted_reason_code": actual["reason_code"],
                "classification": classification,
            }
        )

    disposition_correct = sum(
        item["disposition"] == expected_dispositions[item["observation_id"]]
        for item in run["event_observations"]
    )
    disposition_total = len(run["event_observations"])
    required_deliveries = len(plan["events"]) * len(plan["nodes"])
    coverage = len(applied) / required_deliveries
    maximum = max(convergence_values) if convergence_values else None
    ordered = sorted(convergence_values)
    p95 = ordered[math.ceil(0.95 * len(ordered)) - 1] if ordered else None
    cut_recall = cut_correct / cut_total if cut_total else 0.0
    pre_allow = pre_correct / pre_total if pre_total else 0.0
    preserved_allow = preserve_correct / preserve_total if preserve_total else 0.0
    disposition_accuracy = disposition_correct / disposition_total if disposition_total else 0.0
    acceptance = plan["acceptance"]
    verdict = (
        "pass"
        if (
            coverage >= acceptance["minimum_delivery_coverage_rate"]
            and maximum is not None
            and maximum <= acceptance["maximum_convergence_ms"]
            and deadline_misses <= acceptance["maximum_deadline_miss_count"]
            and stale_allows <= acceptance["maximum_post_deadline_stale_allow_count"]
            and collateral_blocks <= acceptance["maximum_collateral_block_count"]
            and cut_recall >= acceptance["minimum_cut_recall"]
            and pre_allow >= acceptance["minimum_pre_event_allow_rate"]
            and preserved_allow >= acceptance["minimum_preserved_allow_rate"]
            and disposition_accuracy >= acceptance["minimum_signal_disposition_accuracy"]
            and incorrect_decisions == 0
            and incorrect_reasons == 0
        )
        else "fail"
    )
    return {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "implementation": value["implementation"],
        "plan": plan,
        "plan_sha256": _sha256(_canonical(plan)),
        "run": run,
        "run_sha256": _sha256(_canonical(run)),
        "summary": {
            "principal_count": len(plan["principals"]),
            "authority_edge_count": len(plan["authority_edges"]),
            "grant_count": len(plan["grants"]),
            "event_count": len(plan["events"]),
            "node_count": len(plan["nodes"]),
            "affected_authorization_count": affected_count,
            "required_delivery_count": required_deliveries,
            "applied_delivery_count": len(applied),
            "delivery_coverage_rate": coverage,
            "maximum_convergence_ms": maximum,
            "p95_convergence_ms": p95,
            "deadline_miss_count": deadline_misses,
            "post_deadline_stale_allow_count": stale_allows,
            "collateral_block_count": collateral_blocks,
            "cut_recall": cut_recall,
            "pre_event_allow_rate": pre_allow,
            "preserved_allow_rate": preserved_allow,
            "signal_disposition_accuracy": disposition_accuracy,
            "incorrect_decision_count": incorrect_decisions,
            "incorrect_reason_count": incorrect_reasons,
            "verdict": verdict,
        },
        "event_results": event_results,
        "delivery_results": delivery_results,
        "probe_results": probe_results,
        "limitations": list(EVALUATION_LIMITATIONS),
    }


def validate_identity_evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _exact(
        value,
        "identity evaluation",
        (
            "schema",
            "schema_version",
            "generated_at",
            "implementation",
            "plan",
            "plan_sha256",
            "run",
            "run_sha256",
            "summary",
            "event_results",
            "delivery_results",
            "probe_results",
            "limitations",
        ),
    )
    if evaluation["schema"] != EVALUATION_SCHEMA or evaluation["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity evaluation schema")
    implementation = _exact(
        evaluation["implementation"], "evaluation.implementation", ("name", "version")
    )
    if implementation["name"] != "lurebench":
        raise ValueError("identity evaluation producer must be lurebench")
    _id(implementation["version"], "evaluation.implementation.version")
    expected = _evaluation_value(evaluation)
    if evaluation != expected:
        raise ValueError("identity evaluation does not independently recompute")
    return dict(evaluation)


def _load_evaluation(path: Path, *, private: bool = False) -> tuple[Dict[str, Any], bytes]:
    raw = _read(Path(path), private=private)
    value = validate_identity_evaluation(_strict(raw, Path(path).name))
    if raw != _canonical(value):
        raise ValueError("identity evaluation must use canonical JSON")
    return value, raw


def _summary_binding(report: Mapping[str, Any]) -> Dict[str, Any]:
    summary = report["summary"]
    return {
        "affected_authorization_count": summary["affected_authorization_count"],
        "delivery_coverage_rate": summary["delivery_coverage_rate"],
        "p95_convergence_ms": summary["p95_convergence_ms"],
        "maximum_convergence_ms": summary["maximum_convergence_ms"],
        "deadline_miss_count": summary["deadline_miss_count"],
        "post_deadline_stale_allow_count": summary["post_deadline_stale_allow_count"],
        "collateral_block_count": summary["collateral_block_count"],
        "cut_recall": summary["cut_recall"],
        "preserved_allow_rate": summary["preserved_allow_rate"],
    }


def _validate_manifest(value: Any) -> Dict[str, Any]:
    manifest = _exact(
        value,
        "identity bundle manifest",
        (
            "schema",
            "schema_version",
            "bundle_id",
            "created_at",
            "producer",
            "system",
            "plan",
            "receiver",
            "evidence",
            "summary",
            "overall_status",
            "authentication",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if manifest["schema"] != BUNDLE_SCHEMA or manifest["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity bundle schema")
    _portable_id(manifest["bundle_id"], "bundle.bundle_id")
    _timestamp(manifest["created_at"], "bundle.created_at")
    producer = _exact(manifest["producer"], "bundle.producer", ("name", "version"))
    if producer["name"] != "lurescope":
        raise ValueError("identity bundle producer must be lurescope")
    _id(producer["version"], "bundle.producer.version")
    system = _exact(manifest["system"], "bundle.system", ("system_id", "environment"))
    _id(system["system_id"], "bundle.system.system_id")
    _enum(
        system["environment"],
        "bundle.system.environment",
        {"development", "evaluation", "staging", "production"},
    )
    plan = _exact(manifest["plan"], "bundle.plan", ("plan_id", "plan_sha256"))
    _id(plan["plan_id"], "bundle.plan.plan_id")
    _digest(plan["plan_sha256"], "bundle.plan.plan_sha256")
    receiver = _exact(
        manifest["receiver"], "bundle.receiver", ("name", "version", "artifact_sha256")
    )
    _id(receiver["name"], "bundle.receiver.name")
    _id(receiver["version"], "bundle.receiver.version")
    if receiver["artifact_sha256"] is not None:
        _digest(receiver["artifact_sha256"], "bundle.receiver.artifact_sha256")
    evidence = _exact(
        manifest["evidence"], "bundle.evidence", ("file", "schema", "sha256", "run_sha256")
    )
    if (
        evidence["file"] != f"{EVIDENCE_DIRECTORY}/{EVALUATION_FILE}"
        or evidence["schema"] != EVALUATION_SCHEMA
    ):
        raise ValueError("identity bundle evidence contract is invalid")
    _digest(evidence["sha256"], "bundle.evidence.sha256")
    _digest(evidence["run_sha256"], "bundle.evidence.run_sha256")
    summary = _exact(
        manifest["summary"],
        "bundle.summary",
        (
            "affected_authorization_count",
            "delivery_coverage_rate",
            "p95_convergence_ms",
            "maximum_convergence_ms",
            "deadline_miss_count",
            "post_deadline_stale_allow_count",
            "collateral_block_count",
            "cut_recall",
            "preserved_allow_rate",
        ),
    )
    _integer(summary["affected_authorization_count"], "summary affected count", 1, 100_000)
    for field in ("delivery_coverage_rate", "cut_recall", "preserved_allow_rate"):
        _rate(summary[field], f"bundle.summary.{field}")
    for field in (
        "deadline_miss_count",
        "post_deadline_stale_allow_count",
        "collateral_block_count",
    ):
        _integer(summary[field], f"bundle.summary.{field}", 0, MAX_PROBES)
    for field in ("p95_convergence_ms", "maximum_convergence_ms"):
        if summary[field] is not None:
            _integer(summary[field], f"bundle.summary.{field}", 0, 86_400_000)
    _enum(manifest["overall_status"], "bundle.overall_status", {"pass", "fail"})
    authentication = _exact(
        manifest["authentication"], "bundle.authentication", ("mode", "signer_key_id")
    )
    _enum(authentication["mode"], "bundle.authentication.mode", {"unsigned", "ecdsa-p256-dsse"})
    if authentication["mode"] == "unsigned":
        if authentication["signer_key_id"] is not None:
            raise ValueError("unsigned identity bundle cannot name a signer")
    else:
        _digest(authentication["signer_key_id"], "bundle.authentication.signer_key_id")
    if (
        manifest["limitations"] != BUNDLE_LIMITATIONS
        or manifest["interpretation_boundary"] != INTERPRETATION
    ):
        raise ValueError("identity bundle interpretation boundary is invalid")
    return dict(manifest)


def _checkpoint(manifest: Mapping[str, Any], manifest_raw: bytes) -> Dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": MANIFEST_FILE, "digest": {"sha256": _sha256(manifest_raw)}},
            {
                "name": manifest["evidence"]["file"],
                "digest": {"sha256": manifest["evidence"]["sha256"]},
            },
        ],
        "predicateType": CHECKPOINT_PREDICATE,
        "predicate": {
            "bundle_id": manifest["bundle_id"],
            "created_at": manifest["created_at"],
            "system_id": manifest["system"]["system_id"],
            "plan_sha256": manifest["plan"]["plan_sha256"],
            "run_sha256": manifest["evidence"]["run_sha256"],
            "receiver_name": manifest["receiver"]["name"],
            "overall_status": manifest["overall_status"],
            "authentication_mode": manifest["authentication"]["mode"],
            "limitations": list(BUNDLE_LIMITATIONS),
            "interpretation_boundary": INTERPRETATION,
        },
    }


def create_identity_bundle(
    output: Path,
    *,
    bundle_id: str,
    environment: str,
    evaluation: Path,
    signer_public_key_pem: Optional[bytes] = None,
    signing_key_pem: Optional[bytes] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    target = Path(output)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"{target} already exists")
    _portable_id(bundle_id, "bundle_id")
    _enum(environment, "environment", {"development", "evaluation", "staging", "production"})
    if (signer_public_key_pem is None) != (signing_key_pem is None):
        raise ValueError("identity bundle signing requires matching public and private keys")
    key = None
    signer_id = None
    if signer_public_key_pem is not None and signing_key_pem is not None:
        key = _private_key(signing_key_pem)
        signer_id = public_key_id(signer_public_key_pem)
        if not secrets.compare_digest(_private_key_id(key), signer_id):
            raise ValueError("identity signing key does not match its public key")
    report, report_raw = _load_evaluation(evaluation)
    created = created_at or _now_not_before(report["generated_at"])
    _timestamp(created, "bundle.created_at")
    if _time(created) < _time(report["generated_at"]):
        raise ValueError("identity bundle cannot predate its evaluation")
    plan, run = report["plan"], report["run"]
    manifest = _validate_manifest(
        {
            "schema": BUNDLE_SCHEMA,
            "schema_version": 1,
            "bundle_id": bundle_id,
            "created_at": created,
            "producer": {"name": "lurescope", "version": __version__},
            "system": {"system_id": plan["system_id"], "environment": environment},
            "plan": {"plan_id": plan["plan_id"], "plan_sha256": report["plan_sha256"]},
            "receiver": dict(run["implementation"]),
            "evidence": {
                "file": f"{EVIDENCE_DIRECTORY}/{EVALUATION_FILE}",
                "schema": EVALUATION_SCHEMA,
                "sha256": _sha256(report_raw),
                "run_sha256": report["run_sha256"],
            },
            "summary": _summary_binding(report),
            "overall_status": report["summary"]["verdict"],
            "authentication": {
                "mode": "unsigned" if signer_id is None else "ecdsa-p256-dsse",
                "signer_key_id": signer_id,
            },
            "limitations": list(BUNDLE_LIMITATIONS),
            "interpretation_boundary": INTERPRETATION,
        }
    )
    manifest_raw = _canonical(manifest)
    statement_raw = _canonical(_checkpoint(manifest, manifest_raw))
    target.mkdir(mode=0o700)
    evidence_dir = target / EVIDENCE_DIRECTORY
    try:
        evidence_dir.mkdir(mode=0o700)
        _write_new(target / MANIFEST_FILE, manifest_raw)
        _write_new(evidence_dir / EVALUATION_FILE, report_raw)
        _write_new(target / STATEMENT_FILE, statement_raw)
        if key is not None:
            _write_new(target / DSSE_FILE, _canonical(_sign_statement(statement_raw, key)))
        verify_identity_bundle(target, public_key_pem=signer_public_key_pem)
    except Exception:
        for item in sorted(target.rglob("*"), key=lambda path: len(path.parts), reverse=True):
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                item.rmdir()
        target.rmdir()
        raise
    return manifest


def verify_identity_bundle(
    bundle: Path, *, public_key_pem: Optional[bytes] = None
) -> Dict[str, Any]:
    root = Path(bundle)
    if (
        root.is_symlink()
        or not root.is_dir()
        or (os.name == "posix" and root.stat().st_mode & 0o077)
    ):
        raise ValueError("identity bundle must be a private regular directory")
    manifest_raw = _read(root / MANIFEST_FILE, private=True)
    manifest = _validate_manifest(_strict(manifest_raw, MANIFEST_FILE))
    if manifest_raw != _canonical(manifest):
        raise ValueError("identity manifest must use canonical JSON")
    signed = manifest["authentication"]["mode"] == "ecdsa-p256-dsse"
    expected_root = {MANIFEST_FILE, EVIDENCE_DIRECTORY, STATEMENT_FILE} | (
        {DSSE_FILE} if signed else set()
    )
    if {item.name for item in root.iterdir()} != expected_root:
        raise ValueError("identity bundle contains unexpected artifacts")
    evidence_dir = root / EVIDENCE_DIRECTORY
    if (
        evidence_dir.is_symlink()
        or not evidence_dir.is_dir()
        or (os.name == "posix" and evidence_dir.stat().st_mode & 0o077)
    ):
        raise ValueError("identity evidence directory is invalid")
    if {item.name for item in evidence_dir.iterdir()} != {EVALUATION_FILE}:
        raise ValueError("identity evidence set is incomplete or unexpected")
    report, report_raw = _load_evaluation(evidence_dir / EVALUATION_FILE, private=True)
    plan, run = report["plan"], report["run"]
    if (
        manifest["system"]["system_id"] != plan["system_id"]
        or manifest["plan"]
        != {"plan_id": plan["plan_id"], "plan_sha256": report["plan_sha256"]}
        or manifest["receiver"] != run["implementation"]
        or manifest["evidence"]["sha256"] != _sha256(report_raw)
        or manifest["evidence"]["run_sha256"] != report["run_sha256"]
        or manifest["summary"] != _summary_binding(report)
        or manifest["overall_status"] != report["summary"]["verdict"]
    ):
        raise ValueError("identity bundle bindings do not reconcile")
    if _time(manifest["created_at"]) < _time(report["generated_at"]):
        raise ValueError("identity bundle predates its evaluation")
    expected_statement = _checkpoint(manifest, manifest_raw)
    statement_raw = _read(root / STATEMENT_FILE, private=True)
    statement = _strict(statement_raw, STATEMENT_FILE)
    if statement != expected_statement or statement_raw != _canonical(expected_statement):
        raise ValueError("identity checkpoint does not independently recompute")
    key_ids = []
    if signed:
        if public_key_pem is None:
            raise ValueError("signed identity bundle requires its external public key")
        if manifest["authentication"]["signer_key_id"] != public_key_id(public_key_pem):
            raise ValueError("identity public key differs from its signer")
        envelope_raw = _read(root / DSSE_FILE, private=True)
        envelope = _strict(envelope_raw, DSSE_FILE)
        if envelope_raw != _canonical(envelope):
            raise ValueError("identity DSSE must use canonical JSON")
        key_ids.append(_verify_envelope(envelope, statement_raw, public_key_pem))
    elif public_key_pem is not None:
        raise ValueError("unsigned identity bundle does not accept a public key")
    return {
        "valid": True,
        "bundle_id": manifest["bundle_id"],
        "system_id": plan["system_id"],
        "environment": manifest["system"]["environment"],
        "plan_id": plan["plan_id"],
        "manifest_sha256": _sha256(manifest_raw),
        "statement_sha256": _sha256(statement_raw),
        "overall_status": manifest["overall_status"],
        "authenticated": signed,
        "key_ids": key_ids,
        "report": report,
        "interpretation_boundary": INTERPRETATION,
    }


def _oscal_uuid(kind: str, seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"lurescope:lureidentity:{kind}:{seed}"))


def _oscal_prop(name: str, value: Any) -> Dict[str, str]:
    rendered = str(value).lower() if isinstance(value, bool) else str(value)
    return {"name": name, "ns": "https://github.com/immu4989/lurescope/ns/oscal", "value": rendered}


def export_identity_oscal(
    bundle: Path,
    output: Path,
    *,
    assessment_plan_href: str,
    public_key_pem: Optional[bytes] = None,
) -> Dict[str, Any]:
    if not isinstance(assessment_plan_href, str) or not assessment_plan_href.startswith(
        ("https://", "urn:")
    ):
        raise ValueError("assessment_plan_href must be an operator-controlled https: or urn: URI")
    verified = verify_identity_bundle(bundle, public_key_pem=public_key_pem)
    report = verified["report"]
    seed = f"{verified['manifest_sha256']}:{verified['statement_sha256']}"
    observations = []
    for item in report["event_results"]:
        evidence_digest = _sha256(_canonical(item))
        observations.append(
            {
                "uuid": _oscal_uuid("observation", f"{seed}:{item['event_id']}"),
                "title": f"Identity lifecycle closure: {item['event_id']}",
                "description": (
                    "The declared graph cut was independently recomputed from typed identity "
                    "and authorization metadata."
                ),
                "props": [
                    _oscal_prop("event-id", item["event_id"]),
                    _oscal_prop("event-type", item["event_type"]),
                    _oscal_prop(
                        "affected-authorization-count", item["affected_authorization_count"]
                    ),
                ],
                "methods": ["TEST"],
                "types": ["control-objective"],
                "relevant-evidence": [
                    {
                        "href": f"urn:sha256:{evidence_digest}",
                        "description": "Digest of the typed lifecycle closure result.",
                    }
                ],
                "collected": report["generated_at"],
                "remarks": INTERPRETATION,
            }
        )
    document = {
        "$schema": "https://raw.githubusercontent.com/usnistgov/OSCAL/v1.2.2/json/schema/oscal_assessment-results_schema.json",
        "assessment-results": {
            "uuid": _oscal_uuid("document", seed),
            "metadata": {
                "title": f"LureIdentity Evidence — {verified['bundle_id']}",
                "last-modified": report["generated_at"],
                "version": "1.0.0",
                "oscal-version": "1.2.2",
                "props": [
                    _oscal_prop("plan-id", verified["plan_id"]),
                    _oscal_prop("overall-status", verified["overall_status"]),
                    _oscal_prop("manifest-sha256", verified["manifest_sha256"]),
                    _oscal_prop("authenticated", verified["authenticated"]),
                ],
                "remarks": INTERPRETATION,
            },
            "import-ap": {"href": assessment_plan_href},
            "results": [
                {
                    "uuid": _oscal_uuid("result", seed),
                    "title": "Identity lifecycle closure observations",
                    "description": (
                        "Observation-only results; no control-satisfaction determination is made."
                    ),
                    "start": report["run"]["generated_at"],
                    "end": report["generated_at"],
                    "props": [
                        _oscal_prop("overall-status", verified["overall_status"]),
                        _oscal_prop("observation-count", len(observations)),
                    ],
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "description": (
                                    "Controls for which identity lifecycle evidence may be "
                                    "relevant; inclusion is not a satisfaction determination."
                                ),
                                "include-controls": [
                                    {"control-id": control_id}
                                    for control_id in (
                                        "ac-2",
                                        "ac-3",
                                        "ac-6",
                                        "au-2",
                                        "ca-7",
                                        "ia-4",
                                        "ia-5",
                                    )
                                ],
                            }
                        ]
                    },
                    "observations": observations,
                    "remarks": INTERPRETATION,
                }
            ],
        },
    }
    _write_new(Path(output), _canonical(document))
    return document


def export_identity_sarif(
    bundle: Path, output: Path, *, public_key_pem: Optional[bytes] = None
) -> Dict[str, Any]:
    verified = verify_identity_bundle(bundle, public_key_pem=public_key_pem)
    report = verified["report"]
    rules = [
        ("LURE-IDENTITY-001", "Lifecycle event deadline missed"),
        ("LURE-IDENTITY-002", "Stale authorization remained usable"),
        ("LURE-IDENTITY-003", "Preserved authorization was denied"),
        ("LURE-IDENTITY-004", "Lifecycle event disposition mismatch"),
        ("LURE-IDENTITY-005", "Lifecycle decision or reason mismatch"),
    ]
    results = []
    for item in report["delivery_results"]:
        if not item["deadline_met"]:
            results.append(
                {
                    "ruleId": "LURE-IDENTITY-001",
                    "level": "error",
                    "message": {
                        "text": (
                            f"Lifecycle event {item['event_id']} missed its deadline at node "
                            f"{item['node_id']}."
                        )
                    },
                    "fingerprints": {"deliverySha256": _sha256(_canonical(item))},
                    "properties": {
                        "eventId": item["event_id"],
                        "nodeId": item["node_id"],
                        "convergenceMs": item["convergence_ms"],
                    },
                }
            )
    for item in report["probe_results"]:
        rule_id = (
            "LURE-IDENTITY-002"
            if item["classification"] == "stale_authorization"
            else "LURE-IDENTITY-003"
            if item["classification"] == "collateral_denial"
            else "LURE-IDENTITY-005"
            if item["classification"] != "correct"
            else None
        )
        if rule_id:
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error" if rule_id != "LURE-IDENTITY-003" else "warning",
                    "message": {
                        "text": (
                            f"{item['classification']} for probe {item['probe_id']} at node "
                            f"{item['node_id']}."
                        )
                    },
                    "fingerprints": {"probeSha256": _sha256(_canonical(item))},
                    "properties": {
                        "probeId": item["probe_id"],
                        "eventId": item["event_id"],
                        "nodeId": item["node_id"],
                        "actorId": item["actor_id"],
                    },
                }
            )
    if report["summary"]["signal_disposition_accuracy"] < 1.0:
        results.append(
            {
                "ruleId": "LURE-IDENTITY-004",
                "level": "error",
                "message": {
                    "text": "One or more lifecycle event dispositions did not recompute."
                },
                "fingerprints": {"runSha256": report["run_sha256"]},
                "properties": {
                    "signalDispositionAccuracy": report["summary"][
                        "signal_disposition_accuracy"
                    ]
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LureScope LureIdentity Evidence",
                        "version": __version__,
                        "informationUri": (
                            "https://github.com/immu4989/lurescope/blob/main/"
                            "docs/LUREIDENTITY_EVIDENCE.md"
                        ),
                        "rules": [
                            {
                                "id": rule_id,
                                "name": title.replace(" ", ""),
                                "shortDescription": {"text": title},
                                "fullDescription": {"text": f"{title}. {INTERPRETATION}"},
                            }
                            for rule_id, title in rules
                        ],
                    }
                },
                "results": results,
                "properties": {
                    "bundleId": verified["bundle_id"],
                    "overallStatus": verified["overall_status"],
                    "interpretationBoundary": INTERPRETATION,
                },
            }
        ],
    }
    _write_new(Path(output), _canonical(document))
    return document
