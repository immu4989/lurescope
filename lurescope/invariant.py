"""Tamper-evident LureInvariant evidence and remediation comparison.

LureScope independently recomputes LureBench graph and temporal results from
the exact plan and observation bytes it preserves.  The workflow is evidence
only: it does not discover infrastructure, execute probes, or apply a fix.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from . import __version__
from .boundary import (
    _private_key,
    _private_key_id,
    _sign_statement,
    _verify_envelope,
    public_key_id,
)

PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/agent-invariant-plan/v1"
OBSERVATIONS_SCHEMA = "https://github.com/immu4989/lurebench/spec/agent-invariant-observations/v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/agent-invariant-evaluation/v1"
BUNDLE_SCHEMA = "https://github.com/immu4989/lurescope/spec/invariant-evidence-bundle/v1"
COMPARISON_SCHEMA = "https://github.com/immu4989/lurescope/spec/invariant-remediation-comparison/v1"
CHECKPOINT_PREDICATE = "https://github.com/immu4989/lurescope/spec/invariant-evidence-checkpoint/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

MANIFEST_FILE = "bundle.json"
EVIDENCE_DIRECTORY = "evidence"
PLAN_FILE = "plan.json"
OBSERVATIONS_FILE = "observations.json"
EVALUATION_FILE = "evaluation.json"
STATEMENT_FILE = "checkpoint.statement.json"
DSSE_FILE = "checkpoint.dsse.json"
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024

_ID = re.compile(r"^[a-z0-9]+(?:[a-z0-9._-]*[a-z0-9])?$")
_PORTABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,199}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_SOURCE_TYPES = {
    "a2a_agent_card",
    "identity_policy",
    "kubernetes_manifest",
    "mcp_configuration",
    "network_policy",
    "operator_attestation",
    "runtime_telemetry",
    "synthetic_fixture",
    "terraform_plan",
}
_NODE_TYPES = {
    "agent",
    "control_plane",
    "data_store",
    "human",
    "identity_provider",
    "network_zone",
    "sensor",
    "service",
    "tool",
    "workload",
}
_SENSITIVITY = {"public", "internal", "confidential", "restricted", "control"}
_CAPABILITIES = {
    "approve",
    "call",
    "cancel",
    "control",
    "delegate",
    "mint",
    "modify_boundary",
    "observe",
    "persist",
    "reach",
    "read",
    "revoke",
    "write",
}
_CHANNEL_TYPES = {"control", "delegation", "identity", "network", "storage", "telemetry", "tool"}
_EDGE_STATES = {"active", "inactive", "unknown"}
_INVARIANT_TYPES = {
    "bounded_response",
    "forbidden_reachability",
    "no_post_trigger_activity",
    "required_mediation",
}
_EVENT_TYPES = {
    "alert_raised",
    "all_children_stopped",
    "boundary_modified",
    "credential_revoked",
    "credential_use_succeeded",
    "network_request_succeeded",
    "run_restarted",
    "sensor_observed",
    "stop_requested",
    "task_activity",
    "tool_call_succeeded",
}
_OUTCOMES = {"blocked", "failed", "observed", "succeeded"}
_SEVERITIES = {"high", "critical"}
_STATUSES = {"violated", "not_observed_within_declared_boundary", "insufficient_evidence"}

PLAN_LIMITATIONS = [
    "declared_inventory_and_operator_observations_only",
    "graph_paths_are_bounded_to_declared_nodes_edges_capabilities_and_sources",
    "typed_metadata_only_no_targets_payloads_credentials_commands_prompts_or_reasoning",
    "not_observed_is_not_proof_of_universal_unreachability_or_security",
    "results_are_measurement_evidence_not_enforcement_compliance_certification_or_authorization",
]
OBSERVATION_LIMITATIONS = [
    "observations_are_operator_supplied_typed_metadata",
    "no_live_actions_are_executed_by_lurebench",
    "event_completeness_depends_on_declared_sources_and_capture_process",
    "results_do_not_authenticate_source_organizations",
]
REPORT_LIMITATIONS = [
    "semantic_results_recomputed_from_exact_plan_and_observation_bytes",
    "incomplete_sources_or_relevant_unknown_edges_produce_insufficient_evidence",
    "paths_contain_only_synthetic_identifiers_and_are_not_exploit_instructions",
    "passing_does_not_prove_complete_mediation_containment_safety_compliance_or_authorization",
]
BUNDLE_LIMITATIONS = [
    "source_semantics_are_recomputed_but_source_collection_is_not_replayed",
    "signed_evidence_authenticates_a_key_not_an_organization_without_external_trust",
    "bundle_integrity_does_not_establish_inventory_or_telemetry_completeness",
    "passing_is_not_proof_of_containment_safety_compliance_certification_or_authorization",
]
COMPARISON_LIMITATIONS = [
    "comparison_requires_identical_invariants_acceptance_and_source_contracts",
    "effective_means_the_before_violations_are_absent_in_complete_after_evidence",
    "configuration_change_causality_and_unobserved_attack_paths_are_not_proven",
    "comparison_is_not_enforcement_compliance_certification_or_authorization",
]
_INTERPRETATION = (
    "This bundle proves the internal consistency and exact byte bindings of declared graph and "
    "temporal evidence. A pass means violations were not observed within the declared, complete "
    "evidence boundary; it is not proof of universal unreachability, containment, or safety."
)
_COMPARISON_INTERPRETATION = (
    "An effective comparison means the same invariant and evidence-source contracts changed from "
    "one or more observed violations to a complete passing after-evaluation. It does not prove "
    "causality, eliminate undeclared paths, apply a change, or authorize deployment."
)


def _timestamp_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        + "\n"
    ).encode("utf-8")


def _strict(payload: bytes, label: str) -> Any:
    def no_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    def no_constants(value: str) -> None:
        raise ValueError(f"{label} contains non-standard JSON constant {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=no_constants,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc


def _read(path: Path, *, private: bool = False) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError(f"{target} must be a regular local file")
    if target.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"{target.name} exceeds the 4 MiB limit")
    if private and os.name == "posix" and target.stat().st_mode & 0o077:
        raise ValueError(f"{target.name} must not grant group or world access")
    return target.read_bytes()


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _exact(value: Any, field: str, keys: Sequence[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{field} violates its field allowlist")
    return value


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 96 or _ID.fullmatch(value) is None:
        raise ValueError(f"{field} must be a bounded lowercase identifier")
    return value


def _portable_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _PORTABLE_ID.fullmatch(value) is None:
        raise ValueError(f"{field} must be a portable identifier")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed


def _unique_ids(values: Any, field: str, maximum: int) -> list[str]:
    if not isinstance(values, list) or len(values) > maximum:
        raise ValueError(f"{field} must be a bounded array")
    normalized = [_id(value, f"{field}[{index}]") for index, value in enumerate(values)]
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field} contains duplicate identifiers")
    return normalized


def _validate_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "plan",
        (
            "schema",
            "schema_version",
            "plan_id",
            "plan_version",
            "system_id",
            "created_at",
            "sources",
            "nodes",
            "edges",
            "invariants",
            "acceptance",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported invariant plan schema")
    _id(plan["plan_id"], "plan.plan_id")
    _id(plan["plan_version"], "plan.plan_version")
    _id(plan["system_id"], "plan.system_id")
    _timestamp(plan["created_at"], "plan.created_at")
    sources = plan["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 128:
        raise ValueError("plan sources must be a non-empty bounded array")
    source_ids = set()
    required = 0
    for index, source in enumerate(sources):
        field = f"plan.sources[{index}]"
        source = _exact(source, field, ("source_id", "source_type", "artifact_sha256", "required"))
        source_id = _id(source["source_id"], f"{field}.source_id")
        if source_id in source_ids:
            raise ValueError("plan contains duplicate source identifiers")
        source_ids.add(source_id)
        if source["source_type"] not in _SOURCE_TYPES:
            raise ValueError(f"{field}.source_type is unsupported")
        _digest(source["artifact_sha256"], f"{field}.artifact_sha256")
        if not isinstance(source["required"], bool):
            raise ValueError(f"{field}.required must be boolean")
        required += source["required"]
    if not required:
        raise ValueError("plan requires at least one evidence source")
    nodes = plan["nodes"]
    if not isinstance(nodes, list) or not 2 <= len(nodes) <= 4096:
        raise ValueError("plan nodes are invalid")
    node_ids = set()
    for index, node in enumerate(nodes):
        field = f"plan.nodes[{index}]"
        node = _exact(
            node, field, ("node_id", "node_type", "trust_zone", "tenant_id", "sensitivity")
        )
        node_id = _id(node["node_id"], f"{field}.node_id")
        if node_id in node_ids:
            raise ValueError("plan contains duplicate node identifiers")
        node_ids.add(node_id)
        if node["node_type"] not in _NODE_TYPES or node["sensitivity"] not in _SENSITIVITY:
            raise ValueError(f"{field} contains an unsupported node value")
        _id(node["trust_zone"], f"{field}.trust_zone")
        if node["tenant_id"] is not None:
            _id(node["tenant_id"], f"{field}.tenant_id")
    edges = plan["edges"]
    if not isinstance(edges, list) or not 1 <= len(edges) <= 16384:
        raise ValueError("plan edges are invalid")
    edge_ids = set()
    typed_edges = set()
    for index, edge in enumerate(edges):
        field = f"plan.edges[{index}]"
        edge = _exact(
            edge,
            field,
            (
                "edge_id",
                "source_node_id",
                "target_node_id",
                "capability",
                "channel_type",
                "state",
                "evidence_source_id",
            ),
        )
        edge_id = _id(edge["edge_id"], f"{field}.edge_id")
        if edge_id in edge_ids:
            raise ValueError("plan contains duplicate edge identifiers")
        edge_ids.add(edge_id)
        if (
            edge["source_node_id"] not in node_ids
            or edge["target_node_id"] not in node_ids
            or edge["source_node_id"] == edge["target_node_id"]
        ):
            raise ValueError(f"{field} references invalid nodes")
        if (
            edge["capability"] not in _CAPABILITIES
            or edge["channel_type"] not in _CHANNEL_TYPES
            or edge["state"] not in _EDGE_STATES
        ):
            raise ValueError(f"{field} contains an unsupported edge value")
        if edge["evidence_source_id"] not in source_ids:
            raise ValueError(f"{field} references an undeclared source")
        identity = (
            edge["source_node_id"],
            edge["target_node_id"],
            edge["capability"],
            edge["channel_type"],
        )
        if identity in typed_edges:
            raise ValueError("plan contains a duplicate typed edge")
        typed_edges.add(identity)
    invariants = plan["invariants"]
    if not isinstance(invariants, list) or not 1 <= len(invariants) <= 256:
        raise ValueError("plan invariants are invalid")
    invariant_ids = set()
    for index, invariant in enumerate(invariants):
        field = f"plan.invariants[{index}]"
        invariant = _exact(
            invariant,
            field,
            (
                "invariant_id",
                "invariant_type",
                "title",
                "severity",
                "subject_node_ids",
                "target_node_ids",
                "traversable_capabilities",
                "mediation_node_ids",
                "trigger_event_type",
                "response_event_type",
                "prohibited_event_types",
                "maximum_delay_ms",
            ),
        )
        invariant_id = _id(invariant["invariant_id"], f"{field}.invariant_id")
        if invariant_id in invariant_ids:
            raise ValueError("plan contains duplicate invariant identifiers")
        invariant_ids.add(invariant_id)
        kind = invariant["invariant_type"]
        if kind not in _INVARIANT_TYPES or invariant["severity"] not in _SEVERITIES:
            raise ValueError(f"{field} contains an unsupported invariant value")
        if not isinstance(invariant["title"], str) or not 8 <= len(invariant["title"]) <= 160:
            raise ValueError(f"{field}.title is invalid")
        subjects = _unique_ids(invariant["subject_node_ids"], f"{field}.subject_node_ids", 64)
        targets = _unique_ids(invariant["target_node_ids"], f"{field}.target_node_ids", 64)
        mediation = _unique_ids(invariant["mediation_node_ids"], f"{field}.mediation_node_ids", 64)
        if any(item not in node_ids for item in subjects + targets + mediation):
            raise ValueError(f"{field} references an undeclared node")
        capabilities = invariant["traversable_capabilities"]
        prohibited = invariant["prohibited_event_types"]
        if (
            not isinstance(capabilities, list)
            or len(set(capabilities)) != len(capabilities)
            or any(item not in _CAPABILITIES for item in capabilities)
        ):
            raise ValueError(f"{field}.traversable_capabilities is invalid")
        if (
            not isinstance(prohibited, list)
            or len(set(prohibited)) != len(prohibited)
            or any(item not in _EVENT_TYPES for item in prohibited)
        ):
            raise ValueError(f"{field}.prohibited_event_types is invalid")
        trigger = invariant["trigger_event_type"]
        response = invariant["response_event_type"]
        maximum = invariant["maximum_delay_ms"]
        if kind in {"forbidden_reachability", "required_mediation"}:
            if (
                not subjects
                or not targets
                or not capabilities
                or trigger is not None
                or response is not None
                or prohibited
                or maximum is not None
            ):
                raise ValueError(f"{field} graph fields are invalid")
            if (kind == "required_mediation") != bool(mediation):
                raise ValueError(f"{field} mediation fields are invalid")
            if kind == "required_mediation" and set(mediation) & (set(subjects) | set(targets)):
                raise ValueError(f"{field} mediation nodes overlap subjects or targets")
        elif kind == "bounded_response":
            if (
                subjects
                or targets
                or capabilities
                or mediation
                or trigger not in _EVENT_TYPES
                or response not in _EVENT_TYPES
                or prohibited
            ):
                raise ValueError(f"{field} bounded response fields are invalid")
            _integer(maximum, f"{field}.maximum_delay_ms", 1, 86_400_000)
        else:
            if (
                subjects
                or targets
                or capabilities
                or mediation
                or trigger not in _EVENT_TYPES
                or response is not None
                or not prohibited
            ):
                raise ValueError(f"{field} no-post-trigger fields are invalid")
            _integer(maximum, f"{field}.maximum_delay_ms", 0, 86_400_000)
    acceptance = _exact(
        plan["acceptance"], "plan.acceptance", ("maximum_violations", "allow_insufficient_evidence")
    )
    if acceptance["maximum_violations"] != 0:
        raise ValueError("invariant v1 requires zero accepted violations")
    if acceptance["allow_insufficient_evidence"] is not False:
        raise ValueError("invariant v1 never accepts insufficient evidence")
    if plan["limitations"] != PLAN_LIMITATIONS:
        raise ValueError("plan limitations are invalid")
    return dict(plan)


def _validate_observations(value: Any, plan: Mapping[str, Any], plan_sha: str) -> Dict[str, Any]:
    observations = _exact(
        value,
        "observations",
        (
            "schema",
            "schema_version",
            "captured_at",
            "plan_sha256",
            "source_status",
            "events",
            "limitations",
        ),
    )
    if observations["schema"] != OBSERVATIONS_SCHEMA or observations["schema_version"] != 1:
        raise ValueError("unsupported invariant observations schema")
    if _timestamp(observations["captured_at"], "observations.captured_at") < _timestamp(
        plan["created_at"], "plan.created_at"
    ):
        raise ValueError("observations cannot predate the invariant plan")
    if observations["plan_sha256"] != plan_sha:
        raise ValueError("observations do not bind the exact plan bytes")
    sources = {source["source_id"]: source for source in plan["sources"]}
    statuses = observations["source_status"]
    if not isinstance(statuses, list) or len(statuses) != len(sources):
        raise ValueError("observations must contain one status per source")
    seen = set()
    for index, status in enumerate(statuses):
        field = f"observations.source_status[{index}]"
        status = _exact(status, field, ("source_id", "artifact_sha256", "complete"))
        source_id = _id(status["source_id"], f"{field}.source_id")
        if source_id in seen or source_id not in sources:
            raise ValueError("source status is duplicate or undeclared")
        seen.add(source_id)
        if status["artifact_sha256"] != sources[source_id]["artifact_sha256"] or not isinstance(
            status["complete"], bool
        ):
            raise ValueError(f"{field} does not match the source contract")
    if [item["source_id"] for item in statuses] != [item["source_id"] for item in plan["sources"]]:
        raise ValueError("source status order differs from the plan")
    node_ids = {node["node_id"] for node in plan["nodes"]}
    events = observations["events"]
    if not isinstance(events, list) or len(events) > 65536:
        raise ValueError("observation events are invalid")
    event_ids = set()
    prior: Optional[tuple[int, str]] = None
    for index, event in enumerate(events):
        field = f"observations.events[{index}]"
        event = _exact(
            event,
            field,
            (
                "event_id",
                "occurred_ms",
                "event_type",
                "run_id",
                "actor_node_id",
                "target_node_id",
                "outcome",
                "evidence_source_id",
            ),
        )
        event_id = _id(event["event_id"], f"{field}.event_id")
        if event_id in event_ids:
            raise ValueError("observations contain duplicate event identifiers")
        event_ids.add(event_id)
        occurred = _integer(event["occurred_ms"], f"{field}.occurred_ms", 0, 2**53 - 1)
        order = (occurred, event_id)
        if prior is not None and order <= prior:
            raise ValueError("events are not strictly time ordered")
        prior = order
        if event["event_type"] not in _EVENT_TYPES or event["outcome"] not in _OUTCOMES:
            raise ValueError(f"{field} contains an unsupported event value")
        if event["event_type"].endswith("_succeeded") and event["outcome"] != "succeeded":
            raise ValueError(f"{field} succeeded event type requires a succeeded outcome")
        _id(event["run_id"], f"{field}.run_id")
        if event["actor_node_id"] not in node_ids or (
            event["target_node_id"] is not None and event["target_node_id"] not in node_ids
        ):
            raise ValueError(f"{field} references an undeclared node")
        if event["evidence_source_id"] not in sources:
            raise ValueError(f"{field} references an undeclared source")
    if observations["limitations"] != OBSERVATION_LIMITATIONS:
        raise ValueError("observation limitations are invalid")
    return dict(observations)


def _path(
    plan: Mapping[str, Any], invariant: Mapping[str, Any], include_unknown: bool
) -> Optional[tuple[list[str], list[str]]]:
    targets = set(invariant["target_node_ids"])
    capabilities = set(invariant["traversable_capabilities"])
    excluded = (
        set(invariant["mediation_node_ids"])
        if invariant["invariant_type"] == "required_mediation"
        else set()
    )
    adjacency: dict[str, list[Mapping[str, Any]]] = {}
    for edge in plan["edges"]:
        if (
            edge["capability"] not in capabilities
            or edge["state"] == "inactive"
            or (edge["state"] == "unknown" and not include_unknown)
        ):
            continue
        if edge["source_node_id"] in excluded or edge["target_node_id"] in excluded:
            continue
        adjacency.setdefault(edge["source_node_id"], []).append(edge)
    for edges in adjacency.values():
        edges.sort(key=lambda item: (item["target_node_id"], item["edge_id"]))
    queue = deque()
    visited = set()
    for subject in sorted(set(invariant["subject_node_ids"]) - excluded):
        queue.append((subject, [subject], []))
        visited.add(subject)
    while queue:
        node, nodes, edges = queue.popleft()
        if node in targets:
            return nodes, edges
        for edge in adjacency.get(node, []):
            target = edge["target_node_id"]
            if target not in visited:
                visited.add(target)
                queue.append((target, [*nodes, target], [*edges, edge["edge_id"]]))
    return None


def _result(
    plan: Mapping[str, Any],
    observations: Mapping[str, Any],
    invariant: Mapping[str, Any],
    complete: bool,
) -> Dict[str, Any]:
    base = {
        "invariant_id": invariant["invariant_id"],
        "invariant_type": invariant["invariant_type"],
        "severity": invariant["severity"],
        "status": "not_observed_within_declared_boundary",
        "reason_code": "temporal_violation_not_observed",
        "path_node_ids": [],
        "path_edge_ids": [],
        "trigger_event_ids": [],
        "response_event_ids": [],
        "observed_delay_ms": None,
    }
    kind = invariant["invariant_type"]
    if kind in {"forbidden_reachability", "required_mediation"}:
        active = _path(plan, invariant, False)
        possible = active or _path(plan, invariant, True)
        if active:
            base["status"] = "violated"
            base["reason_code"] = (
                "forbidden_path_observed"
                if kind == "forbidden_reachability"
                else "unmediated_path_observed"
            )
            base["path_node_ids"], base["path_edge_ids"] = active
        elif possible or not complete:
            base["status"] = "insufficient_evidence"
            base["reason_code"] = (
                "relevant_path_state_unknown" if possible else "required_source_incomplete"
            )
            if possible:
                base["path_node_ids"], base["path_edge_ids"] = possible
        else:
            base["reason_code"] = (
                "forbidden_path_not_observed"
                if kind == "forbidden_reachability"
                else "unmediated_path_not_observed"
            )
        return base
    events = observations["events"]
    triggers = [event for event in events if event["event_type"] == invariant["trigger_event_type"]]
    base["trigger_event_ids"] = [event["event_id"] for event in triggers]
    if not triggers:
        base["status"] = "insufficient_evidence"
        base["reason_code"] = "trigger_not_observed"
        return base
    if kind == "bounded_response":
        responses = []
        worst = -1
        violation = False
        for trigger in triggers:
            candidates = [
                event
                for event in events
                if event["run_id"] == trigger["run_id"]
                and event["event_type"] == invariant["response_event_type"]
                and event["occurred_ms"] >= trigger["occurred_ms"]
                and event["outcome"] in {"observed", "succeeded"}
            ]
            response = candidates[0] if candidates else None
            if response is None:
                violation = True
                continue
            responses.append(response["event_id"])
            delay = response["occurred_ms"] - trigger["occurred_ms"]
            worst = max(worst, delay)
            violation = violation or delay > invariant["maximum_delay_ms"]
        base["response_event_ids"] = responses
        base["observed_delay_ms"] = worst if worst >= 0 else None
        if violation:
            base["status"] = "violated"
            base["reason_code"] = "response_missing_or_late"
        elif not complete:
            base["status"] = "insufficient_evidence"
            base["reason_code"] = "required_source_incomplete"
        else:
            base["reason_code"] = "response_within_bound"
        return base
    prohibited = set(invariant["prohibited_event_types"])
    offending = sorted(
        {
            event["event_id"]
            for trigger in triggers
            for event in events
            if event["run_id"] == trigger["run_id"]
            and event["event_type"] in prohibited
            and event["occurred_ms"] > trigger["occurred_ms"] + invariant["maximum_delay_ms"]
        }
    )
    base["response_event_ids"] = offending
    if offending:
        base["status"] = "violated"
        base["reason_code"] = "prohibited_post_trigger_activity_observed"
    elif not complete:
        base["status"] = "insufficient_evidence"
        base["reason_code"] = "required_source_incomplete"
    else:
        base["reason_code"] = "post_trigger_activity_not_observed"
    return base


def _derive(
    plan: Mapping[str, Any],
    plan_raw: bytes,
    observations: Mapping[str, Any],
    observations_raw: bytes,
    generated_at: str,
) -> Dict[str, Any]:
    if _timestamp(generated_at, "evaluation.generated_at") < _timestamp(
        observations["captured_at"], "observations.captured_at"
    ):
        raise ValueError("evaluation cannot predate its observations")
    required = [source for source in plan["sources"] if source["required"]]
    status = {item["source_id"]: item for item in observations["source_status"]}
    complete_count = sum(status[source["source_id"]]["complete"] for source in required)
    complete = complete_count == len(required)
    results = [_result(plan, observations, invariant, complete) for invariant in plan["invariants"]]
    violated = sum(result["status"] == "violated" for result in results)
    not_observed = sum(
        result["status"] == "not_observed_within_declared_boundary" for result in results
    )
    insufficient = sum(result["status"] == "insufficient_evidence" for result in results)
    if violated > plan["acceptance"]["maximum_violations"]:
        verdict = "fail"
    elif insufficient:
        verdict = "insufficient_evidence"
    else:
        verdict = "pass"
    return {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "plan": {
            "plan_id": plan["plan_id"],
            "plan_version": plan["plan_version"],
            "system_id": plan["system_id"],
            "plan_sha256": _sha256(plan_raw),
        },
        "observations": {
            "captured_at": observations["captured_at"],
            "observations_sha256": _sha256(observations_raw),
        },
        "acceptance": dict(plan["acceptance"]),
        "results": results,
        "summary": {
            "total_invariants": len(results),
            "violated": violated,
            "not_observed_within_declared_boundary": not_observed,
            "insufficient_evidence": insufficient,
            "required_sources": len(required),
            "complete_required_sources": complete_count,
            "source_coverage": round(complete_count / len(required), 6),
            "unknown_edges": sum(edge["state"] == "unknown" for edge in plan["edges"]),
            "verdict": verdict,
        },
        "limitations": list(REPORT_LIMITATIONS),
    }


def _load_source_evidence(
    plan_path: Path, observations_path: Path, evaluation_path: Path, *, private: bool = False
) -> tuple[Dict[str, Any], bytes, Dict[str, Any], bytes, Dict[str, Any], bytes]:
    plan_raw = _read(plan_path, private=private)
    plan = _validate_plan(_strict(plan_raw, "invariant plan"))
    observations_raw = _read(observations_path, private=private)
    observations = _validate_observations(
        _strict(observations_raw, "invariant observations"), plan, _sha256(plan_raw)
    )
    evaluation_raw = _read(evaluation_path, private=private)
    evaluation = _strict(evaluation_raw, "invariant evaluation")
    _timestamp(
        evaluation.get("generated_at") if isinstance(evaluation, dict) else None,
        "evaluation.generated_at",
    )
    expected = _derive(plan, plan_raw, observations, observations_raw, evaluation["generated_at"])
    if evaluation != expected:
        raise ValueError("invariant evaluation does not independently recompute")
    return plan, plan_raw, observations, observations_raw, evaluation, evaluation_raw


def _validate_manifest(value: Any) -> Dict[str, Any]:
    manifest = _exact(
        value,
        "bundle",
        (
            "schema",
            "schema_version",
            "bundle_id",
            "created_at",
            "producer",
            "system",
            "evidence",
            "overall_status",
            "authentication",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if manifest["schema"] != BUNDLE_SCHEMA or manifest["schema_version"] != 1:
        raise ValueError("unsupported invariant bundle schema")
    _portable_id(manifest["bundle_id"], "bundle.bundle_id")
    _timestamp(manifest["created_at"], "bundle.created_at")
    producer = _exact(manifest["producer"], "bundle.producer", ("name", "version"))
    if producer["name"] != "lurescope" or not isinstance(producer["version"], str):
        raise ValueError("bundle producer is invalid")
    system = _exact(manifest["system"], "bundle.system", ("system_id", "environment"))
    _id(system["system_id"], "bundle.system.system_id")
    if system["environment"] not in {"development", "evaluation", "staging", "production"}:
        raise ValueError("bundle environment is invalid")
    evidence = manifest["evidence"]
    if not isinstance(evidence, list) or len(evidence) != 3:
        raise ValueError("bundle must bind exactly three evidence artifacts")
    expected = {
        "plan": (f"{EVIDENCE_DIRECTORY}/{PLAN_FILE}", PLAN_SCHEMA),
        "observations": (f"{EVIDENCE_DIRECTORY}/{OBSERVATIONS_FILE}", OBSERVATIONS_SCHEMA),
        "evaluation": (f"{EVIDENCE_DIRECTORY}/{EVALUATION_FILE}", EVALUATION_SCHEMA),
    }
    seen = set()
    for index, item in enumerate(evidence):
        item = _exact(
            item, f"bundle.evidence[{index}]", ("kind", "file", "schema", "sha256", "verdict")
        )
        if item["kind"] in seen or item["kind"] not in expected:
            raise ValueError("bundle evidence kind is invalid")
        seen.add(item["kind"])
        file_name, schema = expected[item["kind"]]
        if item["file"] != file_name or item["schema"] != schema:
            raise ValueError("bundle evidence contract is invalid")
        _digest(item["sha256"], "bundle.evidence.sha256")
        allowed_verdicts = (
            {"not_applicable"}
            if item["kind"] != "evaluation"
            else {"pass", "fail", "insufficient_evidence"}
        )
        if item["verdict"] not in allowed_verdicts:
            raise ValueError("bundle evidence verdict is invalid")
    if manifest["overall_status"] not in {"pass", "fail", "insufficient_evidence"}:
        raise ValueError("bundle overall status is invalid")
    authentication = _exact(
        manifest["authentication"], "bundle.authentication", ("mode", "signer_key_id")
    )
    if authentication["mode"] not in {"unsigned", "ecdsa-p256-dsse"}:
        raise ValueError("bundle authentication mode is invalid")
    if authentication["mode"] == "unsigned":
        if authentication["signer_key_id"] is not None:
            raise ValueError("unsigned bundle cannot declare a signer")
    else:
        _digest(authentication["signer_key_id"], "bundle.authentication.signer_key_id")
    if (
        manifest["limitations"] != BUNDLE_LIMITATIONS
        or manifest["interpretation_boundary"] != _INTERPRETATION
    ):
        raise ValueError("bundle claims boundary is invalid")
    return dict(manifest)


def create_invariant_bundle(
    output: Path,
    *,
    bundle_id: str,
    environment: str,
    plan: Path,
    observations: Path,
    evaluation: Path,
    signer_public_key_pem: Optional[bytes] = None,
    signing_key_pem: Optional[bytes] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    target = Path(output)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"{target} already exists")
    _portable_id(bundle_id, "bundle_id")
    if environment not in {"development", "evaluation", "staging", "production"}:
        raise ValueError("environment is unsupported")
    if (signer_public_key_pem is None) != (signing_key_pem is None):
        raise ValueError("bundle signing requires matching public and private keys")
    key = None
    signer_id = None
    if signing_key_pem is not None and signer_public_key_pem is not None:
        key = _private_key(signing_key_pem)
        signer_id = public_key_id(signer_public_key_pem)
        if not secrets.compare_digest(_private_key_id(key), signer_id):
            raise ValueError("bundle signing key does not match the public key")
    source = _load_source_evidence(plan, observations, evaluation)
    plan_value, plan_raw, _, observations_raw, evaluation_value, evaluation_raw = source
    evidence = [
        {
            "kind": "plan",
            "file": f"{EVIDENCE_DIRECTORY}/{PLAN_FILE}",
            "schema": PLAN_SCHEMA,
            "sha256": _sha256(plan_raw),
            "verdict": "not_applicable",
        },
        {
            "kind": "observations",
            "file": f"{EVIDENCE_DIRECTORY}/{OBSERVATIONS_FILE}",
            "schema": OBSERVATIONS_SCHEMA,
            "sha256": _sha256(observations_raw),
            "verdict": "not_applicable",
        },
        {
            "kind": "evaluation",
            "file": f"{EVIDENCE_DIRECTORY}/{EVALUATION_FILE}",
            "schema": EVALUATION_SCHEMA,
            "sha256": _sha256(evaluation_raw),
            "verdict": evaluation_value["summary"]["verdict"],
        },
    ]
    manifest = _validate_manifest(
        {
            "schema": BUNDLE_SCHEMA,
            "schema_version": 1,
            "bundle_id": bundle_id,
            "created_at": created_at or _timestamp_now(),
            "producer": {"name": "lurescope", "version": __version__},
            "system": {"system_id": plan_value["system_id"], "environment": environment},
            "evidence": evidence,
            "overall_status": evaluation_value["summary"]["verdict"],
            "authentication": {
                "mode": "unsigned" if signer_id is None else "ecdsa-p256-dsse",
                "signer_key_id": signer_id,
            },
            "limitations": list(BUNDLE_LIMITATIONS),
            "interpretation_boundary": _INTERPRETATION,
        }
    )
    manifest_raw = _canonical(manifest)
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": MANIFEST_FILE, "digest": {"sha256": _sha256(manifest_raw)}},
            *[{"name": item["file"], "digest": {"sha256": item["sha256"]}} for item in evidence],
        ],
        "predicateType": CHECKPOINT_PREDICATE,
        "predicate": {
            "bundle_id": bundle_id,
            "created_at": manifest["created_at"],
            "system_id": plan_value["system_id"],
            "overall_status": manifest["overall_status"],
            "authentication_mode": manifest["authentication"]["mode"],
            "limitations": list(BUNDLE_LIMITATIONS),
            "interpretation_boundary": _INTERPRETATION,
        },
    }
    statement_raw = _canonical(statement)
    target.mkdir(mode=0o700)
    evidence_dir = target / EVIDENCE_DIRECTORY
    try:
        evidence_dir.mkdir(mode=0o700)
        _write_new(target / MANIFEST_FILE, manifest_raw)
        _write_new(evidence_dir / PLAN_FILE, plan_raw)
        _write_new(evidence_dir / OBSERVATIONS_FILE, observations_raw)
        _write_new(evidence_dir / EVALUATION_FILE, evaluation_raw)
        _write_new(target / STATEMENT_FILE, statement_raw)
        if key is not None:
            _write_new(target / DSSE_FILE, _canonical(_sign_statement(statement_raw, key)))
        verify_invariant_bundle(target, public_key_pem=signer_public_key_pem)
    except Exception:
        for item in sorted(target.rglob("*"), key=lambda path: len(path.parts), reverse=True):
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                item.rmdir()
        target.rmdir()
        raise
    return manifest


def verify_invariant_bundle(
    bundle: Path, *, public_key_pem: Optional[bytes] = None
) -> Dict[str, Any]:
    root = Path(bundle)
    if (
        root.is_symlink()
        or not root.is_dir()
        or (os.name == "posix" and root.stat().st_mode & 0o077)
    ):
        raise ValueError("invariant bundle must be a private regular directory")
    manifest_raw = _read(root / MANIFEST_FILE, private=True)
    manifest = _validate_manifest(_strict(manifest_raw, MANIFEST_FILE))
    if manifest_raw != _canonical(manifest):
        raise ValueError("bundle manifest must use canonical JSON")
    signed = manifest["authentication"]["mode"] == "ecdsa-p256-dsse"
    expected_root = {MANIFEST_FILE, EVIDENCE_DIRECTORY, STATEMENT_FILE} | (
        {DSSE_FILE} if signed else set()
    )
    if {item.name for item in root.iterdir()} != expected_root:
        raise ValueError("bundle contains unexpected artifacts")
    evidence_dir = root / EVIDENCE_DIRECTORY
    if (
        evidence_dir.is_symlink()
        or not evidence_dir.is_dir()
        or (os.name == "posix" and evidence_dir.stat().st_mode & 0o077)
    ):
        raise ValueError("bundle evidence directory is invalid")
    if {item.name for item in evidence_dir.iterdir()} != {
        PLAN_FILE,
        OBSERVATIONS_FILE,
        EVALUATION_FILE,
    }:
        raise ValueError("bundle evidence set is incomplete or unexpected")
    source = _load_source_evidence(
        evidence_dir / PLAN_FILE,
        evidence_dir / OBSERVATIONS_FILE,
        evidence_dir / EVALUATION_FILE,
        private=True,
    )
    plan, plan_raw, _, observations_raw, evaluation, evaluation_raw = source
    raw_by_kind = {"plan": plan_raw, "observations": observations_raw, "evaluation": evaluation_raw}
    evidence_by_kind = {item["kind"]: item for item in manifest["evidence"]}
    for kind, raw in raw_by_kind.items():
        if evidence_by_kind[kind]["sha256"] != _sha256(raw):
            raise ValueError(f"bundle {kind} digest binding is invalid")
    if (
        manifest["system"]["system_id"] != plan["system_id"]
        or manifest["overall_status"] != evaluation["summary"]["verdict"]
        or evidence_by_kind["evaluation"]["verdict"] != evaluation["summary"]["verdict"]
    ):
        raise ValueError("bundle status or system binding does not reconcile")
    statement_raw = _read(root / STATEMENT_FILE, private=True)
    statement = _strict(statement_raw, STATEMENT_FILE)
    expected_statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": MANIFEST_FILE, "digest": {"sha256": _sha256(manifest_raw)}},
            *[
                {"name": item["file"], "digest": {"sha256": item["sha256"]}}
                for item in manifest["evidence"]
            ],
        ],
        "predicateType": CHECKPOINT_PREDICATE,
        "predicate": {
            "bundle_id": manifest["bundle_id"],
            "created_at": manifest["created_at"],
            "system_id": plan["system_id"],
            "overall_status": manifest["overall_status"],
            "authentication_mode": manifest["authentication"]["mode"],
            "limitations": list(BUNDLE_LIMITATIONS),
            "interpretation_boundary": _INTERPRETATION,
        },
    }
    if statement != expected_statement or statement_raw != _canonical(statement):
        raise ValueError("bundle checkpoint statement does not recompute")
    key_ids = []
    if signed:
        if public_key_pem is None:
            raise ValueError("signed invariant bundle requires its external public key")
        if manifest["authentication"]["signer_key_id"] != public_key_id(public_key_pem):
            raise ValueError("bundle public key differs from the declared signer")
        envelope_raw = _read(root / DSSE_FILE, private=True)
        envelope = _strict(envelope_raw, DSSE_FILE)
        if envelope_raw != _canonical(envelope):
            raise ValueError("bundle DSSE must use canonical JSON")
        key_ids.append(_verify_envelope(envelope, statement_raw, public_key_pem))
    elif public_key_pem is not None:
        raise ValueError("unsigned bundle does not accept a public key")
    return {
        "valid": True,
        "bundle_id": manifest["bundle_id"],
        "system_id": plan["system_id"],
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "captured_at": evaluation["observations"]["captured_at"],
        "manifest_sha256": _sha256(manifest_raw),
        "statement_sha256": _sha256(statement_raw),
        "overall_status": manifest["overall_status"],
        "authenticated": signed,
        "key_ids": key_ids,
        "plan": plan,
        "evaluation": evaluation,
        "interpretation_boundary": _INTERPRETATION,
    }


def _comparison_value(
    comparison_id: str, before: Mapping[str, Any], after: Mapping[str, Any], created_at: str
) -> Dict[str, Any]:
    before_plan = before["plan"]
    after_plan = after["plan"]
    if before["system_id"] != after["system_id"] or before_plan["plan_id"] != after_plan["plan_id"]:
        raise ValueError("remediation comparison requires the same system and plan identity")
    if (
        before_plan["invariants"] != after_plan["invariants"]
        or before_plan["acceptance"] != after_plan["acceptance"]
    ):
        raise ValueError("remediation comparison rejects weakened or changed invariants")

    def source_contract(plan: Mapping[str, Any]) -> list[Dict[str, Any]]:
        return [
            {
                "source_id": item["source_id"],
                "source_type": item["source_type"],
                "required": item["required"],
            }
            for item in plan["sources"]
        ]

    if source_contract(before_plan) != source_contract(after_plan):
        raise ValueError("remediation comparison requires the same source contract")
    if _timestamp(after["captured_at"], "after.captured_at") <= _timestamp(
        before["captured_at"], "before.captured_at"
    ):
        raise ValueError("after evidence must be captured after before evidence")
    before_status = {
        item["invariant_id"]: item["status"] for item in before["evaluation"]["results"]
    }
    after_status = {item["invariant_id"]: item["status"] for item in after["evaluation"]["results"]}
    before_violations = {key for key, value in before_status.items() if value == "violated"}
    after_violations = {key for key, value in after_status.items() if value == "violated"}
    resolved = sorted(before_violations - after_violations)
    persistent = sorted(before_violations & after_violations)
    new = sorted(after_violations - before_violations)
    insufficient = sorted(
        key for key, value in after_status.items() if value == "insufficient_evidence"
    )
    if (
        before["overall_status"] == "fail"
        and after["overall_status"] == "pass"
        and resolved
        and not persistent
        and not new
        and not insufficient
    ):
        status = "effective"
    elif new or (before["overall_status"] == "pass" and after["overall_status"] == "fail"):
        status = "regressed"
    elif (
        after["overall_status"] == "insufficient_evidence" or insufficient or not before_violations
    ):
        status = "inconclusive"
    else:
        status = "ineffective"
    contract = {
        "invariants": before_plan["invariants"],
        "acceptance": before_plan["acceptance"],
        "sources": source_contract(before_plan),
    }
    return {
        "schema": COMPARISON_SCHEMA,
        "schema_version": 1,
        "comparison_id": comparison_id,
        "created_at": created_at,
        "producer": {"name": "lurescope", "version": __version__},
        "system_id": before["system_id"],
        "plan_id": before_plan["plan_id"],
        "contract_sha256": _sha256(_canonical(contract)),
        "before": {
            "bundle_id": before["bundle_id"],
            "manifest_sha256": before["manifest_sha256"],
            "statement_sha256": before["statement_sha256"],
            "plan_version": before["plan_version"],
            "captured_at": before["captured_at"],
            "overall_status": before["overall_status"],
            "authenticated": before["authenticated"],
        },
        "after": {
            "bundle_id": after["bundle_id"],
            "manifest_sha256": after["manifest_sha256"],
            "statement_sha256": after["statement_sha256"],
            "plan_version": after["plan_version"],
            "captured_at": after["captured_at"],
            "overall_status": after["overall_status"],
            "authenticated": after["authenticated"],
        },
        "resolved_invariant_ids": resolved,
        "persistent_violation_ids": persistent,
        "new_violation_ids": new,
        "insufficient_invariant_ids": insufficient,
        "summary": {
            "resolved": len(resolved),
            "persistent": len(persistent),
            "new": len(new),
            "insufficient_after": len(insufficient),
            "status": status,
        },
        "limitations": list(COMPARISON_LIMITATIONS),
        "interpretation_boundary": _COMPARISON_INTERPRETATION,
    }


def compare_invariant_bundles(
    before_bundle: Path,
    after_bundle: Path,
    output: Path,
    *,
    comparison_id: str,
    before_public_key_pem: Optional[bytes] = None,
    after_public_key_pem: Optional[bytes] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    _portable_id(comparison_id, "comparison_id")
    before = verify_invariant_bundle(before_bundle, public_key_pem=before_public_key_pem)
    after = verify_invariant_bundle(after_bundle, public_key_pem=after_public_key_pem)
    comparison = _comparison_value(comparison_id, before, after, created_at or _timestamp_now())
    target = Path(output)
    _write_new(target, _canonical(comparison))
    try:
        verify_remediation_comparison(
            target,
            before_bundle,
            after_bundle,
            before_public_key_pem=before_public_key_pem,
            after_public_key_pem=after_public_key_pem,
        )
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return comparison


def verify_remediation_comparison(
    comparison_path: Path,
    before_bundle: Path,
    after_bundle: Path,
    *,
    before_public_key_pem: Optional[bytes] = None,
    after_public_key_pem: Optional[bytes] = None,
) -> Dict[str, Any]:
    raw = _read(comparison_path, private=True)
    comparison = _strict(raw, "remediation comparison")
    if (
        not isinstance(comparison, dict)
        or comparison.get("schema") != COMPARISON_SCHEMA
        or comparison.get("schema_version") != 1
    ):
        raise ValueError("unsupported remediation comparison schema")
    comparison_id = _portable_id(comparison.get("comparison_id"), "comparison.comparison_id")
    created_at = comparison.get("created_at")
    _timestamp(created_at, "comparison.created_at")
    before = verify_invariant_bundle(before_bundle, public_key_pem=before_public_key_pem)
    after = verify_invariant_bundle(after_bundle, public_key_pem=after_public_key_pem)
    expected = _comparison_value(comparison_id, before, after, created_at)
    if comparison != expected or raw != _canonical(comparison):
        raise ValueError("remediation comparison does not recompute from the supplied bundles")
    return {
        "valid": True,
        "comparison_id": comparison_id,
        "comparison_sha256": _sha256(raw),
        "status": comparison["summary"]["status"],
        "resolved_invariant_ids": comparison["resolved_invariant_ids"],
        "interpretation_boundary": _COMPARISON_INTERPRETATION,
    }
