"""Independent, signed evidence for LureRevoke convergence evaluations."""

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

PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerevoke-plan-v1"
RUN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerevoke-run-v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerevoke-evaluation-v1"
BUNDLE_SCHEMA = "https://github.com/immu4989/lurescope/spec/lurerevoke-evidence-bundle/v1"
COMPARISON_SCHEMA = (
    "https://github.com/immu4989/lurescope/spec/lurerevoke-remediation-comparison/v1"
)
CHECKPOINT_PREDICATE = (
    "https://github.com/immu4989/lurescope/spec/lurerevoke-evidence-checkpoint/v1"
)
MAX_NODES = 64
MAX_EVENTS = 64
MAX_PROBES = 4096

CAEP_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
CAEP_CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
CAEP_DEVICE_COMPLIANCE = (
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
)
CAEP_RISK_LEVEL = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
EVENT_REASON = {
    CAEP_SESSION_REVOKED: "session_revoked",
    CAEP_CREDENTIAL_CHANGE: "credential_revoked",
    CAEP_DEVICE_COMPLIANCE: "device_noncompliant",
    CAEP_RISK_LEVEL: "risk_increased",
}
DISPOSITIONS = {"applied", "duplicate", "invalid"}
DECISIONS = {"allow", "block"}
REASONS = {
    "propagation_window",
    "revocation_not_effective",
    "subject_not_revoked",
    "subject_revoked",
}

PLAN_LIMITATIONS = [
    "synthetic_relative_timing_and_opaque_identifiers_only_no_tokens_credentials_or_payloads",
    "caep_event_types_are_metadata_projections_not_security_event_tokens_or_wire_conformance",
    "signal_authentication_transport_delivery_and_clock_sync_require_external_controls",
    "finite_scenarios_do_not_prove_complete_revocation_or_zero_trust_compliance",
]
RUN_LIMITATIONS = [
    "observations_are_claimed_receiver_metadata_not_proof_of_signal_or_enforcement_authenticity",
    "reference_run_is_offline_and_does_not_contact_identity_providers_agents_or_policy_engines",
    "invalid_and_duplicate_signals_are_synthetic_and_contain_no_reusable_security_material",
]
EVALUATION_LIMITATIONS = [
    "metrics_are_recomputed_from_embedded_plan_and_run_metadata",
    "deadline_success_depends_on_external_clock_quality_and_observation_completeness",
    "a_pass_does_not_prove_every_access_path_received_or_enforced_a_revocation",
    "evaluation_is_not_certification_authorization_or_a_claim_of_caep_interoperability",
]
BUNDLE_LIMITATIONS = [
    "plan_run_signal_dispositions_decisions_and_metrics_are_independently_recomputed",
    "a_signature_authenticates_a_key_not_a_transmitter_receiver_node_or_organization",
    "submitted_observations_do_not_prove_complete_event_or_access_path_coverage",
    "passing_is_not_caep_interoperability_zero_trust_compliance_or_deployment_authorization",
]
INTERPRETATION = (
    "LureScope independently recomputed the declared revocation delivery, convergence, signal "
    "dispositions, and access outcomes and bound their exact bytes. This is evidence integrity, "
    "not proof of transmitter, receiver, clock, observation, or enforcement authenticity."
)
COMPARISON_LIMITATIONS = [
    "comparison_requires_identical_plan_system_environment_and_receiver_identity_contracts",
    "effective_means_a_failing_before_evaluation_changed_to_pass_under_the_same_plan",
    "configuration_change_causality_deployment_and_unrepresented_behavior_are_not_proven",
    "comparison_is_not_enforcement_compliance_certification_or_deployment_authorization",
]
COMPARISON_INTERPRETATION = (
    "An effective comparison means the same revocation plan, system, environment, and receiver "
    "identity changed from fail to pass in submitted evidence. It does not prove causality, "
    "deployment, complete observation, or enforcement."
)

MANIFEST_FILE = "bundle.json"
EVIDENCE_DIRECTORY = "evidence"
EVALUATION_FILE = "revocation-evaluation.json"
STATEMENT_FILE = "checkpoint.statement.json"
DSSE_FILE = "checkpoint.dsse.json"


def _enum(value: Any, field: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} is unsupported")
    return value


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _now_not_before(reference: str) -> str:
    current = _timestamp_now()
    return reference if _time(current) < _time(reference) else current


def _signal_material(event: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: event[key] for key in event if key != "signal_sha256"}


def _validate_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "revocation plan",
        (
            "schema",
            "schema_version",
            "plan_id",
            "created_at",
            "system_id",
            "stream",
            "nodes",
            "events",
            "probes",
            "acceptance",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke plan schema")
    _id(plan["plan_id"], "plan.plan_id")
    _id(plan["system_id"], "plan.system_id")
    _timestamp(plan["created_at"], "plan.created_at")
    stream = _exact(
        plan["stream"],
        "plan.stream",
        (
            "transmitter_id",
            "receiver_audience_id",
            "stream_id",
            "profile",
            "authentication_boundary",
        ),
    )
    for field in ("transmitter_id", "receiver_audience_id", "stream_id"):
        _id(stream[field], f"plan.stream.{field}")
    if (
        stream["profile"] != "openid-caep-1.0-final-metadata-projection"
        or stream["authentication_boundary"] != "externally_verified_set_metadata"
    ):
        raise ValueError("revocation stream contract is unsupported")

    if not isinstance(plan["nodes"], list) or not 1 <= len(plan["nodes"]) <= MAX_NODES:
        raise ValueError("plan nodes must be a non-empty bounded array")
    node_ids = []
    for index, item in enumerate(plan["nodes"]):
        node = _exact(item, f"plan.nodes[{index}]", ("node_id", "mediation_point_id"))
        node_ids.append(_id(node["node_id"], "node.node_id"))
        _id(node["mediation_point_id"], "node.mediation_point_id")
    if len(set(node_ids)) != len(node_ids):
        raise ValueError("plan contains duplicate node identifiers")

    if not isinstance(plan["events"], list) or not 1 <= len(plan["events"]) <= MAX_EVENTS:
        raise ValueError("plan events must be a non-empty bounded array")
    events = {}
    sequences = set()
    for index, item in enumerate(plan["events"]):
        event = _exact(
            item,
            f"plan.events[{index}]",
            (
                "event_id",
                "sequence",
                "occurred_at_ms",
                "event_type",
                "subject",
                "attenuation_reason",
                "signal_sha256",
            ),
        )
        event_id = _id(event["event_id"], "event.event_id")
        sequence = _integer(event["sequence"], "event.sequence", 1, 1_000_000)
        if event_id in events or sequence in sequences:
            raise ValueError("plan contains duplicate event identity or sequence")
        sequences.add(sequence)
        _integer(event["occurred_at_ms"], "event.occurred_at_ms", 1, 86_400_000)
        event_type = _enum(event["event_type"], "event.event_type", set(EVENT_REASON))
        subject = _exact(event["subject"], "event.subject", ("format", "id"))
        if subject["format"] != "opaque":
            raise ValueError("event subject format must be opaque")
        _id(subject["id"], "event.subject.id")
        if event["attenuation_reason"] != EVENT_REASON[event_type]:
            raise ValueError("event type and attenuation reason do not reconcile")
        _digest(event["signal_sha256"], "event.signal_sha256")
        if event["signal_sha256"] != _sha256(_canonical(_signal_material(event))):
            raise ValueError("event signal digest does not reconcile")
        events[event_id] = event
    if sorted(sequences) != list(range(1, len(sequences) + 1)):
        raise ValueError("event sequences must be contiguous from one")
    event_subjects = {event["subject"]["id"] for event in events.values()}

    if not isinstance(plan["probes"], list) or not 1 <= len(plan["probes"]) <= MAX_PROBES:
        raise ValueError("plan probes must be a non-empty bounded array")
    probe_ids = []
    for index, item in enumerate(plan["probes"]):
        probe = _exact(
            item,
            f"plan.probes[{index}]",
            ("probe_id", "event_id", "node_id", "attempted_at_ms", "subject_id"),
        )
        probe_ids.append(_id(probe["probe_id"], "probe.probe_id"))
        if probe["event_id"] not in events or probe["node_id"] not in node_ids:
            raise ValueError("probe references an unknown event or node")
        _integer(probe["attempted_at_ms"], "probe.attempted_at_ms", 0, 86_400_000)
        subject_id = _id(probe["subject_id"], "probe.subject_id")
        event_subject = events[probe["event_id"]]["subject"]["id"]
        if subject_id != event_subject and subject_id in event_subjects:
            raise ValueError("probe unrelated subject collides with another campaign event")
    if len(set(probe_ids)) != len(probe_ids):
        raise ValueError("plan contains duplicate probe identifiers")

    acceptance = _exact(
        plan["acceptance"],
        "plan.acceptance",
        (
            "maximum_convergence_ms",
            "maximum_deadline_miss_count",
            "maximum_post_deadline_allow_count",
            "maximum_collateral_block_count",
            "minimum_delivery_coverage_rate",
            "minimum_revoked_block_recall",
            "minimum_pre_event_allow_rate",
            "minimum_signal_disposition_accuracy",
        ),
    )
    _integer(acceptance["maximum_convergence_ms"], "maximum_convergence_ms", 1, 600_000)
    for field in (
        "maximum_deadline_miss_count",
        "maximum_post_deadline_allow_count",
        "maximum_collateral_block_count",
    ):
        _integer(acceptance[field], field, 0, MAX_PROBES)
    for field in (
        "minimum_delivery_coverage_rate",
        "minimum_revoked_block_recall",
        "minimum_pre_event_allow_rate",
        "minimum_signal_disposition_accuracy",
    ):
        _rate(acceptance[field], field)
    if plan["limitations"] != PLAN_LIMITATIONS:
        raise ValueError("plan limitations are invalid")
    return dict(plan)


def _validate_run(value: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    run = _exact(
        value,
        "revocation run",
        (
            "schema",
            "schema_version",
            "run_id",
            "generated_at",
            "implementation",
            "plan_sha256",
            "signal_observations",
            "access_observations",
            "limitations",
        ),
    )
    if run["schema"] != RUN_SCHEMA or run["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke run schema")
    _id(run["run_id"], "run.run_id")
    _timestamp(run["generated_at"], "run.generated_at")
    if _time(run["generated_at"]) < _time(plan["created_at"]):
        raise ValueError("run predates its plan")
    implementation = _exact(
        run["implementation"], "run.implementation", ("name", "version", "artifact_sha256")
    )
    _id(implementation["name"], "implementation.name")
    _id(implementation["version"], "implementation.version")
    if implementation["artifact_sha256"] is not None:
        _digest(implementation["artifact_sha256"], "implementation.artifact_sha256")
    _digest(run["plan_sha256"], "run.plan_sha256")
    if run["plan_sha256"] != _sha256(_canonical(plan)):
        raise ValueError("run plan digest does not reconcile")
    event_ids = {item["event_id"] for item in plan["events"]}
    node_ids = {item["node_id"] for item in plan["nodes"]}
    signals = run["signal_observations"]
    if not isinstance(signals, list) or len(signals) > MAX_EVENTS * MAX_NODES * 4:
        raise ValueError("signal observations must be a bounded array")
    observation_ids = []
    for index, item in enumerate(signals):
        signal = _exact(
            item,
            f"signal[{index}]",
            (
                "observation_id",
                "event_id",
                "node_id",
                "received_at_ms",
                "signal_sha256",
                "disposition",
            ),
        )
        observation_ids.append(_id(signal["observation_id"], "signal.observation_id"))
        if signal["event_id"] not in event_ids or signal["node_id"] not in node_ids:
            raise ValueError("signal references an unknown event or node")
        _integer(signal["received_at_ms"], "signal.received_at_ms", 0, 86_400_000)
        _digest(signal["signal_sha256"], "signal.signal_sha256")
        _enum(signal["disposition"], "signal.disposition", DISPOSITIONS)
    if len(set(observation_ids)) != len(observation_ids):
        raise ValueError("run contains duplicate signal observation identifiers")
    probe_ids = {item["probe_id"] for item in plan["probes"]}
    access = run["access_observations"]
    if not isinstance(access, list) or len(access) != len(probe_ids):
        raise ValueError("run must contain exactly one access observation per probe")
    submitted = []
    for index, item in enumerate(access):
        decision = _exact(item, f"access[{index}]", ("probe_id", "decision", "reason_code"))
        submitted.append(_id(decision["probe_id"], "access.probe_id"))
        _enum(decision["decision"], "access.decision", DECISIONS)
        _enum(decision["reason_code"], "access.reason_code", REASONS)
    if set(submitted) != probe_ids or len(set(submitted)) != len(probe_ids):
        raise ValueError("run access observations do not exactly cover plan probes")
    if run["limitations"] != RUN_LIMITATIONS:
        raise ValueError("run limitations are invalid")
    return dict(run)


def _expected_dispositions(
    plan: Mapping[str, Any], observations: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, str], dict[tuple[str, str], int]]:
    events = {item["event_id"]: item for item in plan["events"]}
    expected = {}
    applied = {}
    seen = set()
    for observation in sorted(
        observations, key=lambda item: (item["received_at_ms"], item["observation_id"])
    ):
        event = events[observation["event_id"]]
        key = (observation["event_id"], observation["node_id"])
        valid = (
            observation["signal_sha256"] == event["signal_sha256"]
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
    probe: Mapping[str, Any],
    event: Mapping[str, Any],
    applied_at: Optional[int],
    deadline: int,
) -> tuple[str, str, str]:
    attempted = probe["attempted_at_ms"]
    if probe["subject_id"] != event["subject"]["id"]:
        return "allow", "subject_not_revoked", "unrelated_subject"
    if attempted < event["occurred_at_ms"]:
        return "allow", "revocation_not_effective", "pre_event"
    if applied_at is not None and attempted >= applied_at:
        return "block", "subject_revoked", "revoked"
    if attempted >= event["occurred_at_ms"] + deadline:
        return "block", "subject_revoked", "post_deadline"
    return "allow", "propagation_window", "propagation_window"


def _evaluation_value(value: Mapping[str, Any]) -> Dict[str, Any]:
    plan = _validate_plan(value["plan"])
    run = _validate_run(value["run"], plan)
    generated_at = _timestamp(value["generated_at"], "evaluation.generated_at")
    if _time(generated_at) < _time(run["generated_at"]):
        raise ValueError("evaluation predates its run")
    expected_dispositions, applied = _expected_dispositions(plan, run["signal_observations"])
    event_map = {item["event_id"]: item for item in plan["events"]}
    access = {item["probe_id"]: item for item in run["access_observations"]}
    deadline = plan["acceptance"]["maximum_convergence_ms"]
    convergence = []
    delivery_results = []
    deadline_misses = 0
    for event in plan["events"]:
        for node in plan["nodes"]:
            received = applied.get((event["event_id"], node["node_id"]))
            elapsed = None if received is None else received - event["occurred_at_ms"]
            met = elapsed is not None and elapsed <= deadline
            if elapsed is not None:
                convergence.append(elapsed)
            deadline_misses += int(not met)
            delivery_results.append(
                {
                    "event_id": event["event_id"],
                    "node_id": node["node_id"],
                    "applied_at_ms": received,
                    "convergence_ms": elapsed,
                    "deadline_met": met,
                }
            )
    probe_results = []
    revoked_total = revoked_correct = pre_total = pre_correct = 0
    post_allows = collateral = incorrect_decisions = incorrect_reasons = 0
    for probe in plan["probes"]:
        event = event_map[probe["event_id"]]
        expected_decision, expected_reason, phase = _expected_probe(
            probe,
            event,
            applied.get((probe["event_id"], probe["node_id"])),
            deadline,
        )
        observed = access[probe["probe_id"]]
        decision_correct = observed["decision"] == expected_decision
        reason_correct = observed["reason_code"] == expected_reason
        incorrect_decisions += int(not decision_correct)
        incorrect_reasons += int(not reason_correct)
        if expected_decision == "block":
            revoked_total += 1
            revoked_correct += int(observed["decision"] == "block")
        if phase == "pre_event":
            pre_total += 1
            pre_correct += int(observed["decision"] == "allow")
        if phase == "unrelated_subject" and observed["decision"] == "block":
            collateral += 1
        if (
            probe["subject_id"] == event["subject"]["id"]
            and probe["attempted_at_ms"] >= event["occurred_at_ms"] + deadline
            and observed["decision"] == "allow"
        ):
            post_allows += 1
        classification = (
            "correct"
            if decision_correct and reason_correct
            else "revocation_bypass"
            if expected_decision == "block" and observed["decision"] == "allow"
            else "collateral_denial"
            if expected_decision == "allow" and observed["decision"] == "block"
            else "wrong_reason"
        )
        probe_results.append(
            {
                "probe_id": probe["probe_id"],
                "event_id": probe["event_id"],
                "node_id": probe["node_id"],
                "phase": phase,
                "expected_decision": expected_decision,
                "submitted_decision": observed["decision"],
                "expected_reason_code": expected_reason,
                "submitted_reason_code": observed["reason_code"],
                "classification": classification,
            }
        )
    disposition_correct = sum(
        item["disposition"] == expected_dispositions[item["observation_id"]]
        for item in run["signal_observations"]
    )
    disposition_total = len(run["signal_observations"])
    required = len(plan["events"]) * len(plan["nodes"])
    coverage = len(applied) / required
    maximum = max(convergence) if convergence else None
    ordered = sorted(convergence)
    p95 = ordered[math.ceil(0.95 * len(ordered)) - 1] if ordered else None
    recall = revoked_correct / revoked_total if revoked_total else 0.0
    pre_allow = pre_correct / pre_total if pre_total else 0.0
    disposition_accuracy = disposition_correct / disposition_total if disposition_total else 0.0
    acceptance = plan["acceptance"]
    verdict = (
        "pass"
        if (
            coverage >= acceptance["minimum_delivery_coverage_rate"]
            and maximum is not None
            and maximum <= acceptance["maximum_convergence_ms"]
            and deadline_misses <= acceptance["maximum_deadline_miss_count"]
            and post_allows <= acceptance["maximum_post_deadline_allow_count"]
            and collateral <= acceptance["maximum_collateral_block_count"]
            and recall >= acceptance["minimum_revoked_block_recall"]
            and pre_allow >= acceptance["minimum_pre_event_allow_rate"]
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
            "event_count": len(plan["events"]),
            "node_count": len(plan["nodes"]),
            "required_delivery_count": required,
            "applied_delivery_count": len(applied),
            "delivery_coverage_rate": coverage,
            "maximum_convergence_ms": maximum,
            "p95_convergence_ms": p95,
            "deadline_miss_count": deadline_misses,
            "post_deadline_allow_count": post_allows,
            "collateral_block_count": collateral,
            "revoked_block_recall": recall,
            "pre_event_allow_rate": pre_allow,
            "signal_disposition_accuracy": disposition_accuracy,
            "incorrect_decision_count": incorrect_decisions,
            "incorrect_reason_count": incorrect_reasons,
            "verdict": verdict,
        },
        "delivery_results": delivery_results,
        "probe_results": probe_results,
        "limitations": list(EVALUATION_LIMITATIONS),
    }


def validate_revocation_evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _exact(
        value,
        "revocation evaluation",
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
            "delivery_results",
            "probe_results",
            "limitations",
        ),
    )
    if evaluation["schema"] != EVALUATION_SCHEMA or evaluation["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke evaluation schema")
    implementation = _exact(
        evaluation["implementation"], "evaluation.implementation", ("name", "version")
    )
    if implementation["name"] != "lurebench":
        raise ValueError("revocation evaluation producer must be lurebench")
    _id(implementation["version"], "evaluation.implementation.version")
    expected = _evaluation_value(evaluation)
    if evaluation != expected:
        raise ValueError("revocation evaluation does not independently recompute")
    return dict(evaluation)


def _load_evaluation(path: Path, *, private: bool = False) -> tuple[Dict[str, Any], bytes]:
    raw = _read(Path(path), private=private)
    value = validate_revocation_evaluation(_strict(raw, Path(path).name))
    if raw != _canonical(value):
        raise ValueError("revocation evaluation must use canonical JSON")
    return value, raw


def _summary_binding(report: Mapping[str, Any]) -> Dict[str, Any]:
    summary = report["summary"]
    return {
        "delivery_coverage_rate": summary["delivery_coverage_rate"],
        "p95_convergence_ms": summary["p95_convergence_ms"],
        "maximum_convergence_ms": summary["maximum_convergence_ms"],
        "deadline_miss_count": summary["deadline_miss_count"],
        "post_deadline_allow_count": summary["post_deadline_allow_count"],
        "collateral_block_count": summary["collateral_block_count"],
        "revoked_block_recall": summary["revoked_block_recall"],
    }


def _validate_manifest(value: Any) -> Dict[str, Any]:
    manifest = _exact(
        value,
        "revocation bundle manifest",
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
        raise ValueError("unsupported LureRevoke bundle schema")
    _portable_id(manifest["bundle_id"], "bundle.bundle_id")
    _timestamp(manifest["created_at"], "bundle.created_at")
    producer = _exact(manifest["producer"], "bundle.producer", ("name", "version"))
    if producer["name"] != "lurescope":
        raise ValueError("bundle producer must be lurescope")
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
        manifest["evidence"],
        "bundle.evidence",
        ("file", "schema", "sha256", "run_sha256"),
    )
    if evidence["file"] != f"{EVIDENCE_DIRECTORY}/{EVALUATION_FILE}":
        raise ValueError("bundle evidence path is invalid")
    if evidence["schema"] != EVALUATION_SCHEMA:
        raise ValueError("bundle evidence schema is invalid")
    _digest(evidence["sha256"], "bundle.evidence.sha256")
    _digest(evidence["run_sha256"], "bundle.evidence.run_sha256")
    summary = _exact(
        manifest["summary"],
        "bundle.summary",
        (
            "delivery_coverage_rate",
            "p95_convergence_ms",
            "maximum_convergence_ms",
            "deadline_miss_count",
            "post_deadline_allow_count",
            "collateral_block_count",
            "revoked_block_recall",
        ),
    )
    for field in ("delivery_coverage_rate", "revoked_block_recall"):
        _rate(summary[field], f"bundle.summary.{field}")
    for field in ("deadline_miss_count", "post_deadline_allow_count", "collateral_block_count"):
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
            raise ValueError("unsigned bundle cannot name a signer")
    else:
        _digest(authentication["signer_key_id"], "bundle.authentication.signer_key_id")
    if (
        manifest["limitations"] != BUNDLE_LIMITATIONS
        or manifest["interpretation_boundary"] != INTERPRETATION
    ):
        raise ValueError("bundle interpretation boundary is invalid")
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


def create_revocation_bundle(
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
        raise ValueError("revocation bundle signing requires matching public and private keys")
    key = None
    signer_id = None
    if signer_public_key_pem is not None and signing_key_pem is not None:
        key = _private_key(signing_key_pem)
        signer_id = public_key_id(signer_public_key_pem)
        if not secrets.compare_digest(_private_key_id(key), signer_id):
            raise ValueError("revocation signing key does not match its public key")
    report, report_raw = _load_evaluation(evaluation)
    created = created_at or _now_not_before(report["generated_at"])
    _timestamp(created, "bundle.created_at")
    if _time(created) < _time(report["generated_at"]):
        raise ValueError("revocation bundle cannot predate its evaluation")
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
        verify_revocation_bundle(target, public_key_pem=signer_public_key_pem)
    except Exception:
        for item in sorted(target.rglob("*"), key=lambda path: len(path.parts), reverse=True):
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                item.rmdir()
        target.rmdir()
        raise
    return manifest


def verify_revocation_bundle(
    bundle: Path, *, public_key_pem: Optional[bytes] = None
) -> Dict[str, Any]:
    root = Path(bundle)
    if (
        root.is_symlink()
        or not root.is_dir()
        or (os.name == "posix" and root.stat().st_mode & 0o077)
    ):
        raise ValueError("revocation bundle must be a private regular directory")
    manifest_raw = _read(root / MANIFEST_FILE, private=True)
    manifest = _validate_manifest(_strict(manifest_raw, MANIFEST_FILE))
    if manifest_raw != _canonical(manifest):
        raise ValueError("revocation manifest must use canonical JSON")
    signed = manifest["authentication"]["mode"] == "ecdsa-p256-dsse"
    expected_root = {MANIFEST_FILE, EVIDENCE_DIRECTORY, STATEMENT_FILE} | (
        {DSSE_FILE} if signed else set()
    )
    if {item.name for item in root.iterdir()} != expected_root:
        raise ValueError("revocation bundle contains unexpected artifacts")
    evidence_dir = root / EVIDENCE_DIRECTORY
    if (
        evidence_dir.is_symlink()
        or not evidence_dir.is_dir()
        or (os.name == "posix" and evidence_dir.stat().st_mode & 0o077)
    ):
        raise ValueError("revocation evidence directory is invalid")
    if {item.name for item in evidence_dir.iterdir()} != {EVALUATION_FILE}:
        raise ValueError("revocation evidence set is incomplete or unexpected")
    report, report_raw = _load_evaluation(evidence_dir / EVALUATION_FILE, private=True)
    plan, run = report["plan"], report["run"]
    if (
        manifest["system"]["system_id"] != plan["system_id"]
        or manifest["plan"] != {"plan_id": plan["plan_id"], "plan_sha256": report["plan_sha256"]}
        or manifest["receiver"] != run["implementation"]
        or manifest["evidence"]["sha256"] != _sha256(report_raw)
        or manifest["evidence"]["run_sha256"] != report["run_sha256"]
        or manifest["summary"] != _summary_binding(report)
        or manifest["overall_status"] != report["summary"]["verdict"]
    ):
        raise ValueError("revocation bundle bindings do not reconcile")
    if _time(manifest["created_at"]) < _time(report["generated_at"]):
        raise ValueError("revocation bundle predates its evaluation")
    expected_statement = _checkpoint(manifest, manifest_raw)
    statement_raw = _read(root / STATEMENT_FILE, private=True)
    statement = _strict(statement_raw, STATEMENT_FILE)
    if statement != expected_statement or statement_raw != _canonical(expected_statement):
        raise ValueError("revocation checkpoint does not independently recompute")
    key_ids = []
    if signed:
        if public_key_pem is None:
            raise ValueError("signed revocation bundle requires its external public key")
        if manifest["authentication"]["signer_key_id"] != public_key_id(public_key_pem):
            raise ValueError("revocation public key differs from its signer")
        envelope_raw = _read(root / DSSE_FILE, private=True)
        envelope = _strict(envelope_raw, DSSE_FILE)
        if envelope_raw != _canonical(envelope):
            raise ValueError("revocation DSSE must use canonical JSON")
        key_ids.append(_verify_envelope(envelope, statement_raw, public_key_pem))
    elif public_key_pem is not None:
        raise ValueError("unsigned revocation bundle does not accept a public key")
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


def _revocation_failure_ids(report: Mapping[str, Any]) -> set[str]:
    failures = {
        f"delivery/{item['event_id']}/{item['node_id']}"
        for item in report["delivery_results"]
        if not item["deadline_met"]
    }
    failures.update(
        f"probe/{item['probe_id']}"
        for item in report["probe_results"]
        if item["classification"] != "correct"
    )
    expected, _ = _expected_dispositions(report["plan"], report["run"]["signal_observations"])
    failures.update(
        f"signal/{item['observation_id']}"
        for item in report["run"]["signal_observations"]
        if item["disposition"] != expected[item["observation_id"]]
    )
    return failures


def _metric_delta(before: Any, after: Any) -> Any:
    if before is None or after is None:
        return None
    if isinstance(before, float) or isinstance(after, float):
        return round(after - before, 12)
    return after - before


def _comparison_value(
    comparison_id: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    created_at: str,
) -> Dict[str, Any]:
    _timestamp(created_at, "comparison.created_at")
    before_report, after_report = before["report"], after["report"]
    before_plan, after_plan = before_report["plan"], after_report["plan"]
    before_receiver = before_report["run"]["implementation"]
    after_receiver = after_report["run"]["implementation"]
    if before["bundle_id"] == after["bundle_id"]:
        raise ValueError("revocation comparison requires distinct bundle identifiers")
    if before["system_id"] != after["system_id"]:
        raise ValueError("revocation comparison requires the same system identity")
    if before["environment"] != after["environment"]:
        raise ValueError("revocation comparison requires the same environment")
    if before_plan != after_plan:
        raise ValueError("revocation comparison rejects a changed plan or acceptance contract")
    if before_receiver["name"] != after_receiver["name"]:
        raise ValueError("revocation comparison requires the same receiver identity")
    if _time(after_report["generated_at"]) <= _time(before_report["generated_at"]):
        raise ValueError("after revocation evidence must be newer than before evidence")
    if _time(created_at) < _time(after_report["generated_at"]):
        raise ValueError("revocation comparison predates after evidence")

    before_status, after_status = before["overall_status"], after["overall_status"]
    status = (
        "effective"
        if (before_status, after_status) == ("fail", "pass")
        else "regressed"
        if (before_status, after_status) == ("pass", "fail")
        else "ineffective"
        if before_status == "fail"
        else "unchanged_pass"
    )
    before_failed = _revocation_failure_ids(before_report)
    after_failed = _revocation_failure_ids(after_report)
    before_summary, after_summary = before_report["summary"], after_report["summary"]
    metric_fields = (
        "delivery_coverage_rate",
        "p95_convergence_ms",
        "maximum_convergence_ms",
        "deadline_miss_count",
        "post_deadline_allow_count",
        "collateral_block_count",
        "revoked_block_recall",
        "pre_event_allow_rate",
        "signal_disposition_accuracy",
        "incorrect_decision_count",
        "incorrect_reason_count",
    )
    return {
        "schema": COMPARISON_SCHEMA,
        "schema_version": 1,
        "comparison_id": comparison_id,
        "created_at": created_at,
        "producer": {"name": "lurescope", "version": __version__},
        "system": {
            "system_id": before["system_id"],
            "environment": before["environment"],
        },
        "contract": {
            "plan_id": before["plan_id"],
            "plan_sha256": before_report["plan_sha256"],
            "receiver_name": before_receiver["name"],
        },
        "before": {
            "bundle_id": before["bundle_id"],
            "manifest_sha256": before["manifest_sha256"],
            "statement_sha256": before["statement_sha256"],
            "run_sha256": before_report["run_sha256"],
            "receiver_version": before_receiver["version"],
            "receiver_artifact_sha256": before_receiver["artifact_sha256"],
            "generated_at": before_report["generated_at"],
            "overall_status": before_status,
            "authenticated": before["authenticated"],
        },
        "after": {
            "bundle_id": after["bundle_id"],
            "manifest_sha256": after["manifest_sha256"],
            "statement_sha256": after["statement_sha256"],
            "run_sha256": after_report["run_sha256"],
            "receiver_version": after_receiver["version"],
            "receiver_artifact_sha256": after_receiver["artifact_sha256"],
            "generated_at": after_report["generated_at"],
            "overall_status": after_status,
            "authenticated": after["authenticated"],
        },
        "resolved_failure_ids": sorted(before_failed - after_failed),
        "persistent_failure_ids": sorted(before_failed & after_failed),
        "new_failure_ids": sorted(after_failed - before_failed),
        "metric_deltas": {
            f"{field}_delta": _metric_delta(before_summary[field], after_summary[field])
            for field in metric_fields
        },
        "summary": {
            "resolved": len(before_failed - after_failed),
            "persistent": len(before_failed & after_failed),
            "new": len(after_failed - before_failed),
            "status": status,
        },
        "limitations": list(COMPARISON_LIMITATIONS),
        "interpretation_boundary": COMPARISON_INTERPRETATION,
    }


def compare_revocation_bundles(
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
    before = verify_revocation_bundle(before_bundle, public_key_pem=before_public_key_pem)
    after = verify_revocation_bundle(after_bundle, public_key_pem=after_public_key_pem)
    comparison_time = created_at or _now_not_before(after["report"]["generated_at"])
    value = _comparison_value(comparison_id, before, after, comparison_time)
    target = Path(output)
    _write_new(target, _canonical(value))
    try:
        verify_revocation_comparison(
            target,
            before_bundle,
            after_bundle,
            before_public_key_pem=before_public_key_pem,
            after_public_key_pem=after_public_key_pem,
        )
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return value


def verify_revocation_comparison(
    comparison: Path,
    before_bundle: Path,
    after_bundle: Path,
    *,
    before_public_key_pem: Optional[bytes] = None,
    after_public_key_pem: Optional[bytes] = None,
) -> Dict[str, Any]:
    raw = _read(Path(comparison), private=True)
    value = _strict(raw, "revocation comparison")
    if not isinstance(value, dict) or value.get("schema") != COMPARISON_SCHEMA:
        raise ValueError("unsupported revocation comparison schema")
    _portable_id(value.get("comparison_id"), "comparison.comparison_id")
    _timestamp(value.get("created_at"), "comparison.created_at")
    before = verify_revocation_bundle(before_bundle, public_key_pem=before_public_key_pem)
    after = verify_revocation_bundle(after_bundle, public_key_pem=after_public_key_pem)
    expected = _comparison_value(value["comparison_id"], before, after, value["created_at"])
    if value != expected or raw != _canonical(expected):
        raise ValueError("revocation remediation comparison does not independently recompute")
    return {
        "valid": True,
        "comparison_id": value["comparison_id"],
        "status": value["summary"]["status"],
        "comparison_sha256": _sha256(raw),
        "interpretation_boundary": COMPARISON_INTERPRETATION,
    }


def _oscal_uuid(kind: str, seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"lurescope:lurerevoke:{kind}:{seed}"))


def _oscal_prop(name: str, value: Any) -> Dict[str, str]:
    rendered = str(value).lower() if isinstance(value, bool) else str(value)
    return {"name": name, "ns": "https://github.com/immu4989/lurescope/ns/oscal", "value": rendered}


def export_revocation_oscal(
    bundle: Path, output: Path, *, assessment_plan_href: str, public_key_pem: Optional[bytes] = None
) -> Dict[str, Any]:
    if not isinstance(assessment_plan_href, str) or not assessment_plan_href.startswith(
        ("https://", "urn:")
    ):
        raise ValueError("assessment_plan_href must be an operator-controlled https: or urn: URI")
    verified = verify_revocation_bundle(bundle, public_key_pem=public_key_pem)
    report = verified["report"]
    seed = f"{verified['manifest_sha256']}:{verified['statement_sha256']}"
    observations = []
    for item in report["delivery_results"]:
        evidence_digest = _sha256(
            _canonical(
                {
                    key: item[key]
                    for key in (
                        "event_id",
                        "node_id",
                        "applied_at_ms",
                        "convergence_ms",
                        "deadline_met",
                    )
                }
            )
        )
        observations.append(
            {
                "uuid": _oscal_uuid("observation", f"{seed}:{item['event_id']}:{item['node_id']}"),
                "title": f"Revocation convergence: {item['event_id']} / {item['node_id']}",
                "description": (
                    "Typed receiver metadata was independently evaluated against the "
                    "declared propagation deadline."
                ),
                "props": [
                    _oscal_prop("event-id", item["event_id"]),
                    _oscal_prop("node-id", item["node_id"]),
                    _oscal_prop("deadline-met", item["deadline_met"]),
                    _oscal_prop("convergence-ms", item["convergence_ms"]),
                ],
                "methods": ["TEST"],
                "types": ["control-objective"],
                "relevant-evidence": [
                    {
                        "href": f"urn:sha256:{evidence_digest}",
                        "description": "Digest of the typed delivery result.",
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
                "title": f"LureRevoke Evidence — {verified['bundle_id']}",
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
                    "title": "Continuous-access revocation observations",
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
                                    "Controls for which revocation evidence may be relevant; "
                                    "inclusion is not a satisfaction determination."
                                ),
                                "include-controls": [
                                    {"control-id": item}
                                    for item in (
                                        "ac-2",
                                        "ac-3",
                                        "ac-6",
                                        "au-2",
                                        "ca-7",
                                        "ia-5",
                                        "si-4",
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


def export_revocation_sarif(
    bundle: Path, output: Path, *, public_key_pem: Optional[bytes] = None
) -> Dict[str, Any]:
    verified = verify_revocation_bundle(bundle, public_key_pem=public_key_pem)
    report = verified["report"]
    rules = [
        ("LURE-REVOKE-001", "Revocation deadline missed", "error"),
        ("LURE-REVOKE-002", "Revoked-subject access allowed", "error"),
        ("LURE-REVOKE-003", "Unrelated subject denied", "warning"),
        ("LURE-REVOKE-004", "Signal disposition mismatch", "error"),
    ]
    results = []
    for item in report["delivery_results"]:
        if not item["deadline_met"]:
            results.append(
                {
                    "ruleId": "LURE-REVOKE-001",
                    "level": "error",
                    "message": {
                        "text": (
                            f"Revocation {item['event_id']} missed its deadline at node "
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
            "LURE-REVOKE-002"
            if item["classification"] == "revocation_bypass"
            else "LURE-REVOKE-003"
            if item["classification"] == "collateral_denial"
            else None
        )
        if rule_id:
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error" if rule_id.endswith("002") else "warning",
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
                    },
                }
            )
    if report["summary"]["signal_disposition_accuracy"] < 1.0:
        results.append(
            {
                "ruleId": "LURE-REVOKE-004",
                "level": "error",
                "message": {
                    "text": (
                        "One or more submitted signal dispositions did not independently recompute."
                    )
                },
                "fingerprints": {"runSha256": report["run_sha256"]},
                "properties": {
                    "signalDispositionAccuracy": report["summary"]["signal_disposition_accuracy"]
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
                        "name": "LureScope LureRevoke Evidence",
                        "version": __version__,
                        "informationUri": "https://github.com/immu4989/lurescope/blob/main/docs/LUREREVOKE_EVIDENCE.md",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": title.replace(" ", ""),
                                "shortDescription": {"text": title},
                                "fullDescription": {"text": f"{title}. {INTERPRETATION}"},
                            }
                            for rule_id, title, _ in rules
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
