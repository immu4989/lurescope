"""Independent verifier for LureMandate's body-free OpenTelemetry projection."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping

from .mandate import LIMITATIONS as RUN_LIMITATIONS
from .mandate import (
    MAX_APPROVALS,
    MAX_INPUT_BYTES,
    MAX_TRANSACTIONS,
    OUTCOMES,
    REASONS,
    RUN_SCHEMA,
    _digest,
    _instant,
    _read,
    _sha256,
    _validate_approval,
    _validate_intent,
    validate_mandate_plan,
    validate_mandate_run,
)
from .mandate import PRIVACY as RUN_PRIVACY
from .permit import _canonical, _exact, _id, _integer, _strict, _timestamp

OTEL_EXPORT_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-otel-log-export/v1"
OTEL_PROJECTION_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-otel-projection/v1"
INTENT_EVENT = "org.lurebench.luremandate.intent_proposed"
APPROVAL_EVENT = "org.lurebench.luremandate.approval_recorded"
DECISION_EVENT = "org.lurebench.luremandate.decision_recorded"
OUTCOME_EVENT = "org.lurebench.luremandate.outcome_recorded"
MAX_RECORDS = MAX_TRANSACTIONS * (MAX_APPROVALS + 3)
MAX_UNIX_NANO = 9_223_372_036_854_775_807
_TRACE_ID = re.compile(r"^[a-f0-9]{32}$")
_SPAN_ID = re.compile(r"^[a-f0-9]{16}$")

EXPORT_LIMITATIONS = [
    "strict_body_free_projection_of_the_opentelemetry_log_data_model_not_raw_otlp",
    "custom_lurebench_event_names_and_attributes_are_not_opentelemetry_semantic_conventions",
    "timestamps_resource_identity_and_attributes_require_external_instrumentation_assurance",
    "only_opaque_identifiers_spiffe_ids_digests_decisions_and_bounded_impact_units_are_accepted",
]
PROJECTION_LIMITATIONS = [
    "projection_rejects_log_body_unknown_attributes_free_text_prompts_commands_payloads_credentials_hosts_urls_and_customer_content",
    "benchmark_timing_uses_origin_clock_timestamp_not_collector_observed_timestamp",
    "each_transaction_requires_one_trace_with_exact_intent_decision_outcome_and_approval_coverage",
    "trace_context_correlates_records_but_does_not_authenticate_or_prove_causality",
    "projection_does_not_prove_telemetry_completeness_clock_sync_delivery_approver_identity_or_enforcement",
    "projection_is_not_otlp_or_opentelemetry_semantic_conventions_conformance",
]
PRIVACY = {
    "body_accepted": False,
    "instrumentation_scope_accepted": False,
    "free_text_or_transaction_content_accepted": False,
    "tokens_credentials_prompts_commands_payloads_hosts_urls_or_customer_content_accepted": False,
    "opaque_identifiers_spiffe_ids_digests_decisions_and_bounded_impact_units_only": True,
}
CLOCK_BOUNDARY = {
    "benchmark_time_field": "Timestamp",
    "collector_time_field": "ObservedTimestamp",
    "observed_timestamp_used_for_benchmark_timing": False,
    "timestamp_resolution": "microsecond_aligned_unix_nanoseconds",
    "event_timestamp_binding": "exact_declared_luremandate_lifecycle_time",
    "external_clock_assurance_required": True,
}

_TX = "luremandate.transaction.id"
_SEQUENCE = "luremandate.transaction.sequence"
_INTENT_KEYS = (
    _TX,
    _SEQUENCE,
    "luremandate.intent.id",
    "luremandate.intent.proposed_at",
    "luremandate.tenant.id",
    "luremandate.run.id",
    "luremandate.agent.id",
    "luremandate.workload.spiffe_id",
    "luremandate.requester.id",
    "luremandate.policy.id",
    "luremandate.action",
    "luremandate.resource.id",
    "luremandate.impact_units",
    "luremandate.intent.nonce",
    "luremandate.intent.sha256",
)
_APPROVAL_KEYS = (
    _TX,
    "luremandate.approval.id",
    "luremandate.approver.id",
    "luremandate.approver.role",
    "luremandate.approval.decision",
    "luremandate.intent.sha256",
    "luremandate.approval.issued_at",
    "luremandate.approval.expires_at",
    "luremandate.approval.nonce",
)
_DECISION_KEYS = (
    _TX,
    "luremandate.decision.id",
    "luremandate.decision.decided_at",
    "luremandate.decision.value",
    "luremandate.decision.reason_code",
)
_OUTCOME_KEYS = (
    _TX,
    "luremandate.outcome.state",
    "luremandate.outcome.observed_at",
    "luremandate.sensor.id",
)


def _unix_nano(value: Any, field: str) -> int:
    instant = _instant(value, field)
    delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _context_id(value: Any, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None or set(value) == {"0"}:
        raise ValueError(f"{field} must be a nonzero lowercase hexadecimal identifier")
    return value


def _receiver(value: Any) -> Dict[str, Any]:
    receiver = _exact(
        value,
        "OpenTelemetry receiver",
        ("name", "instance_id", "version", "artifact_sha256"),
    )
    for name in ("name", "instance_id", "version"):
        _id(receiver[name], f"receiver.{name}")
    if receiver["artifact_sha256"] is not None:
        _digest(receiver["artifact_sha256"], "receiver artifact")
    return dict(receiver)


def _resource(value: Any, receiver: Mapping[str, Any], field: str) -> None:
    resource = _exact(
        value,
        field,
        ("service.name", "service.instance.id", "service.version"),
    )
    if resource != {
        "service.name": receiver["name"],
        "service.instance.id": receiver["instance_id"],
        "service.version": receiver["version"],
    }:
        raise ValueError("OpenTelemetry resource differs from the declared receiver")


def _intent_from_attributes(value: Any, field: str) -> tuple[str, int, Dict[str, Any], str]:
    attributes = _exact(value, field, _INTENT_KEYS)
    transaction_id = _id(attributes[_TX], f"{field}.{_TX}")
    sequence = _integer(attributes[_SEQUENCE], f"{field}.{_SEQUENCE}", 1, MAX_TRANSACTIONS)
    intent = _validate_intent(
        {
            "intent_id": attributes["luremandate.intent.id"],
            "proposed_at": attributes["luremandate.intent.proposed_at"],
            "tenant_id": attributes["luremandate.tenant.id"],
            "run_id": attributes["luremandate.run.id"],
            "agent_id": attributes["luremandate.agent.id"],
            "workload_spiffe_id": attributes["luremandate.workload.spiffe_id"],
            "requester_id": attributes["luremandate.requester.id"],
            "policy_id": attributes["luremandate.policy.id"],
            "action": attributes["luremandate.action"],
            "resource_id": attributes["luremandate.resource.id"],
            "impact_units": attributes["luremandate.impact_units"],
            "intent_nonce": attributes["luremandate.intent.nonce"],
        },
        f"{field}.intent",
    )
    digest = _digest(attributes["luremandate.intent.sha256"], f"{field}.intent_sha256")
    if digest != _sha256(_canonical(intent)):
        raise ValueError("OpenTelemetry intent digest does not match its exact attributes")
    return transaction_id, sequence, intent, digest


def _approval_from_attributes(value: Any, field: str) -> tuple[str, Dict[str, Any]]:
    attributes = _exact(value, field, _APPROVAL_KEYS)
    transaction_id = _id(attributes[_TX], f"{field}.{_TX}")
    approval = _validate_approval(
        {
            "approval_id": attributes["luremandate.approval.id"],
            "approver_id": attributes["luremandate.approver.id"],
            "approver_role": attributes["luremandate.approver.role"],
            "decision": attributes["luremandate.approval.decision"],
            "intent_sha256": attributes["luremandate.intent.sha256"],
            "issued_at": attributes["luremandate.approval.issued_at"],
            "expires_at": attributes["luremandate.approval.expires_at"],
            "nonce": attributes["luremandate.approval.nonce"],
        },
        f"{field}.approval",
    )
    return transaction_id, approval


def _decision_from_attributes(value: Any, field: str) -> tuple[str, Dict[str, Any]]:
    attributes = _exact(value, field, _DECISION_KEYS)
    transaction_id = _id(attributes[_TX], f"{field}.{_TX}")
    decision = {
        "decision_id": _id(attributes["luremandate.decision.id"], f"{field}.decision_id"),
        "decided_at": _timestamp(
            attributes["luremandate.decision.decided_at"], f"{field}.decided_at"
        ),
        "decision": attributes["luremandate.decision.value"],
        "reason_code": attributes["luremandate.decision.reason_code"],
    }
    if decision["decision"] not in {"allow", "block"} or decision["reason_code"] not in REASONS:
        raise ValueError("OpenTelemetry authority decision or reason is unsupported")
    return transaction_id, decision


def _outcome_from_attributes(value: Any, field: str) -> tuple[str, Dict[str, Any]]:
    attributes = _exact(value, field, _OUTCOME_KEYS)
    transaction_id = _id(attributes[_TX], f"{field}.{_TX}")
    state = attributes["luremandate.outcome.state"]
    if state not in OUTCOMES:
        raise ValueError("OpenTelemetry outcome state is unsupported")
    observed_at = attributes["luremandate.outcome.observed_at"]
    sensor_id = attributes["luremandate.sensor.id"]
    if state in {"effect_observed", "no_effect_observed"}:
        _timestamp(observed_at, f"{field}.observed_at")
        _id(sensor_id, f"{field}.sensor_id")
    elif observed_at is not None or sensor_id is not None:
        raise ValueError("unobserved OpenTelemetry outcome claims sensor metadata")
    return transaction_id, {"state": state, "observed_at": observed_at, "sensor_id": sensor_id}


def _groups(export: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    receiver = export["receiver"]
    generated_nano = _unix_nano(export["generated_at"], "generated_at")
    origin = export["time_origin_unix_nano"]
    grouped: Dict[str, Dict[str, Any]] = {}
    trace_transactions: Dict[str, str] = {}
    transaction_traces: Dict[str, str] = {}
    contexts: set[tuple[str, str]] = set()
    for index, item in enumerate(export["records"]):
        record = _exact(
            item,
            f"records[{index}]",
            (
                "Timestamp",
                "ObservedTimestamp",
                "TraceId",
                "SpanId",
                "EventName",
                "Resource",
                "Attributes",
            ),
        )
        timestamp = _integer(record["Timestamp"], "Timestamp", 1, MAX_UNIX_NANO)
        observed = _integer(record["ObservedTimestamp"], "ObservedTimestamp", 1, MAX_UNIX_NANO)
        if timestamp < origin or timestamp > generated_nano or observed > generated_nano:
            raise ValueError("OpenTelemetry record falls outside its export window")
        if timestamp % 1_000 or observed % 1_000:
            raise ValueError("OpenTelemetry timestamps must be microsecond aligned")
        trace_id = _context_id(record["TraceId"], "TraceId", _TRACE_ID)
        span_id = _context_id(record["SpanId"], "SpanId", _SPAN_ID)
        if (trace_id, span_id) in contexts:
            raise ValueError("OpenTelemetry trace/span context is duplicated")
        contexts.add((trace_id, span_id))
        _resource(record["Resource"], receiver, f"records[{index}].Resource")
        event_name = record["EventName"]
        if event_name == INTENT_EVENT:
            transaction_id, sequence, intent, digest = _intent_from_attributes(
                record["Attributes"], f"records[{index}].Attributes"
            )
            event = {"sequence": sequence, "intent": intent, "intent_sha256": digest}
            expected_timestamp = intent["proposed_at"]
        elif event_name == APPROVAL_EVENT:
            transaction_id, event = _approval_from_attributes(
                record["Attributes"], f"records[{index}].Attributes"
            )
            expected_timestamp = event["issued_at"]
        elif event_name == DECISION_EVENT:
            transaction_id, event = _decision_from_attributes(
                record["Attributes"], f"records[{index}].Attributes"
            )
            expected_timestamp = event["decided_at"]
        elif event_name == OUTCOME_EVENT:
            transaction_id, event = _outcome_from_attributes(
                record["Attributes"], f"records[{index}].Attributes"
            )
            expected_timestamp = event["observed_at"]
        else:
            raise ValueError("OpenTelemetry event name is unsupported")
        prior_transaction = trace_transactions.setdefault(trace_id, transaction_id)
        prior_trace = transaction_traces.setdefault(transaction_id, trace_id)
        if prior_transaction != transaction_id or prior_trace != trace_id:
            raise ValueError("each transaction must bind exactly one OpenTelemetry trace")
        group = grouped.setdefault(
            transaction_id, {"intent": [], "approval": [], "decision": [], "outcome": []}
        )
        kind = {
            INTENT_EVENT: "intent",
            APPROVAL_EVENT: "approval",
            DECISION_EVENT: "decision",
            OUTCOME_EVENT: "outcome",
        }[event_name]
        group[kind].append((event, timestamp))
        if expected_timestamp is not None and timestamp != _unix_nano(
            expected_timestamp, f"{event_name} time"
        ):
            raise ValueError("OpenTelemetry Timestamp differs from its declared lifecycle time")
    for transaction_id, group in grouped.items():
        if len(group["intent"]) != 1 or len(group["decision"]) != 1 or len(group["outcome"]) != 1:
            raise ValueError(
                f"transaction {transaction_id} lacks exact intent, decision, or outcome coverage"
            )
        outcome, outcome_timestamp = group["outcome"][0]
        decision = group["decision"][0][0]
        if outcome["observed_at"] is None and outcome_timestamp != _unix_nano(
            decision["decided_at"], "decision time"
        ):
            raise ValueError("unobserved outcome timestamp differs from its decision")
    return grouped


def _validate_export(value: Any, plan_value: Mapping[str, Any]) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value)
    export = _exact(
        value,
        "OpenTelemetry LureMandate log export",
        (
            "schema",
            "schema_version",
            "export_id",
            "generated_at",
            "time_origin_unix_nano",
            "campaign_id",
            "plan_sha256",
            "run_id",
            "started_at",
            "completed_at",
            "receiver",
            "records",
            "privacy",
            "limitations",
        ),
    )
    if export["schema"] != OTEL_EXPORT_SCHEMA or export["schema_version"] != 1:
        raise ValueError("unsupported LureMandate OpenTelemetry export")
    for name in ("export_id", "campaign_id", "run_id"):
        _id(export[name], f"export.{name}")
    _timestamp(export["generated_at"], "generated_at")
    started = _instant(export["started_at"], "started_at")
    completed = _instant(export["completed_at"], "completed_at")
    generated = _instant(export["generated_at"], "generated_at")
    if (
        started <= _instant(plan["created_at"], "plan.created_at")
        or not started <= completed < generated
    ):
        raise ValueError("OpenTelemetry run or export window is invalid")
    origin = _integer(export["time_origin_unix_nano"], "time origin", 1, MAX_UNIX_NANO)
    if origin != _unix_nano(export["started_at"], "started_at"):
        raise ValueError("OpenTelemetry origin differs from run start")
    if export["campaign_id"] != plan["campaign_id"] or _digest(
        export["plan_sha256"], "plan_sha256"
    ) != _sha256(_canonical(plan)):
        raise ValueError("OpenTelemetry export does not bind its plan")
    _receiver(export["receiver"])
    if not isinstance(export["records"], list) or not 1 <= len(export["records"]) <= MAX_RECORDS:
        raise ValueError("OpenTelemetry records must be a nonempty bounded array")
    if export["privacy"] != PRIVACY or export["limitations"] != EXPORT_LIMITATIONS:
        raise ValueError("OpenTelemetry privacy or limitations are incomplete")
    if not 1 <= len(_groups(export)) <= MAX_TRANSACTIONS:
        raise ValueError("OpenTelemetry transaction count is unsupported")
    return dict(export)


def _expected_projection(
    plan_value: Any,
    export_value: Any,
    *,
    producer_version: Any,
) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value)
    export = _validate_export(export_value, plan)
    producer_version = _id(producer_version, "producer version")
    grouped = _groups(export)
    transactions = []
    for transaction_id, group in grouped.items():
        intent_record = group["intent"][0][0]
        transactions.append(
            {
                "transaction_id": transaction_id,
                "sequence": intent_record["sequence"],
                "intent": intent_record["intent"],
                "intent_sha256": intent_record["intent_sha256"],
                "approvals": sorted(
                    (item[0] for item in group["approval"]),
                    key=lambda item: item["approval_id"],
                ),
                "decision": group["decision"][0][0],
                "outcome": group["outcome"][0][0],
            }
        )
    transactions.sort(key=lambda item: item["sequence"])
    receiver = export["receiver"]
    run = validate_mandate_run(
        {
            "schema": RUN_SCHEMA,
            "schema_version": 1,
            "run_id": export["run_id"],
            "campaign_id": export["campaign_id"],
            "plan_sha256": export["plan_sha256"],
            "started_at": export["started_at"],
            "completed_at": export["completed_at"],
            "engine": {
                "engine_id": receiver["name"],
                "engine_version": receiver["version"],
                "engine_artifact_sha256": receiver["artifact_sha256"],
            },
            "transactions": transactions,
            "privacy": dict(RUN_PRIVACY),
            "limitations": list(RUN_LIMITATIONS),
        },
        plan,
    )
    return {
        "schema": OTEL_PROJECTION_SCHEMA,
        "schema_version": 1,
        "generated_at": export["generated_at"],
        "implementation": {"name": "lurebench", "version": producer_version},
        "inputs": {
            "mandate_plan": plan,
            "mandate_plan_sha256": _sha256(_canonical(plan)),
            "otel_log_export": export,
            "otel_log_export_sha256": _sha256(_canonical(export)),
        },
        "run": run,
        "run_sha256": _sha256(_canonical(run)),
        "clock_boundary": dict(CLOCK_BOUNDARY),
        "privacy": dict(PRIVACY),
        "limitations": list(PROJECTION_LIMITATIONS),
    }


def validate_mandate_otel_projection(value: Any) -> Dict[str, Any]:
    projection = _exact(
        value,
        "OpenTelemetry LureMandate projection",
        (
            "schema",
            "schema_version",
            "generated_at",
            "implementation",
            "inputs",
            "run",
            "run_sha256",
            "clock_boundary",
            "privacy",
            "limitations",
        ),
    )
    if projection["schema"] != OTEL_PROJECTION_SCHEMA or projection["schema_version"] != 1:
        raise ValueError("unsupported LureMandate OpenTelemetry projection")
    implementation = _exact(projection["implementation"], "implementation", ("name", "version"))
    if implementation["name"] != "lurebench":
        raise ValueError("LureMandate OpenTelemetry producer is unsupported")
    inputs = projection["inputs"]
    if not isinstance(inputs, dict):
        raise ValueError("LureMandate OpenTelemetry inputs must be an object")
    expected = _expected_projection(
        inputs.get("mandate_plan"),
        inputs.get("otel_log_export"),
        producer_version=implementation["version"],
    )
    if projection != expected:
        raise ValueError("LureMandate OpenTelemetry projection does not independently reproduce")
    return dict(projection)


def load_mandate_otel_projection(path: Path) -> Dict[str, Any]:
    return validate_mandate_otel_projection(
        _strict(
            _read(Path(path), "LureMandate OpenTelemetry projection", MAX_INPUT_BYTES),
            "LureMandate OpenTelemetry projection",
        )
    )
