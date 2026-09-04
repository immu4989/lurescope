"""Independent verifier for LureIdentity's body-free OpenTelemetry projection."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping

from .identity import (
    DECISIONS,
    DISPOSITIONS,
    MAX_EVENTS,
    MAX_NODES,
    MAX_PROBES,
    REASONS,
    RUN_LIMITATIONS,
    RUN_SCHEMA,
    _time,
    _validate_plan,
    _validate_run,
)
from .permit import _canonical, _digest, _exact, _id, _integer, _read, _sha256, _strict, _timestamp

OTEL_EXPORT_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-otel-log-export/v1"
OTEL_PROJECTION_SCHEMA = (
    "https://github.com/immu4989/lurebench/spec/lureidentity-otel-projection/v1"
)
LIFECYCLE_EVENT = "org.lurebench.lureidentity.lifecycle_event_observed"
ACCESS_EVENT = "org.lurebench.lureidentity.access_decided"
MAX_RECORDS = MAX_EVENTS * MAX_NODES * 4 + MAX_PROBES
MAX_UNIX_NANO = 9_223_372_036_854_775_807
_TRACE_ID = re.compile(r"^[a-f0-9]{32}$")
_SPAN_ID = re.compile(r"^[a-f0-9]{16}$")

EXPORT_LIMITATIONS = [
    "strict_body_free_projection_of_the_opentelemetry_log_data_model_not_raw_otlp",
    "custom_lurebench_event_names_and_attributes_are_not_opentelemetry_semantic_conventions",
    "timestamps_service_identity_and_attributes_require_external_instrumentation_assurance",
    "only_opaque_plan_identifiers_digests_decisions_and_reason_codes_are_accepted",
]
PROJECTION_LIMITATIONS = [
    "projection_rejects_log_body_unknown_attributes_raw_directory_or_subject_ids_and_secrets",
    "benchmark_timing_uses_origin_clock_timestamp_not_collector_observed_timestamp",
    "access_event_timestamp_must_equal_the_preregistered_probe_attempt_time",
    "trace_context_correlates_records_but_does_not_authenticate_or_prove_causality",
    "projection_does_not_prove_telemetry_completeness_clock_sync_delivery_or_enforcement",
    "projection_is_not_otlp_or_opentelemetry_semantic_conventions_conformance",
]
PRIVACY = {
    "body_accepted": False,
    "raw_directory_or_subject_identifiers_accepted": False,
    "spiffe_ids_accepted_in_records": False,
    "tokens_credentials_prompts_payloads_or_targets_accepted": False,
    "opaque_plan_identifiers_and_digests_only": True,
}
CLOCK_BOUNDARY = {
    "benchmark_time_field": "Timestamp",
    "collector_time_field": "ObservedTimestamp",
    "observed_timestamp_used_for_benchmark_timing": False,
    "timestamp_resolution": "millisecond_aligned_relative_to_time_origin_unix_nano",
    "access_timestamp_binding": "exact_preregistered_probe_attempt_time",
    "external_clock_assurance_required": True,
}


def _unix_nano(value: str) -> int:
    instant = _time(value).astimezone(timezone.utc)
    delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _relative_ms(value: Any, origin: int, field: str) -> int:
    timestamp = _integer(value, field, 1, MAX_UNIX_NANO)
    delta = timestamp - origin
    if delta < 0 or delta % 1_000_000:
        raise ValueError(f"{field} is not millisecond-aligned at or after the origin")
    return _integer(delta // 1_000_000, f"{field} relative milliseconds", 0, 86_400_000)


def _context_id(value: Any, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None or set(value) == {"0"}:
        raise ValueError(f"{field} must be a nonzero lowercase hexadecimal identifier")
    return value


def _validate_export(value: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    export = _exact(
        value,
        "OpenTelemetry identity log export",
        (
            "schema",
            "schema_version",
            "export_id",
            "generated_at",
            "time_origin_unix_nano",
            "receiver",
            "records",
            "limitations",
        ),
    )
    if export["schema"] != OTEL_EXPORT_SCHEMA or export["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity OpenTelemetry export schema")
    _id(export["export_id"], "otel export.export_id")
    _timestamp(export["generated_at"], "otel export.generated_at")
    if _time(export["generated_at"]) < _time(plan["created_at"]):
        raise ValueError("OpenTelemetry export predates its identity plan")
    origin = _integer(export["time_origin_unix_nano"], "time origin", 1, MAX_UNIX_NANO)
    generated_nano = _unix_nano(export["generated_at"])
    if origin > generated_nano:
        raise ValueError("OpenTelemetry time origin follows export generation")
    receiver = _exact(
        export["receiver"], "OpenTelemetry receiver", ("name", "version", "artifact_sha256")
    )
    _id(receiver["name"], "receiver.name")
    _id(receiver["version"], "receiver.version")
    if receiver["artifact_sha256"] is not None:
        _digest(receiver["artifact_sha256"], "receiver.artifact_sha256")
    records = export["records"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError("OpenTelemetry records must be a nonempty bounded array")
    events = {item["event_id"] for item in plan["events"]}
    nodes = {item["node_id"] for item in plan["nodes"]}
    probes = {item["probe_id"]: item for item in plan["probes"]}
    contexts = set()
    for index, item in enumerate(records):
        record = _exact(
            item,
            f"otel records[{index}]",
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
        relative_ms = _relative_ms(timestamp, origin, "Timestamp")
        observed = _integer(record["ObservedTimestamp"], "ObservedTimestamp", 1, MAX_UNIX_NANO)
        if timestamp > generated_nano or observed > generated_nano:
            raise ValueError("OpenTelemetry record follows export generation")
        context = (
            _context_id(record["TraceId"], "TraceId", _TRACE_ID),
            _context_id(record["SpanId"], "SpanId", _SPAN_ID),
        )
        if context in contexts:
            raise ValueError("OpenTelemetry trace/span context is reused")
        contexts.add(context)
        resource = _exact(
            record["Resource"],
            "OpenTelemetry resource",
            ("service.name", "service.instance.id", "service.version"),
        )
        if (
            resource["service.name"] != receiver["name"]
            or resource["service.version"] != receiver["version"]
        ):
            raise ValueError("OpenTelemetry resource differs from its receiver")
        instance = _id(resource["service.instance.id"], "service.instance.id")
        attributes = record["Attributes"]
        if record["EventName"] == LIFECYCLE_EVENT:
            event_observation = _exact(
                attributes,
                "OpenTelemetry lifecycle attributes",
                ("observation_id", "event_id", "node_id", "event_sha256", "disposition"),
            )
            _id(event_observation["observation_id"], "lifecycle observation_id")
            if (
                event_observation["event_id"] not in events
                or event_observation["node_id"] not in nodes
            ):
                raise ValueError("OpenTelemetry lifecycle record references unknown plan identity")
            if event_observation["node_id"] != instance:
                raise ValueError("OpenTelemetry lifecycle node differs from service instance")
            _digest(event_observation["event_sha256"], "event_sha256")
            if event_observation["disposition"] not in DISPOSITIONS:
                raise ValueError("OpenTelemetry lifecycle disposition is unsupported")
        elif record["EventName"] == ACCESS_EVENT:
            access = _exact(
                attributes,
                "OpenTelemetry access attributes",
                ("probe_id", "decision", "reason_code"),
            )
            if access["probe_id"] not in probes:
                raise ValueError("OpenTelemetry access references an unknown probe")
            probe = probes[access["probe_id"]]
            if probe["node_id"] != instance:
                raise ValueError("OpenTelemetry access node differs from service instance")
            if relative_ms != probe["attempted_at_ms"]:
                raise ValueError("OpenTelemetry access timestamp differs from its planned probe")
            if access["decision"] not in DECISIONS or access["reason_code"] not in REASONS:
                raise ValueError("OpenTelemetry access result is unsupported")
        else:
            raise ValueError("OpenTelemetry event name is unsupported")
    if export["limitations"] != EXPORT_LIMITATIONS:
        raise ValueError("OpenTelemetry export limitations are invalid")
    return dict(export)


def _expected_projection(
    plan_value: Any,
    export_value: Any,
    *,
    run_id: Any,
    producer_version: Any,
) -> Dict[str, Any]:
    plan = _validate_plan(plan_value)
    export = _validate_export(export_value, plan)
    _id(run_id, "projection run_id")
    _id(producer_version, "projection producer version")
    origin = export["time_origin_unix_nano"]
    event_order = {item["event_id"]: index for index, item in enumerate(plan["events"])}
    node_order = {item["node_id"]: index for index, item in enumerate(plan["nodes"])}
    probe_order = {item["probe_id"]: index for index, item in enumerate(plan["probes"])}
    lifecycle_records = sorted(
        (item for item in export["records"] if item["EventName"] == LIFECYCLE_EVENT),
        key=lambda item: (
            event_order[item["Attributes"]["event_id"]],
            node_order[item["Attributes"]["node_id"]],
            item["Timestamp"],
            item["Attributes"]["observation_id"],
            item["TraceId"],
            item["SpanId"],
        ),
    )
    access_records = sorted(
        (item for item in export["records"] if item["EventName"] == ACCESS_EVENT),
        key=lambda item: (
            probe_order[item["Attributes"]["probe_id"]],
            item["TraceId"],
            item["SpanId"],
        ),
    )
    events = []
    access = []
    for record in lifecycle_records:
        attributes = record["Attributes"]
        events.append(
            {
                "observation_id": attributes["observation_id"],
                "event_id": attributes["event_id"],
                "node_id": attributes["node_id"],
                "received_at_ms": _relative_ms(record["Timestamp"], origin, "Timestamp"),
                "event_sha256": attributes["event_sha256"],
                "disposition": attributes["disposition"],
            }
        )
    for record in access_records:
        attributes = record["Attributes"]
        access.append(
            {
                "probe_id": attributes["probe_id"],
                "decision": attributes["decision"],
                "reason_code": attributes["reason_code"],
            }
        )
    run = _validate_run(
        {
            "schema": RUN_SCHEMA,
            "schema_version": 1,
            "run_id": run_id,
            "generated_at": export["generated_at"],
            "implementation": dict(export["receiver"]),
            "plan_sha256": _sha256(_canonical(plan)),
            "event_observations": events,
            "access_observations": access,
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
            "identity_plan": plan,
            "identity_plan_sha256": _sha256(_canonical(plan)),
            "otel_log_export": export,
            "otel_log_export_sha256": _sha256(_canonical(export)),
        },
        "run": run,
        "run_sha256": _sha256(_canonical(run)),
        "clock_boundary": dict(CLOCK_BOUNDARY),
        "privacy": dict(PRIVACY),
        "limitations": list(PROJECTION_LIMITATIONS),
    }


def validate_identity_otel_projection(value: Any) -> Dict[str, Any]:
    projection = _exact(
        value,
        "OpenTelemetry identity projection",
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
        raise ValueError("unsupported OpenTelemetry identity projection schema")
    implementation = _exact(
        projection["implementation"], "projection implementation", ("name", "version")
    )
    if implementation["name"] != "lurebench":
        raise ValueError("OpenTelemetry identity projection producer must be lurebench")
    inputs = projection["inputs"]
    run = projection["run"]
    if not isinstance(inputs, dict) or not isinstance(run, dict):
        raise ValueError("OpenTelemetry identity projection inputs and run must be objects")
    expected = _expected_projection(
        inputs.get("identity_plan"),
        inputs.get("otel_log_export"),
        run_id=run.get("run_id"),
        producer_version=implementation["version"],
    )
    if projection != expected:
        raise ValueError("OpenTelemetry identity projection does not independently recompute")
    return dict(projection)


def load_identity_otel_projection(path: Path) -> Dict[str, Any]:
    raw = _read(Path(path), private=True)
    projection = validate_identity_otel_projection(
        _strict(raw, "OpenTelemetry identity projection")
    )
    if raw != _canonical(projection):
        raise ValueError("OpenTelemetry identity projection must use canonical JSON")
    return projection
