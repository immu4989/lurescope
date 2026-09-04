"""Independent verification of LureChannel cross-run canary-flow evidence.

This module imports no LureBench code.  It revalidates the reviewed topology,
recomputes every test result, and can preserve exact producer inputs in one
private, self-contained report.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .permit import _canonical, _exact, _id, _integer, _strict, _timestamp, _write_new

PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurechannel-plan-v1"
RUN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurechannel-run-v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurechannel-evaluation-v1"
VERIFICATION_SCHEMA = "https://github.com/immu4989/lurescope/spec/lurechannel-verification/v1"
PRODUCER_VERSION = "1.0.0"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_RUNS = 256
MAX_CHANNELS = 512
MAX_SENSORS = 512
MAX_TESTS = 4096
MAX_SIGHTINGS = 16384
CHANNEL_CLASSES = {
    "approved_collaboration",
    "filesystem",
    "metadata_service",
    "network_proxy",
    "object_store",
    "other_controlled",
    "package_service",
}
PHASES = {"active", "post_termination"}
EXPECTATIONS = {"deliver", "isolate"}
LIMITATIONS = [
    "canary_absence_only_applies_to_declared_channels_sensors_windows_and_runs",
    "sensor_completeness_is_operator_asserted_not_independently_discovered",
    "canaries_do_not_execute_exploits_or_establish_universal_noninterference",
    "passing_is_not_containment_safety_compliance_certification_or_deployment_authorization",
]
VERIFICATION_CHECKS = [
    "strict_source_json_reparsed",
    "canonical_plan_binding_recomputed",
    "canonical_run_binding_recomputed",
    "declared_run_lifetimes_rechecked",
    "cross_domain_test_matrix_rechecked",
    "sensor_topology_rechecked",
    "sensor_window_coverage_recomputed",
    "allowed_delivery_controls_recomputed",
    "unexpected_canary_paths_recomputed",
    "unauthorized_flows_recomputed",
    "post_termination_residue_recomputed",
    "producer_evaluation_reproduced",
]
VERIFICATION_LIMITATIONS = [
    "exact_embedded_inputs_and_independent_recomputation_do_not_authenticate_their_issuer",
    "sensor_window_completeness_remains_an_operator_assertion_not_environment_discovery",
    "absence_of_sightings_only_applies_to_the_declared_test_matrix_and_observation_windows",
    "passing_is_not_universal_noninterference_containment_safety_compliance_or_authorization",
]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _instant(value: Any, field: str) -> datetime:
    timestamp = _timestamp(value, field)
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded(value: Any, field: str, maximum: int, *, allow_empty: bool = False) -> list[Any]:
    minimum = 0 if allow_empty else 1
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{field} must be a bounded array")
    return value


def _ordered(values: list[str], field: str) -> None:
    if values != sorted(values) or len(set(values)) != len(values):
        raise ValueError(f"{field} must be sorted and unique")


def _privacy(value: Any, field: str) -> None:
    expected = {
        "canary_payloads": "excluded_digest_only",
        "customer_content": "excluded",
        "secrets": "excluded",
    }
    if _exact(value, field, tuple(expected)) != expected:
        raise ValueError(f"{field} violates the metadata-only profile")


def _limitations(value: Any, expected: list[str], field: str) -> None:
    if value != expected:
        raise ValueError(f"{field} does not preserve the complete claims boundary")


def validate_channel_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "LureChannel plan",
        (
            "schema",
            "schema_version",
            "campaign_id",
            "created_at",
            "environment",
            "runs",
            "channels",
            "sensors",
            "tests",
            "policy",
            "privacy",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureChannel plan schema")
    _id(plan["campaign_id"], "campaign_id")
    created = _instant(plan["created_at"], "created_at")
    environment = _exact(plan["environment"], "environment", ("environment_id", "tenant_id"))
    _id(environment["environment_id"], "environment_id")
    tenant_id = _id(environment["tenant_id"], "tenant_id")

    runs: Dict[str, Mapping[str, Any]] = {}
    run_ids: list[str] = []
    for index, item in enumerate(_bounded(plan["runs"], "runs", MAX_RUNS)):
        run = _exact(
            item,
            f"runs[{index}]",
            ("run_id", "isolation_domain_id", "tenant_id", "started_at", "ended_at"),
        )
        run_id = _id(run["run_id"], "run_id")
        _id(run["isolation_domain_id"], "isolation_domain_id")
        if run["tenant_id"] != tenant_id:
            raise ValueError("declared run is outside the environment tenant")
        started = _instant(run["started_at"], "run started_at")
        if started <= created:
            raise ValueError("declared run must start after plan creation")
        if run["ended_at"] is not None and _instant(run["ended_at"], "run ended_at") <= started:
            raise ValueError("declared run must have a positive lifetime")
        run_ids.append(run_id)
        runs[run_id] = run
    _ordered(run_ids, "run IDs")

    channels: Dict[str, Mapping[str, Any]] = {}
    channel_ids: list[str] = []
    for index, item in enumerate(_bounded(plan["channels"], "channels", MAX_CHANNELS)):
        channel = _exact(item, f"channels[{index}]", ("channel_id", "channel_class", "authorized"))
        channel_id = _id(channel["channel_id"], "channel_id")
        if channel["channel_class"] not in CHANNEL_CLASSES:
            raise ValueError("unsupported channel class")
        if not isinstance(channel["authorized"], bool):
            raise ValueError("channel authorization must be boolean")
        channel_ids.append(channel_id)
        channels[channel_id] = channel
    _ordered(channel_ids, "channel IDs")

    sensors: Dict[str, Mapping[str, Any]] = {}
    sensor_ids: list[str] = []
    for index, item in enumerate(_bounded(plan["sensors"], "sensors", MAX_SENSORS)):
        sensor = _exact(item, f"sensors[{index}]", ("sensor_id", "channel_ids"))
        sensor_id = _id(sensor["sensor_id"], "sensor_id")
        covered = [
            _id(entry, "sensor channel_id")
            for entry in _bounded(sensor["channel_ids"], "sensor channel_ids", MAX_CHANNELS)
        ]
        _ordered(covered, "sensor channel IDs")
        if not set(covered).issubset(channels):
            raise ValueError("sensor references an unknown channel")
        sensor_ids.append(sensor_id)
        sensors[sensor_id] = sensor
    _ordered(sensor_ids, "sensor IDs")

    test_ids: list[str] = []
    categories: set[tuple[str, str]] = set()
    tested_channels: set[str] = set()
    for index, item in enumerate(_bounded(plan["tests"], "tests", MAX_TESTS)):
        test = _exact(
            item,
            f"tests[{index}]",
            (
                "test_id",
                "source_run_id",
                "observer_run_id",
                "channel_id",
                "phase",
                "expectation",
                "maximum_delivery_ms",
                "required_sensor_ids",
            ),
        )
        test_id = _id(test["test_id"], "test_id")
        source, observer = test["source_run_id"], test["observer_run_id"]
        if source not in runs or observer not in runs or source == observer:
            raise ValueError("test must cross two declared runs")
        if runs[source]["isolation_domain_id"] == runs[observer]["isolation_domain_id"]:
            raise ValueError("test must cross isolation domains")
        channel_id = test["channel_id"]
        if (
            channel_id not in channels
            or test["phase"] not in PHASES
            or test["expectation"] not in EXPECTATIONS
        ):
            raise ValueError("test has an unsupported channel, phase, or expectation")
        expected = "deliver" if channels[channel_id]["authorized"] else "isolate"
        if test["expectation"] != expected:
            raise ValueError("test expectation contradicts channel authorization")
        if test["phase"] == "post_termination" and (
            expected != "isolate" or runs[source]["ended_at"] is None
        ):
            raise ValueError("post-termination test lacks an ended isolated source")
        _integer(test["maximum_delivery_ms"], "maximum_delivery_ms", 1, 3_600_000)
        required = [
            _id(entry, "required sensor")
            for entry in _bounded(test["required_sensor_ids"], "required sensors", MAX_SENSORS)
        ]
        _ordered(required, "required sensor IDs")
        if any(
            sensor not in sensors or channel_id not in sensors[sensor]["channel_ids"]
            for sensor in required
        ):
            raise ValueError("required sensor does not cover the tested channel")
        test_ids.append(test_id)
        categories.add((test["phase"], test["expectation"]))
        tested_channels.add(channel_id)
    _ordered(test_ids, "test IDs")
    if not {("active", "deliver"), ("active", "isolate"), ("post_termination", "isolate")}.issubset(
        categories
    ):
        raise ValueError("plan lacks an allowed, denied, or residual-state control")
    if any(
        not channel["authorized"] and key not in tested_channels
        for key, channel in channels.items()
    ):
        raise ValueError("every denied channel must be tested")
    policy = _exact(
        plan["policy"],
        "policy",
        (
            "require_zero_unauthorized_flows",
            "require_zero_residual_flows",
            "require_complete_sensor_windows",
            "require_all_delivery_controls",
        ),
    )
    if any(value is not True for value in policy.values()):
        raise ValueError("LureChannel v1 requires every fail-closed policy")
    _privacy(plan["privacy"], "privacy")
    _limitations(plan["limitations"], LIMITATIONS, "plan limitations")
    return dict(plan)


def _active(run: Mapping[str, Any], instant: datetime) -> bool:
    if instant < _instant(run["started_at"], "run started_at"):
        return False
    return run["ended_at"] is None or instant <= _instant(run["ended_at"], "run ended_at")


def validate_channel_run(value: Any, plan_value: Mapping[str, Any]) -> Dict[str, Any]:
    plan = validate_channel_plan(plan_value)
    run = _exact(
        value,
        "LureChannel run",
        (
            "schema",
            "schema_version",
            "observation_id",
            "campaign_id",
            "plan_sha256",
            "started_at",
            "completed_at",
            "probes",
            "sensor_windows",
            "privacy",
            "limitations",
        ),
    )
    if run["schema"] != RUN_SCHEMA or run["schema_version"] != 1:
        raise ValueError("unsupported LureChannel run schema")
    _id(run["observation_id"], "observation_id")
    if run["campaign_id"] != plan["campaign_id"]:
        raise ValueError("run campaign does not match plan")
    if _digest(run["plan_sha256"], "plan_sha256") != _sha256(_canonical(plan)):
        raise ValueError("run does not bind the canonical plan")
    started = _instant(run["started_at"], "run started_at")
    completed = _instant(run["completed_at"], "run completed_at")
    if completed <= started or started <= _instant(plan["created_at"], "plan created_at"):
        raise ValueError("observation run has an invalid lifetime")

    tests = {item["test_id"]: item for item in plan["tests"]}
    declared_runs = {item["run_id"]: item for item in plan["runs"]}
    sensors = {item["sensor_id"]: item for item in plan["sensors"]}
    channels = {item["channel_id"] for item in plan["channels"]}
    probes = _bounded(run["probes"], "probes", MAX_TESTS)
    test_ids: list[str] = []
    probe_ids: list[str] = []
    canary_digests: list[str] = []
    sighting_ids: set[str] = set()
    for index, item in enumerate(probes):
        probe = _exact(
            item,
            f"probes[{index}]",
            ("test_id", "probe_id", "canary_sha256", "emitted_at", "sightings"),
        )
        test_id = _id(probe["test_id"], "probe test_id")
        probe_ids.append(_id(probe["probe_id"], "probe_id"))
        canary_digests.append(_digest(probe["canary_sha256"], "canary_sha256"))
        if test_id not in tests:
            raise ValueError("probe references an unknown test")
        test_ids.append(test_id)
        emitted = _instant(probe["emitted_at"], "emitted_at")
        if not started <= emitted <= completed:
            raise ValueError("probe emission falls outside observation run")
        test = tests[test_id]
        source = declared_runs[test["source_run_id"]]
        observer = declared_runs[test["observer_run_id"]]
        deadline = emitted + timedelta(milliseconds=test["maximum_delivery_ms"])
        if deadline > completed:
            raise ValueError("probe deadline falls outside observation run")
        if test["phase"] == "active":
            if not _active(source, deadline) or not _active(observer, deadline):
                raise ValueError("active probe deadline falls outside a declared run lifetime")
        elif emitted <= _instant(source["ended_at"], "source ended_at") or not _active(
            observer, deadline
        ):
            raise ValueError("post-termination probe has invalid deadline timing")
        for position, raw in enumerate(
            _bounded(probe["sightings"], "sightings", MAX_SIGHTINGS, allow_empty=True)
        ):
            sighting = _exact(
                raw,
                f"sightings[{position}]",
                ("sighting_id", "sensor_id", "observer_run_id", "channel_id", "observed_at"),
            )
            sighting_id = _id(sighting["sighting_id"], "sighting_id")
            if sighting_id in sighting_ids:
                raise ValueError("duplicate global sighting_id")
            sighting_ids.add(sighting_id)
            if (
                sighting["sensor_id"] not in sensors
                or sighting["observer_run_id"] not in declared_runs
                or sighting["channel_id"] not in channels
            ):
                raise ValueError("sighting references undeclared topology")
            if sighting["channel_id"] not in sensors[sighting["sensor_id"]]["channel_ids"]:
                raise ValueError("sighting is outside declared sensor topology")
            observed = _instant(sighting["observed_at"], "observed_at")
            if not emitted <= observed <= completed:
                raise ValueError("sighting falls outside its probe window")
            if not _active(declared_runs[sighting["observer_run_id"]], observed):
                raise ValueError("sighting observer was inactive at observation time")
    _ordered(test_ids, "probe test IDs")
    if test_ids != list(tests):
        raise ValueError("run must contain exactly one probe per test")
    if len(set(probe_ids)) != len(probe_ids) or len(set(canary_digests)) != len(canary_digests):
        raise ValueError("probe IDs and canary digests must be unique")

    windows = _bounded(run["sensor_windows"], "sensor_windows", MAX_SENSORS * 4)
    keys: list[tuple[str, str]] = []
    for index, item in enumerate(windows):
        window = _exact(
            item,
            f"sensor_windows[{index}]",
            ("sensor_id", "channel_id", "opened_at", "closed_at", "complete"),
        )
        sensor_id = _id(window["sensor_id"], "window sensor_id")
        channel_id = _id(window["channel_id"], "window channel_id")
        if sensor_id not in sensors or channel_id not in sensors[sensor_id]["channel_ids"]:
            raise ValueError("sensor window is outside declared topology")
        opened = _instant(window["opened_at"], "window opened_at")
        closed = _instant(window["closed_at"], "window closed_at")
        if closed <= opened or opened < started or closed > completed:
            raise ValueError("sensor window has an invalid lifetime")
        if not isinstance(window["complete"], bool):
            raise ValueError("sensor window completeness must be boolean")
        keys.append((sensor_id, channel_id))
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise ValueError("sensor windows must be sorted and unique")
    _privacy(run["privacy"], "run privacy")
    _limitations(run["limitations"], LIMITATIONS, "run limitations")
    return dict(run)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _finding(code: str, test_id: str, subject: str) -> Dict[str, str]:
    return {"code": code, "test_id": test_id, "subject": subject}


def _window_covers(
    window: Optional[Mapping[str, Any]], emitted: datetime, deadline: datetime
) -> bool:
    return bool(
        window
        and window["complete"] is True
        and _instant(window["opened_at"], "window opened_at") <= emitted
        and _instant(window["closed_at"], "window closed_at") >= deadline
    )


def _derive(
    plan_value: Mapping[str, Any], run_value: Mapping[str, Any], evaluated_at: str
) -> Dict[str, Any]:
    plan = validate_channel_plan(plan_value)
    run = validate_channel_run(run_value, plan)
    if _instant(evaluated_at, "evaluated_at") < _instant(run["completed_at"], "completed_at"):
        raise ValueError("evaluation predates the observation run")
    tests = {item["test_id"]: item for item in plan["tests"]}
    windows = {(item["sensor_id"], item["channel_id"]): item for item in run["sensor_windows"]}
    results: list[Dict[str, Any]] = []
    findings: list[Dict[str, str]] = []
    required_windows = complete_windows = 0
    deliveries = delivered = isolations = clean_isolations = 0
    unauthorized = residual = failed = inconclusive = 0
    for probe in run["probes"]:
        test = tests[probe["test_id"]]
        emitted = _instant(probe["emitted_at"], "emitted_at")
        deadline = emitted + timedelta(milliseconds=test["maximum_delivery_ms"])
        required_sensors = set(test["required_sensor_ids"])
        gaps = []
        for sensor_id in test["required_sensor_ids"]:
            required_windows += 1
            if _window_covers(windows.get((sensor_id, test["channel_id"])), emitted, deadline):
                complete_windows += 1
            else:
                gaps.append(sensor_id)
        local: list[Dict[str, str]] = []
        expected_sightings = []
        unexpected_sightings = []
        for sighting in probe["sightings"]:
            exact_path = (
                sighting["observer_run_id"] == test["observer_run_id"]
                and sighting["channel_id"] == test["channel_id"]
                and sighting["sensor_id"] in required_sensors
            )
            (expected_sightings if exact_path else unexpected_sightings).append(sighting)
        direct_failure = False
        if test["expectation"] == "isolate":
            isolations += 1
            if probe["sightings"]:
                direct_failure = True
                code = (
                    "residual_state_flow"
                    if test["phase"] == "post_termination"
                    else "unauthorized_flow"
                )
                for sighting in probe["sightings"]:
                    local.append(_finding(code, test["test_id"], sighting["sighting_id"]))
                if code == "residual_state_flow":
                    residual += len(probe["sightings"])
                else:
                    unauthorized += len(probe["sightings"])
            elif not gaps:
                clean_isolations += 1
        else:
            deliveries += 1
            for sighting in unexpected_sightings:
                direct_failure = True
                unauthorized += 1
                local.append(
                    _finding("unexpected_canary_path", test["test_id"], sighting["sighting_id"])
                )
            by_sensor: Dict[str, list[Mapping[str, Any]]] = {}
            for sighting in expected_sightings:
                by_sensor.setdefault(sighting["sensor_id"], []).append(sighting)
                if _instant(sighting["observed_at"], "observed_at") > deadline:
                    direct_failure = True
                    local.append(
                        _finding("late_delivery_control", test["test_id"], sighting["sensor_id"])
                    )
            for sensor_id, values in by_sensor.items():
                if len(values) > 1:
                    direct_failure = True
                    local.append(_finding("duplicate_control_sighting", test["test_id"], sensor_id))
            missing = sorted(required_sensors - set(by_sensor))
            for sensor_id in missing:
                local.append(_finding("missing_delivery_control", test["test_id"], sensor_id))
            if not direct_failure and not missing and not gaps:
                delivered += 1
        for sensor_id in gaps:
            local.append(_finding("sensor_window_incomplete", test["test_id"], sensor_id))
        if direct_failure:
            status = "fail"
            failed += 1
        elif gaps or (
            test["expectation"] == "deliver"
            and any(item["code"] == "missing_delivery_control" for item in local)
        ):
            status = "inconclusive"
            inconclusive += 1
        else:
            status = "pass"
        local.sort(key=lambda item: (item["code"], item["subject"]))
        findings.extend(local)
        results.append(
            {
                "test_id": test["test_id"],
                "phase": test["phase"],
                "expectation": test["expectation"],
                "status": status,
                "sighting_count": len(probe["sightings"]),
                "complete_sensor_window_count": len(test["required_sensor_ids"]) - len(gaps),
                "required_sensor_window_count": len(test["required_sensor_ids"]),
                "findings": local,
            }
        )
    findings.sort(key=lambda item: (item["test_id"], item["code"], item["subject"]))
    verdict = "fail" if failed else "inconclusive" if inconclusive else "pass"
    summary = {
        "verdict": verdict,
        "test_count": len(plan["tests"]),
        "passed_test_count": len(plan["tests"]) - failed - inconclusive,
        "failed_test_count": failed,
        "inconclusive_test_count": inconclusive,
        "delivery_control_count": deliveries,
        "delivered_control_count": delivered,
        "delivery_control_rate": _ratio(delivered, deliveries),
        "isolation_test_count": isolations,
        "clean_isolation_test_count": clean_isolations,
        "unauthorized_flow_count": unauthorized,
        "residual_flow_count": residual,
        "sighting_count": sum(len(item["sightings"]) for item in run["probes"]),
        "required_sensor_window_count": required_windows,
        "complete_sensor_window_count": complete_windows,
        "sensor_coverage_rate": _ratio(complete_windows, required_windows),
        "finding_count": len(findings),
    }
    return {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "evaluation_id": f"{run['observation_id']}-evaluation",
        "evaluated_at": evaluated_at,
        "engine": {"name": "lurebench-lurechannel", "version": PRODUCER_VERSION},
        "plan_sha256": _sha256(_canonical(plan)),
        "run_sha256": _sha256(_canonical(run)),
        "plan": plan,
        "run": run,
        "results": results,
        "findings": findings,
        "summary": summary,
        "limitations": list(LIMITATIONS),
    }


def validate_channel_evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _exact(
        value,
        "LureChannel evaluation",
        (
            "schema",
            "schema_version",
            "evaluation_id",
            "evaluated_at",
            "engine",
            "plan_sha256",
            "run_sha256",
            "plan",
            "run",
            "results",
            "findings",
            "summary",
            "limitations",
        ),
    )
    if evaluation["schema"] != EVALUATION_SCHEMA or evaluation["schema_version"] != 1:
        raise ValueError("unsupported LureChannel evaluation schema")
    _id(evaluation["evaluation_id"], "evaluation_id")
    engine = _exact(evaluation["engine"], "producer engine", ("name", "version"))
    if engine != {"name": "lurebench-lurechannel", "version": PRODUCER_VERSION}:
        raise ValueError("unsupported LureChannel producer engine")
    _digest(evaluation["plan_sha256"], "evaluation plan_sha256")
    _digest(evaluation["run_sha256"], "evaluation run_sha256")
    _limitations(evaluation["limitations"], LIMITATIONS, "evaluation limitations")
    expected = _derive(evaluation["plan"], evaluation["run"], evaluation["evaluated_at"])
    if evaluation != expected:
        raise ValueError("producer LureChannel evaluation does not independently recompute")
    return dict(evaluation)


def _read(path: Path, label: str, maximum: int = MAX_INPUT_BYTES) -> bytes:
    source = Path(path)
    if not source.is_file() or source.is_symlink() or source.parent.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    payload = source.read_bytes()
    if not 1 <= len(payload) <= maximum:
        raise ValueError(f"{label} exceeds its bounded size")
    return payload


def _encode(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be canonical standard base64")
    try:
        payload = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} must be canonical standard base64") from exc
    if _encode(payload) != value or not 1 <= len(payload) <= MAX_INPUT_BYTES:
        raise ValueError(f"{field} must be canonical bounded standard base64")
    return payload


def _document(value: Any, field: str) -> tuple[Dict[str, Any], bytes]:
    document = _exact(value, field, ("document_sha256", "payload_base64"))
    digest = _digest(document["document_sha256"], f"{field}.document_sha256")
    payload = _decode(document["payload_base64"], f"{field}.payload_base64")
    if _sha256(payload) != digest:
        raise ValueError(f"{field} digest does not match embedded bytes")
    return dict(document), payload


def _verification_value(
    plan_payload: bytes,
    run_payload: bytes,
    evaluation_payload: bytes,
    *,
    verified_at: str,
) -> Dict[str, Any]:
    plan = validate_channel_plan(_strict(plan_payload, "LureChannel plan"))
    run = validate_channel_run(_strict(run_payload, "LureChannel run"), plan)
    evaluation = validate_channel_evaluation(
        _strict(evaluation_payload, "LureChannel producer evaluation")
    )
    if evaluation["plan"] != plan or evaluation["run"] != run:
        raise ValueError("producer evaluation does not embed the supplied plan and run")
    fresh = _derive(plan, run, evaluation["evaluated_at"])
    if fresh != evaluation:
        raise ValueError("producer evaluation is not reproduced from supplied inputs")
    if _instant(verified_at, "verified_at") < _instant(evaluation["evaluated_at"], "evaluated_at"):
        raise ValueError("verification predates the producer evaluation")
    summary = dict(evaluation["summary"])
    summary.update(
        {
            "source_documents_reparsed": True,
            "producer_evaluation_reproduced": True,
            "bounded_noninterference_observed": evaluation["summary"]["verdict"] == "pass",
        }
    )
    return {
        "schema": VERIFICATION_SCHEMA,
        "schema_version": 1,
        "verification_id": f"{evaluation['evaluation_id']}-verification",
        "verified_at": verified_at,
        "engine": {"name": "lurescope-lurechannel-independent", "version": __version__},
        "documents": {
            "plan": {
                "document_sha256": _sha256(plan_payload),
                "payload_base64": _encode(plan_payload),
            },
            "run": {
                "document_sha256": _sha256(run_payload),
                "payload_base64": _encode(run_payload),
            },
            "evaluation": {
                "document_sha256": _sha256(evaluation_payload),
                "payload_base64": _encode(evaluation_payload),
            },
        },
        "producer_evaluation": evaluation,
        "checks": list(VERIFICATION_CHECKS),
        "summary": summary,
        "limitations": list(VERIFICATION_LIMITATIONS),
    }


def validate_channel_verification(value: Any) -> Dict[str, Any]:
    verification = _exact(
        value,
        "LureChannel verification",
        (
            "schema",
            "schema_version",
            "verification_id",
            "verified_at",
            "engine",
            "documents",
            "producer_evaluation",
            "checks",
            "summary",
            "limitations",
        ),
    )
    if verification["schema"] != VERIFICATION_SCHEMA or verification["schema_version"] != 1:
        raise ValueError("unsupported LureChannel verification schema")
    _id(verification["verification_id"], "verification_id")
    engine = _exact(verification["engine"], "verification engine", ("name", "version"))
    if engine != {"name": "lurescope-lurechannel-independent", "version": __version__}:
        raise ValueError("unsupported LureChannel verifier engine")
    if verification["checks"] != VERIFICATION_CHECKS:
        raise ValueError("LureChannel verification check set is incomplete")
    _limitations(
        verification["limitations"],
        VERIFICATION_LIMITATIONS,
        "verification limitations",
    )
    documents = _exact(verification["documents"], "documents", ("plan", "run", "evaluation"))
    _, plan_payload = _document(documents["plan"], "embedded plan")
    _, run_payload = _document(documents["run"], "embedded run")
    _, evaluation_payload = _document(documents["evaluation"], "embedded evaluation")
    expected = _verification_value(
        plan_payload,
        run_payload,
        evaluation_payload,
        verified_at=verification["verified_at"],
    )
    if verification != expected:
        raise ValueError("LureChannel verification does not independently reproduce")
    return dict(verification)


def create_channel_verification(
    plan_path: Path,
    run_path: Path,
    evaluation_path: Path,
    output_path: Path,
    *,
    verified_at: Optional[str] = None,
) -> Dict[str, Any]:
    result = _verification_value(
        _read(plan_path, "LureChannel plan"),
        _read(run_path, "LureChannel run"),
        _read(evaluation_path, "LureChannel evaluation"),
        verified_at=verified_at or _now(),
    )
    _write_new(Path(output_path), _canonical(validate_channel_verification(result)))
    return result


def load_channel_verification(path: Path) -> Dict[str, Any]:
    return validate_channel_verification(
        _strict(
            _read(path, "LureChannel verification", MAX_REPORT_BYTES), "LureChannel verification"
        )
    )
