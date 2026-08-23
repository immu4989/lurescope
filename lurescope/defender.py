"""Offline Microsoft Defender EmailEvents pairing for Shadow Inbox pilots.

The Defender portal CSV and exported messages are joined only in memory. Persisted
case records contain a random Shadow Inbox case id and fixed aggregate signals;
tenant addresses, subjects, recipients, message identifiers, and message content
are never copied into the integration artifacts or reports.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import re
import secrets
from collections import Counter
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from lurebench.calibration import clopper_pearson_upper

from . import service
from .integrations import load_inbox_manifest
from .shadow import (
    ShadowDiscovery,
    build_shadow_report,
    discover_shadow_messages,
    load_analyst_labels,
    load_shadow_run,
    materialize_shadow_discovery,
)

DEFENDER_IMPORT_SCHEMA = "https://github.com/immu4989/lurescope/spec/defender-import/v1"
DEFENDER_CASE_SCHEMA = "https://github.com/immu4989/lurescope/spec/defender-case/v1"
DEFENDER_REPORT_SCHEMA = "https://github.com/immu4989/lurescope/spec/defender-report/v1"
DECISION_RULE = "defender_attention_v1"
MAX_CSV_BYTES = 64 * 1024 * 1024
MAX_CSV_ROWS = 100_000
MAX_CSV_FIELD_BYTES = 256 * 1024

_CASE_ID = re.compile(r"^case-[a-f0-9]{16}$")
_IMPORT_KEYS = {
    "schema",
    "schema_version",
    "generated_at",
    "decision_rule",
    "source_csv_sha256",
    "source_row_count",
    "matched_source_row_count",
    "unmatched_source_row_count",
    "message_count",
    "matched_message_count",
    "unmatched_message_count",
    "identifier_columns",
    "shadow_manifest_sha256",
    "cases_file",
    "cases_sha256",
    "privacy",
}
_CASE_KEYS = {
    "schema",
    "schema_version",
    "case_id",
    "processing_status",
    "match_status",
    "matched_event_rows",
    "native_attention",
    "signals",
}
_SIGNALS = (
    "threat_classified",
    "delivery_action_intervened",
    "delivery_location_intervened",
    "user_action_intervened",
)
_ACTION_INTERVENTIONS = {"blocked", "junked", "replaced"}
_LOCATION_INTERVENTIONS = {
    "deleted items",
    "dropped",
    "failed",
    "junk folder",
    "quarantine",
}
_USER_INTERVENTIONS = {
    "blocked sender",
    "delete",
    "deleted",
    "move to junk",
    "moved to junk",
}
_EMPTY_THREATS = {"", "none", "no threats found", "unknown"}
_PRIVACY_EXCLUSIONS = [
    "source_paths",
    "subjects",
    "sender_addresses",
    "recipient_addresses",
    "internet_message_ids",
    "network_message_ids",
    "tenant_identifiers",
    "url_values",
    "attachment_names",
    "message_content",
]


@dataclass(frozen=True)
class DefenderEvent:
    row_number: int
    identifiers: Tuple[str, ...]
    signals: Tuple[str, ...]


@dataclass(frozen=True)
class DefenderCsv:
    source_sha256: str
    events: Tuple[DefenderEvent, ...]
    has_network_message_id: bool
    has_internet_message_id: bool


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
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


def _replace_private(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        _write_new(temporary, payload)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _read_regular(path: Path, max_bytes: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link input: {path}")
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path.name} exceeds the {max_bytes} byte safety limit")
    return path.read_bytes()


def _identifier(kind: str, value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold()
    if not normalized:
        return None
    return f"{kind}:{normalized}"


def _normalized(value: object) -> str:
    return " ".join(str(value or "").strip().casefold().split())


def _event_signals(row: Dict[str, str]) -> Tuple[str, ...]:
    signals: List[str] = []
    threats = _normalized(row.get("ThreatTypes"))
    if threats not in _EMPTY_THREATS:
        signals.append("threat_classified")
    actions = {
        _normalized(row.get("DeliveryAction")),
        _normalized(row.get("LatestDeliveryAction")),
    }
    if actions & _ACTION_INTERVENTIONS:
        signals.append("delivery_action_intervened")
    locations = {
        _normalized(row.get("DeliveryLocation")),
        _normalized(row.get("LatestDeliveryLocation")),
    }
    if locations & _LOCATION_INTERVENTIONS:
        signals.append("delivery_location_intervened")
    if _normalized(row.get("UserLevelAction")) in _USER_INTERVENTIONS:
        signals.append("user_action_intervened")
    return tuple(signals)


def load_defender_csv(path: Path) -> DefenderCsv:
    """Load a bounded portal EmailEvents CSV without retaining sensitive columns."""
    raw = _read_regular(Path(path), MAX_CSV_BYTES)
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Defender CSV must be UTF-8") from exc
    previous_limit = csv.field_size_limit()
    csv.field_size_limit(MAX_CSV_FIELD_BYTES)
    try:
        reader = csv.DictReader(io.StringIO(decoded, newline=""))
        headers = reader.fieldnames
        if not headers or any(not header for header in headers):
            raise ValueError("Defender CSV has an empty or missing header")
        if len(headers) != len(set(headers)):
            raise ValueError("Defender CSV contains duplicate column names")
        has_network = "NetworkMessageId" in headers
        has_internet = "InternetMessageId" in headers
        if not (has_network or has_internet):
            raise ValueError(
                "Defender CSV needs NetworkMessageId or InternetMessageId for offline pairing"
            )
        if "ThreatTypes" not in headers:
            raise ValueError("Defender CSV is missing the EmailEvents ThreatTypes column")
        if not ({"DeliveryAction", "LatestDeliveryAction"} & set(headers)):
            raise ValueError("Defender CSV needs a delivery-action column")
        if not ({"DeliveryLocation", "LatestDeliveryLocation"} & set(headers)):
            raise ValueError("Defender CSV needs a delivery-location column")

        events: List[DefenderEvent] = []
        for row_number, row in enumerate(reader, 2):
            if row_number > MAX_CSV_ROWS + 1:
                raise ValueError(f"Defender CSV exceeds the {MAX_CSV_ROWS} row safety limit")
            if None in row:
                raise ValueError(f"Defender CSV row {row_number} has more fields than headers")
            identifiers = tuple(
                value
                for value in (
                    _identifier("network", row.get("NetworkMessageId")),
                    _identifier("internet", row.get("InternetMessageId")),
                )
                if value is not None
            )
            if not identifiers:
                raise ValueError(f"Defender CSV row {row_number} has no message identifier")
            events.append(DefenderEvent(row_number, identifiers, _event_signals(row)))
    except csv.Error as exc:
        raise ValueError(f"Defender CSV is malformed: {exc}") from exc
    finally:
        csv.field_size_limit(previous_limit)
    if not events:
        raise ValueError("Defender CSV contains no data rows")
    return DefenderCsv(hashlib.sha256(raw).hexdigest(), tuple(events), has_network, has_internet)


def _message_identifiers(raw: bytes) -> Set[str]:
    message = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    identifiers: Set[str] = set()
    for value in message.get_all("Message-ID", []):
        normalized = _identifier("internet", value)
        if normalized:
            identifiers.add(normalized)
    for header in (
        "X-MS-Exchange-Organization-Network-Message-Id",
        "X-MS-Exchange-Organization-NetworkMessageId",
    ):
        for value in message.get_all(header, []):
            normalized = _identifier("network", value)
            if normalized:
                identifiers.add(normalized)
    return identifiers


def _pair_events(
    discovery: ShadowDiscovery, defender: DefenderCsv
) -> Tuple[List[Tuple[int, ...]], Set[int]]:
    index: Dict[str, Set[int]] = {}
    for event_index, event in enumerate(defender.events):
        for identifier in event.identifiers:
            index.setdefault(identifier, set()).add(event_index)
    assignments: List[Tuple[int, ...]] = []
    owners: Dict[int, int] = {}
    matched_rows: Set[int] = set()
    for message_index, message in enumerate(discovery.messages):
        matches: Set[int] = set()
        for identifier in _message_identifiers(message.raw):
            matches.update(index.get(identifier, ()))
        for event_index in matches:
            previous = owners.setdefault(event_index, message_index)
            if previous != message_index:
                row_number = defender.events[event_index].row_number
                raise ValueError(
                    f"Defender CSV row {row_number} ambiguously matches multiple unique messages"
                )
        ordered = tuple(sorted(matches))
        assignments.append(ordered)
        matched_rows.update(ordered)
    return assignments, matched_rows


def import_defender_shadow(
    csv_path: Path,
    inputs: Sequence[Path],
    output_dir: Path,
    *,
    input_format: str = "auto",
    recursive: bool = False,
    detector_name: str = service.DEFAULT_DETECTOR,
    threshold: Optional[float] = None,
    privacy_profile: str = "salted-commitment",
    nonce: Optional[str] = None,
    issuer: Optional[str] = None,
    signing_key_pem: Optional[bytes] = None,
    max_messages: int = 1_000,
) -> Dict[str, Any]:
    """Pair offline Defender events to exported messages and run Shadow Inbox."""
    defender = load_defender_csv(Path(csv_path))
    discovery = discover_shadow_messages(
        inputs,
        input_format=input_format,
        recursive=recursive,
        max_messages=max_messages,
    )
    assignments, matched_rows = _pair_events(discovery, defender)
    run = materialize_shadow_discovery(
        discovery,
        Path(output_dir),
        detector_name=detector_name,
        threshold=threshold,
        privacy_profile=privacy_profile,
        nonce=nonce,
        issuer=issuer,
        signing_key_pem=signing_key_pem,
        max_messages=max_messages,
    )

    case_records = []
    for message, item, event_indexes in zip(
        discovery.messages, run.inbox.items, assignments, strict=True
    ):
        if item.source != message.source:
            raise RuntimeError("internal error: Shadow Inbox case order changed during import")
        signals = sorted(
            {
                signal
                for event_index in event_indexes
                for signal in defender.events[event_index].signals
            }
        )
        case_records.append(
            {
                "schema": DEFENDER_CASE_SCHEMA,
                "schema_version": 1,
                "case_id": item.case_id,
                "processing_status": item.status,
                "match_status": "matched" if event_indexes else "unmatched",
                "matched_event_rows": len(event_indexes),
                "native_attention": bool(signals) if event_indexes else None,
                "signals": signals,
            }
        )
    cases_payload = b"".join(
        (json.dumps(record, sort_keys=True) + "\n").encode("utf-8") for record in case_records
    )
    cases_path = run.output_dir / "defender-cases.jsonl"
    _write_new(cases_path, cases_payload)
    manifest_digest = hashlib.sha256((run.output_dir / "manifest.jsonl").read_bytes()).hexdigest()
    import_record = {
        "schema": DEFENDER_IMPORT_SCHEMA,
        "schema_version": 1,
        "generated_at": run.inbox.summary["generated_at"],
        "decision_rule": DECISION_RULE,
        "source_csv_sha256": defender.source_sha256,
        "source_row_count": len(defender.events),
        "matched_source_row_count": len(matched_rows),
        "unmatched_source_row_count": len(defender.events) - len(matched_rows),
        "message_count": len(discovery.messages),
        "matched_message_count": sum(bool(value) for value in assignments),
        "unmatched_message_count": sum(not value for value in assignments),
        "identifier_columns": {
            "network_message_id": defender.has_network_message_id,
            "internet_message_id": defender.has_internet_message_id,
        },
        "shadow_manifest_sha256": manifest_digest,
        "cases_file": "defender-cases.jsonl",
        "cases_sha256": hashlib.sha256(cases_payload).hexdigest(),
        "privacy": {
            "identifiers_joined_in_memory_only": True,
            "excluded_fields": _PRIVACY_EXCLUSIONS,
        },
    }
    _write_new(
        run.output_dir / "defender-import.json",
        (json.dumps(import_record, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    report = write_defender_report(run.output_dir)
    return {"run": run, "import": import_record, "report": report}


def load_defender_import(bundle: Path) -> Dict[str, Any]:
    path = Path(bundle) / "defender-import.json"
    value = json.loads(_read_regular(path, 256 * 1024))
    if not isinstance(value, dict) or set(value) != _IMPORT_KEYS:
        raise ValueError("defender-import.json violates the v1 privacy allowlist")
    if value.get("schema") != DEFENDER_IMPORT_SCHEMA or value.get("schema_version") != 1:
        raise ValueError("defender-import.json is not a Defender import v1")
    if value.get("decision_rule") != DECISION_RULE:
        raise ValueError("defender-import.json uses an unsupported decision rule")
    for key in ("source_csv_sha256", "shadow_manifest_sha256", "cases_sha256"):
        if not isinstance(value.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", value[key]):
            raise ValueError(f"defender-import.json {key} is invalid")
    count_keys = (
        "source_row_count",
        "matched_source_row_count",
        "unmatched_source_row_count",
        "message_count",
        "matched_message_count",
        "unmatched_message_count",
    )
    for key in count_keys:
        count = value.get(key)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"defender-import.json {key} is invalid")
    if value["source_row_count"] != (
        value["matched_source_row_count"] + value["unmatched_source_row_count"]
    ):
        raise ValueError("defender-import.json source row counts are inconsistent")
    if value["message_count"] != (
        value["matched_message_count"] + value["unmatched_message_count"]
    ):
        raise ValueError("defender-import.json message counts are inconsistent")
    if value.get("cases_file") != "defender-cases.jsonl":
        raise ValueError("defender-import.json contains an unsafe cases path")
    identifiers = value.get("identifier_columns")
    if (
        not isinstance(identifiers, dict)
        or set(identifiers) != {"network_message_id", "internet_message_id"}
        or any(not isinstance(item, bool) for item in identifiers.values())
    ):
        raise ValueError("defender-import.json identifier columns are invalid")
    privacy_value = value.get("privacy")
    if privacy_value != {
        "identifiers_joined_in_memory_only": True,
        "excluded_fields": _PRIVACY_EXCLUSIONS,
    }:
        raise ValueError("defender-import.json privacy declaration is invalid")
    return value


def load_defender_cases(bundle: Path, import_record: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = Path(bundle) / import_record["cases_file"]
    payload = _read_regular(path, 4 * 1024 * 1024)
    if not secrets.compare_digest(
        hashlib.sha256(payload).hexdigest(), import_record["cases_sha256"]
    ):
        raise ValueError("defender-cases.jsonl no longer matches its import binding")
    cases = []
    known: Set[str] = set()
    for line_number, line in enumerate(payload.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict) or set(value) != _CASE_KEYS:
            raise ValueError(f"Defender case line {line_number} violates the v1 allowlist")
        if value.get("schema") != DEFENDER_CASE_SCHEMA or value.get("schema_version") != 1:
            raise ValueError(f"Defender case line {line_number} has an unsupported schema")
        case_id = value.get("case_id")
        if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id) or case_id in known:
            raise ValueError(
                f"Defender case line {line_number} has an invalid or duplicate case_id"
            )
        known.add(case_id)
        if value.get("processing_status") not in {"processed", "error"}:
            raise ValueError(f"Defender case line {line_number} has an invalid processing status")
        if value.get("match_status") not in {"matched", "unmatched"}:
            raise ValueError(f"Defender case line {line_number} has an invalid match status")
        matched_rows = value.get("matched_event_rows")
        if isinstance(matched_rows, bool) or not isinstance(matched_rows, int) or matched_rows < 0:
            raise ValueError(f"Defender case line {line_number} has an invalid row count")
        signals = value.get("signals")
        if (
            not isinstance(signals, list)
            or signals != sorted(set(signals))
            or not set(signals) <= set(_SIGNALS)
        ):
            raise ValueError(f"Defender case line {line_number} has invalid signals")
        if value["match_status"] == "matched":
            if matched_rows < 1 or value.get("native_attention") != bool(signals):
                raise ValueError(f"Defender case line {line_number} has inconsistent matching")
        elif matched_rows != 0 or value.get("native_attention") is not None or signals:
            raise ValueError(f"Defender case line {line_number} has inconsistent non-matching")
        cases.append(value)
    if len(cases) != import_record["message_count"]:
        raise ValueError("Defender case count does not match defender-import.json")
    return cases


def _confusion() -> Dict[str, int]:
    return {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}


def _add_confusion(counts: Dict[str, int], prediction: bool, label: str) -> bool:
    truth = label == "fraud"
    if prediction and truth:
        counts["true_positive"] += 1
    elif prediction:
        counts["false_positive"] += 1
    elif truth:
        counts["false_negative"] += 1
    else:
        counts["true_negative"] += 1
    return prediction == truth


def _performance(counts: Dict[str, int], confidence: float) -> Dict[str, Optional[float]]:
    fraud = counts["true_positive"] + counts["false_negative"]
    benign = counts["false_positive"] + counts["true_negative"]
    recall = counts["true_positive"] / fraud if fraud else None
    fpr = counts["false_positive"] / benign if benign else None
    recall_lower = (
        1 - clopper_pearson_upper(counts["false_negative"], fraud, confidence) if fraud else None
    )
    fpr_upper = (
        clopper_pearson_upper(counts["false_positive"], benign, confidence) if benign else None
    )
    return {
        "recall_estimate": recall,
        "recall_lower_bound": recall_lower,
        "false_positive_rate_estimate": fpr,
        "false_positive_rate_upper_bound": fpr_upper,
    }


def build_defender_report(bundle: Path, confidence: float = 0.95) -> Dict[str, Any]:
    if not math.isfinite(confidence) or not 0.8 <= confidence <= 0.999:
        raise ValueError("confidence must be between 0.8 and 0.999")
    bundle = Path(bundle)
    shadow = build_shadow_report(bundle)  # validates all Shadow bindings first
    run = load_shadow_run(bundle)
    import_record = load_defender_import(bundle)
    cases = load_defender_cases(bundle, import_record)
    manifest_path = bundle / str(run["manifest"])
    manifest_digest = hashlib.sha256(_read_regular(manifest_path, 4 * 1024 * 1024)).hexdigest()
    if not secrets.compare_digest(manifest_digest, import_record["shadow_manifest_sha256"]):
        raise ValueError("Shadow manifest no longer matches the Defender import binding")
    entries = load_inbox_manifest(manifest_path)
    entries_by_id = {entry["case_id"]: entry for entry in entries}
    if set(entries_by_id) != {case["case_id"] for case in cases}:
        raise ValueError("Defender cases do not cover exactly the bound Shadow manifest")
    processed_ids = {case["case_id"] for case in cases if case["processing_status"] == "processed"}
    revisions, labels = load_analyst_labels(
        bundle / str(run["labels"]), allowed_case_ids=processed_ids
    )

    native_confusion = _confusion()
    lurescope_confusion = _confusion()
    signal_counts: Counter[str] = Counter()
    paired = Counter()
    evaluated = 0
    matched_processed = 0
    native_attention_count = 0
    for case in cases:
        if case["processing_status"] != "processed" or case["match_status"] != "matched":
            continue
        matched_processed += 1
        signal_counts.update(case["signals"])
        native_prediction = bool(case["native_attention"])
        native_attention_count += int(native_prediction)
        decision = labels.get(case["case_id"])
        if decision is None or decision["label"] == "uncertain":
            continue
        evaluated += 1
        entry = entries_by_id[case["case_id"]]
        lurescope_prediction = entry["risk_tier"] in {"high", "review"}
        native_correct = _add_confusion(native_confusion, native_prediction, decision["label"])
        lurescope_correct = _add_confusion(
            lurescope_confusion, lurescope_prediction, decision["label"]
        )
        key = (
            "both_correct"
            if native_correct and lurescope_correct
            else "native_only_correct"
            if native_correct
            else "lurescope_only_correct"
            if lurescope_correct
            else "both_incorrect"
        )
        paired[key] += 1

    import_digest = hashlib.sha256(
        _read_regular(bundle / "defender-import.json", 256 * 1024)
    ).hexdigest()
    return {
        "schema": DEFENDER_REPORT_SCHEMA,
        "schema_version": 1,
        "generated_at": shadow["generated_at"],
        "privacy": {
            "aggregate_only": True,
            "contains_case_identifiers": False,
            "contains_message_identifiers": False,
            "excluded_fields": _PRIVACY_EXCLUSIONS,
        },
        "bindings": {
            "defender_import_sha256": import_digest,
            "shadow_manifest_sha256": manifest_digest,
            "labels_sha256": hashlib.sha256(
                _read_regular(bundle / str(run["labels"]), 4 * 1024 * 1024)
            ).hexdigest(),
        },
        "cohort": {
            "messages": import_record["message_count"],
            "matched_messages": import_record["matched_message_count"],
            "unmatched_messages": import_record["unmatched_message_count"],
            "matched_processed_messages": matched_processed,
            "evaluated_matched_messages": evaluated,
            "latest_label_count": len(labels),
            "label_revision_count": len(revisions),
        },
        "native_attention": {
            "decision_rule": DECISION_RULE,
            "attention_count": native_attention_count,
            "signal_counts": {signal: signal_counts[signal] for signal in _SIGNALS},
            "confusion": native_confusion,
            "performance": _performance(native_confusion, confidence),
        },
        "lurescope_paired": {
            "decision_rule": "high_or_review_is_routed_v1",
            "confusion": lurescope_confusion,
            "performance": _performance(lurescope_confusion, confidence),
        },
        "paired_correctness": {
            key: paired[key]
            for key in (
                "both_correct",
                "native_only_correct",
                "lurescope_only_correct",
                "both_incorrect",
            )
        },
        "confidence": {
            "level": confidence,
            "method": "one_sided_clopper_pearson_exact_v1",
            "scope": "per_metric_one_sided",
        },
        "interpretation_boundary": (
            "Only processed messages matched to EmailEvents and carrying a latest fraud or "
            "benign analyst label enter paired performance denominators. Defender attention "
            "means a threat classification, protective delivery action/location, or user action."
        ),
        "limitations": [
            "representative_iid_sample_required",
            "label_quality_not_verified",
            "email_events_export_semantics_may_change",
            "unmatched_messages_excluded_from_paired_performance",
            "per_metric_confidence_not_simultaneous_confidence",
        ],
    }


def render_defender_report_markdown(report: Dict[str, Any]) -> str:
    cohort = report["cohort"]
    native = report["native_attention"]
    lurescope = report["lurescope_paired"]

    def percent(value: Optional[float]) -> str:
        return "not measurable" if value is None else f"{value:.1%}"

    return "\n".join(
        [
            "# LureScope × Microsoft Defender offline comparison",
            "",
            "> Aggregate-only report. Message identifiers, tenant data, addresses, subjects, "
            "> paths, and content are excluded.",
            "",
            "| Cohort measure | Count |",
            "|---|---:|",
            f"| Exported messages | {cohort['messages']} |",
            f"| Matched to EmailEvents | {cohort['matched_messages']} |",
            f"| Evaluated matched messages | {cohort['evaluated_matched_messages']} |",
            "",
            "| Paired measure | Defender attention | LureScope routed |",
            "|---|---:|---:|",
            f"| Recall | {percent(native['performance']['recall_estimate'])} | "
            f"{percent(lurescope['performance']['recall_estimate'])} |",
            f"| Recall lower bound | {percent(native['performance']['recall_lower_bound'])} | "
            f"{percent(lurescope['performance']['recall_lower_bound'])} |",
            f"| False-positive rate | "
            f"{percent(native['performance']['false_positive_rate_estimate'])} | "
            f"{percent(lurescope['performance']['false_positive_rate_estimate'])} |",
            f"| FPR upper bound | "
            f"{percent(native['performance']['false_positive_rate_upper_bound'])} | "
            f"{percent(lurescope['performance']['false_positive_rate_upper_bound'])} |",
            "",
            "## Interpretation boundary",
            "",
            report["interpretation_boundary"],
            "This offline comparison does not connect to Microsoft 365, change message state, "
            "or establish production effectiveness.",
            "",
        ]
    )


def write_defender_report(
    bundle: Path, *, overwrite: bool = False, confidence: float = 0.95
) -> Dict[str, Any]:
    report = build_defender_report(Path(bundle), confidence=confidence)
    targets = (
        (
            Path(bundle) / "defender-report.json",
            (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        ),
        (
            Path(bundle) / "defender-report.md",
            render_defender_report_markdown(report).encode("utf-8"),
        ),
    )
    for path, payload in targets:
        if overwrite:
            _replace_private(path, payload)
        else:
            _write_new(path, payload)
    return report
