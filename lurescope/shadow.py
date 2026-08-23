"""Offline Shadow Inbox pilots over exported mailboxes.

The shadow workflow deliberately never connects to a mailbox or changes message
state. It discovers bounded local exports, removes byte-equivalent duplicates in
memory, delegates assessment and LureProof creation to :mod:`lurescope.inbox`,
and persists only random case identifiers plus minimized evidence. Analyst
decisions use a fixed vocabulary and an append-only log so free-text notes cannot
accidentally copy sensitive message content into a shareable pilot report.
"""

from __future__ import annotations

import hashlib
import json
import mailbox
import os
import re
import secrets
import stat
import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import service
from .inbox import INBOX_SUMMARY_SCHEMA, MAX_INBOX_MESSAGES, InboxRun, process_inbox
from .integrations import load_inbox_manifest
from .triage import MAX_EMAIL_BYTES

SHADOW_RUN_SCHEMA = "https://github.com/immu4989/lurescope/spec/shadow-run/v1"
SHADOW_LABEL_SCHEMA = "https://github.com/immu4989/lurescope/spec/shadow-label/v1"
SHADOW_REPORT_SCHEMA = "https://github.com/immu4989/lurescope/spec/shadow-report/v1"

INPUT_FORMATS = ("auto", "eml", "maildir", "mbox")
ANALYST_LABELS = ("fraud", "benign", "uncertain")
LABEL_REASONS = (
    "confirmed_external",
    "known_legitimate",
    "insufficient_evidence",
    "policy_exception",
    "other",
)
MAX_SHADOW_INPUT_BYTES = 64 * 1024 * 1024
MAX_LABEL_EVENTS = 10_000

_CASE_ID = re.compile(r"^case-[a-f0-9]{16}$")
_RUN_KEYS = {
    "schema",
    "schema_version",
    "generated_at",
    "candidate_count",
    "unique_count",
    "duplicate_count",
    "source_type_counts",
    "unique_source_type_counts",
    "manifest",
    "labels",
    "report_json",
    "report_markdown",
}
_LABEL_KEYS = {
    "schema",
    "schema_version",
    "labeled_at",
    "case_id",
    "label",
    "reason_code",
}
_SUMMARY_KEYS = {
    "schema",
    "schema_version",
    "generated_at",
    "input_count",
    "processed_count",
    "failed_count",
    "risk_counts",
    "detector",
    "requested_threshold",
    "privacy_profile",
    "proofs_signed",
    "manifest",
    "manifest_sha256",
}


@dataclass(frozen=True)
class ShadowMessage:
    """One local-only message; ``source`` is never persisted by this module."""

    source: str
    raw: bytes
    source_type: str


@dataclass(frozen=True)
class ShadowDiscovery:
    messages: List[ShadowMessage]
    candidate_count: int
    duplicate_count: int
    source_type_counts: Dict[str, int]
    unique_source_type_counts: Dict[str, int]


@dataclass(frozen=True)
class ShadowRun:
    output_dir: Path
    discovery: ShadowDiscovery
    inbox: InboxRun
    report: Dict[str, Any]

    @property
    def failed_count(self) -> int:
        return self.inbox.failed_count


@dataclass(frozen=True)
class _Candidate:
    source: str
    source_type: str
    path: Path
    mbox_key: Optional[int] = None


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _write_new(path: Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _replace_private(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        _write_new(temporary, payload)
        os.replace(temporary, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        temporary.unlink(missing_ok=True)


def _is_maildir(path: Path) -> bool:
    return (
        path.is_dir()
        and not path.is_symlink()
        and (path / "cur").is_dir()
        and not (path / "cur").is_symlink()
        and (path / "new").is_dir()
        and not (path / "new").is_symlink()
    )


def _has_symlink_component(path: Path, root: Path) -> bool:
    root = root.absolute()
    try:
        relative = path.absolute().relative_to(root)
    except ValueError:
        return True
    current = root
    if current.is_symlink():
        return True
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return True
    return False


def _safe_files(paths: Sequence[Path], *, root: Optional[Path] = None) -> List[Path]:
    files: List[Path] = []
    for path in paths:
        if path.is_symlink() or (root is not None and _has_symlink_component(path, root)):
            raise ValueError(f"refusing symbolic-link mailbox input: {path}")
        if path.is_file():
            files.append(path)
    return files


def _eml_candidates(path: Path, recursive: bool, source_type: str = "eml") -> List[_Candidate]:
    if path.is_file():
        return [_Candidate(str(path), source_type, path)]
    pattern = "**/*.eml" if recursive else "*.eml"
    return [
        _Candidate(str(item), source_type, item)
        for item in _safe_files(sorted(path.glob(pattern)), root=path)
    ]


def _maildir_candidates(path: Path) -> List[_Candidate]:
    if not _is_maildir(path):
        raise ValueError(f"not a Maildir (expected cur/ and new/): {path}")
    files = _safe_files([
        *sorted((path / "cur").iterdir()),
        *sorted((path / "new").iterdir()),
    ], root=path)
    return [_Candidate(str(item), "maildir", item) for item in files]


def _mbox_candidates(path: Path) -> List[_Candidate]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"not a regular mbox file: {path}")
    box = mailbox.mbox(path, factory=None, create=False)
    try:
        keys = sorted(int(key) for key in box.keys())
    finally:
        box.close()
    return [
        _Candidate(f"{path}#message-{key + 1}", "mbox", path, key)
        for key in keys
    ]


def _auto_candidates(path: Path, recursive: bool) -> List[_Candidate]:
    if _is_maildir(path):
        return _maildir_candidates(path)
    if path.is_file():
        if path.suffix.casefold() in {".mbox", ".mbx"}:
            return _mbox_candidates(path)
        return _eml_candidates(path, recursive=False)
    if not path.is_dir():
        raise FileNotFoundError(path)
    candidates = _eml_candidates(path, recursive)
    if recursive:
        containers = _safe_files(sorted([
            *path.glob("**/*.mbox"),
            *path.glob("**/*.mbx"),
        ]), root=path)
        for container in containers:
            candidates.extend(_mbox_candidates(container))
    return candidates


def _plan_inputs(
    inputs: Sequence[Path], input_format: str, recursive: bool
) -> tuple[List[_Candidate], int]:
    if input_format not in INPUT_FORMATS:
        raise ValueError(f"input_format must be one of: {', '.join(INPUT_FORMATS)}")
    candidates: List[_Candidate] = []
    budget_paths: set[Path] = set()
    for path in inputs:
        if path.is_symlink():
            raise ValueError(f"refusing symbolic-link mailbox input: {path}")
        if not path.exists():
            raise FileNotFoundError(path)
        if input_format == "auto":
            found = _auto_candidates(path, recursive)
        elif input_format == "maildir":
            found = _maildir_candidates(path)
        elif input_format == "mbox":
            found = _mbox_candidates(path)
        else:
            found = _eml_candidates(path, recursive)
        candidates.extend(found)
        budget_paths.update(candidate.path for candidate in found)
    budget = sum(
        min(path.stat().st_size, MAX_SHADOW_INPUT_BYTES + 1)
        for path in budget_paths
    )
    return candidates, budget


def _canonical_digest(raw: bytes) -> bytes:
    normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").rstrip(b"\n")
    return hashlib.sha256(normalized).digest()


def _read_bounded_file(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"not a regular mailbox input: {path}")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read(limit)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def discover_shadow_messages(
    inputs: Sequence[Path],
    *,
    input_format: str = "auto",
    recursive: bool = False,
    max_messages: int = MAX_INBOX_MESSAGES,
    max_total_bytes: int = MAX_SHADOW_INPUT_BYTES,
) -> ShadowDiscovery:
    """Discover, bound, load, and deduplicate local mailbox exports.

    Candidate count and aggregate on-disk size are checked before message bodies
    are loaded. Mbox parsing may scan container boundaries to count messages, but
    no message object is retained before both batch limits pass.
    """
    if max_messages < 1 or max_messages > MAX_INBOX_MESSAGES:
        raise ValueError(f"max_messages must be between 1 and {MAX_INBOX_MESSAGES}")
    if max_total_bytes < 1 or max_total_bytes > MAX_SHADOW_INPUT_BYTES:
        raise ValueError(
            f"max_total_bytes must be between 1 and {MAX_SHADOW_INPUT_BYTES}"
        )
    candidates, planned_bytes = _plan_inputs(
        [Path(path) for path in inputs], input_format, recursive
    )
    if not candidates:
        raise ValueError("no email messages found in the supplied exports")
    if len(candidates) > max_messages:
        raise ValueError(
            f"shadow inbox contains {len(candidates)} candidates; configured limit is "
            f"{max_messages}; no message bodies were read"
        )
    if planned_bytes > max_total_bytes:
        raise ValueError(
            f"mailbox exports require {planned_bytes} bytes; configured batch limit is "
            f"{max_total_bytes}; no message bodies were read"
        )

    source_counts = Counter(candidate.source_type for candidate in candidates)
    boxes: Dict[Path, mailbox.mbox] = {}
    messages: List[ShadowMessage] = []
    unique_counts: Counter[str] = Counter()
    known: set[bytes] = set()
    duplicates = 0
    try:
        for candidate in candidates:
            if candidate.source_type == "mbox":
                box = boxes.get(candidate.path)
                if box is None:
                    box = mailbox.mbox(candidate.path, factory=None, create=False)
                    boxes[candidate.path] = box
                raw = box.get_bytes(candidate.mbox_key, from_=False)
                if len(raw) > MAX_EMAIL_BYTES:
                    raw = raw[: MAX_EMAIL_BYTES + 1]
            else:
                raw = _read_bounded_file(candidate.path, MAX_EMAIL_BYTES + 1)
            if len(raw) > MAX_EMAIL_BYTES:
                # Do not treat equal bounded prefixes as equal full messages. Each
                # oversized candidate must reach the parser and produce its own safe
                # error event instead of being silently removed as a duplicate.
                messages.append(ShadowMessage(candidate.source, raw, candidate.source_type))
                unique_counts[candidate.source_type] += 1
                continue
            fingerprint = _canonical_digest(raw)
            if fingerprint in known:
                duplicates += 1
                continue
            known.add(fingerprint)
            messages.append(ShadowMessage(candidate.source, raw, candidate.source_type))
            unique_counts[candidate.source_type] += 1
    finally:
        for box in boxes.values():
            box.close()

    return ShadowDiscovery(
        messages=messages,
        candidate_count=len(candidates),
        duplicate_count=duplicates,
        source_type_counts=dict(sorted(source_counts.items())),
        unique_source_type_counts=dict(sorted(unique_counts.items())),
    )


def _load_json_object(path: Path, max_bytes: int = 2 * 1024 * 1024) -> Dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link {path.name}")
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path.name} exceeds the {max_bytes} byte safety limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def load_shadow_run(bundle: Path) -> Dict[str, Any]:
    record = _load_json_object(Path(bundle) / "shadow-run.json")
    if set(record) != _RUN_KEYS:
        raise ValueError("shadow-run.json violates the v1 privacy allowlist")
    if record.get("schema") != SHADOW_RUN_SCHEMA or record.get("schema_version") != 1:
        raise ValueError("shadow-run.json is not a Shadow Inbox run v1")
    try:
        generated_at = datetime.fromisoformat(
            str(record["generated_at"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("shadow-run.json has an invalid generated_at") from exc
    if generated_at.tzinfo is None:
        raise ValueError("shadow-run.json generated_at must include a UTC offset")
    for key in ("candidate_count", "unique_count", "duplicate_count"):
        value = record[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"shadow-run.json {key} must be a non-negative integer")
    if not 1 <= record["candidate_count"] <= MAX_INBOX_MESSAGES:
        raise ValueError("shadow-run.json candidate_count is outside the safety limit")
    if not 1 <= record["unique_count"] <= record["candidate_count"]:
        raise ValueError("shadow-run.json unique_count is inconsistent")
    if record["candidate_count"] != record["unique_count"] + record["duplicate_count"]:
        raise ValueError("shadow-run.json candidate counts are inconsistent")
    for key, expected_total in (
        ("source_type_counts", record["candidate_count"]),
        ("unique_source_type_counts", record["unique_count"]),
    ):
        counts = record[key]
        if not isinstance(counts, dict) or not set(counts) <= set(INPUT_FORMATS[1:]):
            raise ValueError(f"shadow-run.json {key} has unsupported source types")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in counts.values()
        ) or sum(counts.values()) != expected_total:
            raise ValueError(f"shadow-run.json {key} is inconsistent")
    expected_files = {
        "manifest": "manifest.jsonl",
        "labels": "analyst-labels.jsonl",
        "report_json": "shadow-report.json",
        "report_markdown": "shadow-report.md",
    }
    if any(record[key] != value for key, value in expected_files.items()):
        raise ValueError("shadow-run.json contains an unsafe or unsupported bundle path")
    return record


def _load_bound_manifest(bundle: Path, run: Dict[str, Any]) -> List[Dict[str, Any]]:
    manifest_path = bundle / str(run["manifest"])
    if manifest_path.is_symlink():
        raise ValueError("refusing symbolic-link Shadow Inbox manifest")
    entries = load_inbox_manifest(manifest_path)
    summary = _load_json_object(bundle / "summary.json")
    if set(summary) != _SUMMARY_KEYS:
        raise ValueError("summary.json violates the inbox summary v1 allowlist")
    if (
        summary.get("schema") != INBOX_SUMMARY_SCHEMA
        or summary.get("schema_version") != 1
        or summary.get("manifest") != "manifest.jsonl"
    ):
        raise ValueError("summary.json is not an inbox summary v1")
    expected_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if not secrets.compare_digest(str(summary.get("manifest_sha256", "")), expected_digest):
        raise ValueError("manifest.jsonl no longer matches its summary digest")
    processed_count = sum(entry["status"] == "processed" for entry in entries)
    failed_count = len(entries) - processed_count
    if (
        summary.get("generated_at") != run["generated_at"]
        or summary.get("input_count") != run["unique_count"]
        or len(entries) != run["unique_count"]
        or summary.get("processed_count") != processed_count
        or summary.get("failed_count") != failed_count
    ):
        raise ValueError("Shadow Inbox run, manifest, and summary counts are inconsistent")
    return entries


def load_analyst_labels(
    path: Path,
    *,
    allowed_case_ids: Optional[set[str]] = None,
) -> tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Load an append-only label log and return all revisions plus latest by case."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("refusing symbolic-link analyst label log")
    if not path.exists():
        return [], {}
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("analyst label log exceeds the 4 MiB safety limit")
    events: List[Dict[str, Any]] = []
    latest: Dict[str, Dict[str, Any]] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"label line {line_number} is not valid JSON") from exc
        if not isinstance(event, dict) or set(event) != _LABEL_KEYS:
            raise ValueError(f"label line {line_number} violates the v1 privacy allowlist")
        if event.get("schema") != SHADOW_LABEL_SCHEMA or event.get("schema_version") != 1:
            raise ValueError(f"label line {line_number} is not a Shadow Inbox label v1")
        if not _CASE_ID.fullmatch(str(event.get("case_id", ""))):
            raise ValueError(f"label line {line_number} has an invalid case_id")
        if event.get("label") not in ANALYST_LABELS:
            raise ValueError(f"label line {line_number} has an unsupported label")
        if event.get("reason_code") not in LABEL_REASONS:
            raise ValueError(f"label line {line_number} has an unsupported reason_code")
        try:
            labeled_at = datetime.fromisoformat(
                str(event.get("labeled_at", "")).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(f"label line {line_number} has an invalid labeled_at") from exc
        if labeled_at.tzinfo is None:
            raise ValueError(f"label line {line_number} labeled_at needs a UTC offset")
        if allowed_case_ids is not None and event["case_id"] not in allowed_case_ids:
            raise ValueError(f"label line {line_number} refers to an unknown processed case")
        events.append(event)
        latest[event["case_id"]] = event
        if len(events) > MAX_LABEL_EVENTS:
            raise ValueError(f"label log exceeds the {MAX_LABEL_EVENTS} event safety limit")
    return events, latest


def append_analyst_label(
    bundle: Path,
    case_id: str,
    label: str,
    reason_code: str,
) -> Dict[str, Any]:
    bundle = Path(bundle)
    run = load_shadow_run(bundle)
    entries = _load_bound_manifest(bundle, run)
    processed_ids = {entry["case_id"] for entry in entries if entry["status"] == "processed"}
    if case_id not in processed_ids:
        raise ValueError("case_id is not a processed case in this Shadow Inbox bundle")
    if label not in ANALYST_LABELS:
        raise ValueError(f"label must be one of: {', '.join(ANALYST_LABELS)}")
    if reason_code not in LABEL_REASONS:
        raise ValueError(f"reason_code must be one of: {', '.join(LABEL_REASONS)}")
    label_path = bundle / "analyst-labels.jsonl"
    events, _ = load_analyst_labels(label_path, allowed_case_ids=processed_ids)
    if len(events) >= MAX_LABEL_EVENTS:
        raise ValueError(f"label log has reached the {MAX_LABEL_EVENTS} event safety limit")
    event = {
        "schema": SHADOW_LABEL_SCHEMA,
        "schema_version": 1,
        "labeled_at": _timestamp(),
        "case_id": case_id,
        "label": label,
        "reason_code": reason_code,
    }
    payload = (json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        label_path,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if os.write(descriptor, payload) != len(payload):
            raise OSError("could not append the complete analyst label event")
        try:
            os.fchmod(descriptor, 0o600)
        except OSError:
            pass
    finally:
        os.close(descriptor)
    write_shadow_reports(bundle, overwrite=True)
    registered_plan = bundle / "pilot-plan.json"
    if registered_plan.exists() or registered_plan.is_symlink():
        # The registered plan copy lets label revisions refresh the decision and
        # prevents a stale gate from appearing current after the evidence changes.
        from .pilot import write_pilot_gate

        write_pilot_gate(bundle, registered_plan)
    defender_import = bundle / "defender-import.json"
    if defender_import.exists() or defender_import.is_symlink():
        from .defender import write_defender_report

        write_defender_report(bundle, overwrite=True)
    return event


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 6) if denominator else None


def build_shadow_report(bundle: Path) -> Dict[str, Any]:
    bundle = Path(bundle)
    run = load_shadow_run(bundle)
    entries = _load_bound_manifest(bundle, run)
    processed = [entry for entry in entries if entry["status"] == "processed"]
    processed_ids = {entry["case_id"] for entry in processed}
    revisions, labels = load_analyst_labels(
        bundle / str(run["labels"]), allowed_case_ids=processed_ids
    )

    risk_counts = Counter(entry["risk_tier"] for entry in processed)
    action_counts = Counter(entry["recommended_action"] for entry in processed)
    evidence_counts: Counter[str] = Counter()
    probabilities: List[float] = []
    eligible_attacks = evasions = recoveries = evasion_cases = 0
    for entry in processed:
        probabilities.append(float(entry["assessment"]["fraud_probability"]))
        evidence_counts.update(entry["assessment"]["evidence_codes"])
        resilience = entry["resilience"]
        eligible_attacks += int(resilience["eligible_attack_count"])
        evasions += int(resilience["evasion_count"])
        recoveries += int(resilience["defense_recovery_count"])
        evasion_cases += int(resilience["evasion_count"] > 0)

    label_counts = Counter(event["label"] for event in labels.values())
    confusion = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}
    evaluated = 0
    for entry in processed:
        decision = labels.get(entry["case_id"])
        if decision is None or decision["label"] == "uncertain":
            continue
        evaluated += 1
        routed = entry["risk_tier"] in {"high", "review"}
        if decision["label"] == "fraud":
            confusion["true_positive" if routed else "false_negative"] += 1
        else:
            confusion["false_positive" if routed else "true_negative"] += 1

    fraud_total = confusion["true_positive"] + confusion["false_negative"]
    benign_total = confusion["false_positive"] + confusion["true_negative"]
    routed_labeled = confusion["true_positive"] + confusion["false_positive"]
    routed_count = risk_counts["high"] + risk_counts["review"]
    report: Dict[str, Any] = {
        "schema": SHADOW_REPORT_SCHEMA,
        "schema_version": 1,
        "generated_at": _timestamp(),
        "privacy": {
            "aggregate_only": True,
            "excluded_fields": [
                "source_paths",
                "subjects",
                "addresses",
                "message_ids",
                "url_values",
                "attachment_names",
                "message_content",
                "raw_message_hashes",
            ],
        },
        "volume": {
            "candidate_count": run["candidate_count"],
            "unique_count": run["unique_count"],
            "duplicate_count": run["duplicate_count"],
            "processed_count": len(processed),
            "failed_count": sum(entry["status"] == "error" for entry in entries),
            "source_type_counts": run["source_type_counts"],
        },
        "routing": {
            "risk_counts": {key: risk_counts[key] for key in ("high", "review", "low")},
            "action_counts": dict(sorted(action_counts.items())),
            "routed_count": routed_count,
            "routed_rate": _ratio(routed_count, len(processed)),
            "mean_fraud_probability": (
                round(statistics.fmean(probabilities), 6) if probabilities else None
            ),
        },
        "evidence": {
            "code_counts": dict(sorted(evidence_counts.items())),
            "top_codes": [
                {"code": code, "count": count}
                for code, count in sorted(
                    evidence_counts.items(), key=lambda item: (-item[1], item[0])
                )[:10]
            ],
        },
        "resilience": {
            "eligible_attack_count": eligible_attacks,
            "evasion_count": evasions,
            "evasion_rate": _ratio(evasions, eligible_attacks),
            "defense_recovery_count": recoveries,
            "recovery_rate_among_evasions": _ratio(recoveries, evasions),
            "cases_with_evasion": evasion_cases,
        },
        "analyst_review": {
            "latest_label_count": len(labels),
            "label_revision_count": len(revisions),
            "coverage": _ratio(len(labels), len(processed)),
            "label_counts": {key: label_counts[key] for key in ANALYST_LABELS},
            "evaluated_count": evaluated,
            "confusion": confusion,
            "routing_recall": _ratio(confusion["true_positive"], fraud_total),
            "routing_false_positive_rate": _ratio(confusion["false_positive"], benign_total),
            "routing_precision": _ratio(confusion["true_positive"], routed_labeled),
        },
        "decision_boundary": (
            "Routing metrics treat high/review as routed and low as not routed. "
            "Uncertain and unlabeled cases are excluded from performance denominators."
        ),
    }
    return report


def render_shadow_report_markdown(report: Dict[str, Any]) -> str:
    volume = report["volume"]
    routing = report["routing"]
    review = report["analyst_review"]
    resilience = report["resilience"]

    def percent(value: Optional[float]) -> str:
        return "not yet measurable" if value is None else f"{value:.1%}"

    lines = [
        "# LureScope Shadow Inbox pilot report",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "> Aggregate-only report. It excludes paths, subjects, addresses, message IDs, URL "
        "> values, attachment names, message content, and raw message hashes.",
        "",
        "## Volume and workload",
        "",
        "| Measure | Value |",
        "|---|---:|",
        f"| Candidate messages | {volume['candidate_count']} |",
        f"| Unique messages | {volume['unique_count']} |",
        f"| Duplicates removed | {volume['duplicate_count']} |",
        f"| Successfully processed | {volume['processed_count']} |",
        f"| Processing failures | {volume['failed_count']} |",
        f"| Routed for review | {routing['routed_count']} ({percent(routing['routed_rate'])}) |",
        "",
        "## Analyst validation",
        "",
        f"Latest labels cover **{percent(review['coverage'])}** of processed messages. "
        f"Performance denominators currently contain **{review['evaluated_count']}** "
        "fraud/benign decisions; uncertain cases are excluded.",
        "",
        "| Measure | Result |",
        "|---|---:|",
        f"| Routing recall | {percent(review['routing_recall'])} |",
        f"| Routing false-positive rate | {percent(review['routing_false_positive_rate'])} |",
        f"| Routing precision | {percent(review['routing_precision'])} |",
        "",
        "## Adversarial resilience",
        "",
        f"Across **{resilience['eligible_attack_count']}** eligible deterministic stress "
        f"tests, **{resilience['evasion_count']}** evaded "
        f"({percent(resilience['evasion_rate'])}); the normalization defense recovered "
        f"**{resilience['defense_recovery_count']}** "
        f"({percent(resilience['recovery_rate_among_evasions'])} of evasions).",
        "",
        "## Most frequent deterministic evidence",
        "",
    ]
    if report["evidence"]["top_codes"]:
        lines.extend(
            f"- `{item['code']}`: {item['count']}"
            for item in report["evidence"]["top_codes"]
        )
    else:
        lines.append("No deterministic email-context evidence was recorded.")
    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        report["decision_boundary"],
        "A low score is not proof of safety. This pilot does not connect to mailboxes, "
        "open attachments, follow links, quarantine messages, or replace analyst review.",
        "",
    ])
    return "\n".join(lines)


def write_shadow_reports(bundle: Path, *, overwrite: bool = False) -> Dict[str, Any]:
    bundle = Path(bundle)
    run = load_shadow_run(bundle)
    report = build_shadow_report(bundle)
    json_payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    markdown_payload = render_shadow_report_markdown(report).encode("utf-8")
    targets = [
        (bundle / str(run["report_json"]), json_payload),
        (bundle / str(run["report_markdown"]), markdown_payload),
    ]
    for path, payload in targets:
        if overwrite:
            _replace_private(path, payload)
        else:
            _write_new(path, payload)
    return report


def run_shadow_inbox(
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
    max_messages: int = MAX_INBOX_MESSAGES,
) -> ShadowRun:
    discovery = discover_shadow_messages(
        inputs,
        input_format=input_format,
        recursive=recursive,
        max_messages=max_messages,
    )
    return materialize_shadow_discovery(
        discovery,
        output_dir,
        detector_name=detector_name,
        threshold=threshold,
        privacy_profile=privacy_profile,
        nonce=nonce,
        issuer=issuer,
        signing_key_pem=signing_key_pem,
        max_messages=max_messages,
    )


def materialize_shadow_discovery(
    discovery: ShadowDiscovery,
    output_dir: Path,
    *,
    detector_name: str = service.DEFAULT_DETECTOR,
    threshold: Optional[float] = None,
    privacy_profile: str = "salted-commitment",
    nonce: Optional[str] = None,
    issuer: Optional[str] = None,
    signing_key_pem: Optional[bytes] = None,
    max_messages: int = MAX_INBOX_MESSAGES,
) -> ShadowRun:
    """Materialize an already bounded discovery into a private Shadow bundle.

    Integrations may inspect transport metadata in memory before this step. The
    discovery object still contains local sources and raw messages, so callers
    must never serialize it.
    """
    if not discovery.messages:
        raise ValueError("Shadow Inbox discovery contains no unique messages")
    if len(discovery.messages) > max_messages:
        raise ValueError("Shadow Inbox discovery exceeds the configured message limit")
    inbox_run = process_inbox(
        [(message.source, message.raw) for message in discovery.messages],
        Path(output_dir),
        detector_name=detector_name,
        threshold=threshold,
        privacy_profile=privacy_profile,
        nonce=nonce,
        issuer=issuer,
        signing_key_pem=signing_key_pem,
        max_messages=max_messages,
    )
    run_record = {
        "schema": SHADOW_RUN_SCHEMA,
        "schema_version": 1,
        "generated_at": inbox_run.summary["generated_at"],
        "candidate_count": discovery.candidate_count,
        "unique_count": len(discovery.messages),
        "duplicate_count": discovery.duplicate_count,
        "source_type_counts": discovery.source_type_counts,
        "unique_source_type_counts": discovery.unique_source_type_counts,
        "manifest": "manifest.jsonl",
        "labels": "analyst-labels.jsonl",
        "report_json": "shadow-report.json",
        "report_markdown": "shadow-report.md",
    }
    _write_new(
        inbox_run.output_dir / "shadow-run.json",
        (json.dumps(run_record, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    _write_new(inbox_run.output_dir / "analyst-labels.jsonl", b"")
    report = write_shadow_reports(inbox_run.output_dir)
    return ShadowRun(inbox_run.output_dir, discovery, inbox_run, report)
