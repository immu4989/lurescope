"""Offline transforms from the minimized inbox manifest to SIEM payloads."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from .inbox import INBOX_SCHEMA, MAX_INBOX_MESSAGES

MAX_MANIFEST_BYTES = 16 * 1024 * 1024
EXPORT_FORMATS = ("json-array", "splunk-hec", "sentinel")
_COMMON_KEYS = {
    "schema", "schema_version", "generated_at", "case_id", "input_index", "status"
}
_PROCESSED_KEYS = _COMMON_KEYS | {
    "risk_tier", "recommended_action", "assessment", "resilience", "proof"
}
_ERROR_KEYS = _COMMON_KEYS | {"error_type"}
_ASSESSMENT_KEYS = {
    "detector", "detector_model", "detector_artifact_sha256", "fraud_probability",
    "label", "threshold", "threshold_source", "policy_id", "evidence_codes",
    "url_count", "attachment_count",
}
_RESILIENCE_KEYS = {
    "clean_flagged", "attack_count", "eligible_attack_count", "evasion_count",
    "defense_recovery_count",
}
_PROOF_KEYS = {
    "file", "artifact_type", "statement_sha256", "signature_count", "key_ids"
}


def _require_exact_keys(
    value: Any, expected: set[str], line_number: int, field: str
) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"manifest line {line_number} field {field} must be an object")
    actual = set(value)
    if actual != expected:
        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        detail = []
        if unexpected:
            detail.append(f"unexpected keys: {', '.join(unexpected)}")
        if missing:
            detail.append(f"missing keys: {', '.join(missing)}")
        raise ValueError(
            f"manifest line {line_number} field {field} violates the v1 schema "
            f"({'; '.join(detail)})"
        )
    return value


def _validate_entry_shape(entry: Any, line_number: int) -> Dict[str, Any]:
    """Enforce the privacy allowlist before an event reaches any export format."""
    if not isinstance(entry, dict):
        raise ValueError(f"manifest line {line_number} must be a JSON object")
    if entry.get("schema") != INBOX_SCHEMA or entry.get("schema_version") != 1:
        raise ValueError(f"manifest line {line_number} is not an inbox-manifest v1 event")
    status = entry.get("status")
    if status == "error":
        return _require_exact_keys(entry, _ERROR_KEYS, line_number, "event")
    if status != "processed":
        raise ValueError(f"manifest line {line_number} has an unsupported status")
    _require_exact_keys(entry, _PROCESSED_KEYS, line_number, "event")
    _require_exact_keys(entry["assessment"], _ASSESSMENT_KEYS, line_number, "assessment")
    _require_exact_keys(entry["resilience"], _RESILIENCE_KEYS, line_number, "resilience")
    _require_exact_keys(entry["proof"], _PROOF_KEYS, line_number, "proof")
    return entry


def load_inbox_manifest(path: Path) -> List[Dict[str, Any]]:
    """Load a bounded v1 manifest and reject mixed or malformed event streams."""
    path = Path(path)
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError(f"manifest exceeds the {MAX_MANIFEST_BYTES} byte safety limit")
    entries: List[Dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"manifest line {line_number} is not valid JSON") from exc
        entries.append(_validate_entry_shape(entry, line_number))
        if len(entries) > MAX_INBOX_MESSAGES:
            raise ValueError(f"manifest exceeds the {MAX_INBOX_MESSAGES} event safety limit")
    if not entries:
        raise ValueError("manifest contains no events")
    return entries


def _sentinel_record(entry: Dict[str, Any]) -> Dict[str, Any]:
    assessment = entry.get("assessment", {})
    resilience = entry.get("resilience", {})
    proof = entry.get("proof", {})
    return {
        "TimeGenerated": entry.get("generated_at"),
        "SchemaVersion": entry["schema_version"],
        "CaseId": entry.get("case_id"),
        "Status": entry["status"],
        "ErrorType": entry.get("error_type"),
        "RiskTier": entry.get("risk_tier"),
        "RecommendedAction": entry.get("recommended_action"),
        "Detector": assessment.get("detector"),
        "DetectorArtifactSha256": assessment.get("detector_artifact_sha256"),
        "FraudProbability": assessment.get("fraud_probability"),
        "Label": assessment.get("label"),
        "Threshold": assessment.get("threshold"),
        "ThresholdSource": assessment.get("threshold_source"),
        "PolicyId": assessment.get("policy_id"),
        "EvidenceCodes": assessment.get("evidence_codes", []),
        "UrlCount": assessment.get("url_count"),
        "AttachmentCount": assessment.get("attachment_count"),
        "EligibleAttackCount": resilience.get("eligible_attack_count"),
        "EvasionCount": resilience.get("evasion_count"),
        "DefenseRecoveryCount": resilience.get("defense_recovery_count"),
        "ProofArtifactType": proof.get("artifact_type"),
        "ProofStatementSha256": proof.get("statement_sha256"),
        "ProofKeyIds": proof.get("key_ids", []),
    }


def render_export(entries: List[Dict[str, Any]], output_format: str) -> bytes:
    """Render without making any network call or adding credentials."""
    entries = [_validate_entry_shape(entry, index) for index, entry in enumerate(entries, 1)]
    if output_format == "json-array":
        return (json.dumps(entries, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    if output_format == "sentinel":
        records = [_sentinel_record(entry) for entry in entries]
        return (json.dumps(records, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    if output_format == "splunk-hec":
        lines = [
            json.dumps(
                {"event": entry, "source": "lurescope", "sourcetype": "lurescope:inbox:v1"},
                ensure_ascii=False,
                sort_keys=True,
            )
            for entry in entries
        ]
        return ("\n".join(lines) + "\n").encode()
    raise ValueError(f"format must be one of: {', '.join(EXPORT_FORMATS)}")


def export_inbox_manifest(manifest_path: Path, output_path: Path, output_format: str) -> int:
    """Transform a manifest into a new private file and return the event count."""
    entries = load_inbox_manifest(manifest_path)
    payload = render_export(entries, output_format)
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except Exception:
        Path(output_path).unlink(missing_ok=True)
        raise
    return len(entries)
