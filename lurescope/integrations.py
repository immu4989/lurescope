"""Offline transforms from the minimized inbox manifest to SIEM payloads."""

from __future__ import annotations

import json
import math
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .inbox import INBOX_SCHEMA, MAX_INBOX_MESSAGES

MAX_MANIFEST_BYTES = 16 * 1024 * 1024
EXPORT_FORMATS = (
    "json-array",
    "splunk-hec",
    "sentinel",
    "ocsf-1.8",
    "ecs-9.4",
    "stix-2.1",
)
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
_LABEL_KEYS = {
    "schema", "schema_version", "labeled_at", "case_id", "label", "reason_code"
}
_ANALYST_LABELS = {"fraud", "benign", "uncertain"}
_LABEL_REASONS = {
    "confirmed_external", "known_legitimate", "insufficient_evidence",
    "policy_exception", "other",
}
_SHADOW_LABEL_SCHEMA = "https://github.com/immu4989/lurescope/spec/shadow-label/v1"
_CASE_ID = re.compile(r"^case-[a-f0-9]{16}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_ACTIONS = {
    "high": "quarantine_and_review",
    "review": "hold_and_verify_sender",
    "low": "continue_normal_controls",
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


def _valid_count(value: Any, *, maximum: Optional[int] = None) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
        and (maximum is None or value <= maximum)
    )


def _validate_timestamp(value: Any, line_number: int, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"manifest line {line_number} field {field} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"manifest line {line_number} field {field} must be an ISO 8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise ValueError(f"manifest line {line_number} field {field} needs a UTC offset")


def _validate_processed_values(entry: Dict[str, Any], line_number: int) -> None:
    risk_tier = entry["risk_tier"]
    if risk_tier not in _ACTIONS or entry["recommended_action"] != _ACTIONS[risk_tier]:
        raise ValueError(f"manifest line {line_number} has inconsistent risk routing")

    assessment = entry["assessment"]
    for key, maximum in (("detector", 100), ("detector_model", 500), ("threshold_source", 100)):
        value = assessment[key]
        if not isinstance(value, str) or not value or len(value) > maximum:
            raise ValueError(f"manifest line {line_number} assessment.{key} is invalid")
    artifact_digest = assessment["detector_artifact_sha256"]
    if artifact_digest is not None and (
        not isinstance(artifact_digest, str) or not _SHA256.fullmatch(artifact_digest)
    ):
        raise ValueError(f"manifest line {line_number} has an invalid detector digest")
    for key in ("fraud_probability", "threshold"):
        value = assessment[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= 1
        ):
            raise ValueError(f"manifest line {line_number} assessment.{key} is invalid")
    if assessment["label"] not in {"fraud", "benign"}:
        raise ValueError(f"manifest line {line_number} has an invalid assessment label")
    policy_id = assessment["policy_id"]
    if policy_id is not None and (
        not isinstance(policy_id, str) or len(policy_id) > 500
    ):
        raise ValueError(f"manifest line {line_number} has an invalid policy_id")
    evidence_codes = assessment["evidence_codes"]
    if (
        not isinstance(evidence_codes, list)
        or len(evidence_codes) > 32
        or any(
            not isinstance(code, str) or not code or len(code) > 100
            for code in evidence_codes
        )
        or len(set(evidence_codes)) != len(evidence_codes)
    ):
        raise ValueError(f"manifest line {line_number} has invalid evidence codes")
    for key in ("url_count", "attachment_count"):
        if not _valid_count(assessment[key]):
            raise ValueError(f"manifest line {line_number} assessment.{key} is invalid")

    resilience = entry["resilience"]
    if not isinstance(resilience["clean_flagged"], bool):
        raise ValueError(f"manifest line {line_number} clean_flagged must be boolean")
    for key in _RESILIENCE_KEYS - {"clean_flagged"}:
        if not _valid_count(resilience[key]):
            raise ValueError(f"manifest line {line_number} resilience.{key} is invalid")
    if not (
        resilience["defense_recovery_count"] <= resilience["evasion_count"]
        <= resilience["eligible_attack_count"] <= resilience["attack_count"]
    ):
        raise ValueError(f"manifest line {line_number} resilience counts are inconsistent")

    proof = entry["proof"]
    expected_files = {
        "statement": f"{entry['case_id']}.lureproof.json",
        "dsse": f"{entry['case_id']}.lureproof.dsse.json",
    }
    artifact_type = proof["artifact_type"]
    if artifact_type not in expected_files or proof["file"] != expected_files[artifact_type]:
        raise ValueError(f"manifest line {line_number} has inconsistent proof metadata")
    if not isinstance(proof["statement_sha256"], str) or not _SHA256.fullmatch(
        proof["statement_sha256"]
    ):
        raise ValueError(f"manifest line {line_number} has an invalid proof digest")
    signature_count = proof["signature_count"]
    key_ids = proof["key_ids"]
    if (
        not _valid_count(signature_count, maximum=16)
        or not isinstance(key_ids, list)
        or len(key_ids) != signature_count
        or any(not isinstance(key, str) or not _SHA256.fullmatch(key) for key in key_ids)
        or len(set(key_ids)) != len(key_ids)
        or (artifact_type == "statement" and signature_count != 0)
        or (artifact_type == "dsse" and signature_count == 0)
    ):
        raise ValueError(f"manifest line {line_number} has invalid proof signatures")


def _validate_entry_shape(entry: Any, line_number: int) -> Dict[str, Any]:
    """Enforce the privacy allowlist before an event reaches any export format."""
    if not isinstance(entry, dict):
        raise ValueError(f"manifest line {line_number} must be a JSON object")
    if entry.get("schema") != INBOX_SCHEMA or entry.get("schema_version") != 1:
        raise ValueError(f"manifest line {line_number} is not an inbox-manifest v1 event")
    _validate_timestamp(entry.get("generated_at"), line_number, "generated_at")
    if not _CASE_ID.fullmatch(str(entry.get("case_id", ""))):
        raise ValueError(f"manifest line {line_number} has an invalid case_id")
    if not _valid_count(entry.get("input_index"), maximum=MAX_INBOX_MESSAGES) or not entry[
        "input_index"
    ]:
        raise ValueError(f"manifest line {line_number} has an invalid input_index")
    status = entry.get("status")
    if status == "error":
        _require_exact_keys(entry, _ERROR_KEYS, line_number, "event")
        error_type = entry["error_type"]
        if not isinstance(error_type, str) or not error_type or len(error_type) > 200:
            raise ValueError(f"manifest line {line_number} has an invalid error_type")
        return entry
    if status != "processed":
        raise ValueError(f"manifest line {line_number} has an unsupported status")
    _require_exact_keys(entry, _PROCESSED_KEYS, line_number, "event")
    _require_exact_keys(entry["assessment"], _ASSESSMENT_KEYS, line_number, "assessment")
    _require_exact_keys(entry["resilience"], _RESILIENCE_KEYS, line_number, "resilience")
    _require_exact_keys(entry["proof"], _PROOF_KEYS, line_number, "proof")
    _validate_processed_values(entry, line_number)
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


def _validated_labels(
    labels_by_case: Optional[Dict[str, Dict[str, Any]]],
    processed_case_ids: set[str],
) -> Dict[str, Dict[str, Any]]:
    labels_by_case = labels_by_case or {}
    for case_id, event in labels_by_case.items():
        if case_id not in processed_case_ids:
            raise ValueError("analyst labels contain an unknown processed case")
        if not isinstance(event, dict) or set(event) != _LABEL_KEYS:
            raise ValueError("analyst label violates the v1 privacy allowlist")
        if (
            event.get("schema") != _SHADOW_LABEL_SCHEMA
            or event.get("schema_version") != 1
            or event.get("case_id") != case_id
            or event.get("label") not in _ANALYST_LABELS
            or event.get("reason_code") not in _LABEL_REASONS
        ):
            raise ValueError("analyst label is inconsistent or unsupported")
        _stix_timestamp(str(event.get("labeled_at", "")))
    return labels_by_case


def _epoch_millis(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("generated_at must include a UTC offset")
    return int(parsed.timestamp() * 1000)


def _stix_timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("generated_at must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _latest_stix_timestamp(first: str, second: str) -> str:
    first_value = datetime.fromisoformat(first.replace("Z", "+00:00"))
    second_value = datetime.fromisoformat(second.replace("Z", "+00:00"))
    return _stix_timestamp(max(first_value, second_value).isoformat())


def _severity(entry: Dict[str, Any]) -> tuple[int, str, int]:
    return {
        "low": (2, "Low", 20),
        "review": (3, "Medium", 50),
        "high": (4, "High", 80),
    }[entry["risk_tier"]]


def _ocsf_record(
    entry: Dict[str, Any], label: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    assessment = entry["assessment"]
    resilience = entry["resilience"]
    severity_id, severity, _ = _severity(entry)
    analyst_label = label["label"] if label else None
    is_alert = entry["risk_tier"] in {"high", "review"} and analyst_label != "benign"
    description = {
        "high": "Locally assessed email requires quarantine and analyst review.",
        "review": "Locally assessed email requires sender verification.",
        "low": "Locally assessed email remains under normal controls.",
    }[entry["risk_tier"]]
    record: Dict[str, Any] = {
        "activity_id": 1,
        "activity_name": "Create",
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
        "time": _epoch_millis(entry["generated_at"]),
        "severity_id": severity_id,
        "severity": severity,
        "is_alert": is_alert,
        "confidence_score": round(float(assessment["fraud_probability"]) * 100),
        "risk_score": round(float(assessment["fraud_probability"]) * 100),
        "finding_info": {
            "uid": entry["case_id"],
            "title": "Potential fraud lure",
            "desc": description,
            "created_time": _epoch_millis(entry["generated_at"]),
        },
        "metadata": {
            "version": "1.8.0",
            "product": {
                "name": "LureScope",
                "vendor_name": "LureScope",
                "version": __version__,
            },
        },
        "unmapped": {
            "lurescope": {
                "risk_tier": entry["risk_tier"],
                "recommended_action": entry["recommended_action"],
                "detector": assessment["detector"],
                "evidence_codes": assessment["evidence_codes"],
                "eligible_attack_count": resilience["eligible_attack_count"],
                "evasion_count": resilience["evasion_count"],
                "defense_recovery_count": resilience["defense_recovery_count"],
                "analyst_label": analyst_label,
            }
        },
    }
    return record


def _ecs_record(
    entry: Dict[str, Any], label: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    assessment = entry["assessment"]
    resilience = entry["resilience"]
    _, _, severity = _severity(entry)
    analyst_label = label["label"] if label else None
    is_alert = entry["risk_tier"] in {"high", "review"} and analyst_label != "benign"
    return {
        "@timestamp": _stix_timestamp(entry["generated_at"]),
        "ecs": {"version": "9.4.0"},
        "event": {
            "id": entry["case_id"],
            "kind": "alert" if is_alert else "event",
            "category": ["email", "intrusion_detection"],
            "type": ["indicator"] if is_alert else ["info"],
            "action": "fraud-lure-assessed",
            "severity": severity,
            "risk_score": round(float(assessment["fraud_probability"]) * 100, 4),
        },
        "observer": {
            "vendor": "LureScope",
            "product": "LureScope",
            "version": __version__,
            "type": "email security",
        },
        "rule": {
            "name": assessment["detector"],
            "ruleset": "LureScope local fraud detection",
        },
        "tags": assessment["evidence_codes"],
        "labels": {
            "lurescope_risk_tier": entry["risk_tier"],
            "lurescope_analyst_label": analyst_label or "unlabeled",
        },
        "lurescope": {
            "recommended_action": entry["recommended_action"],
            "fraud_probability": assessment["fraud_probability"],
            "threshold": assessment["threshold"],
            "threshold_source": assessment["threshold_source"],
            "policy_id": assessment["policy_id"],
            "eligible_attack_count": resilience["eligible_attack_count"],
            "evasion_count": resilience["evasion_count"],
            "defense_recovery_count": resilience["defense_recovery_count"],
        },
    }


def _stix_incident_selected(
    entry: Dict[str, Any], label: Optional[Dict[str, Any]]
) -> bool:
    if label and label["label"] == "benign":
        return False
    if label and label["label"] == "fraud":
        return True
    return entry["risk_tier"] in {"high", "review"}


def _stix_bundle(
    entries: List[Dict[str, Any]], labels: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    identity_id = f"identity--{uuid.uuid4()}"
    created = (
        min(_stix_timestamp(entry["generated_at"]) for entry in entries)
        if entries
        else datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
    )
    objects: List[Dict[str, Any]] = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": created,
        "modified": created,
        "name": "LureScope",
        "identity_class": "system",
    }]
    for entry in entries:
        label = labels.get(entry["case_id"])
        if not _stix_incident_selected(entry, label):
            continue
        modified = _latest_stix_timestamp(
            entry["generated_at"], label["labeled_at"] if label else entry["generated_at"]
        )
        analyst_label = label["label"] if label else "unlabeled"
        incident_id = f"incident--{uuid.uuid4()}"
        objects.append({
            "type": "incident",
            "spec_version": "2.1",
            "id": incident_id,
            "created_by_ref": identity_id,
            "created": _stix_timestamp(entry["generated_at"]),
            "modified": modified,
            "name": f"LureScope fraud-lure case {entry['case_id']}",
            "description": (
                "Privacy-minimized local email assessment. Original message content, "
                "addresses, URLs, and attachment names are intentionally excluded."
            ),
            "labels": [
                "fraud-lure",
                f"risk-{entry['risk_tier']}",
                f"analyst-{analyst_label}",
            ],
            "confidence": round(float(entry["assessment"]["fraud_probability"]) * 100),
        })
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def render_export(
    entries: List[Dict[str, Any]],
    output_format: str,
    labels_by_case: Optional[Dict[str, Dict[str, Any]]] = None,
) -> bytes:
    """Render without making any network call or adding credentials."""
    reviewed_formats = {"ocsf-1.8", "ecs-9.4", "stix-2.1"}
    if labels_by_case and output_format not in reviewed_formats:
        raise ValueError("analyst labels are supported only by OCSF, ECS, and STIX exports")
    entries = [_validate_entry_shape(entry, index) for index, entry in enumerate(entries, 1)]
    processed = [entry for entry in entries if entry["status"] == "processed"]
    labels = _validated_labels(
        labels_by_case, {entry["case_id"] for entry in processed}
    )
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
    if output_format == "ocsf-1.8":
        records = [
            _ocsf_record(entry, labels.get(entry["case_id"])) for entry in processed
        ]
        return (json.dumps(records, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    if output_format == "ecs-9.4":
        lines = [
            json.dumps(
                _ecs_record(entry, labels.get(entry["case_id"])),
                ensure_ascii=False,
                sort_keys=True,
            )
            for entry in processed
        ]
        return (("\n".join(lines) + "\n") if lines else "").encode()
    if output_format == "stix-2.1":
        bundle = _stix_bundle(processed, labels)
        return (json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    raise ValueError(f"format must be one of: {', '.join(EXPORT_FORMATS)}")


def export_inbox_manifest(
    manifest_path: Path,
    output_path: Path,
    output_format: str,
    *,
    labels_path: Optional[Path] = None,
) -> int:
    """Transform a manifest into a new private file and return the event count."""
    if labels_path is not None and output_format not in {"ocsf-1.8", "ecs-9.4", "stix-2.1"}:
        raise ValueError("--labels is supported only by OCSF, ECS, and STIX exports")
    entries = load_inbox_manifest(manifest_path)
    labels: Dict[str, Dict[str, Any]] = {}
    if labels_path is not None:
        from .shadow import load_analyst_labels

        processed_ids = {
            entry["case_id"] for entry in entries if entry["status"] == "processed"
        }
        _, labels = load_analyst_labels(
            labels_path, allowed_case_ids=processed_ids
        )
    payload = render_export(entries, output_format, labels)
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except Exception:
        Path(output_path).unlink(missing_ok=True)
        raise
    if output_format in {"ocsf-1.8", "ecs-9.4"}:
        return sum(entry["status"] == "processed" for entry in entries)
    if output_format == "stix-2.1":
        return sum(
            entry["status"] == "processed"
            and _stix_incident_selected(entry, labels.get(entry["case_id"]))
            for entry in entries
        )
    return len(entries)
