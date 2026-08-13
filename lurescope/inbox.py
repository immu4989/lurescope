"""Batch suspicious-email processing with privacy-minimized case outputs.

The inbox workflow composes the existing safe RFC 5322 parser, deterministic
triage, adversarial resilience checks, and LureProof producer. Output manifests
intentionally exclude source paths, subjects, addresses, message IDs, URLs,
attachment names, and message text. The caller may keep the returned in-memory
source-to-case mapping locally; it is never persisted by this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import service
from .proof import create_email_proof, dumps_proof, sign_statement, verify_proof

INBOX_SCHEMA = "https://github.com/immu4989/lurescope/spec/inbox-event/v1"
INBOX_SUMMARY_SCHEMA = "https://github.com/immu4989/lurescope/spec/inbox-summary/v1"
MAX_INBOX_MESSAGES = 1_000


@dataclass(frozen=True)
class InboxItem:
    """Local-only processing result; ``source`` is never written to the bundle."""

    source: str
    case_id: str
    status: str
    risk_tier: Optional[str] = None
    proof_file: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class InboxRun:
    output_dir: Path
    items: List[InboxItem]
    summary: Dict[str, Any]

    @property
    def failed_count(self) -> int:
        return int(self.summary["failed_count"])


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _write_new(path: Path, payload: bytes, mode: int = 0o600) -> None:
    """Create one private output without following or overwriting an existing path."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _new_case_id(known: set[str]) -> str:
    while True:
        candidate = f"case-{secrets.token_hex(8)}"
        if candidate not in known:
            known.add(candidate)
            return candidate


def _manifest_entry(
    case_id: str,
    input_index: int,
    statement: Dict[str, Any],
    proof_file: str,
    proof_result: Dict[str, Any],
) -> Dict[str, Any]:
    predicate = statement["predicate"]
    assessment = predicate["assessment"]
    resilience = predicate["resilience"]
    return {
        "schema": INBOX_SCHEMA,
        "schema_version": 1,
        "generated_at": predicate["generated_at"],
        "case_id": case_id,
        "input_index": input_index,
        "status": "processed",
        "risk_tier": assessment["risk_tier"],
        "recommended_action": {
            "high": "quarantine_and_review",
            "review": "hold_and_verify_sender",
            "low": "continue_normal_controls",
        }[assessment["risk_tier"]],
        "assessment": {
            "detector": assessment["detector"],
            "detector_model": assessment["detector_model"],
            "detector_artifact_sha256": assessment["detector_artifact_sha256"],
            "fraud_probability": assessment["fraud_probability"],
            "label": assessment["label"],
            "threshold": assessment["threshold"],
            "threshold_source": assessment["threshold_source"],
            "policy_id": assessment["policy_id"],
            "evidence_codes": assessment["evidence_codes"],
            "url_count": assessment["url_count"],
            "attachment_count": assessment["attachment_count"],
        },
        "resilience": {
            "clean_flagged": resilience["clean_flagged"],
            "attack_count": resilience["attack_count"],
            "eligible_attack_count": resilience["eligible_attack_count"],
            "evasion_count": resilience["evasion_count"],
            "defense_recovery_count": resilience["defense_recovery_count"],
        },
        "proof": {
            "file": proof_file,
            "artifact_type": proof_result["artifact_type"],
            "statement_sha256": proof_result["statement_sha256"],
            "signature_count": proof_result["signature_count"],
            "key_ids": proof_result["key_ids"],
        },
    }


def process_inbox(
    messages: Sequence[Tuple[str, bytes]],
    output_dir: Path,
    *,
    detector_name: str = service.DEFAULT_DETECTOR,
    threshold: Optional[float] = None,
    privacy_profile: str = "salted-commitment",
    nonce: Optional[str] = None,
    issuer: Optional[str] = None,
    signing_key_pem: Optional[bytes] = None,
    max_messages: int = MAX_INBOX_MESSAGES,
) -> InboxRun:
    """Process messages into private proofs and a shareable minimized manifest.

    ``messages`` contains local source labels solely for terminal feedback. Those
    labels are retained in the returned ``InboxRun`` but never written to disk.
    The output directory must not already exist, preventing accidental mixing or
    overwriting of case bundles.
    """
    if max_messages < 1 or max_messages > MAX_INBOX_MESSAGES:
        raise ValueError(f"max_messages must be between 1 and {MAX_INBOX_MESSAGES}")
    if not messages:
        raise ValueError("no .eml messages found")
    if len(messages) > max_messages:
        raise ValueError(
            f"inbox contains {len(messages)} messages; configured limit is {max_messages}"
        )

    output_dir = Path(output_dir)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(mode=0o700, exist_ok=False)
    try:
        output_dir.chmod(0o700)
    except OSError:
        pass

    generated_at = _timestamp()
    manifest_path = output_dir / "manifest.jsonl"
    manifest_descriptor = os.open(
        manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    items: List[InboxItem] = []
    known_ids: set[str] = set()
    risk_counts = {"high": 0, "review": 0, "low": 0}
    processed = 0
    failures = 0

    with os.fdopen(manifest_descriptor, "w", encoding="utf-8") as manifest:
        for input_index, (source, raw) in enumerate(messages, start=1):
            case_id = _new_case_id(known_ids)
            try:
                statement = create_email_proof(
                    raw,
                    detector_name,
                    threshold,
                    privacy_profile=privacy_profile,
                    nonce=nonce,
                    issuer=issuer,
                )
                artifact = (
                    sign_statement(statement, signing_key_pem)
                    if signing_key_pem is not None
                    else statement
                )
                proof_result = verify_proof(artifact)
                if not proof_result["valid"]:
                    raise ValueError(
                        "generated proof failed validation: "
                        + "; ".join(proof_result["errors"])
                    )
                suffix = ".lureproof.dsse.json" if signing_key_pem else ".lureproof.json"
                proof_file = f"{case_id}{suffix}"
                proof_bytes = dumps_proof(artifact).encode("utf-8")
                _write_new(output_dir / proof_file, proof_bytes)
                entry = _manifest_entry(
                    case_id, input_index, statement, proof_file, proof_result
                )
                risk_tier = str(entry["risk_tier"])
                risk_counts[risk_tier] += 1
                processed += 1
                items.append(InboxItem(
                    source=source,
                    case_id=case_id,
                    status="processed",
                    risk_tier=risk_tier,
                    proof_file=proof_file,
                ))
            except Exception as exc:  # continue after one malformed or unsupported message
                failures += 1
                entry = {
                    "schema": INBOX_SCHEMA,
                    "schema_version": 1,
                    "generated_at": generated_at,
                    "case_id": case_id,
                    "input_index": input_index,
                    "status": "error",
                    "error_type": type(exc).__name__,
                }
                items.append(InboxItem(
                    source=source,
                    case_id=case_id,
                    status="error",
                    error=f"{type(exc).__name__}: {exc}",
                ))
            manifest.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            manifest.flush()

    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    summary: Dict[str, Any] = {
        "schema": INBOX_SUMMARY_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "input_count": len(messages),
        "processed_count": processed,
        "failed_count": failures,
        "risk_counts": risk_counts,
        "detector": detector_name,
        "requested_threshold": threshold,
        "privacy_profile": privacy_profile,
        "proofs_signed": signing_key_pem is not None,
        "manifest": "manifest.jsonl",
        "manifest_sha256": manifest_sha256,
    }
    _write_new(
        output_dir / "summary.json",
        (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return InboxRun(output_dir=output_dir, items=items, summary=summary)
