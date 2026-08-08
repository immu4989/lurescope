"""LureProof: privacy-minimized, verifiable fraud-control evidence.

A proof records detector provenance and adversarial outcomes without storing the
message, transformed lure text, addresses, URLs, or attachment names. Its digest
detects alteration; it does not authenticate who created the proof.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import __version__, service
from .triage import MAX_SCORE_TEXT, parse_email, triage_email

SPEC_VERSION = "0.1"
LOCAL_ATTACKS = ("homoglyph", "leet", "zero-width", "whitespace")
DEFENSE = "normalize"


def _canonical(value: Dict[str, Any]) -> bytes:
    """Stable UTF-8 JSON encoding used by LureProof 0.1 digest verification."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _digest(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def create_email_proof(
    raw: bytes,
    detector_name: str = service.DEFAULT_DETECTOR,
    threshold: Optional[float] = None,
    engine: Optional[str] = None,
    model: Optional[str] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a shareable proof without retaining message content or identifiers."""
    parsed = parse_email(raw)
    triage = triage_email(raw, detector_name, threshold, engine, model)
    score_text = "\n\n".join(item for item in (parsed.subject, parsed.body) if item).strip()

    outcomes: List[Dict[str, Any]] = []
    for attack_name in LOCAL_ATTACKS:
        result = service.attack(
            score_text[:MAX_SCORE_TEXT],
            attack_name,
            detector_name=detector_name,
            threshold=triage.threshold,
            engine=engine,
            model=model,
            defense=DEFENSE,
        )
        outcomes.append({
            "attack": attack_name,
            "attacked_probability": result.attacked_probability,
            "attacked_flagged": result.attacked_flagged,
            "evaded": result.evaded,
            "defense": DEFENSE,
            "defended_probability": result.defended_probability,
            "defended_flagged": result.defended_flagged,
            "defense_recovered": result.defense_recovered,
            "defended_evaded": result.defended_evaded,
        })

    clean_flagged = triage.content_probability >= triage.threshold
    payload: Dict[str, Any] = {
        "spec": "lureproof",
        "spec_version": SPEC_VERSION,
        "created_at": created_at or _timestamp(),
        "privacy_profile": "shareable-minimized",
        "subject": {
            "media_type": "message/rfc822",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "byte_length": len(raw),
        },
        "assessment": {
            "detector": triage.detector,
            "detector_model": model,
            "fraud_probability": triage.content_probability,
            "label": triage.content_label,
            "risk_tier": triage.risk_tier,
            "threshold": triage.threshold,
            "threshold_source": triage.threshold_source,
            "policy_id": triage.policy_id,
            "evidence_codes": [item.code for item in triage.evidence],
            "url_count": len(triage.urls),
            "attachment_count": len(triage.attachments),
        },
        "resilience": {
            "clean_flagged": clean_flagged,
            "attack_count": len(outcomes),
            "evasion_count": sum(bool(item["evaded"]) for item in outcomes),
            "defense_recovery_count": sum(
                bool(item["defense_recovered"]) for item in outcomes
            ),
            "eligible_attack_count": len(outcomes) if clean_flagged else 0,
            "outcomes": outcomes,
        },
        "implementation": {
            "name": "lurescope",
            "version": __version__,
            "attack_source": "lurebench",
        },
        "framework_mappings": {
            "nist_ai_rmf_functions": ["MEASURE", "MANAGE"],
            "mitre_attack_techniques": ["T1566"],
        },
        "limitations": [
            "Digest integrity does not authenticate the proof issuer.",
            "Outcomes cover deterministic text attacks, not every fraud tactic.",
            "A message hash can correlate identical artifacts across systems.",
        ],
    }
    return {
        **payload,
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "lureproof-json-0.1",
            "digest": _digest(payload),
        },
    }


def verify_proof(proof: Dict[str, Any]) -> Dict[str, Any]:
    """Validate required structure and recompute the LureProof payload digest."""
    errors: List[str] = []
    if proof.get("spec") != "lureproof":
        errors.append("spec must be 'lureproof'")
    if proof.get("spec_version") != SPEC_VERSION:
        errors.append(f"unsupported spec_version; expected {SPEC_VERSION}")
    integrity = proof.get("integrity")
    if not isinstance(integrity, dict):
        errors.append("integrity object is required")
        claimed = None
    else:
        if integrity.get("algorithm") != "sha256":
            errors.append("integrity.algorithm must be 'sha256'")
        if integrity.get("canonicalization") != "lureproof-json-0.1":
            errors.append("unsupported canonicalization")
        claimed = integrity.get("digest")
    for field in ("subject", "assessment", "resilience", "implementation"):
        if not isinstance(proof.get(field), dict):
            errors.append(f"{field} object is required")
    payload = {key: value for key, value in proof.items() if key != "integrity"}
    calculated = _digest(payload)
    if not isinstance(claimed, str) or claimed != calculated:
        errors.append("digest mismatch")
    return {"valid": not errors, "digest": calculated, "errors": errors}


def dumps_proof(proof: Dict[str, Any]) -> str:
    """Human-reviewable serialization; verification remains whitespace-independent."""
    return json.dumps(proof, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
