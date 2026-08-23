"""Produce LureEval receipts from reviewed, pre-registered Shadow Inbox pilots."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from lurebench.receipts import (
    canonical_json,
    create_receipt_statement,
    derive_metrics,
    dumps_artifact,
    load_verified_artifact,
    sha256_bytes,
    sign_statement,
    validate_receipt_statement,
)

from . import __version__
from .defender import load_defender_import
from .pilot import load_pilot_gate, load_pilot_plan, write_pilot_gate
from .policy import load_policy
from .shadow import build_shadow_report, load_shadow_run

MAX_RECEIPT_BYTES = 8 * 1024 * 1024
_POLICY_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def _read_regular(path: Path, max_bytes: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link input: {path}")
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path.name} exceeds the {max_bytes} byte safety limit")
    return path.read_bytes()


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


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 8) if denominator else None


def _control(plan: Mapping[str, Any], policy_path: Optional[Path]) -> Dict[str, Any]:
    registered = plan["control"]
    policy_id = registered["policy_id"]
    policy_sha256 = None
    if policy_id is not None:
        if policy_path is None:
            raise ValueError(
                "the registered plan uses a policy_id; --policy is required to bind its bytes"
            )
        policy_bytes = _read_regular(Path(policy_path), 512 * 1024)
        policy = load_policy(str(Path(policy_path).resolve()))
        if policy.policy_id != policy_id:
            raise ValueError("--policy policy_id does not match the registered Pilot Gate plan")
        policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
        if not _POLICY_DIGEST.fullmatch(policy_sha256):  # defensive invariant
            raise RuntimeError("internal error: invalid policy digest")
    elif policy_path is not None:
        raise ValueError("--policy was supplied but the registered plan has no policy_id")
    return {
        "detector": registered["detector"],
        "detector_artifact_sha256": registered["detector_artifact_sha256"],
        "threshold": registered["threshold"],
        "policy_id": policy_id,
        "policy_sha256": policy_sha256,
    }


def _slices(report: Mapping[str, Any], source_type: str, minimum: int) -> Tuple[list[dict], int]:
    candidates = [
        {
            "dimension": "source_type",
            "value": source_type,
            "count": report["volume"]["processed_count"],
        },
        *[
            {"dimension": "risk_tier", "value": risk, "count": count}
            for risk, count in sorted(report["routing"]["risk_counts"].items())
        ],
    ]
    published = [item for item in candidates if item["count"] >= minimum]
    suppressed = sum(item["count"] < minimum for item in candidates)
    return published, suppressed


def create_lureeval_receipt(
    bundle: Path,
    output_path: Path,
    *,
    sampling: str = "consecutive_sample",
    minimum_slice_count: int = 20,
    issuer: Optional[str] = None,
    policy_path: Optional[Path] = None,
    signing_key_pem: Optional[bytes] = None,
    receipt_id: Optional[str] = None,
    generated_at: Optional[str] = None,
    refresh_gate: bool = True,
) -> Dict[str, Any]:
    """Create a receipt from a semantically current gate, refreshing it by default."""
    bundle = Path(bundle)
    plan_path = bundle / "pilot-plan.json"
    plan = load_pilot_plan(plan_path)
    gate = (
        write_pilot_gate(bundle, plan_path)
        if refresh_gate
        else load_pilot_gate(bundle, plan_path)
    )
    run = load_shadow_run(bundle)
    report = build_shadow_report(bundle)

    manifest_path = bundle / str(run["manifest"])
    labels_path = bundle / str(run["labels"])
    gate_path = bundle / "pilot-gate.json"
    manifest_sha256 = hashlib.sha256(_read_regular(manifest_path, 8 * 1024 * 1024)).hexdigest()
    labels_sha256 = hashlib.sha256(_read_regular(labels_path, 4 * 1024 * 1024)).hexdigest()
    plan_sha256 = hashlib.sha256(_read_regular(plan_path, 512 * 1024)).hexdigest()
    gate_sha256 = hashlib.sha256(_read_regular(gate_path, 2 * 1024 * 1024)).hexdigest()
    if gate["run_binding"] != {
        "generated_at": run["generated_at"],
        "manifest_sha256": manifest_sha256,
        "labels_sha256": labels_sha256,
    }:
        raise RuntimeError("refreshed Pilot Gate does not bind the current Shadow evidence")

    defender_path = bundle / "defender-import.json"
    defender_import = None
    if defender_path.exists() or defender_path.is_symlink():
        defender_import = load_defender_import(bundle)
    source_type = "microsoft_defender_export" if defender_import else "shadow_inbox"
    metrics = gate["metrics"]
    confusion = metrics["confusion"]
    confidence = float(gate["confidence"]["level"])
    slices, suppressed = _slices(report, source_type, minimum_slice_count)
    cohort = {
        "source_type": source_type,
        "run_generated_at": run["generated_at"],
        "processed_count": metrics["processed_count"],
        "failed_count": metrics["failed_count"],
        "latest_label_count": metrics["latest_label_count"],
        "uncertain_label_count": metrics["uncertain_label_count"],
        "evaluated_count": sum(confusion.values()),
        "manifest_sha256": manifest_sha256,
        "labels_sha256": labels_sha256,
        "plan_id": gate["plan_binding"]["plan_id"],
        "plan_sha256": plan_sha256,
        "gate_sha256": gate_sha256,
    }
    resilience = report["resilience"]
    routed = int(metrics["routed_count"])
    outcome = {
        "confusion": confusion,
        "metrics": derive_metrics(confusion, confidence),
        "routing": {
            "routed_count": routed,
            "routed_rate": _ratio(routed, int(metrics["processed_count"])),
        },
        "resilience": {
            "eligible_attack_count": resilience["eligible_attack_count"],
            "evasion_count": resilience["evasion_count"],
            "defense_recovery_count": resilience["defense_recovery_count"],
            "evasion_rate": _ratio(
                resilience["evasion_count"], resilience["eligible_attack_count"]
            ),
            "recovery_rate_among_evasions": _ratio(
                resilience["defense_recovery_count"], resilience["evasion_count"]
            ),
        },
        "pilot_gate": {
            "verdict": gate["verdict"],
            "failed_checks": gate["failed_checks"],
        },
    }
    cohort_commitment = sha256_bytes(
        canonical_json(
            {
                "manifest_sha256": manifest_sha256,
                "labels_sha256": labels_sha256,
                "plan_sha256": plan_sha256,
                "gate_sha256": gate_sha256,
            }
        )
    )
    statement = create_receipt_statement(
        producer_name="lurescope",
        producer_version=__version__,
        issuer=issuer,
        sampling=sampling,
        labeling_protocol=gate["plan_binding"]["labeling_protocol"],
        confidence=confidence,
        minimum_slice_count=minimum_slice_count,
        control=_control(plan, policy_path),
        cohort=cohort,
        outcome=outcome,
        slices=slices,
        suppressed_slice_count=suppressed,
        cohort_sha256=cohort_commitment,
        receipt_id=receipt_id,
        generated_at=generated_at,
    )
    if defender_import is not None:
        defender_digest = hashlib.sha256(_read_regular(defender_path, 512 * 1024)).hexdigest()
        statement["subject"].append(
            {"name": "microsoft-defender-import", "digest": {"sha256": defender_digest}}
        )
        validate_receipt_statement(statement)
    artifact = sign_statement(statement, signing_key_pem) if signing_key_pem else statement
    payload = dumps_artifact(artifact).encode("utf-8")
    if len(payload) > MAX_RECEIPT_BYTES:
        raise ValueError("LureEval artifact exceeds the 8 MiB safety limit")
    _write_new(Path(output_path), payload)
    return artifact


def verify_lureeval_receipt(
    path: Path,
    *,
    public_key_pem: Optional[bytes] = None,
    require_signature: bool = False,
) -> Dict[str, Any]:
    verified = load_verified_artifact(
        Path(path),
        public_key_pem=public_key_pem,
        require_signature=require_signature,
    )
    return {
        "valid": True,
        "statement_sha256": verified.statement_sha256,
        "signed": verified.signed,
        "authenticated": verified.authenticated,
        "key_ids": list(verified.key_ids),
        "predicate_type": verified.statement["predicateType"],
    }
