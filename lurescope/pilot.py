"""Pre-registered, fail-closed decision gates for Shadow Inbox pilots.

The gate deliberately consumes only the privacy-minimized Shadow Inbox bundle.
It binds its result to the registered plan bytes, manifest, and append-only label log,
then evaluates exact one-sided binomial confidence bounds and workload limits.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from lurebench.calibration import clopper_pearson_upper

from . import service
from .inbox import MAX_INBOX_MESSAGES
from .integrations import load_inbox_manifest
from .shadow import build_shadow_report, load_analyst_labels, load_shadow_run

PILOT_PLAN_SCHEMA = "https://github.com/immu4989/lurescope/spec/pilot-plan/v1"
PILOT_GATE_SCHEMA = "https://github.com/immu4989/lurescope/spec/pilot-gate/v1"
PILOT_GATE_METHOD = "one_sided_clopper_pearson_exact_v1"
CONFIDENCE_SCOPE = "per_metric_one_sided"
LABELING_PROTOCOLS = ("full_blinded_review", "full_review")

_PLAN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DETECTOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
_POLICY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_PLAN_KEYS = {
    "schema",
    "schema_version",
    "plan_id",
    "created_at",
    "labeling_protocol",
    "confidence",
    "confidence_scope",
    "control",
    "requirements",
    "acceptance",
}
_CONTROL_KEYS = {"detector", "detector_artifact_sha256", "threshold", "policy_id"}
_REQUIREMENT_KEYS = {
    "min_processed_count",
    "min_fraud_labels",
    "min_benign_labels",
    "required_label_coverage",
    "max_uncertain_rate",
    "max_processing_failure_rate",
}
_ACCEPTANCE_KEYS = {
    "min_routing_recall_lower_bound",
    "max_routing_false_positive_rate_upper_bound",
    "max_routed_rate",
    "max_routed_count",
}
_LIMITATIONS = [
    "representative_iid_sample_required",
    "label_quality_not_verified",
    "labeling_protocol_not_verified",
    "distribution_shift_not_covered",
    "per_metric_confidence_not_simultaneous_confidence",
    "sha256_bindings_are_not_authentication",
]


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _parse_timestamp(value: object, field: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return timestamp


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer of at least {minimum}")
    return value


def _probability(
    value: object,
    field: str,
    *,
    allow_zero: bool = True,
    allow_one: bool = True,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{field} must be finite")
    if result < 0 or result > 1:
        raise ValueError(f"{field} must be between zero and one")
    if not allow_zero and result == 0:
        raise ValueError(f"{field} must be greater than zero")
    if not allow_one and result == 1:
        raise ValueError(f"{field} must be less than one")
    return result


def _read_regular(path: Path, max_bytes: int = 64 * 1024) -> bytes:
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link {path.name}")
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path.name} exceeds the {max_bytes} byte safety limit")
    return path.read_bytes()


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def load_pilot_plan(path: Path) -> Dict[str, Any]:
    """Load and strictly validate a Pilot Gate plan v1."""
    path = Path(path)
    raw = _read_regular(path)
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name} is not valid JSON") from exc
    if not isinstance(plan, dict) or set(plan) != _PLAN_KEYS:
        raise ValueError("pilot plan violates the v1 allowlist")
    if plan.get("schema") != PILOT_PLAN_SCHEMA or plan.get("schema_version") != 1:
        raise ValueError("pilot plan is not a Pilot Gate plan v1")
    if not _PLAN_ID.fullmatch(str(plan.get("plan_id", ""))):
        raise ValueError("plan_id must be a 1-64 character lowercase slug")
    _parse_timestamp(plan["created_at"], "created_at")
    if plan.get("labeling_protocol") not in LABELING_PROTOCOLS:
        raise ValueError("labeling_protocol is unsupported")
    confidence = _probability(
        plan["confidence"], "confidence", allow_zero=False, allow_one=False
    )
    if confidence < 0.8 or confidence > 0.999:
        raise ValueError("confidence must be between 0.8 and 0.999")
    if plan.get("confidence_scope") != CONFIDENCE_SCOPE:
        raise ValueError("confidence_scope is unsupported")

    control = plan.get("control")
    if not isinstance(control, dict) or set(control) != _CONTROL_KEYS:
        raise ValueError("pilot plan control violates the v1 allowlist")
    detector = control.get("detector")
    if not isinstance(detector, str) or not _DETECTOR_ID.fullmatch(detector):
        raise ValueError("control detector must be a 1-100 character identifier")
    if detector not in service.ALWAYS_ON:
        raise ValueError("Pilot Gate supports deterministic local LureProof detectors only")
    artifact_digest = control.get("detector_artifact_sha256")
    if detector == "tfidf-logreg":
        if not isinstance(artifact_digest, str) or not re.fullmatch(
            r"[a-f0-9]{64}", artifact_digest
        ):
            raise ValueError("tfidf-logreg control requires its model artifact SHA-256")
    elif artifact_digest is not None:
        raise ValueError("detectors without a model artifact must register null SHA-256")
    _probability(control.get("threshold"), "control threshold")
    policy_id = control.get("policy_id")
    if policy_id is not None and (
        not isinstance(policy_id, str) or not _POLICY_ID.fullmatch(policy_id)
    ):
        raise ValueError("control policy_id must be null or a safe identifier")

    requirements = plan.get("requirements")
    if not isinstance(requirements, dict) or set(requirements) != _REQUIREMENT_KEYS:
        raise ValueError("pilot plan requirements violate the v1 allowlist")
    minimum_processed = _integer(
        requirements["min_processed_count"], "min_processed_count", minimum=2
    )
    minimum_fraud = _integer(
        requirements["min_fraud_labels"], "min_fraud_labels", minimum=1
    )
    minimum_benign = _integer(
        requirements["min_benign_labels"], "min_benign_labels", minimum=1
    )
    if any(
        value > MAX_INBOX_MESSAGES
        for value in (minimum_processed, minimum_fraud, minimum_benign)
    ):
        raise ValueError(f"pilot sample requirements cannot exceed {MAX_INBOX_MESSAGES}")
    if minimum_fraud + minimum_benign > minimum_processed:
        raise ValueError("fraud and benign label minima cannot exceed min_processed_count")
    required_coverage = _probability(
        requirements["required_label_coverage"], "required_label_coverage"
    )
    if required_coverage != 1:
        raise ValueError("Pilot Gate v1 requires complete latest-label coverage")
    _probability(requirements["max_uncertain_rate"], "max_uncertain_rate")
    _probability(
        requirements["max_processing_failure_rate"],
        "max_processing_failure_rate",
    )

    acceptance = plan.get("acceptance")
    if not isinstance(acceptance, dict) or set(acceptance) != _ACCEPTANCE_KEYS:
        raise ValueError("pilot plan acceptance criteria violate the v1 allowlist")
    _probability(
        acceptance["min_routing_recall_lower_bound"],
        "min_routing_recall_lower_bound",
        allow_zero=False,
    )
    _probability(
        acceptance["max_routing_false_positive_rate_upper_bound"],
        "max_routing_false_positive_rate_upper_bound",
        allow_zero=False,
        allow_one=False,
    )
    _probability(acceptance["max_routed_rate"], "max_routed_rate")
    maximum_routed = _integer(acceptance["max_routed_count"], "max_routed_count")
    if maximum_routed > MAX_INBOX_MESSAGES:
        raise ValueError(f"max_routed_count cannot exceed {MAX_INBOX_MESSAGES}")
    return plan


def create_pilot_plan(
    path: Path,
    *,
    plan_id: str,
    min_processed_count: int,
    min_fraud_labels: int,
    min_benign_labels: int,
    max_uncertain_rate: float,
    max_processing_failure_rate: float,
    min_routing_recall_lower_bound: float,
    max_routing_false_positive_rate_upper_bound: float,
    max_routed_rate: float,
    max_routed_count: int,
    confidence: float = 0.95,
    labeling_protocol: str = "full_blinded_review",
    detector: str = "tfidf-logreg",
    threshold: float = 0.5,
    policy_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new, private plan that cannot overwrite an existing registration."""
    plan: Dict[str, Any] = {
        "schema": PILOT_PLAN_SCHEMA,
        "schema_version": 1,
        "plan_id": plan_id,
        "created_at": _timestamp(),
        "labeling_protocol": labeling_protocol,
        "confidence": confidence,
        "confidence_scope": CONFIDENCE_SCOPE,
        "control": {
            "detector": detector,
            "detector_artifact_sha256": detector_artifact_sha256(detector),
            "threshold": threshold,
            "policy_id": policy_id,
        },
        "requirements": {
            "min_processed_count": min_processed_count,
            "min_fraud_labels": min_fraud_labels,
            "min_benign_labels": min_benign_labels,
            "required_label_coverage": 1.0,
            "max_uncertain_rate": max_uncertain_rate,
            "max_processing_failure_rate": max_processing_failure_rate,
        },
        "acceptance": {
            "min_routing_recall_lower_bound": min_routing_recall_lower_bound,
            "max_routing_false_positive_rate_upper_bound": (
                max_routing_false_positive_rate_upper_bound
            ),
            "max_routed_rate": max_routed_rate,
            "max_routed_count": max_routed_count,
        },
    }
    # Validate before touching the requested path. A private temporary file keeps
    # creation and loading on the same strict parser without relaxing overwrite rules.
    target = Path(path)
    payload = (
        json.dumps(plan, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.validate")
    try:
        _write_new(temporary, payload)
        load_pilot_plan(temporary)
    finally:
        temporary.unlink(missing_ok=True)
    _write_new(target, payload)
    return plan


def pilot_plan_sha256(path: Path) -> str:
    """Return the digest operators can register before running the pilot."""
    load_pilot_plan(path)
    return hashlib.sha256(_read_regular(Path(path))).hexdigest()


def detector_artifact_sha256(detector: str) -> Optional[str]:
    """Return the bundled deterministic detector artifact bound by a new plan."""
    if detector == "tfidf-logreg":
        model = Path(__file__).with_name("models") / "tfidf-logreg-fraud.joblib"
        return hashlib.sha256(model.read_bytes()).hexdigest()
    if detector == "heuristic-v0":
        return None
    raise ValueError("Pilot Gate supports deterministic local LureProof detectors only")


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return numerator / denominator if denominator else None


def _rounded(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(value, 12)


def _recall_lower(true_positives: int, fraud_total: int, confidence: float) -> Optional[float]:
    if not fraud_total:
        return None
    failures = fraud_total - true_positives
    return 1.0 - clopper_pearson_upper(failures, fraud_total, confidence)


def _fpr_upper(false_positives: int, benign_total: int, confidence: float) -> Optional[float]:
    if not benign_total:
        return None
    return clopper_pearson_upper(false_positives, benign_total, confidence)


def _check(
    check_id: str,
    group: str,
    observed: Optional[float],
    operator: str,
    threshold: float,
    *,
    evaluable: bool = True,
) -> Dict[str, Any]:
    if not evaluable or observed is None:
        status = "not_evaluable"
    elif operator == ">=":
        status = "pass" if observed >= threshold else "fail"
    elif operator == "<=":
        status = "pass" if observed <= threshold else "fail"
    else:  # pragma: no cover - all operators are module constants
        raise ValueError(f"unsupported operator: {operator}")
    return {
        "id": check_id,
        "group": group,
        "status": status,
        "observed": _rounded(observed),
        "operator": operator,
        "threshold": threshold,
    }


def build_pilot_gate(bundle: Path, plan_path: Path) -> Dict[str, Any]:
    """Evaluate a pre-registered plan against an aggregate Shadow Inbox report."""
    bundle = Path(bundle)
    plan_path = Path(plan_path)
    plan_digest = hashlib.sha256(_read_regular(plan_path)).hexdigest()
    plan = load_pilot_plan(plan_path)
    run = load_shadow_run(bundle)
    run_timestamp = _parse_timestamp(run["generated_at"], "run generated_at")
    if _parse_timestamp(plan["created_at"], "plan created_at") > run_timestamp:
        raise ValueError("pilot plan must be created before the Shadow Inbox run")
    manifest_path = bundle / str(run["manifest"])
    labels_path = bundle / str(run["labels"])
    manifest_digest = hashlib.sha256(_read_regular(manifest_path, 8 * 1024 * 1024)).hexdigest()
    labels_digest = hashlib.sha256(_read_regular(labels_path, 4 * 1024 * 1024)).hexdigest()
    report = build_shadow_report(bundle)
    requirements = plan["requirements"]
    acceptance = plan["acceptance"]
    review = report["analyst_review"]
    volume = report["volume"]
    routing = report["routing"]
    confusion = review["confusion"]

    processed = int(volume["processed_count"])
    failed = int(volume["failed_count"])
    total_attempted = processed + failed
    fraud_labels = int(review["label_counts"]["fraud"])
    benign_labels = int(review["label_counts"]["benign"])
    uncertain_labels = int(review["label_counts"]["uncertain"])
    coverage = _ratio(int(review["latest_label_count"]), processed)
    uncertain_rate = _ratio(uncertain_labels, processed)
    failure_rate = _ratio(failed, total_attempted)
    routed_count = int(routing["routed_count"])
    routed_rate = _ratio(routed_count, processed)
    recall_estimate = _ratio(int(confusion["true_positive"]), fraud_labels)
    fpr_estimate = _ratio(int(confusion["false_positive"]), benign_labels)
    confidence = float(plan["confidence"])
    recall_lower = _recall_lower(
        int(confusion["true_positive"]), fraud_labels, confidence
    )
    fpr_upper = _fpr_upper(int(confusion["false_positive"]), benign_labels, confidence)

    entries = load_inbox_manifest(manifest_path)
    expected_control = plan["control"]
    for entry in entries:
        if entry["status"] != "processed":
            continue
        assessment = entry["assessment"]
        actual = {
            "detector": assessment["detector"],
            "detector_artifact_sha256": assessment["detector_artifact_sha256"],
            "threshold": assessment["threshold"],
            "policy_id": assessment["policy_id"],
        }
        if actual != expected_control:
            raise ValueError(
                "Shadow Inbox control does not match the pre-registered detector, "
                "model artifact, threshold, and policy_id"
            )
    revisions, _ = load_analyst_labels(labels_path)
    if any(
        _parse_timestamp(event["labeled_at"], "label labeled_at") < run_timestamp
        for event in revisions
    ):
        raise ValueError("analyst labels cannot predate the Shadow Inbox run")
    final_digests = {
        "plan": hashlib.sha256(_read_regular(plan_path)).hexdigest(),
        "manifest": hashlib.sha256(
            _read_regular(manifest_path, 8 * 1024 * 1024)
        ).hexdigest(),
        "labels": hashlib.sha256(_read_regular(labels_path, 4 * 1024 * 1024)).hexdigest(),
    }
    initial_digests = {
        "plan": plan_digest,
        "manifest": manifest_digest,
        "labels": labels_digest,
    }
    if final_digests != initial_digests:
        raise ValueError("pilot plan, manifest, or labels changed during gate evaluation")

    evidence_checks = [
        _check(
            "processed_count",
            "evidence",
            float(processed),
            ">=",
            requirements["min_processed_count"],
        ),
        _check(
            "fraud_label_count",
            "evidence",
            float(fraud_labels),
            ">=",
            requirements["min_fraud_labels"],
        ),
        _check(
            "benign_label_count",
            "evidence",
            float(benign_labels),
            ">=",
            requirements["min_benign_labels"],
        ),
        _check(
            "label_coverage",
            "evidence",
            coverage,
            ">=",
            requirements["required_label_coverage"],
        ),
        _check(
            "uncertain_rate",
            "evidence",
            uncertain_rate,
            "<=",
            requirements["max_uncertain_rate"],
        ),
        _check(
            "processing_failure_rate",
            "evidence",
            failure_rate,
            "<=",
            requirements["max_processing_failure_rate"],
        ),
    ]
    evidence_sufficient = all(item["status"] == "pass" for item in evidence_checks)
    acceptance_checks = [
        _check(
            "routing_recall_lower_bound",
            "acceptance",
            recall_lower,
            ">=",
            acceptance["min_routing_recall_lower_bound"],
            evaluable=evidence_sufficient,
        ),
        _check(
            "routing_false_positive_rate_upper_bound",
            "acceptance",
            fpr_upper,
            "<=",
            acceptance["max_routing_false_positive_rate_upper_bound"],
            evaluable=evidence_sufficient,
        ),
        _check(
            "routed_rate",
            "acceptance",
            routed_rate,
            "<=",
            acceptance["max_routed_rate"],
            evaluable=evidence_sufficient,
        ),
        _check(
            "routed_count",
            "acceptance",
            float(routed_count),
            "<=",
            acceptance["max_routed_count"],
            evaluable=evidence_sufficient,
        ),
    ]
    if not evidence_sufficient:
        verdict = "insufficient_evidence"
        failed_checks = [
            item["id"] for item in evidence_checks if item["status"] != "pass"
        ]
    else:
        failed_checks = [
            item["id"] for item in acceptance_checks if item["status"] != "pass"
        ]
        verdict = "fail" if failed_checks else "pass"

    return {
        "schema": PILOT_GATE_SCHEMA,
        "schema_version": 1,
        "generated_at": _timestamp(),
        "verdict": verdict,
        "failed_checks": failed_checks,
        "method": PILOT_GATE_METHOD,
        "privacy": {
            "aggregate_only": True,
            "contains_case_identifiers": False,
            "contains_message_content": False,
        },
        "plan_binding": {
            "plan_id": plan["plan_id"],
            "created_at": plan["created_at"],
            "labeling_protocol": plan["labeling_protocol"],
            "control": plan["control"],
            "sha256": plan_digest,
        },
        "run_binding": {
            "generated_at": run["generated_at"],
            "manifest_sha256": manifest_digest,
            "labels_sha256": labels_digest,
        },
        "confidence": {
            "level": confidence,
            "scope": CONFIDENCE_SCOPE,
        },
        "metrics": {
            "processed_count": processed,
            "failed_count": failed,
            "latest_label_count": int(review["latest_label_count"]),
            "fraud_label_count": fraud_labels,
            "benign_label_count": benign_labels,
            "uncertain_label_count": uncertain_labels,
            "label_coverage": _rounded(coverage),
            "uncertain_rate": _rounded(uncertain_rate),
            "processing_failure_rate": _rounded(failure_rate),
            "routed_count": routed_count,
            "routed_rate": _rounded(routed_rate),
            "confusion": confusion,
            "routing_recall_estimate": _rounded(recall_estimate),
            "routing_recall_lower_bound": _rounded(recall_lower),
            "routing_false_positive_rate_estimate": _rounded(fpr_estimate),
            "routing_false_positive_rate_upper_bound": _rounded(fpr_upper),
        },
        "checks": [*evidence_checks, *acceptance_checks],
        "interpretation_boundary": (
            "A pass is evidence that this pre-registered sample met the stated gate; "
            "it is not certification, proof of safety, or authorization for enforcement."
        ),
        "limitations": _LIMITATIONS,
    }


def render_pilot_gate_markdown(gate: Dict[str, Any]) -> str:
    """Render a compact aggregate-only decision record."""
    metrics = gate["metrics"]

    def percent(value: Optional[float]) -> str:
        return "not measurable" if value is None else f"{value:.2%}"

    verdict = gate["verdict"].replace("_", " ").upper()
    lines = [
        "# LureScope Pilot Gate",
        "",
        f"## Verdict: {verdict}",
        "",
        f"Plan: `{gate['plan_binding']['plan_id']}`  ",
        f"Plan SHA-256: `{gate['plan_binding']['sha256']}`  ",
        f"Control: `{gate['plan_binding']['control']['detector']}` at threshold "
        f"`{gate['plan_binding']['control']['threshold']}`  ",
        f"Labeling protocol: `{gate['plan_binding']['labeling_protocol']}`  ",
        f"Generated: `{gate['generated_at']}`",
        "",
        "> Aggregate-only decision record. It contains no case identifiers or message content.",
        "",
        "| Measure | Observed |",
        "|---|---:|",
        f"| Processed | {metrics['processed_count']} |",
        f"| Latest-label coverage | {percent(metrics['label_coverage'])} |",
        f"| Fraud / benign / uncertain labels | {metrics['fraud_label_count']} / "
        f"{metrics['benign_label_count']} / {metrics['uncertain_label_count']} |",
        f"| Recall estimate | {percent(metrics['routing_recall_estimate'])} |",
        f"| Recall lower bound | {percent(metrics['routing_recall_lower_bound'])} |",
        f"| False-positive-rate estimate | "
        f"{percent(metrics['routing_false_positive_rate_estimate'])} |",
        f"| False-positive-rate upper bound | "
        f"{percent(metrics['routing_false_positive_rate_upper_bound'])} |",
        f"| Routed workload | {metrics['routed_count']} "
        f"({percent(metrics['routed_rate'])}) |",
        "",
        "## Pre-registered checks",
        "",
        "| Check | Group | Rule | Observed | Status |",
        "|---|---|---:|---:|---|",
    ]
    for item in gate["checks"]:
        observed = "n/a" if item["observed"] is None else str(item["observed"])
        lines.append(
            f"| `{item['id']}` | {item['group']} | {item['operator']} "
            f"{item['threshold']} | {observed} | **{item['status']}** |"
        )
    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        gate["interpretation_boundary"],
        "Confidence is one-sided and per metric; it is not a simultaneous confidence "
        "statement across the complete gate. The result assumes representative independent "
        "sampling and trustworthy labels. The declared review protocol is not technically "
        "verified, and the gate does not cover distribution shift.",
        "",
    ])
    return "\n".join(lines)


def write_pilot_gate(bundle: Path, plan_path: Path) -> Dict[str, Any]:
    """Evaluate and atomically refresh private JSON and Markdown gate artifacts."""
    bundle = Path(bundle)
    plan_path = Path(plan_path)
    source_bytes = _read_regular(plan_path)
    load_pilot_plan(plan_path)
    if _read_regular(plan_path) != source_bytes:
        raise ValueError("pilot plan changed while it was being registered")
    registered_plan = bundle / "pilot-plan.json"
    if plan_path.absolute() != registered_plan.absolute():
        if registered_plan.exists() or registered_plan.is_symlink():
            registered_bytes = _read_regular(registered_plan)
            if not secrets.compare_digest(registered_bytes, source_bytes):
                raise ValueError("bundle is already bound to a different pilot plan")
        else:
            _write_new(registered_plan, source_bytes)
    load_pilot_plan(registered_plan)
    gate = build_pilot_gate(bundle, registered_plan)
    _replace_private(
        bundle / "pilot-gate.json",
        (json.dumps(gate, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    _replace_private(
        bundle / "pilot-gate.md", render_pilot_gate_markdown(gate).encode("utf-8")
    )
    return gate
