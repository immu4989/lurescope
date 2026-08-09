"""Strict loading of versioned decision policies exported by LureBench."""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, Optional

from lurebench.calibration import binomial_cdf, clopper_pearson_upper

_SHA256 = re.compile(r"[a-f0-9]{64}")
_RISK_CONTROL_METHOD = "learn_then_test_fixed_sequence_exact_binomial_v1"


@dataclass(frozen=True)
class RiskControl:
    method: str
    risk: str
    confidence: float
    validation_negatives: int
    false_positives: int
    empirical_fpr: float
    upper_confidence_bound: float
    hypothesis_p_value: float
    threshold_grid_size: int


@dataclass(frozen=True)
class DecisionPolicy:
    policy_id: str
    detector: str
    task: str
    threshold: float
    objective: str
    validation_records: int
    validation_sha256: str
    schema_version: int = 1
    target_fpr: Optional[float] = None
    created_at: str = ""
    evaluation_sha256: Optional[str] = None
    validation_true_positives: Optional[int] = None
    validation_recall: Optional[float] = None
    risk_control: Optional[RiskControl] = None


def _validate_probability(value: float, name: str, *, open_interval: bool = False) -> None:
    numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
    valid = numeric and math.isfinite(value) and (
        0 < value < 1 if open_interval else 0 <= value <= 1
    )
    if not valid:
        interval = "(0, 1)" if open_interval else "[0, 1]"
        raise ValueError(f"policy {name} must be in {interval}")


def _validate_policy(policy: DecisionPolicy) -> None:
    if type(policy.schema_version) is not int or policy.schema_version not in (1, 2):
        raise ValueError(f"unsupported policy schema {policy.schema_version}")
    for value, name in (
        (policy.policy_id, "policy_id"),
        (policy.detector, "detector"),
        (policy.objective, "objective"),
    ):
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError(f"policy {name} must be a non-empty string")
    if policy.task != "fraud":
        raise ValueError("LureScope only serves fraud decision policies")
    _validate_probability(policy.threshold, "threshold")
    if (
        type(policy.validation_records) is not int
        or policy.validation_records < 1
        or not isinstance(policy.validation_sha256, str)
        or not _SHA256.fullmatch(policy.validation_sha256)
    ):
        raise ValueError("policy has invalid validation provenance")
    if not isinstance(policy.created_at, str):
        raise ValueError("policy created_at must be an ISO 8601 timestamp")
    if policy.created_at:
        try:
            created = datetime.fromisoformat(policy.created_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("policy created_at must be an ISO 8601 timestamp") from exc
        if created.tzinfo is None:
            raise ValueError("policy created_at must include a timezone")
    elif policy.schema_version == 2:
        raise ValueError("schema v2 policy requires created_at")

    if policy.schema_version == 1:
        if (
            policy.risk_control is not None
            or policy.evaluation_sha256 is not None
            or policy.validation_true_positives is not None
            or policy.validation_recall is not None
        ):
            raise ValueError("schema v1 cannot carry v2 risk-control evidence")
        if policy.objective == "target_fpr":
            if policy.target_fpr is None:
                raise ValueError("target_fpr policy is missing its target")
            _validate_probability(policy.target_fpr, "target_fpr")
        return

    if policy.objective != "risk_controlled_fpr":
        raise ValueError("schema v2 requires objective='risk_controlled_fpr'")
    if policy.target_fpr is None:
        raise ValueError("risk-controlled policy is missing target_fpr")
    _validate_probability(policy.target_fpr, "target_fpr", open_interval=True)
    if (
        not isinstance(policy.evaluation_sha256, str)
        or not _SHA256.fullmatch(policy.evaluation_sha256)
    ):
        raise ValueError("risk-controlled policy has invalid evaluation provenance")
    control = policy.risk_control
    if control is None:
        raise ValueError("schema v2 policy is missing risk_control")
    if control.method != _RISK_CONTROL_METHOD or control.risk != "false_positive_rate":
        raise ValueError("unsupported risk-control method or risk")
    _validate_probability(control.confidence, "confidence", open_interval=True)
    for name in ("empirical_fpr", "upper_confidence_bound", "hypothesis_p_value"):
        _validate_probability(getattr(control, name), name)
    if (
        type(control.threshold_grid_size) is not int
        or not 2 <= control.threshold_grid_size <= 100_001
    ):
        raise ValueError("policy threshold_grid_size must be between 2 and 100001")
    if (
        type(control.validation_negatives) is not int
        or not 1 <= control.validation_negatives <= policy.validation_records
    ):
        raise ValueError("policy has invalid validation-negative count")
    if (
        type(control.false_positives) is not int
        or not 0 <= control.false_positives <= control.validation_negatives
    ):
        raise ValueError("policy has invalid false-positive count")
    validation_positives = policy.validation_records - control.validation_negatives
    if validation_positives < 1:
        raise ValueError("risk-controlled policy requires validation positives")
    if (
        type(policy.validation_true_positives) is not int
        or not 0 <= policy.validation_true_positives <= validation_positives
    ):
        raise ValueError("policy has invalid validation true-positive count")
    if policy.validation_recall is None:
        raise ValueError("risk-controlled policy is missing validation recall")
    _validate_probability(policy.validation_recall, "validation_recall")

    empirical = control.false_positives / control.validation_negatives
    empirical_recall = policy.validation_true_positives / validation_positives
    expected_p = binomial_cdf(
        control.false_positives, control.validation_negatives, policy.target_fpr
    )
    expected_upper = clopper_pearson_upper(
        control.false_positives, control.validation_negatives, control.confidence
    )
    if not math.isclose(control.empirical_fpr, empirical, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError("policy empirical_fpr is inconsistent with its counts")
    if not math.isclose(
        policy.validation_recall, empirical_recall, rel_tol=0.0, abs_tol=1e-12
    ):
        raise ValueError("policy validation_recall is inconsistent with its counts")
    if not math.isclose(
        control.hypothesis_p_value, expected_p, rel_tol=0.0, abs_tol=1e-12
    ):
        raise ValueError("policy hypothesis_p_value is inconsistent with its counts")
    if not math.isclose(
        control.upper_confidence_bound, expected_upper, rel_tol=0.0, abs_tol=1e-12
    ):
        raise ValueError("policy FPR upper bound is inconsistent with its counts")
    if control.hypothesis_p_value > 1 - control.confidence + 1e-12:
        raise ValueError("policy did not reject FPR above the target")
    if control.upper_confidence_bound > policy.target_fpr + 1e-12:
        raise ValueError("policy FPR upper bound exceeds its target")


@lru_cache(maxsize=8)
def load_policy(path: str) -> DecisionPolicy:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("policy JSON must be an object")
    if payload.get("risk_control") is not None:
        if not isinstance(payload["risk_control"], dict):
            raise ValueError("policy risk_control must be an object")
        payload["risk_control"] = RiskControl(**payload["risk_control"])
    policy = DecisionPolicy(**payload)
    _validate_policy(policy)
    return policy


def configured_policy() -> Optional[DecisionPolicy]:
    path = os.environ.get("LURESCOPE_POLICY_PATH")
    return load_policy(os.path.abspath(path)) if path else None


def policy_status(policy: Optional[DecisionPolicy]) -> Dict[str, Any]:
    """Return public, non-secret deployment metadata for the policy endpoint."""
    if policy is None:
        return {
            "configured": False,
            "assurance_status": "none",
            "limitations": ["No validated decision policy is configured."],
        }
    payload: Dict[str, Any] = {
        "configured": True,
        "assurance_status": (
            "finite_sample_fpr_control" if policy.risk_control else "empirical_validation_only"
        ),
        "schema_version": policy.schema_version,
        "policy_id": policy.policy_id,
        "detector": policy.detector,
        "task": policy.task,
        "threshold": policy.threshold,
        "objective": policy.objective,
        "target_fpr": policy.target_fpr,
        "validation_records": policy.validation_records,
        "validation_sha256": policy.validation_sha256,
        "evaluation_sha256": policy.evaluation_sha256,
        "validation_true_positives": policy.validation_true_positives,
        "validation_recall": policy.validation_recall,
        "created_at": policy.created_at,
        "risk_control": vars(policy.risk_control) if policy.risk_control else None,
    }
    if policy.risk_control:
        payload["limitations"] = [
            "Assumes representative independent validation negatives from the "
            "deployment population.",
            "Does not cover distribution shift, label error, detector changes, or "
            "validation reuse.",
            "The policy digest is provenance metadata, not proof of issuer authenticity.",
        ]
    else:
        payload["limitations"] = [
            "This legacy policy records an empirical validation objective only; it has no "
            "finite-sample FPR guarantee."
        ]
    return payload
