"""Strict loading of versioned decision policies exported by LureBench."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

from lurebench.calibration import binomial_cdf, clopper_pearson_upper
from lurebench.receipts import loads_strict_json

from .local_io import read_regular_file

_SHA256 = re.compile(r"[a-f0-9]{64}")
_RISK_CONTROL_METHOD = "learn_then_test_fixed_sequence_exact_binomial_v1"
MAX_POLICY_BYTES = 64 * 1024
MAX_VALIDATION_RECORDS = 10_000_000


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
class DetectorBinding:
    profile: str
    artifact_sha256: str
    implementation_sha256: str
    runtime_sha256: str


def _bound_identity(policy) -> str:
    risk = asdict(policy.risk_control) if policy.risk_control is not None else None
    if risk is not None:
        for key in ("confidence", "empirical_fpr", "upper_confidence_bound", "hypothesis_p_value"):
            risk[key] = float(risk[key]).hex()
    material = {
        "contract": "decision-policy-bound-evidence-v1",
        "detector": policy.detector, "task": policy.task, "objective": policy.objective,
        "threshold_hex": float(policy.threshold).hex(),
        "target_fpr_hex": None if policy.target_fpr is None else float(policy.target_fpr).hex(),
        "validation_records": policy.validation_records,
        "validation_sha256": policy.validation_sha256,
        "evaluation_sha256": policy.evaluation_sha256,
        "validation_true_positives": policy.validation_true_positives,
        "validation_recall_hex": (None if policy.validation_recall is None
                                  else float(policy.validation_recall).hex()),
        "risk_control": risk,
        "detector_binding": asdict(policy.detector_binding),
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=True).encode("utf-8")).hexdigest()
    return f"{policy.detector[:191]}-{digest}"


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
    detector_binding: Optional[DetectorBinding] = None


def _validate_probability(value: float, name: str, *, open_interval: bool = False) -> None:
    numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
    valid = numeric and (
        0 < value < 1 if open_interval else 0 <= value <= 1
    ) and math.isfinite(value)
    if not valid:
        interval = "(0, 1)" if open_interval else "[0, 1]"
        raise ValueError(f"policy {name} must be in {interval}")


def _validate_policy(policy: DecisionPolicy) -> None:
    if type(policy.schema_version) is int and policy.schema_version == 3:
        binding = policy.detector_binding
        if (not isinstance(binding, DetectorBinding)
                or binding.profile != "lurescope-portable-tfidf-exact-v1"
                or policy.detector != "tfidf-logreg" or policy.task != "fraud"):
            raise ValueError("unsupported policy detector binding")
        for value in (binding.artifact_sha256, binding.implementation_sha256,
                      binding.runtime_sha256, policy.evaluation_sha256):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ValueError("invalid bound policy digest")
        if not policy.created_at:
            raise ValueError("schema v3 requires created_at")
        legacy_version = 2 if policy.risk_control is not None else 1
        _validate_policy(replace(policy, schema_version=legacy_version, detector_binding=None,
            evaluation_sha256=policy.evaluation_sha256 if legacy_version == 2 else None))
        if policy.policy_id != _bound_identity(policy):
            raise ValueError("bound policy identity does not match its evidence")
        return
    if type(policy.schema_version) is not int or policy.schema_version not in (1, 2):
        raise ValueError(f"unsupported policy schema {policy.schema_version}")
    if policy.detector_binding is not None:
        raise ValueError("legacy policies cannot carry detector bindings")
    for value, name in (
        (policy.policy_id, "policy_id"),
        (policy.detector, "detector"),
        (policy.objective, "objective"),
    ):
        if not isinstance(value, str) or not value or len(value) > 256 or any(
            ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value
        ):
            raise ValueError(f"policy {name} must be a non-empty string")
    if policy.task != "fraud":
        raise ValueError("LureScope only serves fraud decision policies")
    _validate_probability(policy.threshold, "threshold")
    if (
        type(policy.validation_records) is not int
        or not 1 <= policy.validation_records <= MAX_VALIDATION_RECORDS
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
        if policy.objective not in {"max_mcc", "target_fpr"}:
            raise ValueError("unsupported empirical policy objective")
        if policy.target_fpr is not None:
            _validate_probability(policy.target_fpr, "target_fpr")
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
    position = policy.threshold * (control.threshold_grid_size - 1)
    if not math.isclose(position, round(position), rel_tol=0.0, abs_tol=1e-10):
        raise ValueError("policy threshold is not on the declared grid")
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
    # The consistency tolerance cannot relax the actual assurance limits.
    if max(control.hypothesis_p_value, expected_p) > 1 - control.confidence:
        raise ValueError("policy did not reject FPR above the target")
    if max(control.upper_confidence_bound, expected_upper) > policy.target_fpr:
        raise ValueError("policy FPR upper bound exceeds its target")


@lru_cache(maxsize=8)
def _parse_policy(raw: bytes) -> DecisionPolicy:
    payload = loads_strict_json(raw)
    if not isinstance(payload, dict):
        raise ValueError("policy JSON must be an object")
    try:
        if payload.get("detector_binding") is not None:
            if not isinstance(payload["detector_binding"], dict):
                raise ValueError("policy detector_binding must be an object")
            payload["detector_binding"] = DetectorBinding(**payload["detector_binding"])
        if payload.get("risk_control") is not None:
            if not isinstance(payload["risk_control"], dict):
                raise ValueError("policy risk_control must be an object")
            payload["risk_control"] = RiskControl(**payload["risk_control"])
        policy = DecisionPolicy(**payload)
    except TypeError as exc:
        raise ValueError("policy has missing or unsupported fields") from exc
    _validate_policy(policy)
    return policy


def load_policy(path: str, *, expected_sha256: Optional[str] = None) -> DecisionPolicy:
    """Validate current bytes; optionally bind them to an externally trusted pin."""
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256)
    ):
        raise ValueError("policy pin must be a lowercase SHA-256 digest")
    raw = read_regular_file(Path(path), maximum=MAX_POLICY_BYTES, label="decision policy")
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("decision policy digest mismatch")
    # Cache expensive count/bound consistency checks by exact content, not path.
    return _parse_policy(raw)


def configured_policy() -> Optional[DecisionPolicy]:
    path = os.environ.get("LURESCOPE_POLICY_PATH")
    pin = os.environ.get("LURESCOPE_POLICY_SHA256")
    if pin is not None and not path:
        raise ValueError("a policy pin requires LURESCOPE_POLICY_PATH")
    return load_policy(os.path.abspath(path), expected_sha256=pin) if path else None


class PolicyRequirementError(RuntimeError):
    """A deployment requirement is unsatisfied; reason is a fixed public code."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__("required decision policy is unavailable")


class PolicyRequestError(RuntimeError):
    """Research overrides are not admitted by this deployment."""


def policy_enforcement() -> str:
    mode = os.environ.get("LURESCOPE_POLICY_ENFORCEMENT", "off")
    if mode not in {"off", "bound", "risk_controlled_bound"}:
        raise PolicyRequirementError("invalid_enforcement")
    return mode


def configured_decision_policy() -> tuple[str, Optional[DecisionPolicy]]:
    """Read current policy bytes and apply operator requirements before inference.

    Configuration and its approved pin are trusted administrative inputs. Deploy
    them together before worker startup; this is not a multi-setting transaction.
    """
    mode = policy_enforcement()
    if mode == "off":
        return mode, configured_policy()
    if not os.environ.get("LURESCOPE_POLICY_PATH"):
        raise PolicyRequirementError("policy_required")
    if not os.environ.get("LURESCOPE_POLICY_SHA256"):
        raise PolicyRequirementError("trusted_pin_required")
    try:
        policy = configured_policy()
    except (OSError, ValueError, RuntimeError) as exc:
        raise PolicyRequirementError("policy_unavailable") from exc
    if policy is None or policy.schema_version != 3 or policy.detector_binding is None:
        raise PolicyRequirementError("bound_policy_required")
    if mode == "risk_controlled_bound" and policy.risk_control is None:
        raise PolicyRequirementError("risk_control_required")
    return mode, policy


def require_research_mode() -> None:
    """Exploratory attacks and proofs are separate from enforced scoring."""
    if policy_enforcement() != "off":
        raise PolicyRequestError("exploratory operations are disabled by policy enforcement")


def policy_status(policy: Optional[DecisionPolicy], *, actual_binding=None) -> Dict[str, Any]:
    """Return public, non-secret deployment metadata for the policy endpoint."""
    if policy is None:
        return {
            "configured": False,
            "assurance_status": "none",
            "detector_binding": "none",
            "detector_configuration_verified": False,
            "detector_binding_status": "unconfigured",
            "limitations": ["No validated decision policy is configured."],
        }
    payload: Dict[str, Any] = {
        "configured": True,
        "detector_binding": "name_only",
        "detector_configuration_verified": False,
        "detector_binding_status": "legacy_unbound",
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
            "This policy records an empirical validation objective only; it has no "
            "finite-sample FPR guarantee."
        ]
    if policy.detector_binding is None:
        payload["limitations"].append(
            "Schema v1/v2 policies match detector names only; deployed model weights, "
            "prompts, preprocessing, and provider configuration are not verified."
        )
    else:
        expected = asdict(policy.detector_binding)
        matched = actual_binding == expected
        payload.update(detector_binding="exact_portable_configuration",
                       detector_configuration=expected,
                       detector_configuration_verified=matched,
                       detector_binding_status=("not_checked" if actual_binding is None
                                                else "match" if matched else "mismatch"))
        payload["limitations"].append(
            "Binding compares portable artifact bytes, installed inference source, and the "
            "declared runtime profile. It is not issuer authentication, process attestation, "
            "or validation of email extraction, upstream preprocessing, or sampling assumptions."
        )
    return payload
