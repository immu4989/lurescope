"""Explicit observation/missingness accounting for offline research scorecards.

Logical completion bounds are not confidence intervals or deployment guarantees.
Kept local so source scripts work with the pinned public producer release.
"""

import math
from numbers import Real

MEASUREMENT_VERSION = "scorecard-outcomes-v2"


def validate_score(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError("score must be a finite probability in [0, 1] or None")
    try:
        value = float(value)
    except (OverflowError, ValueError, TypeError) as exc:
        raise ValueError("score cannot be represented as a probability") from exc
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("score must be a finite probability in [0, 1] or None")
    return value


def validate_threshold(value):
    try:
        result = validate_score(value)
    except ValueError as exc:
        raise ValueError("threshold must be a finite probability in [0, 1]") from exc
    if result is None:
        raise ValueError("threshold must be a finite probability in [0, 1]")
    return result


def names(values, label):
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{label} must be a nonempty sequence of distinct names")
    try:
        values = list(values)
    except TypeError as exc:
        raise ValueError(f"{label} must be a nonempty sequence of distinct names") from exc
    if (not values or any(not isinstance(value, str) or not value.strip() for value in values)
            or len(set(values)) != len(values)):
        raise ValueError(f"{label} must be a nonempty sequence of distinct names")
    return values


def clean_summary(scores, threshold):
    threshold = validate_threshold(threshold)
    scores = [validate_score(value) for value in scores]
    if not scores:
        raise ValueError("scorecard requires at least one fraud record")
    caught = [index for index, value in enumerate(scores)
              if value is not None and value >= threshold]
    abstained = scores.count(None)
    total = len(scores)
    return caught, {
        "n_caught": len(caught), "clean_abstain": abstained,
        "clean_scored": total - abstained, "clean_coverage": (total - abstained) / total,
        # Retain the historical name, but label it as observed recall in reports.
        "clean_recall": len(caught) / total,
        "clean_recall_upper": (len(caught) + abstained) / total,
    }


def summarize_attacked(scores, threshold):
    threshold = validate_threshold(threshold)
    scores = [validate_score(value) for value in scores]
    eligible, abstained = len(scores), scores.count(None)
    scored = eligible - abstained
    evaded = sum(value is not None and value < threshold for value in scores)
    lower = evaded / eligible if eligible else None
    return {
        "status": "no_eligible" if not eligible else "inconclusive" if abstained else "complete",
        "n_eligible": eligible, "n_scored": scored, "n_abstained": abstained,
        "n_evaded": evaded, "coverage": scored / eligible if eligible else None,
        "evasion": lower if not abstained else None,
        "evasion_observed": evaded / scored if scored else None,
        "evasion_lower": lower,
        "evasion_upper": (evaded + abstained) / eligible if eligible else None,
    }


def evasion_label(value, metrics=None, *, compact=False):
    if metrics is None:  # Rendering a legacy aggregate cannot recover missing counts.
        return "—" if value is None else f"{value:.0%}"
    if metrics["status"] == "no_eligible":
        return "no eligible" if compact else "— (no eligible)"
    if metrics["status"] == "inconclusive":
        bounds = f"[{metrics['evasion_lower']:.0%}, {metrics['evasion_upper']:.0%}]"
        rate = f"unknown\n{bounds}" if compact else f"inconclusive {bounds}"
    else:
        rate = f"{metrics['evasion']:.0%}"
    if compact:
        return rate + f"\n{metrics['n_scored']}/{metrics['n_eligible']} scored"
    return (rate + f" ({metrics['n_evaded']} evaded; "
            f"{metrics['n_scored']}/{metrics['n_eligible']} scored)")


def measurement_note(card):
    version = card.get("measurement_version")
    if version == MEASUREMENT_VERSION:
        return "Measurement contract: scorecard-outcomes-v2."
    if version is not None:
        raise ValueError("unsupported scorecard measurement version")
    return ("Legacy aggregate: missing-outcome counts and rate semantics are unverified; "
            "displaying historical values does not upgrade their evidence.")
