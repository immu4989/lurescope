"""Offline prevalence scenarios for analyst review capacity, not risk forecasts.

Flags and abstentions route to review. No automatic actions or claims about
reviewer accuracy, delay, sampling uncertainty, or distribution stability.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from numbers import Real
from pathlib import Path

from .local_io import read_regular_file
from .permit import _strict

COUNT_FIELDS = frozenset({"tp", "fp", "tn", "fn", "abstained_positive", "abstained_negative"})


def _number(value, label, maximum):
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{label} must be a finite nonnegative number")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise ValueError(f"{label} exceeds its numeric bounds") from None
    if not math.isfinite(result) or not 0 <= result <= maximum:
        raise ValueError(f"{label} exceeds its numeric bounds")
    return result


def validate_decision_counts(value):
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "task", "detector", "threshold", "counts",
    }:
        raise ValueError("decision-count input fields do not match version 1")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("unsupported decision-count version")
    if value["task"] != "fraud":
        raise ValueError("fraud capacity planning requires fraud-task counts")
    name = value["detector"]
    if not isinstance(name, str) or not 1 <= len(name) <= 256 or any(
        ord(c) < 32 or ord(c) == 127 for c in name
    ):
        raise ValueError("detector name must be a bounded string without controls")
    threshold = _number(value["threshold"], "threshold", 1)
    counts = value["counts"]
    if not isinstance(counts, Mapping) or set(counts) != COUNT_FIELDS:
        raise ValueError("all six decision outcomes must be supplied")
    if any(type(n) is not int or not 0 <= n <= 10_000_000 for n in counts.values()):
        raise ValueError("decision counts must be bounded nonnegative integers")
    positive = counts["tp"] + counts["fn"] + counts["abstained_positive"]
    negative = counts["tn"] + counts["fp"] + counts["abstained_negative"]
    if not positive or not negative:
        raise ValueError("both ground-truth classes need validation observations")
    return {"schema_version": 1, "task": "fraud", "detector": name,
            "threshold": threshold, "counts": dict(counts)}


def load_decision_counts(path: Path) -> dict:
    return validate_decision_counts(_strict(read_regular_file(
        path, maximum=16 * 1024, label="decision counts",
    ), "decision counts"))


def plan_capacity(
    validation: Mapping, *, messages_per_period: int,
    prevalences: Sequence[float], review_minutes_per_case: float,
    available_review_hours: float,
) -> dict:
    """Project supplied prevalence points while holding class outcome rates fixed."""
    checked = validate_decision_counts(validation)
    if type(messages_per_period) is not int or not 1 <= messages_per_period <= 1_000_000_000:
        raise ValueError("messages_per_period must be an integer from 1 to one billion")
    if not isinstance(prevalences, (list, tuple)) or not 1 <= len(prevalences) <= 32:
        raise ValueError("supply one through 32 prevalence scenarios")
    points = [_number(p, "prevalence", 1) for p in prevalences]
    if len(set(points)) != len(points):
        raise ValueError("prevalence scenarios must be unique")
    minutes = _number(review_minutes_per_case, "review_minutes_per_case", 1440)
    if minutes == 0:
        raise ValueError("review_minutes_per_case must be positive")
    hours = _number(available_review_hours, "available_review_hours", 1_000_000_000)
    counts = checked["counts"]
    positive = counts["tp"] + counts["fn"] + counts["abstained_positive"]
    negative = counts["tn"] + counts["fp"] + counts["abstained_negative"]
    rates = {key: counts[key] / (positive if key in {"tp", "fn", "abstained_positive"}
                                else negative) for key in sorted(COUNT_FIELDS)}
    scenarios = []
    for prevalence in points:
        fraud = messages_per_period * prevalence
        benign = messages_per_period * (1 - prevalence)
        expected = {key: rates[key] * (fraud if key in {"tp", "fn", "abstained_positive"}
                                      else benign) for key in sorted(COUNT_FIELDS)}
        flagged = expected["tp"] + expected["fp"]
        abstained = expected["abstained_positive"] + expected["abstained_negative"]
        review = flagged + abstained
        required_hours = review * minutes / 60
        scenarios.append({
            "fraud_prevalence": prevalence, "expected_outcomes": expected,
            "expected_flagged": flagged, "expected_abstained": abstained,
            "expected_review_cases": review,
            "fraud_share_among_flags": expected["tp"] / flagged if flagged else None,
            "fraud_classified_benign": expected["fn"],
            "fraud_abstained_pending_review": expected["abstained_positive"],
            "required_review_hours": required_hours,
            "exceeds_review_capacity": required_hours > hours,
            "review_hour_shortfall": max(0., required_hours - hours),
        })
    return {
        "schema_version": 1, "analysis": "prevalence_capacity_scenarios",
        "validation": checked,
        "validation_class_sizes": {"positive": positive, "negative": negative},
        "class_conditional_outcome_rates": rates,
        "messages_per_period": messages_per_period,
        "review_minutes_per_case": minutes, "available_review_hours": hours,
        "routing_assumption": "all_flags_and_abstentions_require_review",
        "scenarios": scenarios,
        "limitations": [
            "scenario_arithmetic_not_a_deployment_forecast_or_confidence_interval",
            "prevalences_volume_review_time_and_capacity_are_operator_assumptions",
            "class_conditional_outcome_rates_assumed_stable_across_scenarios",
            "sampling_uncertainty_label_error_and_distribution_shift_not_quantified",
            "reviewer_accuracy_queueing_delays_and_prevention_effect_not_modeled",
            "expected_counts_may_be_fractional_and_are_not_observed_incidents",
            "input_counts_and_detector_identity_are_not_authenticated",
            "aggregate_counts_are_not_differential_privacy",
            "no_automatic_threshold_change_or_authorization_to_deploy",
        ],
    }


def plan_capacity_envelope(
    validation: Mapping, *, messages_per_period: int,
    prevalences: Sequence[float], review_minutes_per_case: float,
    available_review_hours: float, confidence: float = .95,
) -> dict:
    """Simultaneous Hoeffding envelope for two class-conditional review rates.

    A fixed classifier/routing rule and representative independent observations
    within each labeled class are required. The union bound needs no independence
    between classes. It covers all prevalence mixtures of those same two rates,
    NOT realized future counts, selection of models, or repeated peeking.
    """
    level = _number(confidence, "confidence", 1)
    if not 0 < level < 1:
        raise ValueError("confidence must be strictly between zero and one")
    point = plan_capacity(
        validation, messages_per_period=messages_per_period, prevalences=prevalences,
        review_minutes_per_case=review_minutes_per_case,
        available_review_hours=available_review_hours,
    )
    counts = point["validation"]["counts"]
    intervals = {}
    # Four one-sided tails: two directions for each of two labeled classes.
    log_tail = math.log(4.) - math.log1p(-level)
    for name, reviewed in (
        ("positive", counts["tp"] + counts["abstained_positive"]),
        ("negative", counts["fp"] + counts["abstained_negative"]),
    ):
        n = point["validation_class_sizes"][name]
        estimate = reviewed / n
        radius = math.sqrt(log_tail / (2 * n))
        intervals[name] = {
            "observations": n, "reviewed": reviewed, "estimate": estimate,
            "radius_before_clipping": radius,
            "lower": max(0., estimate - radius), "upper": min(1., estimate + radius),
        }
    scenarios = []
    minutes = point["review_minutes_per_case"]
    hours = point["available_review_hours"]
    for scenario in point["scenarios"]:
        p = scenario["fraud_prevalence"]
        lower = messages_per_period * (
            p * intervals["positive"]["lower"] + (1 - p) * intervals["negative"]["lower"]
        )
        upper = messages_per_period * (
            p * intervals["positive"]["upper"] + (1 - p) * intervals["negative"]["upper"]
        )
        lower_hours, upper_hours = lower * minutes / 60, upper * minutes / 60
        if lower_hours > hours:
            relation = "entire_expected_hours_interval_above_capacity"
        elif upper_hours <= hours:
            relation = "entire_expected_hours_interval_within_capacity"
        else:
            relation = "expected_hours_interval_straddles_capacity"
        scenarios.append({
            "fraud_prevalence": p,
            "expected_review_cases": {"lower": lower, "upper": upper},
            "expected_review_hours": {"lower": lower_hours, "upper": upper_hours},
            "capacity_relation": relation,
        })
    return {
        "schema_version": 1, "analysis": "review_capacity_sampling_envelope",
        "method": "hoeffding_two_classes_four_tails_union_bound_v1",
        "confidence": level, "total_error_budget": 1 - level,
        "one_sided_tail_error_budget": (1 - level) / 4,
        "coverage_scope": "both_class_review_rates_and_all_their_prevalence_mixtures",
        "point_scenarios": point, "class_review_rate_intervals": intervals,
        "scenarios": scenarios,
        "limitations": [
            "fixed_classifier_threshold_routing_and_confidence_predeclared_before_validation",
            "representative_independent_observations_required_within_each_ground_truth_class",
            "validation_sample_sizes_fixed_without_optional_stopping_or_repeated_peeking",
            "no_adjustment_for_model_selection_or_multiple_detector_comparisons",
            "class_rates_assumed_stable_from_validation_to_deployment",
            "covers_expected_review_demand_not_realized_future_counts_or_queueing_delays",
            "prevalence_volume_review_time_and_capacity_remain_operator_assumptions",
            "no_bounds_for_precision_fraud_loss_or_reviewer_accuracy",
            "conservative_distribution_free_bounds_may_be_wide",
            "input_identity_and_sampling_assumptions_are_not_authenticated",
            "not_a_deployment_authorization_or_compliance_certificate",
        ],
    }
