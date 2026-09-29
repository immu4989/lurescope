"""Analytical and enumerated-binomial checks of simultaneous review envelopes."""

import json
import math

import pytest

from lurescope.capacity import plan_capacity_envelope
from lurescope.cli import main


def counts(reviewed=2, n=100):
    return dict(schema_version=1, task="fraud", detector="synthetic", threshold=.5,
                counts=dict(tp=reviewed, fn=n - reviewed, fp=reviewed, tn=n - reviewed,
                            abstained_positive=0, abstained_negative=0))


def envelope(data=None, **changes):
    options = dict(messages_per_period=1000, prevalences=[0, .001, .5, 1],
                   review_minutes_per_case=6, available_review_hours=10)
    options.update(changes)
    return plan_capacity_envelope(counts() if data is None else data, **options)


def test_four_tail_error_allocation_and_exact_formula():
    result = envelope()
    radius = math.sqrt(math.log(80) / 200)
    for interval in result["class_review_rate_intervals"].values():
        assert interval["radius_before_clipping"] == pytest.approx(radius)
        assert interval["lower"] == 0
        assert interval["upper"] == pytest.approx(.02 + radius)
    assert result["one_sided_tail_error_budget"] == pytest.approx(.05 / 4)
    assert result["total_error_budget"] == pytest.approx(.05)
    for scenario in result["scenarios"]:
        assert scenario["expected_review_cases"]["upper"] == pytest.approx(1000 * (.02 + radius))
        assert scenario["expected_review_hours"]["upper"] == pytest.approx(100 * (.02 + radius))
        assert scenario["capacity_relation"] == "expected_hours_interval_straddles_capacity"


@pytest.mark.parametrize("n", [1, 2, 5, 20, 50])
@pytest.mark.parametrize("confidence", [.5, .9, .99])
def test_enumerated_sampling_coverage_for_each_class(n, confidence):
    intervals = [envelope(counts(k, n), confidence=confidence)
                 ["class_review_rate_intervals"]["negative"] for k in range(n + 1)]
    # Enumerate every possible observed count rather than simulation. The
    # per-class two-sided failure budget is alpha/2; a union bound covers both.
    for p in [0, .001, .01, .1, .3, .5, .9, .99, 1]:
        covered = math.fsum(math.comb(n, k) * p ** k * (1 - p) ** (n - k)
                            for k, interval in enumerate(intervals)
                            if interval["lower"] <= p <= interval["upper"])
        assert covered >= 1 - (1 - confidence) / 2 - 1e-12


def test_zero_observed_reviews_does_not_claim_zero_population_review_demand():
    result = envelope(counts(0, 100))
    assert result["point_scenarios"]["scenarios"][0]["expected_review_cases"] == 0
    assert result["scenarios"][0]["expected_review_cases"]["upper"] > 0


def test_abstentions_are_review_events_with_no_detection_credit():
    data = counts(0, 100)
    data["counts"].update(fn=0, tn=0, abstained_positive=100, abstained_negative=100)
    result = envelope(data, available_review_hours=0)
    for interval in result["class_review_rate_intervals"].values():
        assert interval["estimate"] == 1
        assert interval["upper"] == 1
    for scenario in result["scenarios"]:
        assert scenario["capacity_relation"] == "entire_expected_hours_interval_above_capacity"


def test_mixture_bounds_contain_all_feasible_endpoint_rates():
    data = counts(10, 100)
    data["counts"].update(tp=80, fn=20)
    result = envelope(data)
    intervals = result["class_review_rate_intervals"]
    for row in result["scenarios"]:
        p = row["fraud_prevalence"]
        for positive in [intervals["positive"]["lower"], intervals["positive"]["upper"]]:
            for negative in [intervals["negative"]["lower"], intervals["negative"]["upper"]]:
                expected = 1000 * (p * positive + (1 - p) * negative)
                assert row["expected_review_cases"]["lower"] <= expected
                assert expected <= row["expected_review_cases"]["upper"]


def test_wider_confidence_and_larger_sample_monotonicity():
    small = envelope(counts(20, 100))["class_review_rate_intervals"]["positive"]
    large = envelope(counts(200, 1000))["class_review_rate_intervals"]["positive"]
    confident = envelope(counts(20, 100), confidence=.999)["class_review_rate_intervals"]
    confident = confident["positive"]
    assert small["lower"] <= large["lower"] <= large["upper"] <= small["upper"]
    assert confident["lower"] <= small["lower"] <= small["upper"] <= confident["upper"]


@pytest.mark.parametrize("confidence", [0, 1, -.1, 1.1, True, "0.95", None,
                                         float("inf"), float("nan")])
def test_invalid_confidence_rejected(confidence):
    with pytest.raises(ValueError):
        envelope(confidence=confidence)


def test_interval_equal_to_capacity_is_within_but_never_safety_authorization():
    result = envelope(counts(100, 100), available_review_hours=100)
    assert all(row["capacity_relation"] == "entire_expected_hours_interval_within_capacity"
               for row in result["scenarios"])
    assert "not_a_deployment_authorization_or_compliance_certificate" in result["limitations"]


def test_cli_opt_in_envelope_and_invalid_confidence(tmp_path, capsys):
    source = tmp_path / "counts.json"
    source.write_text(json.dumps(counts()))
    args = ["capacity-plan", str(source), "--messages-per-period", "1000",
            "--prevalence", ".001", "--review-minutes", "6",
            "--available-review-hours", "10", "--confidence"]
    assert main(args + [".95"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["analysis"] == "review_capacity_sampling_envelope"
    assert main(args + ["1"]) == 2
    captured = capsys.readouterr()
    assert not captured.out
    assert "rejected input" in captured.err
