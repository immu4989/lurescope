"""Independent rational arithmetic checks for offline capacity scenarios."""

import copy
import json
from fractions import Fraction

import pytest

from lurescope.capacity import load_decision_counts, plan_capacity
from lurescope.cli import main


def validation(**changes):
    counts = dict(tp=96, fn=4, fp=2, tn=98, abstained_positive=0, abstained_negative=0)
    counts.update(changes)
    return dict(schema_version=1, task="fraud", detector="synthetic-test", threshold=.5,
                counts=counts)


def plan(data=None, **changes):
    args = dict(messages_per_period=1_000_000, prevalences=[.001, .01, .5],
                review_minutes_per_case=5, available_review_hours=1000)
    args.update(changes)
    return plan_capacity(validation() if data is None else data, **args)


def test_rare_fraud_scenario_exposes_false_positive_review_burden():
    result = plan()
    row = result["scenarios"][0]
    assert row["expected_outcomes"]["tp"] == 960
    assert row["expected_outcomes"]["fp"] == 19980
    assert row["expected_review_cases"] == 20940
    assert row["fraud_share_among_flags"] == pytest.approx(960 / 20940)
    assert row["required_review_hours"] == 1745
    assert row["review_hour_shortfall"] == 745
    assert row["exceeds_review_capacity"] is True


def test_projections_match_fraction_arithmetic_and_conserve_total_messages():
    counts = validation(tp=7, fn=2, fp=3, tn=4, abstained_positive=1, abstained_negative=3)
    result = plan(counts, prevalences=[0., .1, .5, 1.], messages_per_period=120)
    for row in result["scenarios"]:
        p = Fraction(str(row["fraud_prevalence"]))
        for key, observed in counts["counts"].items():
            class_fraction = p if key in {"tp", "fn", "abstained_positive"} else 1 - p
            expected = Fraction(120) * class_fraction * Fraction(observed, 10)
            assert row["expected_outcomes"][key] == pytest.approx(float(expected))
        assert sum(row["expected_outcomes"].values()) == pytest.approx(120)
        expected_review = sum(row["expected_outcomes"][k]
                              for k in ["tp", "fp", "abstained_positive", "abstained_negative"])
        assert row["expected_review_cases"] == pytest.approx(expected_review)


def test_all_abstentions_route_to_review_not_benign_or_detected_fraud():
    result = plan(validation(tp=0, fn=0, fp=0, tn=0,
                             abstained_positive=10, abstained_negative=10),
                  messages_per_period=120, prevalences=[.1])
    row = result["scenarios"][0]
    assert row["expected_review_cases"] == 120
    assert row["expected_flagged"] == 0
    assert row["fraud_share_among_flags"] is None
    assert row["fraud_abstained_pending_review"] == 12
    assert row["fraud_classified_benign"] == 0


def test_absent_class_cannot_be_projected_from_zero_observations():
    with pytest.raises(ValueError, match="both ground-truth"):
        plan(validation(tp=0, fn=0))


@pytest.mark.parametrize("bad", [True, -1, 1.0, "1", 10_000_001])
def test_counts_must_be_bounded_integers(bad):
    with pytest.raises(ValueError):
        plan(validation(tp=bad))


@pytest.mark.parametrize("changes", [
    {"messages_per_period": True}, {"messages_per_period": 0},
    {"messages_per_period": 1_000_000_001}, {"prevalences": []},
    {"prevalences": [.5, .5]}, {"prevalences": [True]},
    {"prevalences": [float("nan")]}, {"prevalences": [1.1]},
    {"review_minutes_per_case": 0}, {"review_minutes_per_case": float("inf")},
    {"available_review_hours": -1}, {"available_review_hours": True},
])
def test_invalid_scenario_assumptions_rejected(changes):
    with pytest.raises(ValueError):
        plan(**changes)


@pytest.mark.parametrize("field,value", [("task", "provenance"), ("schema_version", True),
                                         ("threshold", True), ("detector", "")])
def test_input_contract_cannot_silently_change_task_or_controls(field, value):
    data = validation()
    data[field] = value
    with pytest.raises(ValueError):
        plan(data)


def test_unknown_or_missing_counts_fail_and_input_remains_unchanged():
    data = validation()
    original = copy.deepcopy(data)
    plan(data)
    assert data == original
    data["counts"].pop("abstained_positive")
    with pytest.raises(ValueError):
        plan(data)
    data = validation()
    data["unexpected"] = "not accepted"
    with pytest.raises(ValueError):
        plan(data)


def test_capacity_cli_is_offline_and_reports_overload_without_claiming_failure(tmp_path, capsys):
    path = tmp_path / "counts.json"
    path.write_text(json.dumps(validation()))
    assert main(["capacity-plan", str(path), "--messages-per-period", "1000000",
                 "--prevalence", "0.001", "--review-minutes", "5",
                 "--available-review-hours", "1000"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["scenarios"][0]["exceeds_review_capacity"] is True
    assert result["routing_assumption"] == "all_flags_and_abstentions_require_review"
    path.write_text('{"task":"fraud","task":"provenance"}')
    with pytest.raises(ValueError):
        load_decision_counts(path)


def test_zero_available_capacity_is_defined_without_division_by_zero():
    row = plan(available_review_hours=0)["scenarios"][0]
    assert row["exceeds_review_capacity"] is True
    assert row["review_hour_shortfall"] == row["required_review_hours"]
