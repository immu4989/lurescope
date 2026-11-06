"""Scorecard claims must distinguish observations, missing outcomes and errors."""

import itertools
import threading
from types import SimpleNamespace

import pytest

from scripts import llm_scorecard as llm
from scripts import robustness_scorecard as raw


def raw_sequence(monkeypatch, values):
    scores = iter(values)
    monkeypatch.setattr(raw, "_detector", lambda _: SimpleNamespace(score=lambda _: next(scores)))
    monkeypatch.setattr(raw, "get_attack", lambda _: SimpleNamespace(apply=lambda text: text))
    return raw.compute(["synthetic"], ["noop"], ["a", "b", "c", "d"])


def llm_results(clean, after):
    return {"synthetic": {i: {"clean": c, **dict.fromkeys(llm.ATTACKS, a)}
                           for i, (c, a) in enumerate(zip(clean, after, strict=True))}}


def test_raw_abstention_is_not_a_successful_evasion(monkeypatch):
    # Three clean catches, one clean abstention; then raw/normalized pairs.
    card = raw_sequence(monkeypatch, [0.9, 0.9, 0.9, None, 0.1, None, None, 0.9, 0.9, 0.1])
    row = card["detectors"]["synthetic"]
    cell = row["attacks"]["noop"]
    assert cell["evasion_raw"] is None and cell["evasion_normalized"] is None
    assert row["clean_abstain"] == 1 and row["clean_coverage"] == 0.75
    for side in ("raw", "normalized"):
        metrics = cell[side]
        assert metrics["n_eligible"] == 3 and metrics["n_scored"] == 2
        assert metrics["n_abstained"] == metrics["n_evaded"] == 1
        assert metrics["evasion_observed"] == 0.5
        assert metrics["evasion_lower"] == 1 / 3 and metrics["evasion_upper"] == 2 / 3
    assert card["measurement_version"] == "scorecard-outcomes-v2"


def test_blind_raw_detector_does_not_report_zero_evasion(monkeypatch):
    card = raw_sequence(monkeypatch, [0.1] * 4)
    cell = card["detectors"]["synthetic"]["attacks"]["noop"]
    assert cell["evasion_raw"] is None
    assert cell["raw"]["status"] == "no_eligible"
    assert cell["raw"]["evasion_lower"] is None
    assert "no eligible" in raw.to_markdown(card, "synthetic")


def test_cross_model_point_rate_is_not_computed_on_a_selected_subset():
    card = llm.scorecard(llm_results([0.9] * 3, [0.1, None, 0.9]),
                        {"synthetic": None}, ["a", "b", "c"])
    cell = card["detectors"]["synthetic"]["attacks"]["homoglyph"]
    assert cell["evasion"] is None and cell["evasion_observed"] == 0.5
    assert cell["n_eligible"] == 3 and cell["n_abstained"] == 1
    assert cell["evasion_lower"] == 1 / 3 and cell["evasion_upper"] == 2 / 3
    assert "inconclusive" in llm.to_markdown(card, "synthetic", [], "synthetic")


@pytest.mark.parametrize("value", [True, "0.5", float("nan"), float("inf"), -0.1, 1.1])
@pytest.mark.parametrize("stage", ["clean", "attacked"])
def test_raw_invalid_scores_raise_instead_of_becoming_measurements(monkeypatch, value, stage):
    values = [value] * 4 if stage == "clean" else [0.9] * 4 + [value]
    with pytest.raises(ValueError, match="probability"):
        raw_sequence(monkeypatch, values)


@pytest.mark.parametrize("value", [True, "0.5", float("nan"), float("inf"), -0.1, 1.1])
@pytest.mark.parametrize("stage", ["clean", "attacked"])
def test_cross_model_invalid_scores_raise_even_when_not_eligible(value, stage):
    clean, after = ([value], [0.9]) if stage == "clean" else ([0.1], [value])
    with pytest.raises(ValueError, match="probability"):
        llm.scorecard(llm_results(clean, after), {"synthetic": None}, ["a"])


@pytest.mark.parametrize("threshold", [None, True, "0.5", float("nan"), -0.1, 1.1])
def test_threshold_is_validated_before_any_callbacks(monkeypatch, threshold):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid configuration reached an evaluation callback")
    monkeypatch.setattr(raw, "get_attack", unexpected)
    with pytest.raises(ValueError, match="threshold"):
        raw.compute(["synthetic"], ["noop"], ["a"], threshold)
    with pytest.raises(ValueError, match="threshold"):
        llm.scorecard(llm_results([0.9], [0.1]), {"synthetic": None}, ["a"], threshold)


@pytest.mark.parametrize("value", [True, "0.5", float("nan"), -0.1])
def test_invalid_cached_scores_fail_before_attacks_or_provider_calls(value):
    class NoCalls:
        def apply(self, text):
            pytest.fail("invalid cache reached the attacker")
    with pytest.raises(ValueError, match="cache"):
        llm.run([{"text": "synthetic"}], {"synthetic": None}, NoCalls(),
                {"old-key": value}, {}, 1, threading.Lock())


def test_generated_prose_does_not_invent_dataset_specific_findings(monkeypatch):
    a = raw.to_markdown(raw_sequence(monkeypatch, [0.9] * 12), "synthetic")
    b = llm.to_markdown(llm.scorecard(llm_results([0.9], [0.9]),
                                     {"synthetic": None}, ["a"]), "synthetic", [], "synthetic")
    assert "collapses the" not in a and "reverses them losslessly" not in a
    assert "Three things to read here" not in b and "immunity is bought with recall" not in b
    assert "not confidence intervals" in a and "not confidence intervals" in b
    assert "2026-07-30" in b and "2026-07-26" in b


def test_every_missing_outcome_completion_lies_within_reported_bounds():
    from lurescope.scorecard_metrics import summarize_attacked

    for count in range(5):
        for values in itertools.product([0.1, 0.9, None], repeat=count):
            result = summarize_attacked(values, 0.5)
            assert result["n_eligible"] == count
            assert result["n_scored"] + result["n_abstained"] == count
            if not count:
                assert result["status"] == "no_eligible" and result["evasion"] is None
                continue
            possible = []
            for fill in itertools.product([0.1, 0.9], repeat=values.count(None)):
                replacements = iter(fill)
                completed = [next(replacements) if value is None else value for value in values]
                possible.append(sum(value < 0.5 for value in completed) / count)
            assert result["evasion_lower"] == min(possible)
            assert result["evasion_upper"] == max(possible)
            assert (result["evasion"] is None) == (None in values)


@pytest.mark.parametrize("change", ["missing_detector", "extra_detector", "missing_position",
                                   "extra_position", "boolean_position", "missing_variant",
                                   "extra_variant"])
def test_incomplete_or_extra_result_shape_is_not_an_abstention(change):
    results = llm_results([0.9], [0.1])
    if change == "missing_detector":
        results.clear()
    elif change == "extra_detector":
        results["unrequested"] = results["synthetic"]
    elif change == "missing_position":
        results["synthetic"].clear()
    elif change == "extra_position":
        results["synthetic"][1] = results["synthetic"][0]
    elif change == "boolean_position":
        results["synthetic"] = {False: results["synthetic"][0]}
    elif change == "missing_variant":
        del results["synthetic"][0]["paraphrase"]
    else:
        results["synthetic"][0]["unrequested"] = 0.1
    with pytest.raises(ValueError):
        llm.scorecard(results, {"synthetic": None}, ["a"])


@pytest.mark.parametrize("detectors,attacks,lures", [
    ([], ["noop"], ["a"]), (["d", "d"], ["noop"], ["a"]),
    (["d"], [], ["a"]), (["d"], ["noop", "noop"], ["a"]),
    (["d"], ["noop"], []), (["d"], ["noop"], "text"),
])
def test_raw_empty_or_duplicate_configuration_fails_before_callbacks(
        monkeypatch, detectors, attacks, lures):
    monkeypatch.setattr(raw, "get_attack", lambda _: pytest.fail("callback reached"))
    with pytest.raises(ValueError):
        raw.compute(detectors, attacks, lures)


def test_empty_cross_model_inputs_do_not_produce_a_zero_recall_report():
    with pytest.raises(ValueError):
        llm.scorecard({"synthetic": {}}, {"synthetic": None}, [])
    with pytest.raises(ValueError):
        llm.scorecard({}, {}, ["a"])


def test_all_clean_abstentions_are_visible_and_have_no_eligible_cohort(monkeypatch):
    card = raw_sequence(monkeypatch, [None] * 4)
    row = card["detectors"]["synthetic"]
    assert row["clean_recall"] == 0 and row["clean_recall_upper"] == 1
    assert row["clean_coverage"] == 0 and row["clean_abstain"] == 4
    assert row["attacks"]["noop"]["raw"]["status"] == "no_eligible"


def test_all_attacked_abstentions_are_unknown_over_the_full_unit_interval(monkeypatch):
    card = raw_sequence(monkeypatch, [0.9] * 4 + [None] * 8)
    cell = card["detectors"]["synthetic"]["attacks"]["noop"]["raw"]
    assert cell["n_scored"] == 0 and cell["n_abstained"] == 4
    assert cell["evasion"] is None and cell["evasion_observed"] is None
    assert (cell["evasion_lower"], cell["evasion_upper"]) == (0, 1)
    assert "inconclusive [0%, 100%]" in raw.to_markdown(card, "synthetic")


@pytest.mark.parametrize("threshold,clean,attacked,expected", [
    (0.0, 0.0, 0.0, 0.0), (1.0, 1.0, 1.0, 0.0), (1.0, 1.0, 0.9, 1.0),
])
def test_inclusive_detection_threshold_and_complete_rate(threshold, clean, attacked, expected):
    card = llm.scorecard(llm_results([clean], [attacked]), {"synthetic": None}, ["a"], threshold)
    cell = card["detectors"]["synthetic"]["attacks"]["homoglyph"]
    assert cell["evasion"] == cell["evasion_lower"] == cell["evasion_upper"] == expected
    assert cell["status"] == "complete" and cell["coverage"] == 1


def test_invalid_new_scores_are_never_written_to_the_cache():
    cache = {}
    with pytest.raises(ValueError, match="probability"):
        llm.run([{"text": "synthetic"}], {"synthetic": lambda text: True},
                SimpleNamespace(apply=lambda text: text), cache, {}, 1, threading.Lock())
    assert cache == {}


def test_legacy_display_is_labelled_and_unknown_contract_is_rejected(monkeypatch):
    card = raw_sequence(monkeypatch, [0.9] * 12)
    del card["measurement_version"]
    assert "Legacy aggregate" in raw.to_markdown(card, "synthetic")
    card["measurement_version"] = "unreviewed-future-contract"
    with pytest.raises(ValueError, match="measurement version"):
        raw.to_markdown(card, "synthetic")
    card = llm.scorecard(llm_results([0.9], [0.1]), {"synthetic": None}, ["a"])
    del card["measurement_version"]
    assert "Legacy aggregate" in llm.to_markdown(card, "synthetic", [], "synthetic")
    card["measurement_version"] = "unreviewed-future-contract"
    with pytest.raises(ValueError, match="measurement version"):
        llm.to_markdown(card, "synthetic", [], "synthetic")


@pytest.mark.parametrize("judges", [[], ["same", "same"], [""], [True]])
def test_invalid_judge_panel_fails_before_detector_construction(monkeypatch, judges):
    monkeypatch.setattr(llm, "get_detector", lambda *a, **k: pytest.fail("factory reached"))
    with pytest.raises(ValueError, match="judges"):
        llm.build_detectors(judges)
