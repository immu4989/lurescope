"""Offline tests for the cross-model scorecard aggregation (no network / no key)."""

from __future__ import annotations

import collections

from scripts.llm_scorecard import ATTACKS, scorecard, to_markdown


def _lures(n):
    return [{"id": f"l{i}", "text": f"lure {i}"} for i in range(n)]


def _dets(*names):
    # scorecard() only iterates detector keys; the callables are never invoked here.
    return collections.OrderedDict((n, None) for n in names)


def test_evasion_is_conditioned_on_a_clean_catch_and_abstentions_excluded():
    lures = _lures(4)
    dets = _dets("d")
    # l0 caught then evaded by homoglyph; l1 caught and held; l2 not caught clean
    # (excluded from every attack rate); l3 caught but abstains on homoglyph (excluded).
    def cell(clean, homo):
        return {"clean": clean, "homoglyph": homo, "leet": clean, "zero-width": clean,
                "whitespace": clean, "paraphrase": clean}
    results = {"d": {
        "l0": cell(0.9, 0.1),   # caught, homoglyph evades
        "l1": cell(0.9, 0.9),   # caught, homoglyph held
        "l2": cell(0.2, 0.2),   # not caught clean
        "l3": cell(0.9, None),  # caught, abstains under homoglyph
    }}
    card = scorecard(results, dets, lures)
    row = card["detectors"]["d"]
    assert row["n_caught"] == 3               # l0, l1, l3
    # homoglyph: of caught {l0,l1,l3}, l3 abstains (excluded) -> scored over {l0,l1},
    # one evades -> 50%.
    assert row["attacks"]["homoglyph"]["evasion"] == 0.5
    assert row["attacks"]["homoglyph"]["n_scored"] == 2


def test_zero_recall_detector_reports_none_not_zero():
    lures = _lures(2)
    dets = _dets("blind")
    flat = {a: 0.1 for a in ("clean", *ATTACKS)}
    results = {"blind": {"l0": dict(flat), "l1": dict(flat)}}  # never catches anything
    card = scorecard(results, dets, lures)
    row = card["detectors"]["blind"]
    assert row["n_caught"] == 0
    for a in ATTACKS:
        assert row["attacks"][a]["evasion"] is None   # nothing to evade, not "0%"


def test_markdown_renders_dash_for_none_and_lists_attacks():
    lures = _lures(1)
    dets = _dets("blind")
    flat = {a: 0.1 for a in ("clean", *ATTACKS)}
    card = scorecard({"blind": {"l0": flat}}, dets, lures)
    md = to_markdown(card, "sample", ["m1"], "attacker/x")
    assert "paraphrase" in md
    assert "—" in md            # the None cells render as an em dash, not 0%
    assert "attacker/x" in md   # caveat names the attacker
