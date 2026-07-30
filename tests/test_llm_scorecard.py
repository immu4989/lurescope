"""Offline tests for the cross-model scorecard aggregation (no network / no key)."""

from __future__ import annotations

import collections
import threading

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
    # Keyed by position, matching run(): record ids are not reliably unique.
    results = {"d": {
        0: cell(0.9, 0.1),   # caught, homoglyph evades
        1: cell(0.9, 0.9),   # caught, homoglyph held
        2: cell(0.2, 0.2),   # not caught clean
        3: cell(0.9, None),  # caught, abstains under homoglyph
    }}
    card = scorecard(results, dets, lures)
    row = card["detectors"]["d"]
    assert row["n_caught"] == 3               # lures 0, 1, 3
    # homoglyph: of caught {0,1,3}, lure 3 abstains (excluded) -> scored over {0,1},
    # one evades -> 50%.
    assert row["attacks"]["homoglyph"]["evasion"] == 0.5
    assert row["attacks"]["homoglyph"]["n_scored"] == 2


def test_zero_recall_detector_reports_none_not_zero():
    lures = _lures(2)
    dets = _dets("blind")
    flat = {a: 0.1 for a in ("clean", *ATTACKS)}
    results = {"blind": {0: dict(flat), 1: dict(flat)}}  # never catches anything
    card = scorecard(results, dets, lures)
    row = card["detectors"]["blind"]
    assert row["n_caught"] == 0
    for a in ATTACKS:
        assert row["attacks"][a]["evasion"] is None   # nothing to evade, not "0%"


def test_markdown_renders_dash_for_none_and_lists_attacks():
    lures = _lures(1)
    dets = _dets("blind")
    flat = {a: 0.1 for a in ("clean", *ATTACKS)}
    card = scorecard({"blind": {0: flat}}, dets, lures)
    md = to_markdown(card, "sample", ["m1"], "attacker/x")
    assert "paraphrase" in md
    assert "—" in md            # the None cells render as an em dash, not 0%
    assert "attacker/x" in md   # caveat names the attacker


def test_colliding_record_ids_do_not_collapse_the_sample():
    """Regression: these maps were keyed by ``rec["id"]``, and LureBench shipped
    ~500 generated records whose ids collided across generators. Colliding records
    silently overwrote each other, turning a stated 120-lure sample into 73
    distinct records with some counted three times. Keying by position fixes it."""
    from scripts.llm_scorecard import run

    # Three distinct texts deliberately sharing one id, as the shards did.
    lures = [
        {"id": "gen-bec-000006", "text": "verify your account now"},
        {"id": "gen-bec-000006", "text": "confirm the wire today"},
        {"id": "gen-bec-000006", "text": "your package could not be delivered"},
    ]
    seen = []

    def detector(text):
        seen.append(text)
        return 0.9

    class _NoopAttacker:
        def apply(self, text):
            return text + " (rewritten)"

    dets = collections.OrderedDict([("d", detector)])
    lock = threading.Lock()
    results = run(lures, dets, _NoopAttacker(), {}, {}, workers=1, lock=lock)

    # Every lure must be represented, not just the last one sharing the id.
    assert len(results["d"]) == 3, "records with a shared id collapsed"
    cleans = {results["d"][i]["clean"] for i in range(3)}
    assert cleans == {0.9}
    # Each original text must actually have been scored, not just the last one.
    originals = {lure["text"] for lure in lures}
    assert originals <= set(seen), "a record sharing an id was never scored"

    card = scorecard(results, dets, lures)
    assert card["n_fraud"] == 3
    assert card["detectors"]["d"]["n_caught"] == 3
