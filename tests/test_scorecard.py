"""Tests for the robustness scorecard over the bundled sample corpus."""

from __future__ import annotations

import os

import pytest

pytest.importorskip("sklearn")  # tfidf detector needs scikit-learn

from scripts.robustness_scorecard import (
    DEFAULT_DATA,
    compute,
    load_fraud_lures,
    to_markdown,
)

SAMPLE = os.path.abspath(DEFAULT_DATA)


def test_loader_skips_comments_and_keeps_only_fraud():
    lures = load_fraud_lures(SAMPLE)
    assert len(lures) > 0
    assert all(isinstance(t, str) and t.strip() for t in lures)
    assert not any(t.startswith("//") for t in lures)


def test_scorecard_shape_and_recall():
    lures = load_fraud_lures(SAMPLE)
    card = compute(["tfidf-logreg"], ["homoglyph", "whitespace"], lures)
    assert card["n_fraud"] == len(lures)
    row = card["detectors"]["tfidf-logreg"]
    assert row["n_caught"] > 0                    # the trained model catches clean lures
    assert 0.0 < row["clean_recall"] <= 1.0


def test_normalization_never_increases_evasion_and_zeroes_homoglyph():
    lures = load_fraud_lures(SAMPLE)
    card = compute(["tfidf-logreg", "heuristic-v0"], ["homoglyph", "leet", "zero-width"], lures)
    for row in card["detectors"].values():
        for cell in row["attacks"].values():
            # A defense must never make things worse.
            assert cell["evasion_normalized"] <= cell["evasion_raw"] + 1e-9
        # Homoglyph and zero-width are reversed losslessly -> zero residual evasion.
        assert row["attacks"]["homoglyph"]["evasion_normalized"] == 0.0
        assert row["attacks"]["zero-width"]["evasion_normalized"] == 0.0


def test_markdown_renders_expected_columns():
    lures = load_fraud_lures(SAMPLE)
    card = compute(["tfidf-logreg"], ["homoglyph"], lures)
    md = to_markdown(card, "sample")
    assert "Robustness scorecard" in md
    assert "tfidf-logreg" in md
    assert "homoglyph" in md
