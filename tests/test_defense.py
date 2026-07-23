"""Unit tests for the normalization defense — no model needed."""

from __future__ import annotations

from lurebench.attacks import get_attack

from lurescope.defense import apply_defense, available_defenses, normalize

ORIGINAL = "Verify your account within 24 hours or it will be suspended. Confirm now."


def test_homoglyph_attack_is_fully_reversed():
    attacked = get_attack("homoglyph").apply(ORIGINAL)
    assert attacked != ORIGINAL          # the attack actually changed the text
    assert normalize(attacked) == ORIGINAL


def test_zero_width_attack_is_fully_reversed():
    attacked = get_attack("zero-width").apply(ORIGINAL)
    assert attacked != ORIGINAL
    assert normalize(attacked) == ORIGINAL


def test_leet_is_undone_in_words_but_numbers_survive():
    normed = normalize("Ver1fy your 4cc0unt within 24 hours")
    assert "verify" in normed.lower()
    assert "account" in normed.lower()
    assert "24 hours" in normed        # standalone number is not de-leeted


def test_normalize_is_idempotent_on_clean_text():
    assert normalize(ORIGINAL) == ORIGINAL


def test_none_defense_is_identity_and_registry_lists_normalize():
    assert "normalize" in available_defenses()
    assert "none" in available_defenses()
    assert apply_defense("none", ORIGINAL) == ORIGINAL


def test_unknown_defense_raises():
    try:
        apply_defense("does-not-exist", ORIGINAL)
    except ValueError as exc:
        assert "does-not-exist" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for unknown defense")
