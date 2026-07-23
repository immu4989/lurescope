"""Input-normalization defense against character-level evasion.

The character attacks in LureBench (``homoglyph``, ``leet``, ``zero-width``,
``whitespace``) all work the same way: leave a message legible to a human while
breaking the exact tokens a detector matches on. The obvious counter is to
normalize the text *before* scoring it. This module is that defense.

It is deliberately honest about what it can and cannot recover:

* ``homoglyph``  — fully reversed. Confusable Cyrillic/Greek letters are mapped
  back to their Latin lookalikes losslessly, so ``vеrifу`` becomes ``verify``.
* ``zero-width`` — fully reversed. Invisible format characters (category ``Cf``)
  are stripped.
* ``leet``       — best-effort. Unambiguous digit-for-letter swaps are undone in
  a word context (``acc0unt`` -> ``account``); standalone numbers such as a price
  or ``24 hours`` are left untouched, and the ``1`` = ``i`` / ``l`` ambiguity means
  some leet survives.
* ``whitespace`` — NOT reversed. Re-joining ``ve rify`` cannot be done without
  also merging legitimately separate words, so this defense leaves it alone.

That residue is the point: normalization closes the lossless *typographic* attacks
almost entirely, which throws the remaining gap — semantic paraphrase (``llm-*``) —
into relief. A defended detector that still misses a paraphrase is failing on
meaning, not on spelling.
"""

from __future__ import annotations

import unicodedata

# Confusable Cyrillic/Greek code points -> their Latin lookalike. A superset of the
# substitutions LureBench's homoglyph attack makes, so the attack is fully reversed,
# plus common extras a real fraudster would reach for.
_CONFUSABLES = {
    # Cyrillic -> Latin (lowercase)
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ո": "n", "ν": "v",
    # Cyrillic -> Latin (uppercase)
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "К": "K", "М": "M",
    "О": "O", "Р": "P", "Т": "T", "Х": "X", "І": "I", "Ѕ": "S", "Ј": "J",
    # Greek -> Latin
    "ο": "o", "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P", "Τ": "T", "Υ": "Y",
    "Χ": "X", "ρ": "p", "τ": "t", "ι": "i",
}

# Reverse of LureBench's leet map. Applied only next to a letter (see ``_deleet``),
# so numbers standing on their own survive.
_DELEET = {"4": "a", "3": "e", "0": "o", "5": "s", "7": "t", "8": "b", "1": "i"}


def _strip_invisibles(text: str) -> str:
    """Drop Unicode format characters (zero-width spaces, joiners, BOM, ...)."""
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def _demap_confusables(text: str) -> str:
    return "".join(_CONFUSABLES.get(ch, ch) for ch in text)


def _deleet(text: str) -> str:
    """Undo leet digits that sit in a word (a letter on either side)."""
    chars = list(text)
    n = len(chars)
    for i, ch in enumerate(chars):
        repl = _DELEET.get(ch)
        if repl is None:
            continue
        left = chars[i - 1].isalpha() if i > 0 else False
        right = chars[i + 1].isalpha() if i + 1 < n else False
        if left or right:
            chars[i] = repl
    return "".join(chars)


def normalize(text: str) -> str:
    """Undo character-level obfuscation as far as it can be done losslessly.

    Order matters: strip invisibles first (so joiners don't split a run), then
    NFKC-fold compatibility forms, map confusables back to Latin, and finally
    undo in-word leet.
    """
    text = _strip_invisibles(text)
    text = unicodedata.normalize("NFKC", text)
    text = _demap_confusables(text)
    text = _deleet(text)
    return text


# Registry so the API / demo can list defenses the way it lists attacks.
DEFENSES = {
    "none": lambda t: t,
    "normalize": normalize,
}


def available_defenses() -> list:
    return list(DEFENSES)


def apply_defense(name: str, text: str) -> str:
    try:
        fn = DEFENSES[name]
    except KeyError as exc:
        raise ValueError(
            f"unknown defense {name!r}; available: {available_defenses()}"
        ) from exc
    return fn(text)
