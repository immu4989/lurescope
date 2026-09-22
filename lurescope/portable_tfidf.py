"""Narrow, data-only inference for the bundled word TF-IDF fraud classifier.

This is not a general sklearn deserializer. No model-supplied code, regex,
imports, paths, or callbacks are evaluated. Parent directories must be trusted.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path

from lurebench.receipts import loads_strict_json

from .local_io import read_regular_file

PROFILE = "word-unigram-bigram-sublinear-l2-logistic-v1"
MAX_MODEL_BYTES = 8 * 1024 * 1024
MAX_TEXT_CHARS = 100_000
_TOKEN = re.compile(r"(?u)\b\w\w+\b")
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _number(value, *, minimum=-1_000_000, maximum=1_000_000):
    if type(value) not in (int, float):
        raise ValueError("model weights must be finite bounded numbers")
    if not minimum <= value <= maximum or not math.isfinite(value):
        raise ValueError("model weights must be finite bounded numbers")
    return float(value)


class PortableTfidfDetector:
    """Full-precision, bounded JSON weights with fixed inference semantics."""

    name = "tfidf-logreg"
    task = "fraud"

    def __init__(self, path: Path, *, expected_sha256: str):
        if not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256):
            raise ValueError("an external SHA-256 model pin is required")
        raw = read_regular_file(path, maximum=MAX_MODEL_BYTES, label="portable model")
        self.artifact_sha256 = hashlib.sha256(raw).hexdigest()
        if self.artifact_sha256 != expected_sha256:
            raise ValueError("portable model digest mismatch")
        model = loads_strict_json(raw)
        if not isinstance(model, dict) or set(model) != {
            "profile", "source_sha256", "intercept", "features",
        }:
            raise ValueError("invalid portable model fields")
        if model["profile"] != PROFILE:
            raise ValueError("unsupported portable model profile")
        source = model["source_sha256"]
        if not isinstance(source, str) or not _DIGEST.fullmatch(source):
            raise ValueError("invalid source model digest")
        self.source_sha256 = source
        self._intercept = _number(model["intercept"])
        features = model["features"]
        if not isinstance(features, list) or not 1 <= len(features) <= 50_000:
            raise ValueError("invalid portable model feature count")
        self._features = {}
        for index, feature in enumerate(features):
            if not isinstance(feature, list) or len(feature) != 3:
                raise ValueError("invalid portable model feature")
            term, idf, coefficient = feature
            if not isinstance(term, str) or not 2 <= len(term) <= 512:
                raise ValueError("invalid portable model term")
            parts = term.split(" ")
            if (
                len(parts) not in (1, 2) or term != term.lower()
                or any(_TOKEN.fullmatch(part) is None for part in parts)
                or term in self._features
            ):
                raise ValueError("invalid or duplicate portable model term")
            self._features[term] = (index, _number(idf, minimum=1), _number(coefficient))
        self._positive = tuple(sorted(
            self._features, key=lambda term: -self._features[term][2],
        ))

    def score(self, lure) -> float:
        text = lure.text
        if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
            raise ValueError("portable model text exceeds its bounded string profile")
        words = _TOKEN.findall(text.lower())
        counts = Counter(words)
        counts.update(a + " " + b for a, b in zip(words, words[1:], strict=False))
        weighted = []
        for term, count in counts.items():
            feature = self._features.get(term)
            if feature is not None:
                index, idf, coefficient = feature
                weighted.append((index, (1 + math.log(count)) * idf, coefficient))
        weighted.sort()
        norm = math.sqrt(math.fsum(weight * weight for _, weight, _ in weighted))
        logit = self._intercept
        if norm:
            logit += math.fsum(weight / norm * coef for _, weight, coef in weighted)
        if logit >= 0:
            return 1 / (1 + math.exp(-logit))
        exp = math.exp(logit)
        return exp / (1 + exp)

    def top_positive_features(self, top_k: int = 25) -> list[str]:
        if type(top_k) is not int or top_k < 0:
            raise ValueError("top_k must be a nonnegative integer")
        return list(self._positive[:top_k])
