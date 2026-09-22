#!/usr/bin/env python3
"""Convert a TRUSTED, externally pinned joblib model to data-only JSON.

Conversion still executes pickle deserialization. Never use on untrusted models.
The output contains public model weights, not secrets, and is created exclusively.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tempfile
from pathlib import Path

from lurescope.local_io import read_regular_file
from lurescope.portable_tfidf import PROFILE, PortableTfidfDetector


def export(source: Path, expected_sha256: str, out: Path) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("expected SHA-256 must be lowercase hexadecimal")
    raw = read_regular_file(source, maximum=16 * 1024 * 1024, label="trusted model")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("trusted source digest mismatch; deserialization not attempted")
    import joblib
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    bundle = joblib.load(io.BytesIO(raw))
    if bundle.get("task") != "fraud":
        raise ValueError("unsupported model task")
    pipe = bundle["pipeline"]
    if type(pipe) is not Pipeline or [name for name, _ in pipe.steps] != ["tfidf", "clf"]:
        raise ValueError("unsupported pipeline")
    vec, clf = pipe.named_steps["tfidf"], pipe.named_steps["clf"]
    if type(vec) is not TfidfVectorizer or type(clf) is not LogisticRegression:
        raise ValueError("unsupported estimators")
    required = {
        "analyzer": "word", "token_pattern": r"(?u)\b\w\w+\b", "lowercase": True,
        "strip_accents": None, "preprocessor": None, "tokenizer": None,
        "stop_words": None, "ngram_range": (1, 2), "sublinear_tf": True,
        "norm": "l2", "use_idf": True, "binary": False,
    }
    if any(vec.get_params()[key] != value for key, value in required.items()):
        raise ValueError("unsupported vectorizer configuration")
    if vec.dtype is not np.float64 or clf.multi_class == "multinomial":
        raise ValueError("unsupported precision or logistic link")
    size = len(vec.vocabulary_)
    if (
        list(clf.classes_) != [0, 1] or clf.coef_.shape != (1, size)
        or clf.intercept_.shape != (1,) or len(vec.idf_) != size
        or sorted(vec.vocabulary_.values()) != list(range(size))
    ):
        raise ValueError("unsupported classifier dimensions/classes")
    terms = sorted(vec.vocabulary_, key=vec.vocabulary_.get)
    model = {
        "profile": PROFILE, "source_sha256": expected_sha256,
        "intercept": float(clf.intercept_[0]),
        "features": [[term, float(vec.idf_[i]), float(clf.coef_[0][i])]
                     for i, term in enumerate(terms)],
    }
    payload = json.dumps(model, ensure_ascii=False, separators=(",", ":"),
                         allow_nan=False).encode("utf-8") + b"\n"
    digest = hashlib.sha256(payload).hexdigest()
    # Validate the serving contract before publishing a destination artifact.
    with tempfile.TemporaryDirectory(prefix="lurescope-portable-export-") as temporary:
        candidate = Path(temporary) / "model.json"
        candidate.write_bytes(payload)
        PortableTfidfDetector(candidate, expected_sha256=digest)
    with out.open("xb") as stream:
        stream.write(payload)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-joblib", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(export(args.trusted_joblib, args.expected_sha256, args.out))


if __name__ == "__main__":
    main()
