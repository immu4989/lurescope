#!/usr/bin/env python3
"""Export the bundled tfidf-logreg model to space/model.json for the static Space.

The Hugging Face Static Space (space/index.html) runs inference in the browser, so
it needs the trained model as JSON: for each vocabulary term its idf weight and its
logistic-regression coefficient, plus the intercept. The JS in index.html replicates
sklearn's TfidfVectorizer transform (sublinear tf, L2 norm) exactly — verified to
match the Python service to 4 decimals.

    python scripts/export_static_model.py

Requires the model artifact at lurescope/models/tfidf-logreg-fraud.joblib.
"""

from __future__ import annotations

import json
import os

import joblib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL = os.path.join(HERE, "lurescope", "models", "tfidf-logreg-fraud.joblib")
OUT = os.path.join(HERE, "space", "model.json")


def main() -> None:
    d = joblib.load(MODEL)
    pipe = d["pipeline"]
    vec = pipe.named_steps["tfidf"]
    clf = pipe.named_steps["clf"]
    idf = vec.idf_
    coef = clf.coef_[0]

    vocab = {
        term: [round(float(idf[idx]), 5), round(float(coef[idx]), 5)]
        for term, idx in vec.vocabulary_.items()
    }
    model = {
        "intercept": round(float(clf.intercept_[0]), 6),
        "ngram_max": vec.ngram_range[1],
        "sublinear_tf": bool(vec.sublinear_tf),
        "norm": vec.norm,
        "vocab": vocab,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(model, f, separators=(",", ":"))
    print(f"wrote {OUT}  ({os.path.getsize(OUT) / 1e6:.2f} MB, {len(vocab)} features)")


if __name__ == "__main__":
    main()
