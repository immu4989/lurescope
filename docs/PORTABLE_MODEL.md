# Data-only default model

On this source branch, the default `tfidf-logreg` serving path loads
`lurescope/models/tfidf-logreg-fraud.json`, not the bundled joblib file. This is a
narrow fixed inference profile, not a general scikit-learn model loader.

The loader checks its external SHA-256 pin before parsing, reads at most 8 MiB
from a regular non-symlink file, and rejects unexpected fields, duplicate JSON
keys, unsupported profiles, duplicate terms, and invalid/bounded weights. It
supports at most 50,000 features and 100,000 input characters. The public API's
existing smaller request limits still apply. Parent directories must be trusted.

Inference uses Python Unicode lowercase and word tokenization, unigrams/bigrams,
sublinear term counts, learned IDF, L2 normalization, and a binary logistic link.
Weights retain full floating-point precision. No artifact-supplied code, imports,
regular expressions, file paths, or callbacks are evaluated.

Regression tests compare over 1,000 inputs with the existing trusted scikit-learn
model, including multilingual text, empty inputs, repetition, sampled vocabulary,
and bundled pilot emails. Scores must agree within **1e-12 absolute probability**;
this is a tested numerical tolerance, not bitwise equivalence or a proof for all
possible strings/Python Unicode versions. Top positive feature order is preserved.
The rounded browser model is a separate artifact and has not been replaced.

LureProof records the hash of the JSON bytes actually loaded for scoring. Older
proofs naming the joblib artifact remain valid historical records. The proof's
existing `sklearn_version` field remains installed-environment metadata, not a
claim that scikit-learn executed this new default inference path.

## Reproduce the conversion

Only convert a model whose origin you trust. **The export step still executes
joblib/pickle deserialization.** A hash is not evidence of publisher identity unless
you obtained that hash through an independently trusted channel.

```sh
python -m scripts.export_portable_tfidf \
  --trusted-joblib lurescope/models/tfidf-logreg-fraud.joblib \
  --expected-sha256 84c7254c464ff9faa3ede012691c13d53da08ab1f26223633af7b9377d60ed0b \
  --out /tmp/lurescope-portable-model-new.json
```

The destination must not exist. Expected exported SHA-256:
`12b30fae44d49f77c748c669552117ba25400cd9439bf4c9871bae31a8b16055`.
Run `pytest -q tests/test_portable_tfidf.py` to check parity and reproducibility.
Model updates require deliberate review of both the artifact and its source-code
pin; a mismatch fails closed instead of falling back to pickle.

The old joblib artifact and training dependencies remain packaged for compatibility
and trusted reproduction. This change does not remove all executable-model paths
from extended detectors, fix Accelerate advisories, establish model provenance,
or demonstrate improved fraud accuracy. No model was retrained and no paid API
was called. It reduces the default serving path's deserialization attack surface.
