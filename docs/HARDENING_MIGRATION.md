# Source-branch hardening: deployment migration

These changes are **unreleased**, not part of published PyPI 0.11.0. No production
deployment or paid-provider experiment is implied by the offline verification.

## Default scoring model

The default detector name remains `tfidf-logreg`, but serving now uses pinned,
full-precision JSON weights with a fixed inference profile. It does not unpickle
the bundled model. Over 1,000 test inputs must match the trusted original within
1e-12 absolute probability; feature rankings are also checked.

See [portable model](PORTABLE_MODEL.md) for the exact artifact pins, conversion
procedure, numerical limitations, and trusted-source requirements. Original
joblib/training dependencies remain available for reproducibility. The rounded
browser model is unchanged. This is not a claim of improved fraud accuracy.

New LureProofs and pilot plans bind the JSON bytes actually loaded. New operational
pilots require the new pin; historical receipt validation recognizes both reviewed
model pins. Old preregistered plans are not silently rewritten to match a new
artifact. Review and register a new plan before evaluating the changed deployment.

## API clients

Detector abstentions and invalid/non-finite scores no longer become zero-risk
benign results. Score/triage/proof calls fail without issuing a decision or proof.
Provider exception content is redacted from HTTP error responses. Clients should
route unavailable decisions to explicit handling/review, not turn an error into
an allow decision. See [public deployment](PUBLIC_DEPLOYMENT.md).

Direct Python service calls validate thresholds before detector work. Explicit
invalid creation timestamps are rejected instead of being replaced with now.

## Policies and evidence files

Policy loading uses bounded strict JSON and content-based validation caching.
Optional `LURESCOPE_POLICY_SHA256` binds an operator-approved artifact; a changed
file fails before scoring. Without a pin, changed bytes are revalidated. Review
the [policy configuration guide](RISK_CONTROLLED_POLICY.md) before deployment.

Legacy local-evidence readers now reject nonregular/symlink files, oversized reads,
and observed changes during reading. Parent directories must remain trusted.
The new [checkpoint byte verifier](CHECKPOINT_VERIFICATION.md) independently checks
a pinned preflight report's byte bindings without loading a model; it is not an
independent tensor parser or publisher-authentication service.

## Offline verification

```sh
python -m pytest -q
ruff check lurescope tests scripts
node --test tests/browser_engine.test.cjs tests/evidence_explorer.test.cjs
python scripts/check_producer_contract.py
python scripts/verify_mandate_independence.py
python -m build --no-isolation
```

CI also installs the wheel outside the checkout, verifies ten authority profiles,
and runs `scripts/check_installed_model.py --installed-root PATH` in a fresh
interpreter with pickle/joblib/sklearn/NumPy/Torch imports blocked. This verifies
the packaged default model path, not every optional detector or deployment.

Local wheels still named 0.11.0 are test artifacts: do not upload them over an
existing release. Versioning, protected-branch review, live CI, and publishing are
separate release steps. No government certification, procurement approval, model
safety guarantee, or production-readiness claim follows from passing these tests.
