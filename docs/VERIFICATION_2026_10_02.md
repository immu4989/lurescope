# Local verification on 2 October 2026

This records offline checks of the unreleased work on `feat/lurepermit-lurerange`,
based on commit `71fdb593cafa7907ad8a34d82c509cd6c130c8af`. Changes remain local and
uncommitted. Neither published PyPI 0.11.0 nor hosted labs were updated. Local
0.11.0 distribution files are test artifacts, not a new release.

## What changed

Email uploads preserve original bytes through API triage and proof generation.
New assessments reject over-limit readable text instead of scoring a prefix.
Attachment and embedded-message descendants are excluded from outer-message
text, links, image cues, and nested filename extraction. Malformed links produce
review evidence rather than interrupting domain checks. Attachments are not scanned.

The deliberately limited browser MIME parser rejects unsupported structures,
encodings, charsets, and extended filename parameters. It decodes supported HTML
references once before scoring and quoted-link checks. Unsupported references
require the full API, not a partial low-risk result. This is not full HTML5 or
mail-client rendering parity.

Workbench request guards suppress stale score, attack, email, evidence, and proof
results after user selections change. They do not cancel server/provider work
already started. Content-bound script URLs and cache revalidation address stale
browser assets; they do not authenticate their origin.

The browser model is included in the wheel. Both rounded copies are regenerated
from pinned data-only serving weights without unpickling. Prototype-shaped tokens
cannot access inherited vocabulary properties. Browser heuristic matching now
handles Unicode word boundaries, decimal digits, and selected case-folding
differences consistently with the Python baseline.

Evidence Explorer displays planned LureBench panels as comparisons, never winners.
It exposes common-cohort coverage, missingness, and adjusted p-values while retaining
inference warnings. JSON intake rejects ambiguous keys, malformed Unicode, unsafe
numbers, and excessive structure, including decoded DSSE payloads. The browser
does not recompute statistics or authenticate signatures.

Proof creation validates shared controls and bounded keys before scoring. Inbox
batches validate shared settings before creating outputs. Proof generation no
longer imports scikit-learn solely to report its installed distribution version.
Historical proof verification remains available under its original contract.

## Checks and results

The local Python interpreter was 3.12.13. Browser unit tests ran with Node.

| Check | Result |
| --- | --- |
| Full Python suite with normal dependency resolution | 1,012 passed, 16 warnings |
| Full Python suite with adjacent LureBench source | 1,012 passed, 16 warnings |
| Browser tests across five test files | 94 passed |
| Ruff and Git diff whitespace checks | Passed |
| Content-bound script URL check | Passed |
| Both rounded models regenerated read-only from pinned weights | Exact match |
| Producer contract pins | 26 matched |
| Authority verifier with producer imports forbidden | 10 artifacts verified |
| Exact wheel source/assets check, including nested modules | 164 files matched |
| Source-distribution browser reproduction inputs | 18 exact files matched |
| Installed authority self-test outside checkout | 10 of 10 profiles passed |
| Installed scoring and email proof with ML/serialization imports blocked | Passed |
| Installed browser assets and scoring | Passed |

Cross-language regressions cover 2,048 synthetic heuristic boundary/case inputs,
261 rounded TF-IDF comparisons with a declared tolerance, and 32 HTML numeric-
reference email cases. They are not a multilingual accuracy study. Source archive
checks concern browser reproduction inputs, not a claim that every development
workflow can run from the archive alone.

Local browser checks exercised mobile scoring, stale-result suppression,
byte-preserving email intake, and the synthetic comparison-panel view. They do
not replace accessibility testing, a browser matrix, or production load testing.
Warnings include Starlette/httpx and joblib/NumPy deprecations. No paid calls,
model downloads, commits, pushes, or production updates were made in this cycle.

## Reproduce and review

```sh
python -m pytest -q
ruff check lurescope tests scripts
node --test tests/browser_engine.test.cjs tests/evidence_explorer.test.cjs \
  tests/capacity_planner.test.cjs tests/capacity_ui.test.cjs tests/workbench_ui.test.cjs
python scripts/stamp_static_assets.py --check
python scripts/export_static_model.py --check
python scripts/check_producer_contract.py
python scripts/verify_mandate_independence.py
```

Before release, review the diff and [migration notes](HARDENING_MIGRATION.md), run
protected remote CI, assign a new version, rebuild, and repeat installed-package
checks. Local test success is not government certification, procurement approval,
fraud-detection effectiveness, or deployment readiness. Keep human review and
existing email-security controls; no low-risk score means a message is safe.
