# Local verification on 12 October 2026

The unreleased Evidence Explorer now displays LureBench grouped uncertainty
reports locally, including sample/group counts, answer coverage, point estimates,
nominal intervals, unavailable statuses, and conditional-draw warnings. No report
or underlying message data is uploaded by the view. This is source-branch work,
not a public deployment or package release.

## Verification results

- **1,174 Python tests passed**, with 16 existing Starlette/httpx and NumPy/joblib
  warnings, using the current sibling LureBench source branch.
- **107 browser tests passed** across the five Node suites. New tests cover the
  producer fixture, one-group unavailability, entirely abstaining data, browser
  global/Node parity, inconsistent displayed arithmetic, coercions, bounds,
  status contradictions, and real file-intake-to-renderer behavior.
- Ruff and `git diff --check` passed. Script URLs match exact updated asset bytes.
- The unchanged producer contract passed **26 artifact pins**; **10 authority
  artifacts** verified with LureBench imports forbidden.
- An offline wheel passed the **164 exact source/asset/reference file** check.
  Installed browser checks outside the checkout passed model scoring, asset
  presence, grouped-report summary generation, and rejection of an altered recall bound.
- The source distribution retained **19 exact browser reproduction inputs**,
  including the new synthetic uncertainty fixture and browser tests.

The fixture matches the current LureBench producer exactly: six synthetic
observations, three declared groups, 97 replicates, seed 41. It is not detector
performance evidence. The live loopback preview displayed the expected 6/3
record/unit counts, 4/6 answered records, and conditional warnings. Only the
evidence workflow was visually checked; a static-only preview has no scoring
API. The temporary preview tab and server were closed after inspection.

## Limits

The browser checks displayed arithmetic and consistency, not bootstrap draws,
AUC, input fingerprints, signatures, or statistical assumptions. It never issues
a deployment pass. Use `lurebench verify-uncertainty` with reviewed local inputs
and explicit controls to reproduce the full report. The strict JavaScript JSON
boundary requires safe integer seeds; larger unsigned 64-bit seeds require the
Python CLI. Reproduction does not establish independence or authentication.

No public site, PyPI package, or release was updated by these checks. Local wheels
still carry 0.11.0 as test artifacts, not replacement public distributions. See
[Evidence Explorer interpretation](EVIDENCE_EXPLORER.md).
