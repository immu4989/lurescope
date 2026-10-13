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

## Subsequent local authentication milestone

The next local milestone rejects ambiguous credential headers before key
derivation, bounds custom key/verifier inputs, and limits concurrent scrypt
verification to two requests per process. This work is uncommitted and unpushed
at verification time. Existing scrypt work factors remain unchanged.

- **55 authentication-boundary tests passed**. They cover duplicate and conflicting
  headers, oversized and unsupported tokens without KDF calls, real scrypt at
  the 32/512-character boundaries, rotation, bounded verifier configuration,
  checking every rotation candidate, and slot release on matches, mismatches,
  and exceptions. A synchronized two-worker test confirms the next request is
  rejected without another derivation while the first two checks are running.
- Real ASGI client checks confirm fixed `401`/`503` diagnostics, retry headers,
  health access during saturation, and unchanged unrestricted local operation.
  These tests use synthetic credentials, not configured production keys.
- Full LureScope suite: **1,229 passed**, with 16 existing warnings.
  Companion LureBench suite: **1,762 passed, 39 skipped**, with nine existing
  warnings and the previously documented temporary urllib3 overlay.
- All **107 browser tests**, Ruff, whitespace checks, static asset URL checks,
  **26 producer pins**, and **10 independent authority artifacts** passed.
- The rebuilt wheel matched **164 exact files**. The source archive retained
  **19 browser reproduction inputs** plus byte-exact new authentication tests
  and the installed-authentication check script. The manifest was corrected
  after archive inspection found that the new script was initially omitted.
- Installed authentication, data-only scoring/proof, and browser checks passed
  outside the checkout on Python **3.12.13**. Authentication checks are wired
  into the existing installed-wheel CI job; hosted CI has not run these local edits.

The guard bounds concurrent KDF work, not unauthenticated request rate, total
memory/CPU, request duration, or distributed attack impact. Real clients may
receive retryable saturation errors. Configuration changes affect subsequent
settings snapshots, not already-running checks. Keep gateway protections and
follow the [custom-key migration limits](PUBLIC_DEPLOYMENT.md#source-branch-authentication-work-limits).
No public deployment, provider traffic, credential provisioning, or release was
performed by this verification.

## Subsequent local provenance boundary milestone

The fraud service now rejects Binoculars before constructing a detector, and
its capability catalog explains that the adapter is provenance-only. The
five new service-boundary tests passed for score, attack, email triage, proof,
and catalog behavior. Before the change, the synthetic provenance-only backend
could produce successful fraud score, attack, and triage responses.

Full verification passed **1,234 Scope tests**, **1,819 Bench tests** (39 skips),
and **107 browser tests**, with the same existing warnings and Bench dependency
overlay noted above. The rebuilt Scope wheel matched **164 exact files**; the
source archive retained **19 browser inputs**. Producer-contract and independent
authority checks retained all **26** and **10** passing artifacts respectively.
Both local wheels were installed together outside the checkouts. Installed
Scope model/proof and authentication checks passed on Python **3.12.13**;
the model check now explicitly rejects provenance-only fraud scoring.

Ruff and whitespace checks passed. The restriction requires no actual optional
model or provider call and does not rewrite historical evidence. Changes remain
local, uncommitted, and unpushed at verification time; no release was created.

## Subsequent local detector lifecycle milestone

The service now caches only its three fixed local detector names. Request engine
and model options cannot multiply these instances, and per-name locks prevent
duplicate successful construction on concurrent cold requests. Provider detectors
are created for each service operation instead of retaining captured provider
configuration and credentials across operations. Direct Python service calls
also reject names outside the serving catalog before registry construction.

Before the fix, 11 of the initial 14 regression cases failed. They reproduced
local-instance multiplication, stale default engines and credentials, concurrent
duplicate construction, and construction of unserved names. The final expanded
suite has **21 passing lifecycle tests**, including a real LureBench judge
constructor with synthetic credentials and changed provider presets, an ASGI
allowlist/dispatch check after changing the default engine, synchronized cold
loads and clearing, independent local-model locks, weak-reference release, and
reuse of one provider detector across the three scores in an attack operation.
No real provider calls, credentials, or downloaded weights are used.

Full verification passed **1,255 Scope tests**, **1,819 Bench tests** (39 skips),
and **107 browser tests**. The existing 16 Scope warnings, nine Bench warnings,
and temporary Bench urllib3 overlay are unchanged. Ruff, whitespace checks,
static asset URL checks, **26 producer pins**, and **10 independent authority
artifacts** passed. LureBench source was unchanged in this milestone.

The rebuilt Scope wheel matched **164 exact files**. Its source archive retained
**19 browser inputs** and byte-exact lifecycle tests and installed smoke script.
The previously built Bench wheel still matched **156 exact files** and was
installed beside the new Scope wheel into a fresh temporary directory.
Installed model/proof, authentication, and browser checks passed outside both
checkouts on Python **3.12.13**. The existing installed-model CI check now covers
local cache reuse, uncached provider constructors, and rejection of unserved names.

This bounds retained local instances, not total memory, inference concurrency,
constructor wait time, or SDK cleanup. Provider connection reuse changes, and
live environment mutation is not atomic reconfiguration. See
[deployment lifecycle limits](PUBLIC_DEPLOYMENT.md#source-branch-detector-lifecycle).
This milestone remains local and unpushed. The local 0.11.0 build artifacts are
verification outputs, not replacement public releases or a deployment.
