# Local verification 13 October 2026

Status notes within earlier sections describe each verification milestone at
that time. Those changes were subsequently pushed through `288fb04`; the
enforcement and numerical milestones at the end remain local, uncommitted, and unreleased.

Moderation provider failures must not create a fraud decision, an evasion claim,
or a proof. The companion source-branch LureBench adapter now validates a complete
numeric moderation result and raises on malformed evidence. LureScope's existing
runtime-error handling returns a redacted failure. These local changes are not
part of published PyPI 0.11.0 and remain uncommitted and unpushed.

## Moderation route verification

All **seven new route tests passed**. Three provider-runtime failure tests verify
fixed `502` responses on score, attack, and triage without provider diagnostics or
results. A fourth test confirms proof creation rejects moderation before model
construction. Three paired cases exercise the actual new LureBench parser with a
synthetic client, then confirm recovery after correcting the score to valid zero.
The paired cases explicitly skip with an older installed companion parser; that
skip is not evidence of the parsing fix being deployed.

The rebuilt local wheels were installed together in a fresh temporary directory.
An installed ASGI check independently exercised all four routes using the actual
new adapter: malformed scores produced three `502` responses, proof creation
stopped with `400` before another provider-client call, and valid-zero scoring
recovered successfully. No network or real provider credential was involved.

## Supporting verification and limitations

The full paired-source Scope suite passed **1,262 tests**, with 16 existing
warnings and no skips. The companion Bench suite passed **1,970 tests**, with
40 skips and 15 warnings using its documented temporary urllib3 overlay. Its
optional Pydantic moderation case passed separately in the Scope environment,
where all **69 moderation contract cases** passed.

The **107 browser tests**, **26 producer pins**, and **10 independent authority
artifacts** passed, as did Ruff, whitespace, and static asset URL checks. Scope's
wheel matched **164 exact files**, and its source archive retained **19 browser
inputs**. Installed model/proof, authentication, and browser checks passed under
Python **3.12.13**. Companion Bench installed checks passed under Python **3.12.13**
and **3.13.15** with optional SDK/model imports blocked.

This verifies malformed-result handling, not moderation accuracy or fraud
calibration. The actual OpenAI SDK was unavailable in the offline cache; the
checks used synthetic client responses, actual parser code, and Pydantic-shaped
category objects. A service-only upgrade with an older LureBench dependency does
not apply the parser fix. Review [deployment boundaries](PUBLIC_DEPLOYMENT.md)
and deploy compatible companion builds together. Local wheels remain test
artifacts; nothing was pushed, published, or deployed.

## Subsequent policy binding disclosure milestone

Policy status now reports `detector_binding: name_only` and
`detector_configuration_verified: false` for configured schema v1/v2 policies.
An unconfigured service reports `none` binding and no verified configuration.
These fields distinguish validation arithmetic from deployment equivalence:
neither schema verifies model weights, prompts, preprocessing, or provider
settings against the calibration run. Policy application behavior is unchanged.

- **Six new tests** cover empirical and risk-controlled status through Python,
  CLI, and HTTP, the unconfigured endpoint, and all three generated LureBench
  calibration objectives. Response-model serialization retains the fields and
  limitations. Historical policy loading remains covered by the existing suite.
- Full paired-source Scope: **1,268 passed, 16 warnings**. Companion Bench:
  **2,013 passed, 40 skipped, 15 warnings**, using its documented urllib3 overlay.
  The **107 browser tests**, **26 producer pins**, **10 independent authority
  artifacts**, Ruff, whitespace, and static asset URL checks passed.
- Wheels matched **164 Scope** and **156 Bench** package/authority files, and
  Scope's source archive retained **19 browser inputs**. Installed Scope loaded
  new full-digest policy IDs for all three objectives without rewriting them,
  and retained the name-only disclosure with model frameworks blocked. Installed
  model/proof, authentication, and browser checks passed. Companion installed
  checks passed on Python **3.12.13** and **3.13.15** with optional imports blocked.

A stronger policy evidence ID improves change detection, not authentication or
model verification. Deployment must still independently review configuration
equivalence and revalidate after changes. No live provider calls, public package
release, or deployment occurred. This milestone remains local and unpushed.

## Subsequent bound portable calibration milestone

`lurescope calibrate` collects validation scores using the bundled portable
detector and exports a v3 policy through LureBench. Matching policy-backed scores
require the exact portable artifact, installed inference-source digest, and
declared runtime profile. The service checks before inference and before
publication; model weights and metadata are immutable through ordinary Python
interfaces. Joblib source hashes are not treated as inference-equivalence claims.

- **34 new binding tests** passed. They cover all three calibration objectives,
  independent consumer ID checks, malformed/tampered evidence, offline versus
  deployment status, constructor-free invalid-plan rejection, exact portable
  bytes despite unchanged source-joblib identity, explicit thresholds, another
  detector's defaults, runtime/configuration mismatch, HTTP redaction, proof
  refusal, normal-interface immutability, and byte-exact producer schema agreement.
- A separate CLI regression confirms that policy inspection does not resolve
  a supplied symlink before the regular-file loader can reject it.
- Full paired Scope: **1,305 passed, 16 warnings**. Bench: **2,043 passed,
  40 skipped, 15 warnings** with its existing urllib3 overlay. The **107 browser
  tests**, Ruff, whitespace, **26 historical producer pins**, **10 independent
  authority artifacts**, and static asset URL checks passed.
- Updated wheel verifiers require the v3 schema. Wheels matched **166 Scope**
  and **157 Bench** exact package/authority files; Scope's source archive retained
  **19 browser inputs**. Installed Scope checked all three bound-policy objectives
  with model frameworks blocked; model/proof, authentication, and browser checks
  passed. Bench installed checks passed under **3.12.13** and **3.13.15**.
- A fresh installed CLI generated a bound policy from two synthetic records
  under Python **3.12.13**, outside the repositories with `-I -S`. Matching
  installed 3.12 scoring succeeded. The identical policy remained structurally
  valid under **3.13.15**, but deployment verification reported `mismatch` and
  policy-backed scoring failed. Installed 3.12 HTTP status and scoring passed.

This verifies the declared local configuration boundary, not fraud accuracy,
issuer authentication, hardware/process attestation, or end-to-end preprocessing.
Legacy and provider policies remain configuration-unverified. The first profile
intentionally requires recalibration after runtime/implementation changes rather
than inferring cross-implementation equivalence. See the operational limits in
[bound policy deployment](BOUND_POLICY.md). Nothing was pushed or released, and
no provider calls or model-training runs were made for this milestone.

## Required policy admission milestone

Operator enforcement now requires an approved file pin and bound v3 evidence
before producing policy-backed scores. The stronger mode additionally requires
validated risk-control evidence. Client threshold, detector, engine, or model
overrides cannot opt out. Admission runs before detector construction and before
HTTP provider quota reservation. Exploratory attacks and new proofs require a
separate research worker; existing proof verification remains independent.

- **42 new tests** passed. They cover strict mode parsing, absent/invalid pins,
  missing or corrupt files, legacy downgrades with old and newly approved pins,
  empirical-policy rejection by the stronger mode, all supported bound objectives,
  HTTP/Python override rejection, equal-threshold overrides, actual email triage,
  warm-worker configuration changes, proof-batch preflight, and historical proof
  verification without inference.
- HTTP `/policy/readiness` and CLI `policy --check-readiness` agree for ready and
  unready deployments. Tests reject a runtime mismatch, missing trust, invalid
  public security configuration, and a conflicting detector allowlist. Readiness
  checks do not invoke prediction. The unconfigured research demo remains live
  while correctly reporting that enforced scoring is not ready.
- Full paired Scope: **1,367 passed, 16 warnings**. Bench: **2,059 passed,
  40 skipped, 15 warnings**, using its existing urllib3 overlay. Together with
  **107 browser tests**, this is **3,533 passing tests**. Ruff, whitespace,
  **26 historical producer pins**, **10 independent authority artifacts**, and
  static asset checks passed.
- Wheels matched **166 Scope** and **157 Bench** exact source/authority files;
  Scope's source archive retained **19 browser inputs**. Installed model/proof,
  authentication, and browser checks passed. The model check now exercises
  enforced pinned scoring, override/exploration refusal, readiness, and pin removal
  with model frameworks blocked. Bench installed checks passed under Python
  **3.12.13** and **3.13.15**.
- An independent installed ASGI/fresh-process CLI check under **3.12.13** verified
  readiness, pinned scoring, three HTTP override/exploration rejections, and
  fail-closed scoring/readiness after removing the pin from a warm worker.

The companion Bench change documents how statistical evidence connects to
enforced serving; it does not change calibration mathematics. These synthetic
checks establish admission behavior, not new accuracy or compliance evidence.
Configuration remains trusted, updates are not multi-setting transactions, and
in-flight work is not cancelled. Readiness is not a capacity or future-outcome
guarantee. All new work remains local; no provider calls, model downloads,
GitHub pushes, release publication, or production configuration changes occurred.

## Paired numerical implementation verification

The source-branch LureBench dependency now streams binomial weights, removes a
rounded subnormal-tail fixed point, and calculates zero-event upper bounds with
a stable closed form. Scope's policy, pilot, and evaluation consumers benefit
only when deployed with the updated companion build; no code in this change
patches an older installed dependency.

Three new consumer cases verify consistent counts-only policy evidence with
400, 100,000, and 9,999,999 negatives. The final paired suite passed **1,370 Scope
tests** (16 warnings), **2,098 Bench tests** (40 skips, 15 warnings with the existing
urllib3 overlay), and **107 browser tests**. Bench's 39 new numerical cases include
Decimal/SciPy oracles, nonzero-event beta quantiles, and a memory regression.
The large counts are synthetic metadata, not newly evaluated messages.

Ruff, whitespace, 26 historical producer pins, 10 independent authority artifacts,
static assets, 157 Bench/166 Scope wheel file checks, and 19 browser source-archive
inputs passed. Installed model/proof, enforced policy, authentication, and browser
checks passed; Bench's installed numerical checks passed on Python 3.12 and 3.13
without optional dependencies. Statistical methods and consumer schema versions
are unchanged. The workflow remains local and unpushed, with no provider calls
or deployment changes.

## Strict statistical acceptance boundary

The policy consumer now requires both reported and recomputed statistics to
satisfy the confidence/FPR limits without an added tolerance. Four new consumer
regressions previously accepted boundary violations; all now reject them.
The paired producer has four corresponding checks and a selector regression for
contradictory extreme-confidence evidence. Previously tolerated borderline
artifacts may fail validation, without being rewritten.

The final paired suites passed **1,374 Scope tests**, **2,103 Bench tests**, and
**107 browser tests** (**3,584 total**), retaining 16 Scope warnings and 40 Bench
skips/15 warnings with the existing urllib3 overlay. Ruff, producer pins,
independent authority checks, static assets, and installed package checks passed.
A separate installed check verified both rejection paths and selector refusal
without optional dependencies. All changes remain local and unpushed.
