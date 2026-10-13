# Local verification 13 October 2026

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
