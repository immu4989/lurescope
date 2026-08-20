# Changelog

## Unreleased

### Added
- Added a private, offline SCuBA Assurance Drift Ledger that compares two
  semantically verified Combined Email Assurance bundles only when their
  ScubaGear contract, exact release, selected products, assurance profile, and
  assessment plan match and report time increases. It deterministically records
  regressions, improvements, newly failing, added, removed, unchanged, and
  deliberately non-comparable transitions without making causal or compliance
  claims.
- Added candidate POA&M lifecycle observations (`new_candidate`,
  `persistent_candidate`, `no_longer_observed`, and `not_candidate`), separate
  Pilot Gate verdict change, minimized before/after snapshots, human-readable
  Markdown and standalone HTML, NIST OSCAL 1.2.2 observations without findings,
  an in-toto statement, optional P-256 DSSE authentication, and predecessor
  statement chaining with source-continuity verification.
- Added `lurescope assurance drift` and `verify-drift`, including optional
  authenticated reverification of both original source bundles, strict public
  JSON Schemas, official OSCAL validation, offline execution tests, conservative
  transition semantics, tamper tests, chain tests, and an operator guide.
- Added an offline CISA SCuBA Evidence Bridge for ScubaGear 1.8.x consolidated
  reports. It validates a strict allowlisted contract, reconciles every summary
  count to the underlying results, selects AAD, Defender, and Exchange Online,
  and exports only product, control ID, result, and criticality as explicitly
  sensitive, privacy-minimized evidence.
- Added combined NIST OSCAL 1.2.2 Assessment Results, candidate-only POA&M items
  for failing `Shall` controls, an in-toto statement binding every artifact by
  SHA-256, optional exact-payload ECDSA P-256 DSSE signing, and an offline
  verifier for package structure, cross-file bindings, semantics, and signatures.
- Added strict SCuBA evidence, combined in-toto Statement, and DSSE envelope JSON
  Schemas; a synthetic no-real-data fixture; adversarial privacy and tamper tests;
  and byte-locked official NIST POA&M schema validation alongside the existing
  Assessment Plan and Results checks.

### Security
- Bound every imported result group to the official versioned CISA baseline URL
  matching the report's declared ScubaGear release. Configured supplemental
  organizational fields remain confined to the discarded raw provider payload;
  tests cover official UTF-8 BOM input and verify those values cannot enter
  minimized evidence.
- Drift packages fail closed on release, contract, scope, profile, plan, or time
  mismatch; non-canonical JSON; unsafe permissions; symlinks; unexpected files;
  report, OSCAL, statement, snapshot, or signature tampering; broken predecessor
  continuity; and mismatched externally supplied source bundles.
- The bridge fails closed on unknown source fields, unsupported ScubaGear
  versions, inconsistent summaries, duplicate or cross-product control IDs,
  symlinks, unsafe permissions, unexpected output files, overwrite attempts,
  artifact rebinding, and signature mismatch. Tenant identity, raw settings,
  free-text details, comments, requirements, and remediation annotations never
  enter the derived bundle.

## 0.8.0 — 2026-08-18

### Added
- Added a private, no-overwrite Federal Email Assurance Profile that composes a
  pre-registered Pilot Gate with NIST OSCAL 1.2.2 Assessment Plan and Assessment
  Results artifacts. It imports an operator-controlled SSP by portable identifier,
  binds every plan and result by SHA-256, emits aggregate observations for CA-7,
  SI-4, and SI-8 without findings or compliance claims, and fails closed on tampering
  or bundle rebinding. The offline path is tested with network sockets disabled and
  both OSCAL documents are validated against byte-locked official NIST schemas.
- Added a one-command, network-free synthetic Golden Pilot that locks every fixture
  and the bundled detector by SHA-256, applies predeclared ground truth, exercises
  the complete Shadow Inbox and Pilot Gate path, requires a real `pass`, validates
  all public schemas, scans privacy exclusions, verifies private permissions, and
  emits a strict aggregate verification receipt. Fixture tampering, network access,
  stale output, and schema relaxation fail tests, and the command runs explicitly in
  CI. The source distribution now carries the frozen lock, runner, fixtures, schemas,
  and linked operator guides needed to reproduce the same pass outside the checkout.
- Added Pilot Gate, a pre-run, no-overwrite statistical contract for Shadow Inbox
  pilots that binds the registered control, minimized manifest, and analyst-label
  log; requires complete review and minimum class evidence; computes exact one-sided
  Clopper–Pearson recall/FPR bounds; enforces analyst-workload limits; and returns
  distinct `insufficient_evidence`, `fail`, and `pass` verdicts with automation-safe
  exit codes. The registered plan is retained in the bundle so later label revisions
  refresh the gate instead of leaving a stale decision behind.
- Added strict Pilot Gate plan/result JSON Schemas, private aggregate-only JSON and
  Markdown decision artifacts, causal ordering and control-mismatch checks, known-
  bound statistical tests, and an operator protocol with explicit assumptions.
- Added `lurescope shadow` for no-enforcement pilots over exported `.eml`, Maildir,
  and mbox data, with conservative deduplication, fixed-vocabulary append-only
  analyst labels, and aggregate-only workload, routing, validation, and resilience
  reports.
- Added offline OCSF 1.8 Detection Finding, ECS 9.4 NDJSON, and STIX 2.1 Incident
  mappings that preserve the inbox manifest's privacy allowlist and can incorporate
  the latest reviewed label.
- Added deterministic QR/scan-language and image-dominant HTML review cues without
  decoding image payloads, plus a fully synthetic six-message pilot pack.
- Added strict Shadow Inbox run, label, and report JSON Schemas and end-to-end
  ingestion, privacy, metrics, CLI, and standards-export tests.
- Added a weekly, source-checkout-free PyPI installation and runtime smoke test
  across Python 3.10, 3.12, and 3.13.
- Added a hardened Docker Compose profile with authentication, rate limiting,
  provider spending disabled, immutable image digest, loopback binding, bounded
  resources and logs, and the same container isolation enforced in CI.
- Added a five-minute workflow from a saved `.eml` through local triage,
  privacy-minimized LureProof, and offline Splunk/Sentinel transforms.
- Ignored the local key, reported-email, and case-output paths used by the
  operational guides to reduce accidental commits of sensitive artifacts.

### Changed
- Documented the Shadow Inbox review protocol, metric denominators, standards
  mapping boundaries, privacy limitations, and non-enforcement safety boundary.
- Converted the Hugging Face demo to a static-only Docker Space whose build
  installs an exact hash-pinned LureScope wheel from PyPI and extracts its packaged
  browser interface without exposing message-content endpoints.

### Security
- Bound Shadow Inbox labels and reports to the original manifest digest and
  summary counts; rejected symlinked inputs and metadata, unsafe bundle paths,
  malformed manifest values, and ambiguous oversized-prefix deduplication.

## 0.7.1 — 2026-08-12

### Changed
- Replaced LureScope's direct Zenodo source dependency with the exact public
  `lurebench[train]==0.9.1` PyPI release, making standard index installation
  portable across pip, uv, build frontends, and downstream package indexes.
- Made `python -m pip install lurescope` the primary installation path while
  retaining editable source installation for contributors.

### Security
- Added tokenless PyPI publication through a narrowly scoped GitHub Actions OIDC
  trusted publisher and a manually approved `pypi` deployment environment.

## 0.7.0 — 2026-08-12

### Added
- Added `lurescope inbox`, a bounded local batch workflow that turns reported
  `.eml` files into random case IDs, one privacy-minimized LureProof per valid
  message, a JSONL routing manifest, and an aggregate summary without persisting
  source paths, subjects, addresses, message IDs, URL values, attachment names,
  or message content.
- Added strict inbox event and summary JSON schemas, private no-overwrite output
  permissions, safe partial-failure records, optional batch DSSE signing, and
  offline `splunk-hec`, Microsoft Sentinel, and generic JSON-array transforms.
- Added pre-read message-count and 64 MiB aggregate batch limits plus bounded
  per-file reads, preventing large mailbox inputs from exhausting process memory.
- Added a fail-closed release gate that verifies version metadata and protected
  tag ancestry, attests wheel and source distributions, and publishes the
  hardened multi-architecture container to GHCR with an SBOM and provenance
  attestation.

### Security
- Added a universal, hash-bearing `uv.lock` and changed CI and container builds
  to frozen dependency resolution.
- Pinned all CI, Pages, Python-base, and build-tool dependencies to immutable
  commit or image digests; restricted the CI token to read-only contents.
- Replaced the build-time Git checkout and mutable OS package installation with
  the exact LureBench v0.9.0 release source verified by SHA-256.
- Moved the LureBench source dependency to its immutable, version-specific
  Zenodo record to avoid transient GitHub release-asset redirects in CI.
- Replaced shell pipelines over HTTP responses in the container smoke test with
  a checked-in, fail-closed verifier that parses response data without executing
  it.
- Raised the minimum Python version from 3.9 to 3.10. Python 3.9 is end-of-life,
  and its last-compatible Starlette, Pillow, pytest, and python-dotenv branches
  contain known vulnerabilities. The maintained Python resolution uses fixed
  releases.

### Changed
- Corrected the public Python support badge to 3.10+.

## 0.6.0 — 2026-08-12

### Added
- CodeQL and OpenSSF Scorecard workflows, private vulnerability reporting, and
  structured integration-request and Q&A forms.
- Fail-closed public API mode with random-salted, memory-hard scrypt API-key
  verification, constant-time comparison, per-credential sliding-window rate
  limiting, safe detector/attack/provider/model defaults, and a provider-call
  circuit breaker.
- `GET /security` and a production-boundary guide that reports deployment
  posture without exposing credentials or provider keys.
- Strict support for LureBench schema-v2 risk-controlled decision policies.
  LureScope independently recomputes exact binomial p-values and one-sided FPR
  bounds and rejects internally inconsistent or insufficient policy evidence.
- `GET /policy` and `lurescope policy` for deployment-readiness inspection,
  explicitly distinguishing finite-sample FPR control, empirical-only legacy
  thresholds, and an unconfigured service.
- Operator documentation for policy creation, validation, serving, monitoring,
  assumptions, and the boundary between provenance digests and authentication.
- A GitHub Pages edition of the adversarial lab. The exported 50,000-feature
  model, deterministic attacks, normalization defense, and bounded `.eml`
  preview run entirely in the browser without sending message content away.
- Automated Pages deployment, social metadata, a web manifest, sitemap, and
  browser-engine regression tests.

### Changed
- Hardened the Docker path with a small build context, multi-stage build,
  non-root runtime, no Git/build toolchain in the final image, built-in health
  check, and an exact LureBench commit pin for reproducible policy verification.
- Added a CI smoke test that exercises the read-only, capability-dropped
  container and verifies both its health and scoring endpoints.
- Documented localhost-only key forwarding and the requirement for
  authentication and rate limiting before exposing paid provider routes.
- Replaced the static repository banner with a lightweight animated operational
  radar that shows the score → attack → defend workflow.
- The Pages edition explicitly routes strict LureProof creation, RFC-complete
  parsing, and semantic attacks to the full local API rather than overstating
  what a static browser runtime can verify.

## 0.5.1 — 2026-08-08

### Security and design correction
- **Corrected LureProof verification semantics.** Version 0.5.0 embedded an
  ordinary SHA-256 digest beside its payload. That detects accidental edits only
  when the editor does not recompute the digest; it does not resist an adversary
  and should not have been described as tamper detection.
- Replaced the custom artifact with a strict in-toto Statement and optional DSSE
  envelope. Signed proofs authenticate the exact payload bytes and payload type
  against an externally trusted ECDSA P-256 public key; unsigned statements are
  now reported explicitly as unauthenticated.
- Added safe key generation, verifier nonces, signed issuer claims, offline signing,
  required-signature mode, wrong-key and payload-replacement tests, and strict
  nested validation with cross-field invariants.
- Made salted subject commitments the default. Raw email SHA-256 is now
  the explicit `correlatable` profile rather than an unavoidable privacy cost.
- Added detector artifact and LureBench version provenance, input truncation
  disclosure, full Statement and DSSE schemas, and a browser download workflow.

### Changed
- The reference producer accepts deterministic local detectors only. This avoids
  provider charges and prevents nondeterministic LLM outputs from being presented
  as reproducible evidence.

## 0.5.0 — 2026-08-08

### Added
- **LureProof 0.1**, an experimental, vendor-neutral resilience passport for a
  suspicious email: minimized message identity, detector and threshold provenance,
  deterministic attack/defense outcomes, implementation provenance, limitations,
  and independently recomputable content addressing. Authentication was added and
  the integrity claim corrected in 0.5.1.
- `lurescope proof`, `lurescope verify`, `POST /proof/email`, and
  `POST /proof/verify` workflows.
- A public JSON Schema, design and standards-landscape document, privacy regression
  tests, deterministic reproduction test, tamper test, CLI test, and API test.

## 0.4.0 — 2026-08-08

### Added
- Privacy-first `.eml` triage through the web lab, `lurescope triage`, and
  `POST /triage/email`, including directory batches and JSONL output.
- Safe standard-library email parsing that never fetches links or opens attachment
  contents; HTML active content is excluded from scored visible text.
- Transparent context evidence for Reply-To domain mismatch, explicit email-auth
  failures, punycode/IP links, executable and archive attachment names.
- Stable triage schema, risk routing, recommended human actions, defanged example,
  and a real-world workflow guide with explicit safety boundaries.

## 0.3.0 — 2026-08-05

### Added
- A complete visual redesign for both the API-backed demo and zero-backend Space:
  forensic-console identity, guided score/attack/defend flow, responsive layouts,
  visible threshold provenance, keyboard focus states, and reduced-motion support.
- A coordinated repository hero graphic shared with the LureBench visual system.
- Strict loading of versioned decision policies exported by LureBench 0.9 through
  `LURESCOPE_POLICY_PATH`. Policies must carry a validation row count and SHA-256
  provenance digest and must target fraud detection.
- `/score` now reports `policy_id` and `threshold_source`, distinguishing a
  validation-selected policy from a caller override or the legacy 0.5 default.

### Changed
- Omitting `/score.threshold` uses a configured policy when its detector matches.
  Explicit thresholds remain fully backward compatible and always take priority.

## 0.2.1 — 2026-07-30

### Fixed
- **The cross-model scorecard measured a smaller sample than it reported.**
  `scripts/llm_scorecard.py` keyed its per-record maps by `rec["id"]`, and
  LureBench shipped roughly 500 generated records whose ids collided across
  generators. Colliding records overwrote each other, so the table headed
  *120 fraud lures* was computed over 73 distinct records, 25 of them counted two
  or three times. The maps are now keyed by position, which cannot collide, and
  the ids themselves are fixed upstream in LureBench 0.8.0.

  The effect was not uniform, because the collided records were mostly the harder
  BEC lures: judge clean recall was understated by 4 to 10 points, and
  `deepseek-v4-flash` paraphrase evasion moved from 27% to 16% while
  `qwen-2.5-7b` moved from 21% to 29%. `LLM_SCORECARD.md` and the README are
  regenerated and corrected.

  One claim does not survive: the best-recall judge is no longer the most
  paraphrase-evadable. `qwen-2.5-7b` now holds that position and has among the
  lowest recall.

- **Corrections are no longer deleted by regeneration.** The 2026-07-26
  calibration correction had been written into `LLM_SCORECARD.md` by hand and was
  silently removed the next time the script rebuilt the file. Both corrections now
  live in the generator and survive a rerun.

- `ruff` is pinned in the `dev` extra. An unpinned linter installs a newer default
  rule set in CI than the one used locally, which is how LureBench's CI went red
  on a green commit.

### Added
- A regression test that runs three distinct texts sharing one record id and
  asserts none are dropped. It fails against the previous id-keyed implementation.


## 0.2.0 — 2026-07-27

Adds a defense, exposes the detectors teams actually deploy, and publishes two
corpus-level scorecards. One entry below is a correction to a result this project
previously published.

### Added
- **`normalize` defense** (`lurescope/defense.py`) and a `defense` field on
  `/attack`, so one call shows the full loop: clean score, attacked score, then
  the score after input normalization. It strips invisible format characters,
  folds confusable Cyrillic and Greek back to Latin, and undoes in-word leet.
  `defense_recovered` and `defended_evaded` report whether the defense turned an
  evasion back into a catch.
- **Extended detectors.** `/capabilities` now advertises all six LureBench
  detectors rather than two. `llm-judge`, `openai-moderation`, `llama-guard-3`
  and `binoculars` are key- or dependency-gated; requesting one without its
  requirement returns a clear `400` naming what is missing, never a `500`.
- **Robustness scorecard** (`scripts/robustness_scorecard.py`, `SCORECARD.md`):
  detector by attack evasion rates over a corpus, raw and after the defense.
  Normalization drives homoglyph and zero-width evasion to 0% for both baseline
  detectors, leaves a 16% leet residue, and does nothing for whitespace.
- **Cross-model scorecard** (`scripts/llm_scorecard.py`, `LLM_SCORECARD.md`):
  the LLM-judge detector across five models via one OpenRouter key, against the
  four character attacks and an LLM paraphrase.
- The browser demo and the Hugging Face Space both gained the defense, with the
  JavaScript port verified byte-for-byte against Python across every attack.
- Community infrastructure: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, `CITATION.cff`, issue and PR templates, Dependabot, pre-commit.

### Changed
- README reframed around the three-move story: score, evade, defend.

### Fixed
- **Corrected the recall claim.** The cross-model scorecard originally read the
  judges' low clean recall as a capability trade-off, "immunity to character
  attacks bought with recall". Re-measured over the full 2,056-record LureBench
  `core/test` set with threshold-free metrics, that was wrong: the judges post an
  AUC of 0.89 to 0.94 and are simply miscalibrated at the 0.50 cutoff. Dropping
  `deepseek-v4-flash` to a 0.10 threshold lifts recall from 0.750 to 0.856 at a
  2.5% false-positive rate. The character-attack immunity and the paraphrase
  weakness both stand; the recall trade-off does not.

## 0.1.0 — 2026-07-13

Initial release.

### Added
- FastAPI service with `/health`, `/capabilities`, `/score`, `/attack`, and a
  self-contained browser demo at `/`.
- `tfidf-logreg` (bundled trained model) and `heuristic-v0` detectors, reusing
  LureBench so the served and benchmarked models cannot drift.
- Four character attacks and two LLM-driven attacks.
- Zero-backend Hugging Face Space that replicates scikit-learn's TfidfVectorizer
  transform in JavaScript, verified to match the Python service to four decimals.
- Dockerfile, CI across Python 3.9 / 3.11 / 3.12.
