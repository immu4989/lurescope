# Changelog

## Unreleased

### Added
- Added independent LureChannel verification for metadata-only cross-run
  isolation evidence. LureScope imports no LureBench code while strictly
  reparsing exact plan, observation, and producer-evaluation bytes and
  rederiving run lifetimes, sensor topology and windows, positive delivery
  controls, active denied flows, unexpected paths, and post-termination
  residue. Its mode-0600 no-overwrite report embeds all three sources for
  complete offline `check` recomputation. Shared schemas and vectors, a
  verification schema, CLI workflow, Evidence Explorer support, an operator
  guide, and tamper tests are included. Sensor completeness remains an operator
  assertion, and a pass is not universal noninterference, containment, safety,
  compliance, certification, or deployment authorization.
- Added an independent LureBOM Twin verifier that reparses the original
  CycloneDX 1.7 and SPDX 3.0.1 bytes without importing LureBench, rederives the
  explicit component map, digest/PURL/class/artifact bindings, directed
  dependency parity, findings, metrics, and projection-loss paths, and requires
  exact reproduction of the producer evaluation. Its mode-0600 no-overwrite
  report embeds both source BOMs for complete offline `check` recomputation.
  Shared schemas and vectors, a private verification schema, CLI workflow,
  Evidence Explorer support, an operator guide, and adversarial tamper tests
  are included without claiming full source-standard conformance, issuer
  authenticity, BOM completeness, vulnerability/license analysis, compliance,
  or artifact safety.
- Added independent LureAttest verification for real provenance documents.
  LureScope imports no LureBench code while recompiling the exact trust plan,
  requiring a complete non-symlink evidence directory, pinning externally
  supplied ECDSA P-256 keys by SPKI digest, authenticating the original DSSE
  payload bytes, and verifying bounded in-toto Statement v1 / SLSA Provenance
  v1 subject, signer–builder, build-type, source-dependency, and canonical
  external-parameter expectations. Standard and URL-safe base64 are supported,
  and DSSE `keyid` remains only a hint. Three public schemas, a real signed
  three-envelope vector, private self-contained no-overwrite reports, key and
  commitment helper commands, documentation, packaging, and adversarial tests
  are included. The profile explicitly excludes Sigstore certificate,
  transparency-log and timestamp verification, build-platform certification,
  artifact safety, compliance, and authorization.
- Added independent LureRecall verification for transitive AI-artifact
  incident response. Without importing LureBench, LureScope reconstructs the
  bounded lineage DAG, reapplies actionable `affected` and
  `under_investigation` status, rederives every impacted component, artifact
  root, workload, node, shortest path, exact replacement, and
  pre/quarantine/recovery probe, then recomputes delivery, delay, quarantine,
  recovery, compromised-use, wrong-replacement, collateral, finding, check, and
  verdict output. The self-contained report binds all six exact sources and
  preserves a valid response failure as a valid failed verification. Six public
  schemas, a shared five-file golden vector, private no-overwrite CLI,
  packaging, an operator guide, browser-ready evidence, and adversarial tests
  are included without loading or authenticating source documents or artifact
  bytes.
- Added independent LureArtifact verification and a five-source LureIdentity
  deployment gate. Without importing LureBench, LureScope rederives the exact
  identity plan, recompiles complete active-workload artifact coverage, and
  recomputes claimed per-node model, container, policy, AI-BOM, and SLSA
  provenance findings. It detects substitutions, SPIFFE drift, unsafe model
  serialization, embedded/remote code, and unapproved builders without loading
  artifact bytes. A self-contained verification schema, shared five-file golden
  vector, private no-overwrite CLI, package data, operator guide, and
  adversarial tests are included. The deployment gate requires the exact same
  identity campaign proof and adds immutable artifact campaign, plan,
  observation, and evaluation digests; a valid failed artifact evaluation
  remains a valid failed gate.
- Added independent verification for LureIdentity campaign compilation.
  LureScope imports no LureBench code while re-deriving event sequence and
  digests, complete authorization cuts, every unchanged authorized actor outside
  each event cone, stable node/phase probes, and the bounded matrix. A shared
  golden conformance vector exercises both implementations, and a public,
  self-contained verification artifact binds the exact campaign and derived
  plan digests. The identity deployment gate now requires this fourth source,
  preventing a valid but manually under-specified plan from reaching a release
  decision. CLI, browser inspection, schemas, packaging, and adversarial
  plan/report substitution tests are included.
- Added independent LureIdentity evidence. LureScope revalidates the complete
  group → human → agent → workload DAG and independently recomputes baseline
  grants, event dependency cones, exact authorization cuts, exhaustive cut and
  preservation probe coverage, event dispositions, convergence, stale access,
  collateral denial, every metric, and the verdict without importing LureBench.
  Alternate authority paths, undeclared affected actors, preserved actors inside
  a cut cone, and partial per-node probe designs fail closed.
- Added `lurescope identity create`, `verify`, `export-oscal`, and
  `export-sarif`; optional P-256 DSSE-authenticated in-toto checkpoints; three
  strict public bundle schemas; official-schema-validated observation-only OSCAL
  1.2.2; location-free SARIF 2.1.0 failures; canonical private no-overwrite
  evidence; and browser Evidence Explorer summaries. A hand-computed
  interoperability vector avoids self-confirming producer/verifier test logic,
  and a full cross-repository run verifies LureBench's 279-probe, nine-point
  reference evaluation without claiming identity authenticity, SCIM
  interoperability, complete mediation, enforcement, or compliance.
- Added independent LureIdentity/LurePermit topology verification and a
  policy-pinned deployment gate. The topology audit binds exact plan and runtime
  profile bytes, requires every declared mediation point, rejects undeclared
  nodes, and checks each workload SPIFFE trust domain against the profile
  allowlist without claiming discovery or SVID authentication. The gate requires
  an externally pinned P-256 bundle signer, system, environment, receiver name
  and artifact digest, independently recompiled campaign, pre-run runtime
  profile, freshness floor, convergence
  ceiling, strict zero-failure/complete-rate thresholds, and pre/window/post cut
  probes at every node. It rejects cross-campaign rebinding and stale or
  wrong-build evidence. A public gate schema, CLI verification, browser summary,
  end-to-end integration test, and adversarial tests are included.
- Added an independent verifier for LureIdentity's strict body-free
  OpenTelemetry projection. It revalidates the exact event/resource/attribute
  vocabulary, privacy exclusions, timestamp and trace-context constraints,
  canonical plan-ordered output, and all plan/export/run SHA-256 bindings
  without importing LureBench. The deployment gate now requires this third
  source and rejects any plan, run, receiver, or timing rebinding across
  topology, telemetry, and authenticated evidence. Four upstream contract
  schemas are packaged for offline resolution; CLI, browser, and adversarial
  coverage are included without claiming telemetry completeness or causality.
- Replaced separate runtime and identity SPIFFE regexes with a shared local
  parser that independently enforces the stable SPIFFE ID trust-domain, URI,
  path-segment, ASCII, and length rules. Workload fields require non-root paths;
  ambiguous authority components, percent encoding, relative/empty segments,
  trailing slashes, and Unicode fail closed. Adversarial vectors match the
  producer without importing it; the shared versioned conformance corpus and
  public schema are packaged for offline consumers, while SVID, Workload API,
  trust-bundle, and possession claims remain explicitly external.
- Added independent LureRevoke evidence. LureScope revalidates CAEP-shaped
  event metadata, opaque subjects, receiver observations, signal digests,
  duplicate/invalid dispositions, access decisions, and every convergence,
  coverage, leakage, collateral-denial, and verdict metric without importing
  LureBench revocation code.
- Added `lurescope revoke create`, `verify`, `export-oscal`, and `export-sarif`;
  optional P-256 DSSE-authenticated in-toto checkpoints; three public schemas;
  official-schema-validated observation-only OSCAL 1.2.2; SARIF 2.1.0 failure
  export; exact canonical private bundles; and an operator guide with explicit
  signal, clock, observation, enforcement, and compliance boundaries.
- Added canonical `lurescope revoke compare` and `verify-comparison` workflows.
  They require the exact same plan and acceptance thresholds, system,
  environment, and receiver name; require newer after evidence; independently
  verify optional signatures from both source bundles; bind both manifests,
  checkpoints, and runs; classify resolved, persistent, and new
  delivery/probe/disposition failures; and expose exact after-minus-before
  metric deltas through a public schema and the browser Evidence Explorer.
- Extended offline checkpoint witnessing and distinct-key quorum verification
  to signed LureRevoke bundles. Witness requests bind only plan/checkpoint
  digests, status, sequence, and a nonce; unsigned revocation evidence is
  refused. The documentation maps this narrowly to RFC 9943 accountability
  concepts while explicitly disclaiming COSE Receipts, RFC 9942 VDS proofs,
  Transparency Service operation, public-log inclusion, or evidence authenticity.
- Added a signed append-only LureRevoke registry for repeated campaigns. It
  enforces one system/environment/receiver registration policy, admits only
  authenticated bundles, rejects digest replay and non-monotonic evaluation
  time, publishes entries atomically, chains entries and tree heads, computes
  RFC 9162 domain-separated SHA-256 Merkle roots incrementally, authenticates
  every prefix with P-256 DSSE, and detects rollback/conflict against an
  externally retained tree head. Five public schemas and CLI workflows are
  explicit that this is not an RFC 9943 service, RFC 9942 VDS, CT log, or proof
  of global non-equivocation.
- Added portable authenticated LureRevoke registry inclusion proofs. The
  generator exports one privacy-minimized entry, the shortest RFC 9162 audit
  path, registry policy, and exact signed tree head; the standalone verifier
  recomputes the path and authenticates DSSE without the rest of the registry.
  A self-contained public schema, CLI create/verify commands, browser
  inspection, exhaustive unbalanced-tree tests, and explicit consistency and
  non-equivocation limitations are included.
- Added portable authenticated registry consistency proofs between historical
  signed heads. The generator discloses no entries; the standalone verifier
  authenticates both DSSE heads and implements RFC 9162's prefix-consistency
  algorithm. Exhaustive tests cover every prefix pair through 17-leaf
  unbalanced trees, with schema, CLI, browser, tamper, and adjacent-chain checks.
- Added an independent interoperability regression that reproduces all four
  inclusion paths and all three consistency paths in RFC 9162's named
  seven-leaf example, preventing a mutually consistent generator/verifier pair
  from silently agreeing on non-standard proof ordering.
- Hardened registry crash recovery by staging append artifacts in a private
  sibling directory rather than inside the strict committed-entry namespace.
  An abrupt pre-rename process death can no longer poison verification of an
  otherwise valid registry with an orphan `.pending` directory.
- Added authenticated dual-head comparison for observer gossip. It classifies
  identical heads, preserves two valid same-size conflicting statements as
  portable equivocation evidence, and refuses to infer consistency for
  different sizes. Create/verify CLI commands, a public schema, browser
  inspection, distinct exit status, and real forked-registry tests are included.
- Added `lurescope revoke verify-topology`, an implementation-independent
  verifier for LureBench's LureRevoke/LurePermit scope audit, plus browser
  inspection. It revalidates both embedded contracts and exact digests and
  recomputes every point/action/sensor/node mapping, replica count, missing and
  unmapped set, coverage metric, and verdict without importing LureBench.
- Added `lurescope revoke verify-otel`, an independent verifier for LureBench's
  body-free OpenTelemetry-to-LureRevoke projection, plus browser inspection. It
  rejects bodies and unknown attributes and recomputes receiver/resource/node/
  probe bindings, trace-context uniqueness, timing boundaries, exact source and
  run digests, privacy exclusions, and canonical output without importing the
  producer implementation.
- Added `lurescope revoke gate` and `verify-gate`, a cross-artifact deployment
  decision that independently verifies and binds one topology audit, body-free
  OpenTelemetry projection, and authenticated evidence bundle to the same exact
  plan, run, system, and receiver. The strict public schema records every source
  digest and refuses unsigned, mismatched, stale, noncanonical, or altered
  inputs while retaining explicit deployment and enforcement limitations.
  Regression tests construct independently valid artifacts from different
  campaigns and receiver runs to prove cross-artifact substitution is rejected,
  rather than testing only malformed input. The gate also rejects a runtime
  topology first declared after the receiver run, while explicitly treating
  that chronology as a declared-clock assertion rather than trusted time.
  Gate creation and verification require an expected signer key ID in addition
  to the public-key file, preventing a substituted bundle and matching attacker
  key from becoming a new trust root by accident.
  A full-coverage invariant additionally requires pre-event,
  propagation-window, post-deadline, and unrelated-subject controls for every
  event/node pair, rejecting sparse plans even when their thresholds permit it.
  Availability controls must be globally unrelated to every campaign subject,
  so one event's revoked subject cannot masquerade as another event's control.
  The independent core plan validator enforces the same invariant before any
  evaluation, projection, bundle, or gate is accepted.
  A non-configurable deployment floor requires all four rate metrics to equal
  one and all three failure budgets to equal zero, preventing threshold
  dilution while leaving the declared convergence deadline deployment-specific.
  Gate creation and verification therefore require an external maximum allowed
  convergence value and reject a plan whose declared deadline exceeds it; the
  same protected-policy input is mandatory in the composite action.
  A mandatory external minimum run timestamp also rejects replay of
  stale-but-authentic campaigns without depending on the verifier's wall clock.
  External deployment policy now also pins system, environment, receiver name,
  and a mandatory receiver artifact digest, closing staging-to-production and
  wrong-build substitution paths.
- Added a reusable, fail-closed GitHub composite action for the deployment
  gate. It installs the verifier from the action's pinned source revision,
  accepts the trust key only as an external path, avoids direct user-input shell
  interpolation, and is regression-tested for immutable action dependencies.
- Added repository-wide CODEOWNERS coverage so protected branches can require
  maintainer review for code, schemas, workflows, and local actions. Executable
  workflow-security tests reject mutable action references, absent top-level
  permission boundaries, and `pull_request_target` triggers. Release uploads
  now fail on existing assets instead of silently replacing files under a tag,
  same-tag release runs are serialized, every checkout disables persisted Git
  credentials, and every job has a
  regression-enforced execution timeout. Python build backends now run in an
  unprivileged job; a separate job downloads the immutable artifact before
  receiving OIDC attestation and release-write authority.
- Added a repository-wide Markdown link regression so expanding operator and
  evidence guides cannot silently ship broken local navigation.
- Added the citation, Code of Conduct, and Security Policy to the LureScope
  source distribution, with a packaging regression preventing their omission.
- Added independent LurePermit runtime-mediation evidence. LureScope revalidates
  the profile, permit, exact requests, SPIFFE declarations, mediation mapping,
  chained receipts, policy identity, and sensor bindings, then recomputes all
  effective, bypassed, unmediated, unknown, and incomplete classifications,
  coverage rates, counts, and the verdict without importing LureBench runtime
  code.
- Added `lurescope runtime create`, `verify`, `compare`,
  `verify-comparison`, `export-oscal`, and `export-sarif`; optional ECDSA P-256
  DSSE checkpoints; same-contract remediation comparison; four public schemas;
  observation-only OSCAL 1.2.2 validated against NIST's official schema; SARIF
  2.1.0 for non-effective outcomes; browser Evidence Explorer support; and a
  complete operator guide.
- Added independently verified LurePermit/LureRange evidence bundles. LureScope
  revalidates the embedded permit and suite, independently derives all expected
  decisions, recomputes per-scenario results and aggregate metrics, preserves
  exact canonical evaluation bytes, and optionally authenticates an in-toto
  checkpoint with ECDSA P-256 DSSE.
- Added `lurescope range create`, `verify`, `compare`, and
  `verify-comparison`; strict fail-to-pass remediation comparison under an
  unchanged permit, suite, acceptance, system, and engine identity; four public
  schemas; browser Evidence Explorer support; and an end-to-end operator guide.
- Added LureInvariant evidence bundles that independently recompute LureBench
  graph and temporal semantics, preserve exact plan/observation/evaluation bytes,
  bind them in an in-toto checkpoint, and optionally authenticate canonical
  checkpoint bytes with ECDSA P-256 DSSE.
- Added strict before/after remediation comparison that requires the same system,
  plan identity, invariants, acceptance thresholds, and source contract; reports
  effective, ineffective, regressed, or inconclusive; and recomputes from both
  original bundles. Added `lurescope invariant`, four public schemas, local
  browser inspection, an end-to-end operator guide, and tamper tests.
- Added LureBoundary preregistration and append-only assurance for autonomous-agent
  boundary-monitor evaluations. Plans bind the system, environment, model, suite,
  monitor, optional policy/controller artifacts, acceptance thresholds, human
  response authority, optional OSCAL Assessment Plan, and signing identity.
- Added `lurescope boundary init`, `append`, `verify`, and `export-oscal`; exact
  LureBench report preservation; independently recomputed metrics and verdicts;
  sticky breach state; hash-chained in-toto checkpoints; optional ECDSA P-256
  DSSE; strict public plan/entry schemas; and an operator guide.
- Added observation-only NIST OSCAL 1.2.2 Assessment Results for trajectory
  recall, benign false-positive rate, maximum detection delay, and category
  accuracy, validated against the vendored official NIST schema without findings
  or control-satisfaction claims.
- Added combined agent-assurance portfolios that preserve exact LureCoverage,
  LureDelegation, and LureIR reports, bind them to the latest independently
  verified LureBoundary checkpoint, recompute source aggregates and verdicts,
  derive a fail-closed overall status, and optionally authenticate one in-toto
  statement with P-256 DSSE. Nested source fields use strict allowlists;
  coverage ordering and delay verdicts, delegation alert/category/delay fields,
  and LureIR containment recall are independently reconciled.
- Added observation-only OSCAL 1.2.2 portfolio export with four digest-bound
  `TEST` observations and no findings, validated against the vendored official
  NIST schema.
- Added BoundaryWatch, an adapter from completed, disjoint scheduled boundary
  and coverage runs into a preregistered four-monitor LureWatch family for probe
  misses, benign false alarms, lineage failures, and duplicate delivery. Entries
  retain aggregate counts and a commitment to source reports, never events.
  Appends enforce preregistered monitor/artifact/manifest bindings and reject a
  source commitment that has already been counted.
- Added offline independent checkpoint witnessing for LureBoundary and LureWatch:
  canonical requests, P-256 DSSE-authenticated in-toto receipts, current-bundle
  binding checks, and multi-witness quorum verification requiring distinct IDs
  and signing keys. The format is explicitly SCITT-aligned rather than falsely
  claiming RFC 9943 Transparency Service or Rekor inclusion.
- Added `lurescope agent-assurance`, `boundary-watch`, and `witness` workflows;
  strict portfolio, checkpoint, witness request, and witness receipt schemas;
  an end-to-end operator guide; private permissions; and signed, tamper, quorum,
  aggregate-only, and official-OSCAL tests.

### Security
- LureRange bundle verification rejects unsafe permissions, symlinks,
  unexpected files, duplicate keys, noncanonical JSON, unsupported fields,
  changed suite expectations, report or digest substitution, rewritten metrics
  or verdicts, weakened comparison contracts, signer/key substitution, and DSSE
  payload/signature mismatch. Typed inputs have no content, target, URL,
  credential-value, command, payload, or reasoning fields.
- Invariant bundle verification rejects duplicate keys, unknown fields and files,
  unsafe permissions, symlinks, noncanonical JSON, digest or report substitution,
  source-contract mismatch, altered semantics, signer/key substitution, and DSSE
  payload/signature mismatch. A remediation cannot pass by weakening its checks,
  and missing after-evidence is inconclusive.
- LureScope records and authenticates typed evidence only; it does not collect
  infrastructure, execute probes, apply remediation, enforce a boundary, or make
  compliance, certification, safety, or authorization claims.
- LureBoundary rejects unknown fields and artifacts, duplicate JSON keys and
  evaluation IDs, non-finite values, unsafe permissions, symbolic links, sequence
  gaps, report/metric/threshold substitution, noncanonical chain records,
  altered evidence, key substitution, and DSSE payload/signature mismatch.
- Response actions are immutable evidence fields with `action_executed: false`;
  LureScope never performs shutdown, revocation, network blocking, controller
  mutation, compliance determination, certification, or authorization.
- Combined portfolio verification requires the original bound LureBoundary
  bundle and rejects report-byte substitution, rewritten metrics or verdicts,
  unexpected files, symlinks, unsafe permissions, noncanonical records, signer
  substitution, and DSSE mismatch. Witness requests contain checkpoint digests
  only and no events, prompts, commands, payloads, credentials, or reasoning.

## 0.11.0 — 2026-08-27

### Added
- Added LureWatch, an anytime-valid post-deployment FPR/FNR monitor using a
  predeclared finite mixture of Bernoulli e-processes. Repeated inspection at
  submitted adjudicated-batch boundaries retains the declared per-monitor error
  guarantee, while Bonferroni allocation controls the fixed monitor family.
- Added `lurescope monitor init`, `append`, and `verify`; immutable detector,
  threshold, LureBench policy, sampling, labeling, risk-limit, and signer
  bindings; aggregate-only confusion-count entries; sticky breach evidence;
  hash-chained in-toto checkpoints; optional P-256 DSSE authentication; strict
  public plan, entry, and checkpoint schemas; and an operator/research guide.
- Added deterministic exact-path statistical tests, signed and unsigned
  end-to-end tests, generic slice-family support, schema validation, CLI exit-code
  coverage, privacy scans, private-permission checks, and adversarial chain,
  signature, plan, count, duplicate-batch, and sequence-gap tests.

### Security
- LureWatch fails closed on unknown fields, duplicate keys, non-finite values,
  non-canonical JSON, symlinks, unsafe permissions, unexpected artifacts, reused
  batch IDs, altered aggregate counts, non-recomputing statistics, chain gaps,
  signer substitution, and DSSE payload or signature mismatch. Signed plans bind
  one externally supplied P-256 trust key before the first outcome is observed.

### Changed
- Pinned the public Space build to the exact LureScope 0.10.0 PyPI wheel SHA-256
  and the hardened Compose deployment to the immutable multi-architecture 0.10.0
  GHCR index digest published by the protected release workflow.

## 0.10.0 — 2026-08-23

### Added
- Added `lurescope pilot run` and `pilot verify`, an atomic, installable,
  network-free synthetic operational workflow. It packages byte-locked fixtures,
  creates one pre-registered Pilot Gate, signs and authenticates a LureEval
  receipt with an in-memory-only P-256 key, emits NIST OSCAL 1.2.2 observations,
  writes local Splunk/Sentinel/OCSF exports, and produces a strict digest index.
- Added a no-write verifier that recomputes the Shadow report and Pilot Gate,
  validates every LureProof and fixed artifact binding, authenticates LureEval,
  checks OSCAL and SIEM cross-bindings, enforces private permissions, scans fixture
  privacy exclusions, and rejects persisted private keys or unexpected files.

### Security
- Added read-only Pilot Gate semantic verification so downstream LureEval and
  OSCAL artifacts can bind one exact gate instead of independently refreshing
  timestamps. Pilot plan/gate loading now rejects duplicate JSON keys,
  non-finite constants, malformed UTF-8, stale evidence, and semantic tampering.
- Operational pilot creation uses a private sibling staging directory, refuses
  overwrite and symlink targets, verifies the complete bundle before atomic
  rename, and removes only its own incomplete staging directory on failure.

### Changed
- Pinned the public Space build to the exact LureScope 0.9.0 PyPI wheel SHA-256
  and the hardened Compose deployment to the immutable multi-architecture 0.9.0
  GHCR index digest published by the protected release workflow.

## 0.9.0 — 2026-08-23

### Added
- Added `lurescope lureeval create` and `verify` for cross-organization,
  privacy-minimized operational evaluation receipts. Each in-toto Statement
  refreshes and binds the current Pilot Gate, manifest, latest-label log,
  registered plan, detector artifact, threshold, and optional policy bytes;
  recomputes exact metrics; suppresses small slices; and optionally authenticates
  canonical payload bytes with P-256 DSSE. LureBench owns the strict protocol,
  verifier, and compatible multi-site aggregator.
- Added `lurescope defender import` and `report` for an offline, paired comparison
  of Microsoft Defender `EmailEvents` and LureScope routing. The importer joins
  Exchange/Internet message identifiers to exported `.eml` evidence only in
  memory, persists random case IDs and four fixed native-attention signals, and
  reports matched-cohort confusion counts with exact one-sided recall/FPR bounds.
- Added a no-upload browser Evidence Explorer for LureEval receipts/aggregates,
  Pilot Gates, Defender and Shadow reports, LureProof, and combined SCuBA/drift
  statements. It explains metrics, byte bindings, privacy boundaries, and
  limitations while correctly distinguishing “DSSE signature present” from
  trusted-key authentication.
- Added strict Defender import, minimized-case, and paired-report schemas;
  cross-repository LureEval tests; browser explorer tests; official Microsoft
  export guidance; and complete operator/trust-boundary documentation.
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
- Defender imports reject oversized/malformed CSV, missing contract columns,
  symbolic links, duplicate headers, identifier-free rows, and one event row
  matching multiple unique messages before creating a bundle. Byte bindings and
  strict allowlists detect later case/import/manifest/label changes, and privacy
  tests scan every persisted file for tenant paths, subjects, addresses, message
  IDs, recipients, and content.
- LureEval output refuses stale Gate bindings, unbound policy IDs, small published
  slices, unsupported source fields, overwrites, and symbolic-link inputs.
  Browser inspection never upgrades unverified envelope bytes into an
  authentication claim.
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
