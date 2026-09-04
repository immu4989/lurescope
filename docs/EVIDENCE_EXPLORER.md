# Browser Evidence Explorer

The [GitHub Pages lab](https://immu4989.github.io/lurescope/) can open operational
evidence locally in the browser. Choose **Evidence JSON** near the bottom of the
page to inspect:

- LureEval source receipts and compatible aggregates;
- Pilot Gate and Shadow Inbox reports;
- offline Microsoft Defender paired reports;
- LureProof statements and DSSE envelopes; and
- combined SCuBA assurance and drift-ledger statements;
- LureWatch aggregate entries and in-toto checkpoint/DSSE artifacts; and
- LureBoundary plans, LureBench evaluations, append-only entries, and
  in-toto checkpoint/DSSE artifacts;
- LureCoverage, LureDelegation, and LureIR evaluation reports;
- combined agent-assurance portfolios and in-toto checkpoints; and
- checkpoint witness requests and embedded DSSE receipts; and
- LureInvariant plans, evaluations, evidence-bundle manifests, in-toto
  checkpoint/DSSE artifacts, and strict remediation comparisons; and
- LureRange evaluations, evidence-bundle manifests, in-toto checkpoint/DSSE
  artifacts, and strict permit-remediation comparisons; and
- LurePermit runtime evaluations, runtime-mediation bundle manifests, in-toto
  checkpoint/DSSE artifacts, and strict runtime-remediation comparisons; and
- LureRevoke evaluations, signed evidence-bundle manifests, in-toto
  checkpoint/DSSE artifacts, strict same-plan remediation comparisons, and
  privacy-minimized registry configs, entries, signed Merkle tree heads, and
  portable inclusion and consistency proofs, dual-head split-view comparisons,
  runtime-topology coverage audits, body-free OpenTelemetry projections, and
  cross-artifact deployment gates.
- LureIdentity evaluations, signed evidence-bundle manifests, in-toto
  checkpoint/DSSE artifacts, runtime-topology/trust-domain audits, body-free
  OpenTelemetry projections, and five-source cross-artifact deployment gates;
- independent LureArtifact verification reports binding workload deployments to
  exact model, container, policy, SLSA provenance, and AI-BOM metadata; and
- independent LureRecall verification reports for transitive artifact blast
  radius, advisory delivery, quarantine, exact recovery, and collateral control;
- private LureAttest authenticated-provenance verification reports; and
- private LureBOM Twin reports that embed exact CycloneDX 1.7 and SPDX 3.0.1
  documents plus their common-denominator semantic reconciliation; and
- private LureChannel reports that bind exact plans, observation runs, and
  producer evaluations for allowed delivery, denied active flow, and
  post-termination residue tests.

The file is bounded to 8 MiB, read with the browser File API, parsed in the tab,
and never sent to the LureScope API or another origin. The explorer shows the
artifact type, decision state, core metrics, SHA-256 byte bindings, privacy
exclusions, and machine-readable limitations.

This is an explanation surface, not the normative verifier. It performs bounded
shape inspection and decodes an in-toto DSSE payload, but it does not accept a
public key or authenticate the signature. A badge saying “signature present”
means only that an envelope carries signature bytes. Use the corresponding CLI
verification command and a trusted public key before relying on issuer identity
or semantic validity.

For LureWatch, browser inspection also does not recompute the e-process, fixed
family correction, or predecessor chain. Use `lurescope monitor verify` for the
normative statistical and integrity check.

For LureBoundary, browser inspection does not recompute confusion counts,
metrics, detection delay, category accuracy, plan bindings, sticky breach state,
or checkpoint links. Use `lurescope boundary verify` with the externally trusted
public key when the plan is signed.

For combined portfolios and witnesses, the browser does not recompute source
reports, verify the bound LureBoundary bundle, authenticate embedded receipt
signatures, or establish a witness quorum. Use `lurescope agent-assurance verify`
and `lurescope witness verify`/`quorum` with independently trusted public keys.

For LureInvariant, the browser does not traverse the graph, evaluate temporal
bounds, establish source completeness, authenticate bundle signatures, or
recompute a remediation comparison. Use `lurescope invariant verify` and
`lurescope invariant verify-comparison` with public keys obtained through a
separately trusted channel. See the [complete evidence workflow and claims
boundary](LUREINVARIANT_EVIDENCE.md).

For LureRange, the browser does not independently derive policy expectations,
recompute metrics, authenticate a checkpoint, or establish that a named engine
produced the decisions. Use `lurescope range verify` and
`lurescope range verify-comparison` with public keys obtained through a
separately trusted channel. See the [complete LurePermit evidence workflow and
claims boundary](LUREPERMIT_EVIDENCE.md).

For runtime-mediation evidence, the browser displays request and mediation-point
coverage, bypass/unmediated/unknown counts, profile/permit/trace digests, policy
identity, and the claims boundary. It does not validate the receipt chain,
authenticate SPIFFE/OAuth declarations or sensors, recompute reconciliation, or
verify DSSE. Use `lurescope runtime verify` with a separately trusted public key.
See the [signed runtime evidence workflow](RUNTIME_MEDIATION_EVIDENCE.md).

For LureRevoke evidence, the browser displays delivery coverage, p95/maximum
convergence, deadline misses, post-deadline allows, collateral blocks, receiver
identity, exact plan/run/evaluation bindings, and before/after failure counts
and metric deltas. It does not independently derive signal dispositions or
access expectations, recompute a comparison from its source bundles, or
authenticate the signature, recompute a registry's Merkle history, detect
rollback without an external retained head, or establish transmitter, receiver,
clock, node, observation, or enforcement authenticity. Use the applicable
`lurescope revoke verify`, `verify-comparison`, `verify-topology`, `verify-otel`,
`verify-gate`, `registry-verify`, `registry-verify-inclusion`,
`registry-verify-consistency`, or `registry-verify-head-comparison` command. Gate
verification additionally requires the exact sources, external policy, and a
separately trusted bundle key. See the
[signed LureRevoke evidence workflow](LUREREVOKE_EVIDENCE.md).

For LureIdentity evidence, the browser displays the independently reported
authorization-cut count, cut recall, preservation rate, event delivery,
convergence, stale allows, collateral blocks, receiver identity, exact
plan/run/evaluation bindings, declared enforcement-point and workload-domain
coverage, campaign-derived cut/control/probe counts, body-free telemetry and
clock boundaries, workload-to-artifact verification, and deployment-gate
policy. It does not recompile the campaign, traverse the authority graph,
recompute topology, telemetry, artifact, or gate checks, authenticate directory
events, SVIDs, observations, builders, provenance, AI-BOMs, or signatures,
discover mediation points, or establish SCIM or OpenTelemetry interoperability.
Use `lurescope identity verify-campaign`, `verify`, `verify-topology`,
`verify-otel`, and `verify-gate` with exact sources and a public key obtained
through a separately trusted channel. See the [signed LureIdentity evidence
workflow](LUREIDENTITY_EVIDENCE.md).

For LureArtifact verification, the browser displays active workload,
deployment, artifact, provenance, AI-BOM, and finding counts plus all six exact
source digests. It does not independently recompile the identity or artifact
campaign, rederive either plan, load or inspect artifact bytes, validate package
URLs, authenticate observations or builders, verify SLSA signatures, or parse
the bound AI-BOM document. Use `lurescope artifact check` for the independent
local recomputation and apply separate artifact scanning, signature, builder,
license, and vulnerability controls. See the [LureArtifact verification
workflow and claims boundary](LUREARTIFACT_VERIFICATION.md).

For LureRecall verification, the browser displays actionable and affected
component, artifact-root, workload, deployment, and node counts; delivery
coverage and p95 delay; quarantine and recovery recall; unaffected preservation;
compromised allows; wrong replacements; collateral blocks; findings; and all
six source digests. It does not traverse the graph or recompute response
evidence, parse or authenticate the source advisory, establish lineage
completeness, load artifact bytes, or prove quarantine or restoration. Use
`lurescope recall check` for independent local recomputation and retain trusted
advisory, provenance, scanning, runtime-sensor, and incident-command controls.
See the [LureRecall verification workflow and claims
boundary](LURERECALL_VERIFICATION.md).

For LureAttest verification, the browser displays workload, attestation,
authenticated-envelope, expectation-match, policy SLSA-floor, pinned-key,
embedded-envelope, finding, and verifier-check counts plus the exact artifact
plan, trust policy, and LureAttest plan digests. The report contains full
provenance envelopes and public keys and must remain private. The browser does
not re-authenticate DSSE signatures, reparse SLSA statements, validate Sigstore
certificates/transparency/timestamps, certify a builder, open subject artifacts,
or establish safety or authorization. Use `lurescope attest check` for the
self-contained offline cryptographic and semantic recomputation. See the
[LureAttest authenticated provenance workflow](LUREATTEST_VERIFICATION.md).

For LureBOM Twin verification, the browser displays component and dependency
parity, artifact-subject coverage, projection-loss paths, findings, source-byte
reparse state, producer-reproduction state, and the three primary digests. The
report embeds both complete source BOM documents and must remain private. The
browser does not decode and reparse those bytes, reproduce mappings, validate
the complete SPDX or CycloneDX schemas, authenticate an issuer, fetch external
references, or establish inventory completeness, vulnerability/license state,
or artifact safety. Use `lurescope bom check` for the self-contained normative
recomputation. Reports larger than the explorer's 8 MiB input limit, up to the
CLI verifier's 32 MiB report limit, must be checked with the CLI. See the
[LureBOM verification workflow](LUREBOM_VERIFICATION.md).

For LureChannel verification, the browser displays pass, fail, and inconclusive
counts; allowed-delivery and isolation controls; required and complete sensor
windows; unauthorized and residual flows; findings; independent-reproduction
state; and all three exact source-byte digests. Raw canaries, customer content,
and secrets are excluded by contract, but internal run, tenant,
isolation-domain, channel, and sensor identifiers make the report private. The
browser does not decode and reparse the embedded sources, recompute results,
authenticate sensor assertions, discover unknown paths, or establish universal
noninterference or containment. Use `lurescope channel check` for self-contained
normative recomputation. Reports larger than the explorer's 8 MiB input limit,
up to the CLI verifier's 32 MiB report limit, must be checked with the CLI. See
the [LureChannel verification workflow](LURECHANNEL_VERIFICATION.md).

For a deployment gate, the browser shows the declared and policy convergence
limits, minimum accepted run timestamp, deployment identity, receiver artifact,
and all source bindings. It does not authenticate the caller-supplied policy or
recompute the ten LureRevoke or thirteen LureIdentity checks. LureIdentity gate
verification requires the exact campaign, artifact, topology, telemetry, and
signed lifecycle-evidence sources.
