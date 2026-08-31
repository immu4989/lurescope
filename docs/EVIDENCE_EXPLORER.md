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

For a deployment gate, the browser shows the declared and policy convergence
limits, minimum accepted run timestamp, deployment identity, receiver artifact,
and all source bindings. It does not authenticate the caller-supplied policy or
recompute any of the ten checks.
