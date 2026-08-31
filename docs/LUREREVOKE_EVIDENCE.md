# Independently verified LureRevoke evidence

LureScope independently validates a LureBench LureRevoke evaluation and
recomputes its event digests, receiver dispositions, first valid delivery per
event/node pair, convergence distribution, access outcomes, aggregate metrics,
and verdict. It then preserves the exact canonical evaluation bytes in an
in-toto checkpoint that can be authenticated with ECDSA P-256 DSSE.

The verifier does not import `lurebench.revocation`. This gives organizations a
separate implementation for checking evidence produced by a receiver benchmark.

## End-to-end workflow

Create the evaluation with LureBench:

```bash
lurebench revocation-export --out revocation-plan.json
lurebench revocation-run --plan revocation-plan.json --out revocation-run.json
lurebench revocation-eval \
  --plan revocation-plan.json --run revocation-run.json \
  --out revocation-evaluation.json
```

Create a key and signed private bundle:

```bash
lurescope keygen \
  --private-out revoke-private.pem \
  --public-out revoke-public.pem

lurescope revoke create \
  --evaluation revocation-evaluation.json \
  --bundle-id agent-revocation-1 \
  --environment evaluation \
  --signer-public-key revoke-public.pem \
  --signing-key revoke-private.pem \
  --out agent-revocation-1.evidence
```

`keygen` prints the SHA-256 key ID. Record that value in a separately governed
trust policy as `REVOKE_SIGNER_KEY_ID`; do not recover it from the bundle under
review when enforcing a deployment gate.

Verify strict semantics, canonical bytes, and the signature using the public key
obtained through a separately trusted channel:

```bash
lurescope revoke verify agent-revocation-1.evidence \
  --public-key revoke-public.pem
```

Signed bundles cannot be verified without the external key. The key is never
copied into the bundle, and a substituted key is rejected.

## Prove remediation without moving the goalposts

Create a second bundle after changing the receiver implementation, then compare
the exact before/after evidence. The plan—including every node, event, probe,
and acceptance threshold—must be byte-equivalent. System identity, environment,
and receiver name must also remain fixed; only the receiver version/artifact and
observations may change. The after evaluation must be newer.

```bash
lurescope revoke compare \
  before-revocation.evidence after-revocation.evidence \
  --comparison-id receiver-remediation-1 \
  --before-public-key before-revoke-public.pem \
  --after-public-key after-revoke-public.pem \
  --out revocation-remediation.json

lurescope revoke verify-comparison \
  revocation-remediation.json \
  before-revocation.evidence after-revocation.evidence \
  --before-public-key before-revoke-public.pem \
  --after-public-key after-revoke-public.pem
```

The source bundles may be signed by different independently governed keys. A
signed source cannot be compared without its matching external public key.

| Status | Exact meaning |
|---|---|
| `effective` | A failing before evaluation passes after under the identical contract. |
| `regressed` | A passing before evaluation fails after. |
| `ineffective` | Both evaluations fail. |
| `unchanged_pass` | Both evaluations pass. |

The comparison lists resolved, persistent, and new failure identifiers across
late/missing deliveries, incorrect access outcomes, and signal-disposition
mismatches. It also reports after-minus-before deltas for coverage, convergence,
leakage, collateral denial, recall, pre-event availability, disposition
accuracy, and decision/reason errors. Positive deltas improve rates; negative
deltas improve convergence time and error counts. `null` means a convergence
delta was not comparable because one side had no valid delivery.

The comparison is canonical, mode `0600`, no-overwrite, and independently
recomputed from both bundles. It binds both manifests, checkpoints, runs, plan,
receiver versions/artifacts, source authentication states, and evaluation time.
It does not prove which change caused an outcome or that either implementation
was deployed.

## Obtain independent witness receipts

A standalone signed bundle proves control of its producer key, but its absence
from a later collection does not prove it never existed. Export the checkpoint
digest to one or more independently controlled witnesses:

```bash
lurescope witness request agent-revocation-1.evidence \
  --kind lurerevoke \
  --public-key revoke-public.pem \
  --request-id revocation-observation-1 \
  --out revoke-witness-request.json

# Run on the independent witness system.
lurescope witness issue revoke-witness-request.json \
  --witness-id external-auditor-a \
  --signing-key witness-a-private.pem \
  --out witness-a-receipt.json

lurescope witness verify \
  revoke-witness-request.json witness-a-receipt.json \
  --public-key witness-a-public.pem \
  --bundle agent-revocation-1.evidence \
  --bundle-public-key revoke-public.pem
```

LureRevoke witnessing refuses unsigned source bundles. The request contains only
the plan digest, checkpoint digest, status, sequence `1`, nonce, and declared
limitations—not the evaluation, subjects, events, observations, or receiver
artifact. `lurescope witness quorum` can require receipts from multiple distinct
witness IDs and keys.

This mechanism follows the accountability idea in
[RFC 9943 (SCITT Architecture)](https://www.rfc-editor.org/rfc/rfc9943.html),
which separates issuer-signed statements from independently verifiable
registration receipts. It is intentionally an offline DSSE observation receipt,
not a COSE Receipt, RFC 9942 VDS proof, RFC 9943 Transparency Service, public
append-only log, or proof of registration in an external service.

## Preserve an append-only revocation history

For repeated campaigns, a folder of individually valid bundles still permits
accidental reordering, replay, or selective removal. The local LureRevoke
registry admits only authenticated bundles for one fixed system, environment,
and receiver identity and commits each privacy-minimized registration record to
an authenticated tree head.

Initialize with a dedicated registry key (separate from bundle and witness
keys):

```bash
lurescope keygen \
  --private-out registry-private.pem \
  --public-out registry-public.pem

lurescope revoke registry-init \
  --registry-id agency-revocation-history \
  --system-id your-agent-platform \
  --environment production \
  --receiver-name your-caep-receiver \
  --signer-public-key registry-public.pem \
  --out revocation.registry
```

Verify and atomically append each signed bundle:

```bash
lurescope revoke registry-append \
  revocation.registry agent-revocation-1.evidence \
  --registry-public-key registry-public.pem \
  --registry-signing-key registry-private.pem \
  --bundle-public-key revoke-public.pem

lurescope revoke registry-verify revocation.registry \
  --registry-public-key registry-public.pem
```

Every entry contains only system/environment, receiver version and optional
artifact digest, bundle signer key ID, manifest/checkpoint/plan/run digests,
evaluation time, and pass/fail status. It contains no evaluation, subject/event
identifier, observation, token, credential, prompt, payload, or target.

The tree uses RFC 9162's domain separation—`SHA-256(0x00 || entry)` for leaves
and `SHA-256(0x01 || left || right)` for nodes—and every prefix produces a
P-256 DSSE-authenticated in-toto tree head. Verification recomputes the complete
Merkle history, entry chain, tree-head chain, signatures, admission policy,
strictly increasing evaluation time, and replay uniqueness.

An append is prepared in a private sibling directory and atomically renamed
into the committed `entries/` namespace only after every artifact is written,
file- and directory-flushed, and signature-verified. An abrupt pre-rename process failure can leave
an inert sibling directory for an operator to inspect or remove, but cannot
make the committed registry unverifiable.

Copy a tree-head statement and DSSE to independently retained storage, then
require it during later verification:

```bash
lurescope revoke registry-verify revocation.registry \
  --registry-public-key registry-public.pem \
  --trusted-head-statement retained/tree-head.statement.json \
  --trusted-head-dsse retained/tree-head.dsse.json
```

This detects a current registry that is shorter than, or conflicts with, the
retained prefix. Without an independently retained or witnessed head, a local
attacker who can replace the entire directory can still roll back its tail.

Export a portable proof when an auditor needs to verify one registration but
should not receive the complete history:

```bash
lurescope revoke registry-prove-inclusion revocation.registry \
  --sequence 17 \
  --registry-public-key registry-public.pem \
  --out registration-17.inclusion.json

lurescope revoke registry-verify-inclusion registration-17.inclusion.json \
  --registry-public-key registry-public.pem
```

The proof carries one privacy-minimized entry, the shortest RFC 9162 inclusion
path, registry policy, and the exact signed tree head. Verification independently
recomputes the leaf and path, validates all cross-field bindings, and
authenticates the embedded DSSE without requiring the other registry entries.
Use `--tree-size` while creating a proof to bind it to a specific historical
head. The proof establishes membership in that one authenticated tree; it does
not establish consistency with another head or global non-equivocation.

Prove that a newer signed tree is an append-only extension of an older signed
tree without disclosing any registration entry:

```bash
lurescope revoke registry-prove-consistency revocation.registry \
  --first-tree-size 10 \
  --second-tree-size 25 \
  --registry-public-key registry-public.pem \
  --out heads-10-to-25.consistency.json

lurescope revoke registry-verify-consistency heads-10-to-25.consistency.json \
  --registry-public-key registry-public.pem
```

The verifier authenticates both embedded tree heads and applies RFC 9162's
consistency algorithm to their shortest Merkle path. A valid result proves that
the first committed sequence is an exact prefix of the second. It does not rule
out a conflicting signed head that was never presented, so independent head
exchange or witness quorum remains necessary for broader non-equivocation.

When two observers exchange heads, authenticate and compare them directly:

```bash
lurescope revoke registry-compare-heads \
  --registry-config revocation.registry/registry.json \
  --first-statement observer-a/tree-head.statement.json \
  --first-dsse observer-a/tree-head.dsse.json \
  --second-statement observer-b/tree-head.statement.json \
  --second-dsse observer-b/tree-head.dsse.json \
  --registry-public-key registry-public.pem \
  --out head-comparison.json

lurescope revoke registry-verify-head-comparison head-comparison.json \
  --registry-public-key registry-public.pem
```

Two authenticated canonical statements at the same tree size are either
`identical` or `equivocation`; the latter returns exit `1` and preserves both
signed heads as portable evidence. Different sizes are reported as
`different_sizes_consistency_not_evaluated` and also return `1` until the
separate consistency proof is supplied. This detects only conflicts among heads
that observers actually exchange; it does not establish global
non-equivocation or attribute a conflict to operator intent versus key
compromise.

The registry borrows its Merkle construction from
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) and its accountability
goals from RFC 9943. It is a bounded local evidence registry—not a public CT
log, online Transparency Service, COSE Receipt, RFC 9942 VDS implementation,
proof of non-equivocation across observers, or standards-conformance claim.
The implementation tests every inclusion path and prefix-consistency proof for
tree sizes through 17 and separately pins path ordering to RFC 9162's named
seven-leaf example (including its four inclusion and three consistency paths).

## Independently verify topology scope

When LureBench emits a `revocation-topology-audit.json`, independently recompute
its exact plan/profile bindings and every mediation-point mapping in LureScope:

```bash
lurescope revoke verify-topology revocation-topology-audit.json
```

The verifier uses LureScope's independent LureRevoke plan and LurePermit Runtime
profile validators. It rejects changed input digests, cross-system inputs,
missing or unmapped counts, altered point/action/sensor/node mappings, replica
counts, coverage, verdict, noncanonical JSON, symlinks, unsafe permissions, and
oversized input. A valid failing audit exits `1`; malformed or tampered evidence
exits `2`.

This verifies the declared scope calculation only. It still cannot discover an
undeclared gateway or prove node deployment, reachability, fault-domain
independence, signal delivery, or access enforcement.

## Independently verify the OpenTelemetry projection

LureBench's strict body-free OpenTelemetry bridge embeds its exact plan, source
log projection, and resulting run. Recompute that transformation in LureScope
without importing LureBench:

```bash
lurescope revoke verify-otel receiver-otel.projection.json
```

The verifier independently rejects log bodies and unknown attributes, checks
receiver/resource/node/probe relationships, trace/span uniqueness, source-time
alignment and bounds, exact plan/source/run digests, privacy and clock
boundaries, canonical JSON, symlinks, unsafe permissions, and oversized input.
It uses OpenTelemetry `Timestamp` for declared benchmark timing and retains but
does not score `ObservedTimestamp`, because those fields can be measured by
different clocks. See the LureBench
[instrumentation and projection guide](https://github.com/immu4989/lurebench/blob/main/docs/LUREREVOKE_OPENTELEMETRY.md).

Successful recomputation proves transformation integrity only—not telemetry
completeness, clock synchronization, trace authenticity, causality, signal
delivery, or access enforcement.

## Bind all three sources into one deployment gate

A passing topology audit, a telemetry projection, and a signed evaluation can
each be valid while referring to different plans or runs. Create a strict gate
that refuses that cross-artifact substitution:

```bash
lurescope revoke gate \
  revocation-topology-audit.json \
  receiver-otel.projection.json \
  agent-revocation-1.evidence \
  --bundle-public-key revoke-public.pem \
  --expected-bundle-key-id "$REVOKE_SIGNER_KEY_ID" \
  --maximum-allowed-convergence-ms 500 \
  --minimum-run-generated-at 2026-08-30T00:00:00Z \
  --expected-system-id agency-agent-platform \
  --expected-environment production \
  --expected-receiver-name caep-receiver \
  --expected-receiver-artifact-sha256 "$RECEIVER_ARTIFACT_SHA256" \
  --gate-id production-revocation-gate \
  --out revocation-deployment-gate.json

lurescope revoke verify-gate \
  revocation-deployment-gate.json \
  revocation-topology-audit.json \
  receiver-otel.projection.json \
  agent-revocation-1.evidence \
  --bundle-public-key revoke-public.pem \
  --expected-bundle-key-id "$REVOKE_SIGNER_KEY_ID" \
  --maximum-allowed-convergence-ms 500 \
  --minimum-run-generated-at 2026-08-30T00:00:00Z \
  --expected-system-id agency-agent-platform \
  --expected-environment production \
  --expected-receiver-name caep-receiver \
  --expected-receiver-artifact-sha256 "$RECEIVER_ARTIFACT_SHA256"
```

The gate independently verifies all three sources and requires one exact plan
across them, one exact receiver run across telemetry and evidence, one system
and receiver, a complete declared topology, a passing convergence evaluation,
one authenticated bundle signer, and a runtime-topology profile declared no
later than the receiver run. Every event/node pair must also contain pre-event,
propagation-window, post-deadline, and unrelated-subject probes; a sparse plan
cannot become deployment evidence merely by lowering acceptance thresholds.
Availability-control subjects must be unrelated to every campaign event, not
merely to the event attached to that probe, preventing cross-event contamination.
The v1 gate also imposes a non-configurable acceptance floor: 100% delivery,
revoked-subject block recall, pre-event availability, and signal-disposition
accuracy, with zero deadline misses, post-deadline allows, and collateral
blocks. The convergence deadline remains an explicit deployment choice, but a
producer cannot obtain a gate pass by weakening any other threshold.
An external minimum run timestamp rejects stale-but-authentic campaigns while
keeping verification deterministic and independent of a verifier's wall clock.
The gate records canonical source digests so a
later verifier must receive the same bytes. A valid failing gate exits `1`;
tampered, malformed, mismatched, unsigned, or unauthenticated sources exit `2`.

This is a reproducible release-policy input, not a deployment authorization.
It does not prove topology discovery, telemetry completeness, clock sync,
causality, node authenticity, or that a deny decision prevented an operation.
The preregistration check compares declared timestamps and therefore still
requires external clock assurance.

### Enforce the gate in GitHub Actions

The repository includes a fail-closed composite action. Pin it to the full
40-character commit for the release you reviewed; do not use a mutable branch:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@YOUR_REVIEWED_FULL_COMMIT
  - uses: immu4989/lurescope/.github/actions/verify-lurerevoke-gate@LURESCOPE_FULL_COMMIT
    with:
      gate: evidence/revocation-deployment-gate.json
      topology-audit: evidence/revocation-topology-audit.json
      otel-projection: evidence/receiver-otel.projection.json
      evidence-bundle: evidence/agent-revocation-1.evidence
      bundle-public-key: trust/revoke-public.pem
      expected-bundle-key-id: YOUR_SEPARATELY_RECORDED_64_HEX_KEY_ID
      maximum-allowed-convergence-ms: "500"
      minimum-run-generated-at: "2026-08-30T00:00:00Z"
      expected-system-id: agency-agent-platform
      expected-environment: production
      expected-receiver-name: caep-receiver
      expected-receiver-artifact-sha256: YOUR_PINNED_64_HEX_ARTIFACT_DIGEST
```

The public key and expected key ID should come from a separately governed trust
source, not from the evidence bundle being checked. Pinning both prevents an
attacker from substituting a new bundle and its matching public key.
The convergence ceiling should likewise come from protected deployment policy,
not from the submitted plan.
Set the minimum run timestamp from the release window in the same protected
policy; do not derive it from the submitted evidence.
The expected system, environment, receiver name, and receiver artifact digest
must come from that policy as well. A missing receiver artifact digest is
rejected rather than treated as an unverifiable wildcard.
The gate proves that those caller-supplied values were enforced; it cannot prove
who approved them. Store the workflow, trust material, signer key ID, receiver
digest, and convergence ceiling in separately governed, access-controlled
configuration. Require code-owner review for changes to the workflow and gate
configuration, and protect the branch or deployment environment that consumes
the result. Otherwise, a contributor who can change both evidence and policy can
make a correctly verified gate answer the wrong authorization question.
User-controlled paths are passed through environment variables rather than
interpolated into shell source. The action
installs the verifier from its own pinned revision and fails the job on a
failing, malformed, mismatched, or unauthenticated gate.

## Bundle layout

```text
agent-revocation-1.evidence/
├── bundle.json
├── checkpoint.dsse.json
├── checkpoint.statement.json
└── evidence/
    └── revocation-evaluation.json
```

Directories are private (`0700`) and files are mode `0600` on POSIX. Inputs
must be bounded regular non-symlink files, JSON is strict and canonical, and
outputs never overwrite an existing path.

The manifest binds the system, plan, receiver implementation identity, optional
receiver artifact digest, exact evaluation and run digests, key identity,
status, and independently recomputed summary. The checkpoint binds the manifest
and evaluation as in-toto subjects. Changing either exact byte stream breaks
verification.

## What is independently recomputed

- the strict plan and run field allowlists and reference integrity;
- contiguous event sequence, CAEP event-type/attenuation semantics, opaque
  subjects, and exact event metadata digest;
- first digest-valid signal application for every event/node pair;
- whether each submitted signal disposition was `applied`, `duplicate`, or
  `invalid`;
- delivery coverage, maximum and nearest-rank p95 convergence, deadline misses,
  and every event/node delivery result;
- pre-event, propagation-window, post-application, post-deadline, and unrelated
  subject access semantics;
- post-deadline allows, revoked-subject block recall, collateral blocks,
  decision/reason errors, probe classifications, acceptance gates, and verdict.

The producer's summary, expected decisions, reasons, signal dispositions, and
verdict are never accepted as authority.

## Federal and developer exports

Export observation-only OSCAL 1.2.2 Assessment Results:

```bash
lurescope revoke export-oscal agent-revocation-1.evidence \
  --public-key revoke-public.pem \
  --assessment-plan-href urn:uuid:YOUR-ASSESSMENT-PLAN \
  --out revocation-assessment-results.json
```

The export is validated in tests against NIST's official OSCAL 1.2.2 JSON
schema. AC-2, AC-3, AC-6, AU-2, CA-7, IA-5, and SI-4 are selected only as
controls for which the observations may be relevant. The document contains no
findings or control-satisfaction determination.

Export failures for code-scanning and security-platform workflows:

```bash
lurescope revoke export-sarif agent-revocation-1.evidence \
  --public-key revoke-public.pem \
  --out revocation.sarif.json
```

SARIF rules distinguish deadline misses, revocation bypass, collateral denial,
and signal-disposition mismatch. Results contain opaque identifiers, timing,
and digests but no tokens, credentials, targets, prompts, payloads, URLs, or
reasoning.

## Standards relationship

The measured surface is motivated by:

- [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0-final.html)
- [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [NIST SP 800-207A](https://doi.org/10.6028/NIST.SP.800-207A)
- [NIST OSCAL 1.2.2](https://pages.nist.gov/OSCAL/)
- [RFC 9943: SCITT Architecture](https://www.rfc-editor.org/rfc/rfc9943.html)

Public machine-readable contracts:

- [`lurerevoke-evidence-bundle-v1.schema.json`](../spec/lurerevoke-evidence-bundle-v1.schema.json)
- [`lurerevoke-evidence-checkpoint-v1.schema.json`](../spec/lurerevoke-evidence-checkpoint-v1.schema.json)
- [`lurerevoke-evidence-dsse-v1.schema.json`](../spec/lurerevoke-evidence-dsse-v1.schema.json)
- [`lurerevoke-remediation-comparison-v1.schema.json`](../spec/lurerevoke-remediation-comparison-v1.schema.json)
- [`lurerevoke-registry-v1.schema.json`](../spec/lurerevoke-registry-v1.schema.json)
- [`lurerevoke-registry-entry-v1.schema.json`](../spec/lurerevoke-registry-entry-v1.schema.json)
- [`lurerevoke-registry-tree-head-v1.schema.json`](../spec/lurerevoke-registry-tree-head-v1.schema.json)
- [`lurerevoke-registry-inclusion-proof-v1.schema.json`](../spec/lurerevoke-registry-inclusion-proof-v1.schema.json)
- [`lurerevoke-registry-consistency-proof-v1.schema.json`](../spec/lurerevoke-registry-consistency-proof-v1.schema.json)
- [`lurerevoke-registry-head-comparison-v1.schema.json`](../spec/lurerevoke-registry-head-comparison-v1.schema.json)
- [`lurerevoke-deployment-gate-v1.schema.json`](../spec/lurerevoke-deployment-gate-v1.schema.json)

Those organizations do not endorse this project. LureRevoke projects selected
CAEP event identifiers into a smaller benchmark contract; it does not implement
or certify the SET or SSF wire protocols.

## Claims boundary

This workflow proves exact byte binding, strict contract validation,
independent metric recomputation, and—when enabled—control of an external
signing key. It does not prove:

- transmitter, receiver, node, observation, event, or clock authenticity;
- SET signature, issuer, audience, transport, or CAEP/SSF interoperability;
- that all production signals, nodes, accesses, or bypasses were submitted;
- that a block decision prevented the underlying operation;
- zero-trust maturity, control satisfaction, compliance, certification, or
  deployment authorization.

Use the bundle as one reproducible evidence input inside a governed assessment,
not as a substitute for operational validation.
