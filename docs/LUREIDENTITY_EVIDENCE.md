# Independently verified LureIdentity evidence

LureScope verifies that a LureBench LureIdentity report is a valid consequence
of its embedded authority graph, lifecycle events, receiver observations, and
acceptance contract. It does not import LureBench's verifier or trust the
producer's summary, per-event cut list, per-probe expectations, or verdict.

The evidence plane is metadata-only. It contains no SCIM payload, credentials,
tokens, prompts, commands, target locations, URLs, or model reasoning.

Before evaluating a run, LureScope can also independently recompile the exact
LureBench campaign. Its implementation imports no LureBench code. It derives
event sequence and digests, complete actor cuts, every unchanged
baseline-authorized actor outside each event cone, and every node/phase probe,
then requires the supplied plan to be byte-equivalent in content. The resulting
self-contained verification artifact embeds the campaign and binds both its
canonical digest and the independently derived plan digest.

LureArtifact adds a second independent compiler boundary. It requires every
active workload in that exact identity plan and binds each assigned node to the
reviewed model, container, policy, AI-BOM, and SLSA provenance metadata. See
the [independent artifact verification workflow](LUREARTIFACT_VERIFICATION.md).

## What is independently recomputed

The verifier reconstructs the directed acyclic group → human → agent → workload
graph, derives effective grants, and applies each lifecycle event independently
to the same baseline. It then checks:

- relationship endpoint kinds, active principals, canonical SPIFFE ID syntax,
  graph acyclicity, grant references, and duplicate authority;
- human deactivation, group-membership removal, delegation revocation, and
  workload retirement target semantics;
- source-event and normalized-event digests;
- exact cut-actor coverage, complete loss of each required actor's baseline
  authorization, and preservation of unrelated controls outside the event cone;
- pre-event and post-deadline probes for every cut authorization at every node,
  plus post-deadline probes for every required preserved authorization;
- invalid, first-valid, and duplicate event dispositions in receiver-time order;
- delivery coverage, p95/maximum convergence, and deadline misses;
- graph-derived access decisions, reason codes, stale post-deadline allows,
  collateral blocks, cut recall, pre-event availability, preserved availability,
  disposition accuracy, and the final verdict; and
- canonical plan, run, evaluation, manifest, checkpoint, and signature bindings.

The separate topology verifier recomputes the mapping from every identity plan
node to every mediation point in the exact embedded LurePermit Runtime profile.
It also checks each workload SPIFFE trust domain against that profile's allowlist.
Missing points, undeclared points, untrusted workload domains, cross-system
inputs, altered counts, and changed byte commitments fail closed. This is a
comparison of declarations, not network discovery or SVID authentication.

An alternate path that keeps a required agent or workload authorized is not a
partial pass: it makes the plan invalid. Unknown fields, duplicate JSON keys,
noncanonical evidence, missing required probes, and changed digests also fail
closed.

## Create and verify a signed bundle

Generate the source evaluation with LureBench:

```bash
lurebench identity-compose \
  --campaign conformance/lureidentity-campaign-v1/campaign.json \
  --out identity-plan.json
lurescope identity verify-campaign \
  conformance/lureidentity-campaign-v1/campaign.json identity-plan.json \
  --out identity-campaign-verification.json
lurebench identity-topology-audit \
  --plan identity-plan.json \
  --profile runtime-profile.json \
  --out identity-topology-audit.json

lurebench identity-otel-project \
  --plan identity-plan.json \
  --logs identity-otel-export.json \
  --run-id identity-production-run-1 \
  --out identity-otel-projection.json \
  --run-out identity-run.json
lurebench identity-eval \
  --plan identity-plan.json \
  --run identity-run.json \
  --out identity-evaluation.json
```

Set `RECEIVER_SHA256` to the lowercase SHA-256 digest of the reviewed receiver
artifact. Do not use a placeholder for a deployment decision. The runtime
profile must name the same system and should be approved before collection.

Create a P-256 key pair, then bind and authenticate the exact evaluation bytes:

```bash
lurescope keygen \
  --private-out identity-private.pem \
  --public-out identity-public.pem

lurescope identity create \
  --evaluation identity-evaluation.json \
  --bundle-id agent-identity-2026-09 \
  --environment evaluation \
  --signer-public-key identity-public.pem \
  --signing-key identity-private.pem \
  --out agent-identity.evidence

lurescope identity verify agent-identity.evidence \
  --public-key identity-public.pem
lurescope identity verify-topology identity-topology-audit.json
lurescope identity verify-otel identity-otel-projection.json
```

Before a deployment decision, produce and independently verify the exact
workload artifact inventory. Replace `artifact-observe` with separately
governed production collection; the command shown creates only a synthetic
passing fixture:

```bash
lurebench artifact-compose \
  --identity-plan identity-plan.json \
  --campaign conformance/lureartifact-v1/campaign.json \
  --out artifact-plan.json
lurebench artifact-observe \
  --plan artifact-plan.json --out artifact-observation.json
lurebench artifact-eval \
  --plan artifact-plan.json --observation artifact-observation.json \
  --out artifact-evaluation.json
lurescope artifact verify \
  identity-campaign-verification.json \
  conformance/lureartifact-v1/campaign.json \
  artifact-plan.json artifact-observation.json artifact-evaluation.json \
  --out artifact-verification.json
```

Obtain the public key through a separately trusted channel. A signature
authenticates possession of that key; it does not establish that the key belongs
to a directory, organization, human, agent, workload, receiver, or sensor.

The private, non-overwriting bundle contains:

```text
agent-identity.evidence/
├── bundle.json
├── checkpoint.statement.json
├── checkpoint.dsse.json
└── evidence/
    └── identity-evaluation.json
```

Unsigned bundles omit `checkpoint.dsse.json` and must be verified without a
public key. Directories are mode `0700` and files mode `0600` on POSIX. The
verifier rejects symlinks, unexpected files, noncanonical JSON, mismatched
digests, report tampering, missing keys for signed bundles, and keys supplied to
unsigned bundles.

## Make a fail-closed deployment decision

Record the `keyid:` printed by `lurescope keygen`, then bind the independently
verified identity/artifact compilation, topology, telemetry, and signed bundle to
separately governed release policy:

```bash
lurescope identity gate \
  identity-campaign-verification.json \
  artifact-verification.json \
  identity-topology-audit.json identity-otel-projection.json \
  agent-identity.evidence \
  --bundle-public-key identity-public.pem \
  --expected-bundle-key-id "$IDENTITY_KEY_ID" \
  --maximum-allowed-convergence-ms 500 \
  --minimum-run-generated-at 2026-09-03T00:00:00Z \
  --expected-system-id agent-platform \
  --expected-environment production \
  --expected-receiver-name identity-receiver \
  --expected-receiver-artifact-sha256 "$RECEIVER_SHA256" \
  --gate-id agent-identity-release-1 \
  --out identity-deployment-gate.json

lurescope identity verify-gate \
  identity-deployment-gate.json \
  identity-campaign-verification.json \
  artifact-verification.json \
  identity-topology-audit.json identity-otel-projection.json \
  agent-identity.evidence \
  --bundle-public-key identity-public.pem \
  --expected-bundle-key-id "$IDENTITY_KEY_ID" \
  --maximum-allowed-convergence-ms 500 \
  --minimum-run-generated-at 2026-09-03T00:00:00Z \
  --expected-system-id agent-platform \
  --expected-environment production \
  --expected-receiver-name identity-receiver \
  --expected-receiver-artifact-sha256 "$RECEIVER_SHA256"
```

The gate requires independently recompiled identity and artifact campaigns,
one authenticated and pinned bundle signer, independent recomputation of the
body-free telemetry projection, exact identity-plan agreement across both
compiler proofs, topology, projection, and evidence, and exact run agreement
between telemetry and signed evidence. It also binds exact artifact campaign,
plan, observation, and evaluation digests and requires the independently
recomputed workload-artifact verdict to pass. It
also requires a runtime profile dated no later than the run; complete declared
mediation-point and workload-domain coverage; zero accepted deadline misses,
stale allows, collateral blocks, or decision/reason errors; all required rates
fixed at 1.0; and a pre-event, propagation-window, and post-deadline probe for
every cut authorization at every node. The deployment deadline and freshness
floor come from external policy and are embedded in the result. A valid failing
gate exits `1`; invalid input or a binding failure exits `2`.

## Export federal and engineering evidence

Create observation-only OSCAL 1.2.2 assessment results:

```bash
lurescope identity export-oscal agent-identity.evidence \
  --public-key identity-public.pem \
  --assessment-plan-href urn:example:assessment-plan:agent-identity \
  --out identity.assessment-results.json
```

The export lists each independently recomputed lifecycle cut as a test
observation and references potentially relevant NIST SP 800-53 controls. It
intentionally contains no `findings` or control-satisfaction determination. The
project validates it against the official NIST OSCAL 1.2.2 assessment-results
schema.

Export machine-readable failures for code scanning and engineering workflows:

```bash
lurescope identity export-sarif agent-identity.evidence \
  --public-key identity-public.pem \
  --out identity.sarif.json
```

SARIF rules cover missed lifecycle deadlines, stale authorization, collateral
denial, event-disposition mismatch, and decision/reason mismatch. Results use
stable typed identifiers and hashes but no source locations or identity payloads.

## Browser inspection

Open the [GitHub Pages Evidence Explorer](https://immu4989.github.io/lurescope/#evidence)
and choose the campaign verification, artifact verification, evaluation, topology audit, bundle
manifest, deployment gate, OpenTelemetry projection, checkpoint statement, or
DSSE file. Parsing happens
locally in the tab. The
browser summarizes cuts, preservation, declared enforcement/trust-domain and
artifact coverage, release policy, and byte bindings but is not the normative verifier
and does not authenticate DSSE. Use `lurescope identity verify-campaign`,
`verify`, `verify-topology`, `verify-otel`, `artifact check`, and `verify-gate`
for those decisions.

## Standards boundary

The lifecycle profile is a narrow metadata projection of the SCIM core
`User.active` and `Group.members` attributes in [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643.html).
It is not a SCIM HTTP, PATCH, provisioning, authentication, authorization, or
interoperability test under [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644.html).
SPIFFE IDs are independently checked against the stable specification's bounded
trust-domain and path grammar. Workload fields require a non-root path and reject
userinfo, ports, percent encoding, query/fragment components, empty or relative
segments, Unicode, and oversized values. This still does not authenticate SVIDs,
the Workload API, bundle ownership, or private-key possession.

The February 2026 [NIST NCCoE agent identity and authorization concept
paper](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept)
motivates interoperable agent identity, authorization, delegation, lifecycle,
and audit. It is a draft concept paper, not a final standard. OSCAL export is a
portable observation format, not a NIST endorsement or compliance decision.
The graph is not an NGAC implementation or conformance claim.

## Claims boundary

A valid signed bundle proves that the exact submitted bytes were accepted by the
independent LureScope semantics and authenticated by the supplied key. It does
not prove that:

- the directory event, human, group, agent, workload, SPIFFE identity, receiver,
  enforcement point, clock, or sensor was authentic;
- every real authority path, grant, node, access path, or observation was
  declared and complete;
- OpenTelemetry records were complete, independently collected, causally
  linked, or transported over OTLP;
- the runtime profile discovered every real enforcement point or that an
  allowlisted SPIFFE trust domain issued or authenticated an SVID;
- the source-event digest corresponds to externally retained authentic bytes;
- workload artifact observations were complete or independently measured, or
  matching model, image, policy, AI-BOM, and provenance digests establish
  content safety, builder trust, or provenance authenticity;
- a SCIM operation was authorized, transported, or applied;
- a downstream policy engine or service enforced a block; or
- the system satisfies NIST guidance, zero trust, FedRAMP, FISMA, CMMC, SOC 2,
  ISO 27001, or another legal, regulatory, procurement, or assurance requirement.

These limitations are embedded in the bundle and checkpoint schemas and cannot
be removed while retaining a valid artifact.
