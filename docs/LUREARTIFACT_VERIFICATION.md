# Independently verified workload-to-artifact authorization

LureScope independently verifies LureArtifact evidence without importing
LureBench. It rederives the LureIdentity plan, recompiles the LureArtifact
campaign, recomputes the complete workload/node deployment matrix, and
recalculates every producer finding and verdict.

This closes a deployment-evidence gap: an authorized SPIFFE workload can still
load the wrong model, image, policy, AI-BOM, or provenance statement. The
identity deployment gate therefore requires LureArtifact verification as a
fifth exact source.

## Produce and independently verify the artifacts

```bash
# Identity compiler proof
lurebench identity-compose \
  --campaign conformance/lureidentity-campaign-v1/campaign.json \
  --out identity-plan.json
lurescope identity verify-campaign \
  conformance/lureidentity-campaign-v1/campaign.json \
  identity-plan.json \
  --out identity-campaign-verification.json

# Artifact authorization and claimed deployment observation
lurebench artifact-compose \
  --identity-plan identity-plan.json \
  --campaign conformance/lureartifact-v1/campaign.json \
  --out artifact-plan.json
lurebench artifact-observe \
  --plan artifact-plan.json \
  --out artifact-observation.json
lurebench artifact-eval \
  --plan artifact-plan.json \
  --observation artifact-observation.json \
  --out artifact-evaluation.json

# Independent, self-contained verification
lurescope artifact verify \
  identity-campaign-verification.json \
  conformance/lureartifact-v1/campaign.json \
  artifact-plan.json artifact-observation.json artifact-evaluation.json \
  --out artifact-verification.json
lurescope artifact check artifact-verification.json
```

`artifact-observe` is a deterministic success fixture. A production evaluation
must replace it with claimed metadata from a separately governed collector.
Neither repository contains an adapter that claims trusted discovery.

The verification artifact embeds all five source objects and binds:

- the exact identity campaign verification and independently derived identity
  plan digest;
- the exact artifact campaign and independently derived artifact plan digest;
- the exact observation and producer evaluation digests;
- every active workload, canonical SPIFFE ID, and assigned node;
- 4 required artifact bindings and 3 SLSA provenance bindings per deployment;
- AI-BOM document and subject coverage; and
- all independently recomputed findings, checks, counts, and verdict.

The verifier accepts a valid failing producer evaluation and preserves its
`fail` status. Successful recomputation never turns failed deployment evidence
into a pass. Files are strict canonical JSON; new outputs are mode `0600` on
POSIX and are never overwritten.

## Add it to the identity deployment gate

Pass `artifact-verification.json` immediately after the identity campaign
verification:

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
```

The gate requires the artifact verifier to embed the exact same identity
campaign proof, identity-plan digest, and system as topology, telemetry, and
signed lifecycle evidence. It also includes the exact artifact campaign, plan,
observation, and evaluation digests in its contract. A failing artifact report
produces a valid failing gate; cross-campaign substitution is invalid input.

## Standards and security boundary

The plan uses an in-toto Statement v1 identifier and a bounded projection of
[SLSA Provenance v1](https://slsa.dev/spec/v1.1/provenance). AI-BOM labels cover
[SPDX 3.0.1 AI](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/) and
CycloneDX 1.6/1.7. LureScope validates the projection and exact digests, not the
complete external documents or their signatures.

No artifact bytes, credentials, prompts, model content, or model reasoning are
accepted. Package URLs and builder/build identifiers are treated only as
metadata; nothing is fetched, scanned, loaded, imported, executed, or
deserialized.

A pass does not prove collector completeness, SVID possession, artifact
safety, builder trust, provenance authenticity, AI-BOM completeness, supply
chain containment, compliance, certification, or deployment authorization.
Those controls remain external and must be separately governed.
