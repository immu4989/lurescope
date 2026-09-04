# Independent LureRecall verification

LureScope independently verifies a LureRecall incident-response evaluation
without importing LureBench. It revalidates the exact LureArtifact plan,
reconstructs the normalized dependency DAG, reapplies actionable VEX-like
status, rederives the transitive blast radius, rebuilds every deployment and
pre/quarantine/recovery probe, and recomputes the producer's findings, metrics,
checks, and verdict.

The verifier reads metadata only. It does not parse the source VEX, SPDX,
CycloneDX, GUAC, or provenance document and never opens model, container,
dataset, policy, replacement, or other artifact bytes.

## Verify the public vector

First use LureBench to create or collect the six exact source artifacts. The
bundled vector can be verified directly:

```bash
lurescope recall verify \
  conformance/lureartifact-v1/plan.json \
  conformance/lurerecall-v1/lineage.json \
  conformance/lurerecall-v1/advisory.json \
  conformance/lurerecall-v1/plan.json \
  conformance/lurerecall-v1/run.json \
  conformance/lurerecall-v1/evaluation.json \
  --out recall-verification.json

lurescope recall check recall-verification.json
```

Both commands independently recompute the report. Outputs are canonical JSON,
created mode `0600`, and never overwrite an existing path. Inputs are bounded,
strict duplicate-key/NaN-rejecting JSON; symbolic-link files are refused.

## What is bound

The self-contained verification embeds and SHA-256 binds:

1. the exact LureArtifact deployment plan;
2. the normalized lineage;
3. the VEX-like advisory projection;
4. the derived LureRecall plan;
5. the claimed response run; and
6. the producer evaluation.

Twelve explicit checks separate verifier integrity from deployment outcome. A
well-formed response failure remains a valid verification whose first eleven
recomputation checks pass and whose final
`recall_response_policy_satisfied` check fails. “The verifier reproduced the
failure” is never converted into “the response passed.”

The report preserves actionable/affected component counts, affected root,
workload, deployment, and node counts, delivery coverage and delay,
quarantine/recovery recall, unaffected preservation, compromised allows, wrong
replacements, collateral blocks, and the complete finding set.

## Trust boundary

A passing verification means two local implementations agree that the supplied
metadata satisfies the declared LureRecall contract. It does not prove:

- lineage completeness, relationship truth, or runtime reachability;
- advisory authenticity, issuer authority, status accuracy, or exploitability;
- source-document, artifact, builder, model, dataset, or replacement safety;
- advisory delivery, cache eviction, workload stop, replacement, or restoration;
- telemetry origin, completeness, clock quality, or causality; or
- containment, recovery, authorization, certification, or compliance.

Authenticate source documents and runtime evidence through independently
trusted keys, validate provenance and transparency evidence, inspect and scan
replacement bytes, and retain ordinary incident-command approval around this
verification.
