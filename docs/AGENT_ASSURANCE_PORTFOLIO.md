# Combined agent assurance portfolio and continuous witnessing

LureScope combines four independently recomputable evidence surfaces:

1. LureBoundary monitor behavior;
2. LureCoverage telemetry completeness;
3. LureDelegation identity and capability handling; and
4. LureIR incident-response readiness.

The resulting portfolio preserves exact LureBench reports, binds them to the
current verified LureBoundary checkpoint, and optionally authenticates one
in-toto statement with ECDSA P-256 DSSE. It does not execute enforcement or make
a compliance, certification, safety, or authorization decision.

## Create the source evidence

From a LureBench checkout, create the boundary, coverage, delegation, and
incident-response reports. The full commands and response contracts are in the
[LureBench interoperability guide](https://github.com/immu4989/lurebench/blob/main/docs/AGENT_ASSURANCE_INTEROP.md).

Create and append the preregistered boundary bundle:

```bash
lurescope boundary init \
  --out ./boundary-bundle \
  --plan-id agent-release-1 \
  --evaluation boundary-evaluation.json \
  --system-id agent-platform \
  --model-id release-candidate \
  --authority-id security-lead

lurescope boundary append ./boundary-bundle boundary-evaluation.json \
  --evaluation-id release-candidate-1
```

For authenticated portfolio evidence, generate an external key and keep the
private key outside every evidence directory:

```bash
lurescope keygen \
  --private-out portfolio-private.pem \
  --public-out portfolio-public.pem
```

## Create and verify the combined portfolio

```bash
lurescope agent-assurance create \
  --out ./agent-assurance \
  --portfolio-id release-assurance-1 \
  --system-id agent-platform \
  --environment evaluation \
  --boundary-bundle ./boundary-bundle \
  --coverage-report coverage-evaluation.json \
  --delegation-report delegation-evaluation.json \
  --incident-response-report lureir-evaluation.json \
  --signer-public-key portfolio-public.pem \
  --signing-key portfolio-private.pem

lurescope agent-assurance verify ./agent-assurance \
  --boundary-bundle ./boundary-bundle \
  --portfolio-public-key portfolio-public.pem
```

Verification independently recomputes source-report aggregates and verdicts,
verifies the supplied boundary bundle, checks exact report bytes and SHA-256
bindings, recomputes overall status and the in-toto statement, and authenticates
the optional DSSE signature. Any failing source or boundary breach makes the
combined status `breach`.

The portfolio is deliberately not self-asserting: verification requires the
bound LureBoundary bundle. This prevents a copied summary from substituting for
the original append-only evidence.

```text
agent-assurance/
├── portfolio.json
├── evidence/
│   ├── coverage.json
│   ├── delegation.json
│   └── incident-response.json
├── checkpoint.statement.json
└── checkpoint.dsse.json       # signed portfolios only
```

## Export observation-only NIST OSCAL

```bash
lurescope agent-assurance export-oscal ./agent-assurance \
  --boundary-bundle ./boundary-bundle \
  --portfolio-public-key portfolio-public.pem \
  --assessment-plan-href urn:uuid:11111111-1111-4111-8111-111111111111 \
  --out agent-assurance-oscal.json
```

The OSCAL 1.2.2 Assessment Results document contains four `TEST` observations
and no findings. It references evidence by digest and identifies AC-6, AU-10,
CA-7, IR-4, and SI-4 as reviewed controls for which evidence may be relevant.
Selection is not a control-satisfaction determination, and the exporter does not
create or validate an Assessment Plan, SSP, POA&M, ATO, or authorization.

## BoundaryWatch: continuous scheduled probes

Preregister the fixed monitor family before collecting a batch:

```bash
lurescope boundary-watch init \
  --out ./boundary-watch \
  --plan-id scheduled-agent-boundary-v1 \
  --monitor-id vendor-monitor \
  --monitor-artifact-sha256 <image-id-sha256> \
  --coverage-manifest-id reference-agent-boundaries \
  --coverage-manifest-sha256 <manifest-sha256>
```

Append one completed, disjoint scheduled batch:

```bash
lurescope boundary-watch append ./boundary-watch \
  --batch-id 2026-08-29T12 \
  --coverage-report coverage-evaluation.json \
  --boundary-evaluation boundary-evaluation.json

lurescope boundary-watch verify ./boundary-watch
```

The adapter contributes only four aggregate counts: probe misses, benign false
alarms, lineage failures, and duplicate deliveries. It commits to the exact
coverage and boundary report bytes without retaining events. LureWatch applies a
predeclared mixture-Bernoulli e-process and Bonferroni control to the fixed
family; alarms are sticky. Each append must match the preregistered monitor,
optional monitor artifact, and optional coverage-manifest bindings. Reusing the
same source-report commitment under a different batch ID is rejected.

Anytime-valid interpretation requires disjoint scheduled synthetic probe batches
whose outcomes satisfy the plan assumptions. Do not submit dependent production
incidents as if they were independent trials. A model, monitor, policy,
controller, sensor route, population, or schedule change requires a new plan.

## Independent offline witnesses

Local hash chains cannot independently reveal deletion of their newest entries.
Export the current checkpoint to a separately controlled witness:

```bash
lurescope witness request ./boundary-bundle \
  --kind lureboundary \
  --request-id release-1-checkpoint \
  --out witness-request.json
```

On the independent witness system:

```bash
lurescope witness issue witness-request.json \
  --witness-id independent-auditor-a \
  --signing-key witness-a-private.pem \
  --out witness-a-receipt.json
```

Back on the verifier:

```bash
lurescope witness verify witness-request.json witness-a-receipt.json \
  --public-key witness-a-public.pem \
  --bundle ./boundary-bundle
```

For two independently controlled witnesses:

```bash
lurescope witness quorum witness-request.json \
  --receipt witness-a-receipt.json --public-key witness-a-public.pem \
  --receipt witness-b-receipt.json --public-key witness-b-public.pem \
  --minimum 2 \
  --bundle ./boundary-bundle
```

Quorum verification requires distinct witness IDs and public keys. The portable
receipt is an in-toto statement authenticated with DSSE and works offline. It is
aligned with SCITT's signed-statement and independent-receipt concepts, but is
not an RFC 9943 Transparency Service receipt or proof of registration in Rekor.
Organizations can submit the digest-bound statement to their chosen transparency
service without changing the local evidence format.

## Claims boundary

Signatures authenticate keys, not organizations, unless keys are distributed
through an independently trusted process. Sensor acknowledgements remain
operator-supplied evidence. Passing does not prove complete mediation, truthful
production telemetry, runtime enforcement, model safety, incident-response
staffing, compliance, certification, or authorization to operate.
