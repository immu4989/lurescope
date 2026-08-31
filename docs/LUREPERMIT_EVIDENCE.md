# Signed LurePermit and LureRange evidence

LureScope turns a LureBench LureRange evaluation into a private, tamper-evident
bundle. It independently validates the embedded LurePermit, derives every range
expectation from the typed request metadata, recomputes all per-scenario results
and aggregate metrics, and binds the exact canonical report bytes in an in-toto
checkpoint. The checkpoint can be authenticated with ECDSA P-256 DSSE.

This separation is intentional: LureBench runs the conformance measurement;
LureScope does not trust its reported expectations, metrics, or verdict.

## Complete signed workflow

Create the permit, reviewed range, and evaluation with LureBench:

```bash
lurebench permit-init --out permit.json
lurebench range-export --out range-suite.json
lurebench range-eval \
  --permit permit.json \
  --suite range-suite.json \
  --engine-id organization-gateway \
  --engine-version 2.3.1 \
  --engine-artifact-sha256 <64-hex-digest> \
  --out before-evaluation.json
```

For a private policy gateway, use LureBench's Python callable interface. The
gateway receives one typed request and the permit; scenario prose, labels, and
expectations remain in the harness. The gateway adapter must make a policy
decision only—it must not execute the requested operation.

Create a signing keypair. Keep the private key under your organization's key
management process and distribute the public key through a separately trusted
channel:

```bash
lurescope keygen \
  --private-out range-private.pem \
  --public-out range-public.pem
```

Create and verify the private bundle:

```bash
lurescope range create \
  --evaluation before-evaluation.json \
  --bundle-id organization-gateway-2.3.1 \
  --environment evaluation \
  --signer-public-key range-public.pem \
  --signing-key range-private.pem \
  --out before.range

lurescope range verify before.range \
  --public-key range-public.pem
```

Exit `0` means a passing bundle, exit `1` means a valid failing bundle, and exit
`2` means the evidence failed validation, authentication, or I/O checks.

## Bundle layout

```text
before.range/
├── bundle.json
├── checkpoint.statement.json
├── checkpoint.dsse.json
└── evidence/
    └── lurerange-evaluation.json
```

Unsigned bundles omit `checkpoint.dsse.json`. Directories are mode `0700` and
files are mode `0600` on POSIX. Creation refuses existing targets. Verification
rejects symbolic links, unsafe permissions, unexpected files, duplicate JSON
keys, noncanonical JSON, digest substitution, expectation or metric rewriting,
signer substitution, and DSSE payload/signature mismatch.

## Prove a remediation under the same contract

After changing the policy gateway, evaluate it again with the exact same permit
and suite, then create `after.range`. The engine identity must remain the same;
its version and artifact digest may change.

```bash
lurescope range compare before.range after.range \
  --comparison-id gateway-remediation-1 \
  --before-public-key range-public.pem \
  --after-public-key range-public.pem \
  --out range-remediation.json

lurescope range verify-comparison range-remediation.json \
  before.range after.range \
  --before-public-key range-public.pem \
  --after-public-key range-public.pem
```

| State | Meaning |
|---|---|
| `effective` | A failing before report passes after under the identical permit, suite, thresholds, and engine identity. |
| `regressed` | A passing before report fails after. |
| `ineffective` | Both reports fail. |
| `unchanged_pass` | Both reports pass; there was no failing conformance result to remediate. |

The comparison lists resolved, persistent, and newly failing scenario IDs. It
binds both source manifests and checkpoints. Verification recomputes the result
from both original bundles and refuses a changed permit, acceptance threshold,
range suite, system, permit identity, or engine identity.

## Public formats

- [`lurerange-evidence-bundle-v1.schema.json`](../spec/lurerange-evidence-bundle-v1.schema.json)
- [`lurerange-evidence-checkpoint-v1.schema.json`](../spec/lurerange-evidence-checkpoint-v1.schema.json)
- [`lurerange-evidence-dsse-v1.schema.json`](../spec/lurerange-evidence-dsse-v1.schema.json)
- [`lurerange-remediation-comparison-v1.schema.json`](../spec/lurerange-remediation-comparison-v1.schema.json)

The [browser Evidence Explorer](https://immu4989.github.io/lurescope/#evidence)
can explain these artifacts locally without uploading them. Browser inspection
does not authenticate signatures or recompute semantics; use the CLI and an
externally trusted public key for normative verification.

## Claims boundary

Independent recomputation establishes that the declared permit, suite
expectations, decision records, metrics, and verdict are internally consistent.
The bundle does not attest that the named external engine actually produced the
decision records. A signature authenticates a key, not an organization or
engine, unless an external trust process establishes that identity.

A pass does not prove runtime mediation, sensor completeness, workload or
network isolation, credential safety, containment, compliance, certification,
or deployment authorization. LureScope never executes a tool call, process,
network request, credential operation, stop, revocation, or remediation.
