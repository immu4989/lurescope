# LureInvariant evidence and remediation verification

LureScope turns a LureBench LureInvariant evaluation into a private,
tamper-evident evidence bundle. It independently implements the graph and temporal
semantics rather than trusting reported metrics, binds the exact source bytes in
an in-toto statement, and can authenticate that statement with ECDSA P-256 DSSE.

The remediation comparator only compares the same system and plan identity. It
rejects changed invariants, acceptance thresholds, and source contracts, so an
“after” result cannot become effective merely because the test was weakened.

## Complete signed workflow

Generate the before and after reports with LureBench. A valid failing evaluation
returns exit `1`; continue to preserve that evidence.

```bash
lurebench invariant-eval \
  --plan /path/to/lurebench/examples/lureinvariant/before-plan.json \
  --observations /path/to/lurebench/examples/lureinvariant/before-observations.json \
  --out before-evaluation.json

lurebench invariant-eval \
  --plan /path/to/lurebench/examples/lureinvariant/after-plan.json \
  --observations /path/to/lurebench/examples/lureinvariant/after-observations.json \
  --out after-evaluation.json
```

Create a local P-256 keypair. Protect the private key according to your
organization's key-management policy; the reference command writes it mode
`0600` and never places it inside a bundle.

```bash
lurescope keygen \
  --private-out invariant-signing-private.pem \
  --public-out invariant-signing-public.pem
```

Create signed before and after bundles:

```bash
lurescope invariant create \
  --plan /path/to/lurebench/examples/lureinvariant/before-plan.json \
  --observations /path/to/lurebench/examples/lureinvariant/before-observations.json \
  --evaluation before-evaluation.json \
  --bundle-id release-before --environment evaluation \
  --signer-public-key invariant-signing-public.pem \
  --signing-key invariant-signing-private.pem \
  --out before-invariant.bundle

lurescope invariant create \
  --plan /path/to/lurebench/examples/lureinvariant/after-plan.json \
  --observations /path/to/lurebench/examples/lureinvariant/after-observations.json \
  --evaluation after-evaluation.json \
  --bundle-id release-after --environment evaluation \
  --signer-public-key invariant-signing-public.pem \
  --signing-key invariant-signing-private.pem \
  --out after-invariant.bundle
```

Verify each bundle and compare the remediation:

```bash
lurescope invariant verify before-invariant.bundle \
  --public-key invariant-signing-public.pem
lurescope invariant verify after-invariant.bundle \
  --public-key invariant-signing-public.pem

lurescope invariant compare before-invariant.bundle after-invariant.bundle \
  --comparison-id release-remediation \
  --before-public-key invariant-signing-public.pem \
  --after-public-key invariant-signing-public.pem \
  --out remediation-comparison.json

lurescope invariant verify-comparison remediation-comparison.json \
  before-invariant.bundle after-invariant.bundle \
  --before-public-key invariant-signing-public.pem \
  --after-public-key invariant-signing-public.pem
```

Exit `0` means a passing bundle or effective remediation, exit `1` means a valid
negative or inconclusive result, and exit `2` means invalid input or failed
verification.

## Bundle layout

```text
before-invariant.bundle/
├── bundle.json
├── checkpoint.statement.json
├── checkpoint.dsse.json
└── evidence/
    ├── plan.json
    ├── observations.json
    └── evaluation.json
```

Unsigned bundles omit `checkpoint.dsse.json`. Bundle directories are private;
files are mode `0600`, directories are mode `0700`, symbolic links and unexpected
files are rejected, and creation never overwrites an existing target.

## Remediation states

| State | Meaning |
|---|---|
| `effective` | A failing before bundle becomes a complete pass, at least one violation is resolved, and no violation persists or appears. |
| `ineffective` | Before violations persist without a new regression or evidence gap. |
| `regressed` | A new violation appears, or a passing before bundle becomes a failure. |
| `inconclusive` | After evidence is insufficient, or the before bundle contains no violation to demonstrate remediation against. |

The comparison binds both manifest and checkpoint digests plus a digest of the
unchanged invariant, acceptance, and source contract. Verification recomputes the
comparison from both original bundles.

## Public formats

- [`invariant-evidence-bundle-v1.schema.json`](../spec/invariant-evidence-bundle-v1.schema.json)
- [`invariant-evidence-checkpoint-v1.schema.json`](../spec/invariant-evidence-checkpoint-v1.schema.json)
- [`invariant-evidence-dsse-v1.schema.json`](../spec/invariant-evidence-dsse-v1.schema.json)
- [`invariant-remediation-comparison-v1.schema.json`](../spec/invariant-remediation-comparison-v1.schema.json)

The [browser Evidence Explorer](https://immu4989.github.io/lurescope/#evidence)
can explain these artifacts locally without uploading them. It does not
cryptographically authenticate signatures or recompute semantics; use the CLI
with a public key obtained through a separately trusted channel.

## Claims boundary

A passing bundle means violations were not observed within the declared,
complete evidence boundary. An effective comparison means the same checks moved
from observed violation to complete passing evidence. Neither proves inventory or
telemetry completeness, causality, universal unreachability, containment, safety,
compliance, certification, organizational identity, or authorization. LureScope
records evidence and never applies remediation or enforcement.
