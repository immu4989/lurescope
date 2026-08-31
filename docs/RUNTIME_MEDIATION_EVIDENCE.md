# Signed runtime-mediation evidence

LureScope independently validates a LureBench LurePermit runtime evaluation,
recomputes its profile and permit digests, strict request shapes, receipt chain,
sensor bindings, classifications, coverage metrics, and verdict, then preserves
the exact canonical evaluation bytes in an in-toto checkpoint. The checkpoint
can be authenticated with ECDSA P-256 DSSE.

The implementation intentionally does not import `lurebench.runtime`. This
separates evidence verification from the producer implementation. It does reuse
LureScope's independent LurePermit v1 request validator.

## End-to-end workflow

Create a healthy synthetic trace and evaluation with LureBench:

```bash
lurebench runtime-trace --out runtime-trace.json
lurebench runtime-eval \
  --trace runtime-trace.json \
  --out runtime-evaluation.json
```

Create a signing key and a private evidence bundle:

```bash
lurescope keygen \
  --private-out runtime-private.pem \
  --public-out runtime-public.pem

lurescope runtime create \
  --evaluation runtime-evaluation.json \
  --bundle-id agent-platform-runtime-1 \
  --environment evaluation \
  --signer-public-key runtime-public.pem \
  --signing-key runtime-private.pem \
  --out agent-platform-runtime-1.evidence
```

Verify exact bytes, all independent semantics, and the signature:

```bash
lurescope runtime verify agent-platform-runtime-1.evidence \
  --public-key runtime-public.pem
```

Files and directories are private (`0600` and `0700` on POSIX), inputs must be
regular non-symlink files, JSON is strict and canonical, and output paths are
never overwritten.

## Bundle contents

```text
agent-platform-runtime-1.evidence/
├── bundle.json
├── checkpoint.dsse.json
├── checkpoint.statement.json
└── evidence/
    └── runtime-evaluation.json
```

The manifest binds the system, runtime profile ID/version/digest, permit digest,
one policy engine identity, exact evaluation digest, trace digest, result, and
signer key ID. A bundle rejects traces whose receipts claim multiple policy
identities; mixed engines need separate evidence bundles.

The external public key is never copied into the bundle. Verification requires
the operator to supply a separately trusted key and rejects signer substitution.
A valid signature authenticates control of that key, not the policy engine,
sensor, software publisher, or organization unless separate governance
establishes that identity.

## What is independently recomputed

- the strict LurePermit and runtime-profile contracts;
- canonical SPIFFE IDs and declared trust-domain membership;
- identity-to-action, permit, and mediation-point bindings;
- typed MCP and OAuth/OIDC metadata shape (never token values);
- every receipt's exact request digest, decision binding, timestamp, and
  predecessor digest;
- unique correlation, receipt, and observation identifiers;
- sensor-to-request, mediation-point, effect-class, receipt, and timestamp
  bindings;
- required-sensor state and `effective`, `control_bypass`, `unmediated`,
  `unknown`, and `incomplete_effect` classifications;
- stateful expected decisions and reasons, including replay and sticky stop;
- decision/reason accuracy, request coverage, distinct mediation-point coverage,
  unknown rate, all counts, and the final acceptance verdict.

LureScope is deliberately stricter about observation semantics: the declared
effect class must correspond to the request action type.

## Compare remediation without moving the goalposts

Create a second bundle after changing the policy implementation, not the
evidence contract:

```bash
lurescope runtime compare \
  agent-platform-runtime-before.evidence \
  agent-platform-runtime-after.evidence \
  --comparison-id policy-remediation-1 \
  --before-public-key before-public.pem \
  --after-public-key after-public.pem \
  --out runtime-remediation.json

lurescope runtime verify-comparison \
  runtime-remediation.json \
  agent-platform-runtime-before.evidence \
  agent-platform-runtime-after.evidence \
  --before-public-key before-public.pem \
  --after-public-key after-public.pem
```

Comparison requires the same system and exact runtime profile, including the
permit and acceptance thresholds, plus the same policy engine ID. Policy version
and artifact digest may change. The after evaluation must be newer. Outcomes are
`effective`, `regressed`, `ineffective`, or `unchanged_pass`; resolved,
persistent, and new correlation IDs are independently derived.

An effective result is a same-contract fail-to-pass change in submitted
evidence. It does not prove the policy change caused the improvement or was
deployed.

## Export for federal and developer workflows

Export observation-only OSCAL 1.2.2 Assessment Results:

```bash
lurescope runtime export-oscal agent-platform-runtime-1.evidence \
  --public-key runtime-public.pem \
  --assessment-plan-href urn:uuid:YOUR-ASSESSMENT-PLAN \
  --out runtime-assessment-results.json
```

The output is validated in tests against NIST's official OSCAL 1.2.2 JSON
schema. It selects AC-3, AC-6, AU-2, AU-10, CA-7, IA-3, IR-4, and SI-4 only as
controls for which the evidence may be relevant. It contains observations and
no findings or control-satisfaction determination.

Export non-effective outcomes as SARIF 2.1.0:

```bash
lurescope runtime export-sarif agent-platform-runtime-1.evidence \
  --public-key runtime-public.pem \
  --out runtime-mediation.sarif.json
```

SARIF rules distinguish control bypass, unmediated effect, unknown evidence,
and an allowed action whose effect was not observed. Results contain typed
identifiers and digests but no file locations, prompts, actions, secrets,
credentials, tokens, URLs, payloads, or reasoning.

## Browser inspection

The no-upload [Evidence Explorer](https://immu4989.github.io/lurescope/#evidence)
summarizes runtime evaluations, bundle manifests, remediation comparisons, and
checkpoint/DSSE files locally in the browser. Browser inspection intentionally
does not claim cryptographic authentication or strict semantic verification;
use the CLI with a trusted public key for those claims.

## Claims boundary

This workflow proves exact byte binding, strict contract validation,
independent recomputation, and—when enabled—control of an external signing key.
It does not prove that every action traversed a mediation point, that declared
workload identities or sensors were authentic, that sensor coverage was
complete, that a named engine produced the receipts, or that a deployment is
contained, safe, compliant, certified, or authorized.
