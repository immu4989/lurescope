# Independent LureMandate verification

LureScope independently verifies LureBench LureMandate evidence without
importing LureBench. It strictly parses the original plan, run, and evaluation;
recomputes every expected decision; and preserves the exact source bytes in a
self-contained private report.

## Verify

```bash
lurescope mandate verify \
  mandate-plan.json \
  mandate-run.json \
  mandate-evaluation.json \
  --verified-at 2026-09-05T15:18:00Z \
  --out mandate-verification.json

lurescope mandate check mandate-verification.json
```

Both commands return `0` for pass, `1` for a valid fail or inconclusive report,
and `2` for malformed, inconsistent, missing, oversized, symlinked, or otherwise
invalid evidence. Output is mode `0600` on POSIX and never overwritten.

## Independently verify a black-box conformance score

LureBench can remove transaction decisions, reason codes, expected answers,
and outcomes from an ordered challenge before it is sent to a proprietary
gateway. LureScope has a separate implementation of the scoring contract and
imports no LureBench code:

```bash
lurescope mandate verify-conformance \
  mandate-challenge.json \
  gateway-submission.json \
  mandate-conformance-score.json \
  --out mandate-conformance-verification.json

lurescope mandate check-conformance \
  mandate-conformance-verification.json
```

The verifier strictly reparses all three source documents, confirms that the
challenge contains only the input-side transaction shape, requires the
submission to cover every opaque case exactly once and in order, and rebuilds
the complete one-session run. It independently re-derives replay and rolling
budget state, every expected decision and reason, invalid allows, collateral
denials, exact-match counts, and the reason-code coverage table. It then
requires the producer score to match byte-for-byte at the parsed data-model
boundary.

The private mode-`0600` report embeds the exact source bytes and can be checked
offline. Canonical challenge and submission digests normalize insignificant
JSON formatting; the report's document digests still expose any source-byte
change. The public exhaustive vector has 25 cases and reaches all 21 v1
decision outcomes without changing the signed 16-case core evidence chain. A
pass covers only those cases: it neither authenticates the claimed external
engine nor proves that expected answers were impossible to infer, every numeric
or policy-composition boundary was exercised, omitted actions were discovered,
or mediation was complete.

## Authenticate the black-box gateway submission

The gateway can sign its canonical answer set before it leaves the gateway
boundary. The reference signer validates the challenge/submission relationship
first, requires a mode-`0600` P-256 private key on POSIX, emits exactly one DSSE
signature, and never overwrites output:

```bash
lurescope mandate sign-conformance \
  mandate-challenge.json \
  gateway-submission.json \
  --private-key gateway.private.pem \
  --out gateway-submission.dsse.json
```

Keep that private key outside the evidence directory. Obtain the gateway public
key and its lowercase SHA-256 SubjectPublicKeyInfo fingerprint through a
separately trusted configuration channel, then combine the signed submission
with the independent conformance verification:

```bash
lurescope mandate authenticate-conformance \
  mandate-conformance-verification.json \
  gateway-submission.dsse.json \
  --gateway-public-key gateway.public.pem \
  --expected-gateway-key-id "$PINNED_GATEWAY_KEY_SHA256" \
  --out authenticated-conformance-verification.json

lurescope mandate check-conformance-auth \
  authenticated-conformance-verification.json
```

The authenticated report embeds the exact independent verification bytes,
canonical DSSE envelope, and public key. `check-conformance-auth` therefore
reparses and recomputes the full score, rebinds the exact submitted answers,
reconstructs the key fingerprint, and re-authenticates the P-256 signature
offline. Substituting a key, payload, signature, score, digest, timestamp, or
summary fails closed.

This proves possession of the private key corresponding to the externally
pinned public key for the exact canonical submission. It does not prove that
the key belongs to the named gateway, that the gateway mediated runtime
actions, that the key is hardware-backed or unrevoked, or that conformance is a
compliance certification or deployment authorization. Production systems
should sign inside a protected KMS/HSM-backed gateway and manage the external
key-to-gateway mapping and revocation policy independently. The public vector
ships only `gateway-conformance.public.pem`; no gateway private key is
published.

## Independently verify pairwise input coverage

The exhaustive conformance profile reaches all 21 decision outcomes; the
separate pairwise profile asks a different question: did the test inputs cover
every binary value combination for every pair of 15 declared authority
factors? LureBench uses a 16-row orthogonal array and combines that measured
coverage with the ordinary gateway score. LureScope imports no LureBench code
and independently derives every factor from the embedded challenge, enumerates
all 105 factor pairs and 420 required interactions, and recomputes the pass
conjunction:

```bash
lurescope mandate verify-pairwise \
  gateway-pairwise-assurance.json \
  --out gateway-pairwise-verification.json

lurescope mandate check-pairwise \
  gateway-pairwise-verification.json
```

The private self-contained verification preserves the producer report's exact
bytes. It passes only if the gateway answered all 16 cases correctly and every
pair contains `00`, `01`, `10`, and `11`. The public source corpus and
independent report are in `conformance/luremandate-pairwise-v1/`.

This complements stateful outcome coverage; it does not replace it. Strength-2
binary coverage does not establish higher-order interactions, all feasible
production values, structural coverage of a proprietary implementation,
runtime mediation, safety, or certification. See NIST's research on
[combinatorial coverage](https://csrc.nist.gov/projects/automated-combinatorial-testing-for-software/combinatorial-coverage-measurement)
and [ordered sequence coverage](https://www.nist.gov/publications/ensuring-reliability-through-combinatorial-sequence-coverage).

## Independently verify counterfactual guard pairs

The counterfactual profile places a valid control immediately before one mutant
for each of the 20 denial reasons. LureScope independently rebuilds the 20
semantic-dimension vectors, identifies the exact changed dimensions, rechecks
both gateway answers and reasons, and preserves the producer report bytes:

```bash
lurescope mandate verify-counterfactual \
  gateway-counterfactual-assurance.json \
  --out gateway-counterfactual-verification.json

lurescope mandate check-counterfactual \
  gateway-counterfactual-verification.json
```

A public 40-case corpus and independent verification are in
`conformance/luremandate-counterfactual-v1/`. Eighteen guard pairs isolate one
declared semantic dimension. Approval-count and exact-replay pairs disclose
their dependency-coupled changes and are not counted as single-dimension
evidence.

This is contract-level counterfactual sensitivity, not formal MC/DC or proof of
source-code causality. It does not authenticate the gateway, establish higher
interaction or sequence coverage, discover omitted actions, prove complete
mediation, or certify a system. The distinction follows the FAA's discussion
of structural condition/decision coverage in
[Software Assurance Approaches, Considerations, and Limitations](https://www.faa.gov/sites/faa.gov/files/aircraft/air_cert/design_approvals/air_software/TC-15-57.pdf).

## Authenticate approval evidence

The base verifier proves deterministic agreement, not who approved. The
authenticated workflow closes a narrower, operationally useful gap: it verifies
that every unique approval claim is represented by one exact canonical payload
and carries a valid P-256 DSSE signature under the public key independently
pinned for that claimed approver.

First compile the payloads from the final plan and run:

```bash
lurebench mandate-statements \
  --plan mandate-plan.json \
  --run mandate-run.json \
  --out-dir mandate-statements
```

In production, the approval service should sign each statement at approval
time, preferably with protected non-exportable keys. The local signer is a
reference and interoperability tool:

```bash
lurescope mandate sign \
  mandate-statements/approval-01.statement.json \
  --private-key approver-operator.private.pem \
  --out mandate-evidence/approval-01.dsse.json
```

Repeat once per statement, preserving the exact filename stem. Keep private
keys outside the evidence directory and repository. Then authenticate the full
set using a public-key mapping obtained independently from the run:

```bash
lurescope mandate authenticate \
  mandate-plan.json \
  mandate-run.json \
  mandate-evaluation.json \
  mandate-evidence \
  --approver-key approver-operator=approver-operator.public.pem \
  --approver-key approver-mission=approver-mission.public.pem \
  --approver-key approver-security=approver-security.public.pem \
  --approver-key requester-a=requester-a.public.pem \
  --out mandate-authenticated-verification.json

lurescope mandate check-auth mandate-authenticated-verification.json
```

The verifier fails closed unless the evidence directory exactly covers every
unique approval, every DSSE payload is canonical and exactly matches the run,
every signature key ID matches the supplied key fingerprint, the mapping covers
exactly the claimed approvers, and every approver has a distinct key. That final
rule prevents one signing key from masquerading as two people to satisfy dual
control.

Authentication covers rejected and accepted claims alike. A valid signature on
a self-approval, expired approval, or approval for another intent proves only
who controls the mapped key; it does not make the policy decision valid.

`check-auth` re-authenticates the embedded plan, run, producer evaluation,
public keys, and signatures without external files. The report is therefore
portable, but the original external key-to-person mapping remains the reviewer's
trust input. The public reproducible vector is in
`conformance/luremandate-v1/`: four public keys, 18 DSSE envelopes, and one
self-contained authenticated verification. No private keys are published.

## Verify an OpenTelemetry projection

LureBench can project a strict body-free OpenTelemetry event export into a
LureMandate run. LureScope independently reconstructs the run from the embedded
plan and 67-record public export, then checks every digest and the complete
producer artifact:

```bash
lurescope mandate verify-otel mandate-otel-projection.json
```

The verifier requires one trace per transaction, unique trace/span contexts,
one intent, decision, and outcome event per transaction, all approval events,
exact event-to-lifecycle timestamp equality, a single receiver resource, and
the complete privacy and claims boundary. It rejects `Body`,
`InstrumentationScope`, free text, unknown attributes, missing lifecycle
events, trace splitting or merging, source-time rebinding, and digest changes.

`ObservedTimestamp` stays in the byte-bound export but never drives authority
chronology. Reordering records therefore preserves the projected run but changes
the exact source digest. This verifies the declared projection; it does not
prove telemetry completeness, delivery, clock synchronization, source
authentication, or enforcement.

## Authenticate the telemetry receiver

Projection validation does not identify who emitted the export. A receiver can
sign the validated canonical export using the dedicated DSSE payload type
`application/vnd.luremandate.otel-log-export+json`. The local signer is a
reference interoperability tool; production receivers should sign at export
finalization using a protected non-exportable key:

```bash
lurescope mandate sign-otel-export \
  mandate-plan.json \
  mandate-otel-export.json \
  --private-key receiver.private.pem \
  --out mandate-otel-export.dsse.json

lurescope mandate authenticate-otel \
  mandate-otel-projection.json \
  mandate-otel-export.dsse.json \
  --receiver-public-key receiver.public.pem \
  --expected-receiver-key-id "$EXPECTED_RECEIVER_KEY_SHA256" \
  --out mandate-authenticated-otel-projection.json

lurescope mandate check-otel-auth \
  mandate-authenticated-otel-projection.json
```

`authenticate-otel` requires the separately supplied key to match the expected
P-256 SPKI fingerprint, independently recomputes the projection, requires a
canonical one-signature DSSE envelope, and authenticates the exact canonical
export embedded by that projection. The report preserves the original
projection bytes, envelope bytes, and public key for offline re-authentication.
No private key is embedded or published.

This closes source substitution for the submitted export. It does not prove
that instrumentation was non-bypassable, that all events were delivered, that
clocks were synchronized, that the named receiver instance possessed the key,
or that an effect sensor reported a real-world outcome. The deployment gate
below independently pins the receiver key-to-deployment mapping.

## Bind all five sources into one deployment gate

Individually valid reports can still be unsafe to combine: an authenticated
approval report could refer to different source bytes, a telemetry projection
could describe another run, or an embedded public key could be valid but not
the key your organization authorized. The LureMandate deployment gate closes
those substitution paths for the submitted evidence.

First create a separately governed approver-key policy before the benchmark
plan is registered. It contains no private keys:

```json
{
  "schema": "https://github.com/immu4989/lurescope/spec/luremandate-approver-key-policy/v1",
  "schema_version": 1,
  "policy_id": "production-authority-keys",
  "created_at": "2026-09-05T14:58:00Z",
  "campaign_id": "authority-campaign-1",
  "environment": {
    "environment_id": "production",
    "tenant_id": "agency-tenant"
  },
  "approver_keys": [
    {
      "approver_id": "mission-owner",
      "public_key_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

The records must be sorted by `approver_id`, cover exactly the approvers in the
authenticated report, and assign a distinct P-256 public-key fingerprint to
each person. Store this policy in a protected repository or another
independently controlled configuration channel.

Create and independently recheck the gate:

```bash
lurescope mandate gate \
  mandate-verification.json \
  mandate-authenticated-verification.json \
  mandate-otel-projection.json \
  mandate-authenticated-otel-projection.json \
  approver-key-policy.json \
  --gate-id production-authority-gate \
  --minimum-run-started-at 2026-09-05T15:00:00Z \
  --expected-engine-id luremandate-reference \
  --expected-engine-version 1.0.0 \
  --expected-engine-artifact-sha256 "$EXPECTED_ENGINE_SHA256" \
  --expected-receiver-instance-id authority-gateway-instance-1 \
  --expected-receiver-key-id "$EXPECTED_RECEIVER_KEY_SHA256" \
  --out mandate-deployment-gate.json

lurescope mandate verify-gate \
  mandate-deployment-gate.json \
  mandate-verification.json \
  mandate-authenticated-verification.json \
  mandate-otel-projection.json \
  mandate-authenticated-otel-projection.json \
  approver-key-policy.json \
  --minimum-run-started-at 2026-09-05T15:00:00Z \
  --expected-engine-id luremandate-reference \
  --expected-engine-version 1.0.0 \
  --expected-engine-artifact-sha256 "$EXPECTED_ENGINE_SHA256" \
  --expected-receiver-instance-id authority-gateway-instance-1 \
  --expected-receiver-key-id "$EXPECTED_RECEIVER_KEY_SHA256"
```

The gate requires exact semantic/authenticated document-byte equality; exact
plan, run, and evaluation object equality with telemetry; matching canonical
digests; a key policy created no later than the plan; exact external key pins;
and the caller-supplied engine build, receiver instance, receiver signing key,
and freshness floor.
It records the SHA-256 digest of each source's actual bytes, not just its parsed
JSON. Verification therefore requires those same five files and the same
external policy values.

Gate output is mode `0600` on POSIX and is never overwritten. Both commands
return `0` for pass, `1` for a valid reproduced failure, and `2` for malformed,
tampered, mismatched, stale, unpinned, or otherwise invalid evidence. A pass is
a bounded evidence decision, not permission to deploy.

## Export federal and engineering evidence

After the gate exists, LureScope can translate its typed results into an OSCAL
1.2.2 Assessment Results document for assessment workflows and a SARIF 2.1.0
document for code-scanning and engineering workflows. These are not unchecked
format conversions: each command independently reverifies the gate, all five
exact source files, and every caller-supplied policy value before creating an
output file.

```bash
lurescope mandate export-oscal \
  mandate-deployment-gate.json \
  mandate-verification.json \
  mandate-authenticated-verification.json \
  mandate-otel-projection.json \
  mandate-authenticated-otel-projection.json \
  approver-key-policy.json \
  --assessment-plan-href urn:agency:assessment-plan:transaction-authority \
  --minimum-run-started-at 2026-09-05T15:00:00Z \
  --expected-engine-id luremandate-reference \
  --expected-engine-version 1.0.0 \
  --expected-engine-artifact-sha256 "$EXPECTED_ENGINE_SHA256" \
  --expected-receiver-instance-id authority-gateway-instance-1 \
  --expected-receiver-key-id "$EXPECTED_RECEIVER_KEY_SHA256" \
  --out mandate-assessment-results.oscal.json

lurescope mandate export-sarif \
  mandate-deployment-gate.json \
  mandate-verification.json \
  mandate-authenticated-verification.json \
  mandate-otel-projection.json \
  mandate-authenticated-otel-projection.json \
  approver-key-policy.json \
  --minimum-run-started-at 2026-09-05T15:00:00Z \
  --expected-engine-id luremandate-reference \
  --expected-engine-version 1.0.0 \
  --expected-engine-artifact-sha256 "$EXPECTED_ENGINE_SHA256" \
  --expected-receiver-instance-id authority-gateway-instance-1 \
  --expected-receiver-key-id "$EXPECTED_RECEIVER_KEY_SHA256" \
  --out mandate-gate.sarif.json
```

The OSCAL document contains one observation per gate check and deliberately no
`findings` or `risks`; its control selection means only that the evidence may
be relevant to those controls. The SARIF document contains one location-free
error result per failed check and an empty `results` array for a passing gate.
Its invocation records `executionSuccessful: true` whenever export and
verification succeeded, independently of the gate status, as required by the
SARIF execution semantics.

Both exports contain fixed descriptions, typed statuses, and cryptographic
digests only. They omit transaction, requester, approver, parameter, decision,
and event-body data. Output is mode `0600` on POSIX and never overwritten. The
public conformance examples are `oscal-assessment-results.json` and
`mandate-gate.sarif.json`; offline tests validate them against the official
NIST OSCAL 1.2.2 and OASIS SARIF 2.1.0 Errata 01 schemas.

For CI, pin the included composite action to a reviewed full commit SHA. Keep
the workflow and referenced policy files behind required code-owner review:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@FULL_COMMIT_SHA
    with:
      persist-credentials: false
  - uses: immu4989/lurescope/.github/actions/verify-luremandate-gate@LURESCOPE_FULL_COMMIT
    with:
      gate: evidence/mandate-deployment-gate.json
      semantic-verification: evidence/mandate-verification.json
      authenticated-verification: evidence/mandate-authenticated-verification.json
      otel-projection: evidence/mandate-otel-projection.json
      authenticated-otel-projection: evidence/mandate-authenticated-otel-projection.json
      approver-key-policy: policy/mandate-approver-keys.json
      minimum-run-started-at: "2026-09-05T15:00:00Z"
      expected-engine-id: luremandate-reference
      expected-engine-version: 1.0.0
      expected-engine-artifact-sha256: ${{ vars.MANDATE_ENGINE_SHA256 }}
      expected-receiver-instance-id: authority-gateway-instance-1
      expected-receiver-key-id: ${{ vars.MANDATE_RECEIVER_KEY_SHA256 }}
```

Do not replace either `FULL_COMMIT_SHA` placeholder with a mutable branch or
tag. The action passes user-controlled paths and policy values through
environment variables rather than interpolating them into its shell program.

## Independent checks

The verifier rebuilds:

1. exact canonical plan and intent SHA-256 bindings;
2. campaign tenant, run, agent, workload SPIFFE ID, and policy assignment;
3. distinct approver count and required-role coverage;
4. requester/approver separation of duties;
5. proposal, issuance, decision, expiry, and maximum-TTL chronology;
6. global approval-ID and nonce consumption;
7. per-transaction impact ceilings;
8. requester- or tenant-scoped rolling cumulative budgets;
9. invalid allows, collateral denials, and reason-code errors;
10. effects observed before a decision or after authority should have blocked;
11. unknown outcomes as inconclusive evidence.

It then verifies that its newly derived evaluation is identical to the producer
evaluation. A valid producer failure remains a valid verified failure; the
verifier does not turn successful parsing into a pass.

## Inspect locally in the browser

Open the [LureScope Evidence Explorer](https://immu4989.github.io/lurescope/#evidence)
and choose `mandate-verification.json`,
`mandate-authenticated-verification.json`, `mandate-otel-projection.json`,
`mandate-authenticated-otel-projection.json`, `approver-key-policy.json`, or
`mandate-deployment-gate.json`.
The browser shows decision and event coverage, authority bypasses, signature
coverage, distinct pinned keys, exact document digests, privacy boundaries, and
limitations without uploading the file.

The browser is an inspection surface and deliberately does not authenticate
signatures. Run `lurescope mandate check` for base evidence or
`lurescope mandate check-auth` for strict re-authentication. Run
`lurescope mandate verify-gate` with the exact five sources and independently
governed policy values for the release decision.

## Real-world mappings

| Environment | Example metadata-only authority policy |
|---|---|
| Government | mission owner + security reviewer before a high-impact control-plane change |
| Financial services | requester-independent dual approval plus rolling tenant transaction budget |
| Healthcare | care-operation owner + privacy/security role before a bulk agent action |
| Critical infrastructure | operator + safety reviewer before a consequential configuration transition |
| Frontier AI | deployment owner + security reviewer before model, policy, credential, or egress changes |
| SaaS platforms | customer admin + provider control role for cross-tenant or irreversible automation |

These are examples, not legal or compliance mappings. Organizations must define
their own roles, impact scale, thresholds, and evidence retention.

## Trust boundary

The base report proves deterministic agreement over exact submitted bytes and
does not authenticate an approver. The authenticated report verifies exact
approval metadata and P-256 DSSE signatures against reviewer-supplied public
keys. It does not prove that a key belongs to a person, validate directory roles,
establish human comprehension, hardware/KMS custody, revocation status, or
trusted time. Neither report authenticates the effect sensor, discovers omitted
transactions, proves complete runtime enforcement, confers legal authority, or
establishes compliance. Both reports embed internal metadata and should be
handled as private assurance evidence.

Use the [LureBench contract](https://github.com/immu4989/lurebench/blob/main/docs/LUREMANDATE.md)
for producer semantics and the same standards context: NIST agent identity and
authority guidance, NIST separation of duties, RFC 9396 structured transaction
authorization, and RFC 9449 request binding and replay defense.
