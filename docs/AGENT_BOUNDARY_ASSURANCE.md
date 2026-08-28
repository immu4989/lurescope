# LureBoundary: tamper-evident agent assurance

LureScope turns a LureBench boundary evaluation into a preregistered,
append-only evidence package. The package binds one system, model, suite,
monitor, optional policy and controller artifacts, acceptance thresholds,
response authority, and optional signing identity before evidence is appended.

It is an assurance and audit layer—not another runtime agent gateway. Existing
controllers remain responsible for authorization and enforcement. LureScope
records that human review or shutdown review is required; it never pauses a
run, revokes a credential, blocks a network request, or changes a control plane.

## End-to-end workflow

### 1. Produce a safe evaluation

From a LureBench source checkout:

```bash
lurebench boundary-eval --out boundary-evaluation.json
```

Review the report and its suite digest. The event vocabulary cannot contain
prompts, commands, payloads, credentials, hosts, URLs, paths, or reasoning.

### 2. Optionally create an external signing identity

```bash
lurescope keygen \
  --private-out boundary-private.pem \
  --public-out boundary-public.pem
```

The private key remains outside the evidence bundle. Distribute the public key
through an independently trusted channel; copying a key from beside the bundle
does not establish issuer identity.

### 3. Preregister the assurance plan

```bash
lurescope boundary init \
  --out ./agent-boundary-evidence \
  --plan-id frontier-evaluation-v1 \
  --evaluation boundary-evaluation.json \
  --system-id evaluation-platform-a \
  --environment evaluation \
  --model-id model-release-candidate \
  --model-sha256 <model-artifact-sha256> \
  --policy-id least-authority-v3 \
  --policy-sha256 <policy-artifact-sha256> \
  --controller-id runtime-controller-v2 \
  --controller-sha256 <controller-artifact-sha256> \
  --authority-id security-evaluation-lead \
  --critical-action evaluation_shutdown_review \
  --review-sla-minutes 15 \
  --signer-public-key boundary-public.pem \
  --oscal-ap-href urn:uuid:11111111-1111-4111-8111-111111111111
```

`--evaluation` supplies the exact suite, monitor, and threshold bindings. This
prevents a later append from silently substituting an easier suite, a different
monitor, or weaker acceptance criteria. Policy, controller, model, signature,
and OSCAL bindings are optional, but strongly recommended for reportable use.

### 4. Append an evaluation

```bash
lurescope boundary append ./agent-boundary-evidence \
  boundary-evaluation.json \
  --evaluation-id 2026-08-28-release-candidate-1 \
  --signing-key boundary-private.pem
```

Exit status `0` means the append succeeded and the bundle is still passing.
Exit status `1` means the append succeeded and a breach is now recorded. Exit
status `2` means validation, integrity, permissions, or authentication failed.

A breach is sticky. A later passing run remains useful evidence, but it cannot
rewrite the bundle status to pass. Recovery requires the registered human
authority to investigate and create a new plan when the model, policy,
controller, monitor, suite, or operating boundary changes.

### 5. Verify independently

```bash
lurescope boundary verify ./agent-boundary-evidence \
  --public-key boundary-public.pem
```

Verification recomputes report counts, recall, false-positive rate, category
accuracy, detection delay, verdict, plan bindings, entry decisions, sticky
status, every SHA-256 link, every in-toto checkpoint, and every DSSE signature.
It fails closed on unknown artifacts, unsafe permissions, symbolic links,
duplicate IDs or JSON keys, sequence gaps, key substitution, altered evidence,
noncanonical chain records, or mismatched payload bytes.

### 6. Export observation-only NIST OSCAL evidence

The plan must have registered `--oscal-ap-href`:

```bash
lurescope boundary export-oscal ./agent-boundary-evidence \
  --public-key boundary-public.pem \
  --out boundary-assessment-results.json
```

The export uses NIST OSCAL 1.2.2 Assessment Results and contains four `TEST`
observations: trajectory recall, benign false-positive rate, maximum detection
delay, and category accuracy. It includes no findings and maps evidence as
relevant—not determinative—to NIST SP 800-53 AC-6, CA-7, IR-4, and SI-4. The
output is validated in CI against a byte-locked official NIST schema.

The OSCAL artifact does not create an Assessment Plan or System Security Plan,
satisfy a control, grant an Authorization to Operate, certify a product, or
authorize autonomous enforcement.

## Evidence layout

```text
agent-boundary-evidence/
├── boundary-plan.json
├── evaluations/
│   └── 00000001.json
├── entries/
│   └── 00000001.json
└── checkpoints/
    ├── 00000001.statement.json
    └── 00000001.dsse.json       # signed plans only
```

Every directory is mode `0700` and every file is mode `0600` on POSIX. The
evaluation bytes are preserved exactly. The entry binds the plan, report,
predecessor, decision, response authority, and non-execution flag. The in-toto
statement binds the plan, evaluation, entry, and predecessor statement.

The chain detects mutation, insertion, and reordering. Like any local append-only
log, it cannot independently detect deletion of its final entries when an
attacker can replace the whole directory. Register the latest statement digest
in a separately controlled transparency, records, ticketing, or release system.

## Organizational use

| User | Defensible use |
|---|---|
| Frontier AI lab | Bind model/controller versions before an evaluation and preserve evidence that boundary-monitor criteria were or were not met. |
| Cloud or cybersecurity vendor | Publish a vendor-neutral report for a proprietary monitor without exposing prompts, credentials, or incident payloads. |
| Government program | Attach observation-only OSCAL evidence to an operator-owned assessment process while retaining human authorization. |
| Enterprise assurance team | Compare release candidates under one fixed suite and prevent a later pass from erasing an earlier boundary breach. |
| Independent evaluator | Authenticate exact evidence bytes and detect suite, monitor, threshold, or signer substitution. |

## Claims boundary

Authentication proves that the holder of the bound private key signed the exact
checkpoint bytes; trusted key distribution establishes who that signer is.
Neither proves that telemetry is complete or truthful. Passing the suite does
not prove deployment containment, complete mediation, sensor completeness,
monitor correctness, model safety, compliance, certification, or authorization.

The incident-derived benchmark rationale and strict protocol are documented in
the [LureBench guide](https://github.com/immu4989/lurebench/blob/main/docs/AGENT_BOUNDARY_ASSURANCE.md).
