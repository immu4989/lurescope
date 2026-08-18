# Pilot Gate: pre-register the decision before seeing the result

Pilot Gate turns a Shadow Inbox exercise into a reproducible, fail-closed decision
record. It does not choose deployment thresholds or certify a control. It answers a
narrower question:

> Did this exact control, on this pre-declared sample, collect enough reviewed
> evidence to meet the acceptance and analyst-workload limits written before the
> run?

The workflow is offline. The gate reads only a privacy-minimized Shadow Inbox bundle
and writes aggregate JSON and Markdown. It never connects to a mailbox or provider.

## Verify the machinery before designing a real pilot

From a source checkout, run the locked synthetic Golden Pilot:

```bash
uv run --frozen --extra dev python scripts/run_golden_pilot.py \
  --out ./golden-shadow-pilot
```

It verifies reviewed fixture and model digests, conservative deduplication, fixed
ground truth, all three strict schemas, privacy exclusions, private permissions, and
a real end-to-end `pass`. Read the resulting `golden-pilot-receipt.json` and
`pilot-gate.md`, then discard its thresholds. Five synthetic cases can verify the
software path but cannot support a production claim. See the
[Golden Pilot contract](../examples/shadow-pilot/README.md).

## 1. Approve the protocol first

Before creating the machine-readable plan, record these decisions in the pilot's
approved ticket or study protocol:

- sampling frame, inclusion/exclusion rules, pilot dates, and duplicate policy;
- who establishes ground truth and which trusted sources they may use;
- how reviewers remain blind to LureScope scores and routing decisions;
- minimum fraud and benign labels, allowed uncertain and processing-failure rates;
- recall, false-positive, and analyst-capacity limits;
- the exact detector, threshold or validated policy, software version, and owner;
- what a pass permits, who approves it, and the rollback and monitoring plan.

`full_blinded_review` is a declaration, not a technically enforced property. The
review workflow must keep `manifest.jsonl`, model scores, and risk tiers away from
ground-truth reviewers until labels are final. The gate cannot verify reviewer
independence, sampling quality, or label correctness.

## 2. Create and externally register the plan

This illustrative plan requires 400 processed messages, complete latest-label
coverage, at least 100 fraud and 300 benign labels, exact one-sided 95% bounds, and
explicit workload limits:

```bash
lurescope shadow plan --out ./pilot-plan.json \
  --plan-id august-soc-pilot \
  --detector tfidf-logreg --threshold 0.5 \
  --min-processed 400 \
  --min-fraud-labels 100 --min-benign-labels 300 \
  --max-uncertain-rate 0.02 --max-failure-rate 0.01 \
  --min-recall-lower 0.90 --max-fpr-upper 0.01 \
  --max-routed-rate 0.25 --max-routed-count 100 \
  --confidence 0.95
```

The command creates a mode-`0600` JSON file and refuses to overwrite an existing
plan. It prints the plan's SHA-256 digest. Before running LureScope, copy that digest
to an append-only ticket, signed approval, version-controlled protocol, transparency
log, or another system whose timestamp is independent of the pilot operator.

The local timestamp and SHA-256 binding are provenance, not authentication. Without
an external registration, someone who can rewrite the plan can also rewrite its
timestamp and recompute its digest.

The numbers above demonstrate the interface; they are not universal deployment
recommendations. At 95% one-sided confidence, 300 benign examples with zero false
positives produce an exact upper FPR bound of about 0.994%, while 100 fraud examples
with zero misses produce an exact recall lower bound of about 97.05%. Real sample
requirements must follow the organization's costs, prevalence, sampling design, and
risk tolerance.

When a LureBench policy is the control, set `--threshold` to that policy's threshold
and add `--policy-id POLICY_ID`. The subsequent run must load that policy and omit an
explicit request threshold. Pilot Gate checks every processed manifest record and
rejects a detector, model-artifact digest, resolved threshold, or policy ID that
differs from the plan.

## 3. Run the exact registered control

For the explicit-threshold example:

```bash
lurescope shadow run /approved/export --recursive \
  --detector tfidf-logreg --threshold 0.5 \
  --out ./shadow-pilot
```

The plan must predate `shadow-run.json`. A plan created after the run is rejected.
Every processed record's detector, bundled model-artifact SHA-256, resolved threshold,
and policy ID must match the registered control exactly.

## 4. Label the complete processed sample

Use the fixed-vocabulary append-only workflow described in
[Shadow Inbox](SHADOW_INBOX.md#record-analyst-decisions). Pilot Gate v1 requires a
latest label for every successfully processed case. `uncertain` is still available,
but its rate must stay within the registered limit and it is excluded from recall
and FPR denominators.

Keep the source-to-case mapping, raw exports, and reviewer records in the approved
restricted system. Do not copy subjects, addresses, message bodies, URLs, or
attachments into the plan or gate artifacts.

## 5. Evaluate the gate

```bash
lurescope shadow gate ./shadow-pilot --plan ./pilot-plan.json
```

The command atomically refreshes private `pilot-gate.json` and `pilot-gate.md` files
and stores the exact registered bytes as private `pilot-plan.json` inside the bundle.
Later label revisions automatically refresh the gate, so a decision cannot silently
remain stale after its evidence changes. The result binds the decision to SHA-256
digests of:

- the pre-registered plan;
- the privacy-minimized run manifest; and
- the complete append-only analyst-label log.

Exit codes are designed for automation:

| Exit | Meaning |
|---:|---|
| `0` | `pass`: all evidence and acceptance checks passed |
| `1` | `insufficient_evidence` or `fail`: do not promote the control |
| `2` | invalid/tampered artifact, post-run plan, control mismatch, or operational error |

## Decision logic

Evidence checks run first:

- processed, fraud-label, and benign-label minima;
- exactly 100% latest-label coverage;
- uncertain-label rate among processed messages;
- processing-failure rate among all unique attempted messages.

If any evidence check fails, the verdict is `insufficient_evidence`. Performance and
workload checks are marked `not_evaluable`; a favorable point estimate cannot turn
an underpowered or incomplete pilot into a pass.

Once evidence is sufficient, Pilot Gate evaluates:

- exact one-sided Clopper–Pearson lower bound for routing recall, where
  `high`/`review` are routed and `low` is not routed;
- exact one-sided Clopper–Pearson upper bound for routing FPR;
- routed-message rate and absolute routed-message count.

Any failed acceptance check produces `fail`; only an empty failed-check list produces
`pass`. Bounds use the plan's confidence level independently for each metric. A 95%
recall bound and a 95% FPR bound do **not** make the complete gate a simultaneous 95%
confidence statement.

## What a pass does not establish

A pass is evidence about one registered control and one reviewed sample. It is not:

- proof that the sample represents future traffic;
- protection against distribution or attacker shift;
- verification that labels or blinding were correct;
- a privacy, security, standards, or regulatory certification;
- authorization to quarantine, delete, or otherwise enforce on live mail.

Use a pass as one input to a human change-control decision. Continue secure email
gateway, authentication, sandboxing, reporting, monitoring, rollback, and periodic
revalidation controls.
