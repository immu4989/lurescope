# Deploy a risk-controlled decision policy

LureScope can serve two kinds of LureBench threshold artifact:

- schema v1 records a threshold selected against an empirical validation
  objective; and
- schema v2 carries finite-sample evidence that a requested population
  false-positive rate is controlled at a declared confidence level.

The distinction is visible to operators and API clients. LureScope never relabels
a v1 point estimate as statistical assurance.

## 1. Create the policy in LureBench

Use a frozen detector and a validation set that was not used to train or choose
that detector:

```bash
lurebench calibrate \
  --validation validation.jsonl \
  --detector tfidf-logreg \
  --model-path models/tfidf-logreg-fraud.joblib \
  --objective risk_controlled_fpr \
  --target-fpr 0.01 \
  --confidence 0.95 \
  --threshold-grid-size 1001 \
  --out policies/tfidf-1pct-fpr-95.json
```

LureBench exits without writing a policy if the evidence is insufficient. Read
the full [method and assumptions](https://github.com/immu4989/lurebench/blob/main/docs/RISK_CONTROL.md).

## 2. Validate it offline

```bash
lurescope policy policies/tfidf-1pct-fpr-95.json
```

LureScope rejects unknown fields, unsupported schema or methods, malformed
provenance, impossible counts, and risk statistics that do not recompute exactly.
In particular, it independently recalculates the binomial p-value and one-sided
confidence bound from the exported false-positive count.
The canonical schema is vendored at
[`spec/decision-policy-v2.schema.json`](../spec/decision-policy-v2.schema.json)
for offline tooling.

This consistency check is not issuer authentication. The SHA-256 fields support
reproduction and change detection when compared to trusted records; sign the
artifact in your normal release or attestation system if policy origin matters.

## 3. Configure the service

```bash
export LURESCOPE_POLICY_PATH=/absolute/path/to/policies/tfidf-1pct-fpr-95.json
uvicorn lurescope.app:app
```

When a `/score` request omits `threshold` and its detector matches the policy,
LureScope uses the policy threshold and returns its `policy_id`. An explicit
request threshold always overrides the configured policy and therefore does not
inherit its assurance. A request for another detector also falls back to that
detector's default threshold.

## 4. Inspect production configuration

```bash
curl -s http://127.0.0.1:8000/policy
```

The response exposes no message content or credentials. It reports:

- `assurance_status`: `finite_sample_fpr_control`,
  `empirical_validation_only`, or `none`;
- policy and detector identity, threshold, target, and validation digests;
- validation-negative and false-positive counts, exact p-value, confidence, and
  upper bound for schema v2;
- empirical validation recall as a utility point estimate, without presenting it
  as a recall guarantee; and
- the assumptions that limit interpretation.

This endpoint is suitable for readiness checks and deployment inventories, but
it is intentionally not folded into `/health`: liveness and statistical fitness
are different operational questions.

## 5. Monitor and renew

The finite-sample statement assumes representative independent validation
negatives. It does not cover population shift, bad labels, a changed model or
prompt, provider model aliases, preprocessing changes, or adversarial robustness.
Track those changes, collect newly adjudicated benign traffic, and issue a new
policy after a material change. Continue to run LureBench robustness and slice
evaluations; a controlled aggregate FPR can still hide a weak language, channel,
or population segment.
