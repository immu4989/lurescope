# Deploy a risk-controlled decision policy

LureScope can serve these LureBench threshold artifacts:

- schema v1 records a threshold selected against an empirical validation
  objective; and
- schema v2 carries finite-sample evidence that a requested population
  false-positive rate is controlled at a declared confidence level; and
- source-branch schema v3 adds a checked portable configuration binding to
  either kind of evidence. Use the [bound calibration workflow](BOUND_POLICY.md)
  for the actual bundled serving model instead of transferring a joblib policy.

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
provenance, impossible counts, and risk statistics that do not match recomputation
within the loader's numerical consistency tolerance.
That tolerance never increases the confidence or FPR acceptance limit: both
reported and recomputed p-values/bounds must satisfy the unrelaxed criteria.
Borderline artifacts admitted by older tolerance checks may be rejected. Preserve
the original evidence and review or recalibrate; do not edit counts or assurances
to make an artifact pass. Validation does not rewrite the file.
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

On this source branch, you can additionally set `LURESCOPE_POLICY_SHA256` to the
64-character lowercase digest of policy bytes approved through your trusted
release process. A changed file then fails closed; obtaining a hash from the
same untrusted source as the file does not authenticate its author. A pin without
`LURESCOPE_POLICY_PATH` is a configuration error.

The loader checks the current file on each use, rejects symlinks, duplicate JSON
keys and files over 64 KiB, and caches expensive validation by exact content rather
than by pathname. Unpinned changes are revalidated, not silently ignored. Replace
files atomically during deployment; concurrent in-place changes may be rejected.
This serving profile supports up to 10 million validation records and verifies
that a risk-controlled threshold belongs to its declared grid. These are local
resource/consistency checks, not authentication or re-evaluation of unseen data.

Compatible source-branch LureBench builds stream binomial weights without retaining
a distribution-sized list and avoid subnormal recurrence plateaus. Zero-error
upper bounds use a stable closed form rather than repeated CDF inversion. The
consumer tests include counts-only synthetic artifacts up to the 10-million-record
limit; these are arithmetic tests, not real evaluations of that many messages.
Upgrade the companion package to receive the numerical implementation change;
upgrading only LureScope does not change an older installed LureBench function.

Revalidate a policy when changing the detector or model artifact, including a
change of inference implementation. The portable-model parity tests are not a
replacement for your organization's policy acceptance checks.

When a `/score` request omits `threshold` and its detector name matches the policy,
LureScope uses the policy threshold and returns its `policy_id`. An explicit
request threshold overrides the configured policy in the default research mode and does not
inherit its assurance. A request for another detector also falls back to that
detector's default threshold.

For mandatory reviewed decisions, use the source-branch
[operator enforcement mode](BOUND_POLICY.md#require-reviewed-policy-decisions).
It rejects those overrides and requires a pinned bound policy; artifact inspection
alone does not establish that requests are forced to use the artifact.

Legacy schemas v1/v2 bind names only. They do not verify deployed weights,
prompts, preprocessing, or provider configuration against the calibration run.
Even a trusted policy-file hash verifies only that file, not model equivalence.
Operators must independently review and revalidate the deployed configuration;
neither `validated_policy` nor a finite-sample assurance status proves that match.

## 4. Inspect production configuration

```bash
curl -s http://127.0.0.1:8000/policy
```

The response exposes no message content or credentials. It reports:

- `assurance_status`: `finite_sample_fpr_control`,
  `empirical_validation_only`, or `none`;
- on this source branch, `detector_binding`: `name_only` for configured v1/v2
  policies or `none` when unconfigured, and `detector_configuration_verified`:
  `false` for both legacy schemas; v3 reports `exact_portable_configuration`
  and a `detector_binding_status` of `match` or `mismatch` after deployment checks;
- policy and detector identity, threshold, target, and validation digests;
- validation-negative and false-positive counts, exact p-value, confidence, and
  upper bound for schema v2;
- empirical validation recall as a utility point estimate, without presenting it
  as a recall guarantee; and
- the assumptions that limit interpretation.

This endpoint is suitable for readiness checks and deployment inventories, but
it is intentionally not folded into `/health`: liveness and statistical fitness
are different operational questions.

New source-branch LureBench policies carry full SHA-256 evidence IDs that change
with observed labels or scores, even when the threshold does not change.
LureScope preserves those IDs and historical IDs without rewriting them. The
longer ID improves evidence change detection, not deployed model verification
or issuer authentication.

## 5. Monitor and renew

The finite-sample statement assumes representative independent validation
negatives. It does not cover population shift, bad labels, a changed model or
prompt, provider model aliases, preprocessing changes, or adversarial robustness.
Track those changes, collect newly adjudicated benign traffic, and issue a new
policy after a material change. Continue to run LureBench robustness and slice
evaluations; a controlled aggregate FPR can still hide a weak language, channel,
or population segment.
