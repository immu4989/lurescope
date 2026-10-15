# Calibrate and verify the deployed portable model

Source-branch schema v3 prevents a decision threshold calibrated for one
portable model configuration from being silently applied to another. LureScope
calibrates with its actual bundled data-only detector, then compares the loaded
model, implementation, and runtime identities before policy-backed scoring.
Mismatch produces no score, triage result, or new proof under that policy.

This workflow requires compatible source-branch LureScope and LureBench builds;
it is not part of published PyPI 0.11.0. It currently supports the bundled
portable `tfidf-logreg` fraud model. Provider-backed detectors and heuristic or
joblib policies do not acquire configuration verification by matching a name.

## Calibrate on the intended serving runtime

Prepare fresh labelled validation records in LureBench JSONL format. Use the
same text preparation as production, and freeze the detector and validation
design before collecting results. Do not reuse the bundled training corpus or
strip family annotations to pass the independence check.

```bash
lurescope calibrate --validation validation.jsonl \
  --objective risk_controlled_fpr --target-fpr 0.01 \
  --confidence 0.95 --threshold-grid-size 1001 \
  --out policies/portable-bound.json
lurescope policy policies/portable-bound.json --check-deployment
```

The output directory must already exist. Calibration ignores any configured
policy threshold and constructs a fresh instance of the actual portable model.
It checks controls before input reads, sample size and known lineage before
construction, and configuration before and after collecting complete scores.
An impossible or invalid plan exits with code 2; scoring/publication failure
exits with code 1. Existing policy outputs are atomically replaced only after
successful evidence validation. Preserve reviewed policies under versioned paths.

`max_mcc` and `target_fpr` are also available for empirical threshold selection.
Binding an empirical policy does not give it a population-risk guarantee.
The risk-controlled objective retains its existing exact-binomial method,
sample-size requirements, and independence assumptions.

## Deploy trusted policy bytes

```bash
export LURESCOPE_POLICY_PATH=/absolute/path/to/policies/portable-bound.json
# Set this to the SHA-256 approved through your trusted release process.
export LURESCOPE_POLICY_SHA256=YOUR_APPROVED_64_CHARACTER_LOWERCASE_DIGEST
uvicorn lurescope.app:app
```

Do not use the placeholder as a real pin, and do not obtain both policy and pin
from an untrusted source. A self-consistent policy is not authenticated: someone
who can replace both the artifact and its identity can issue a different policy.
The existing trusted file pin detects replacement, including downgrade to a
legacy artifact. Protect configuration, installed code, and parent directories.

For a matching detector request with no explicit threshold, a v3 policy is checked
before scoring and again before publishing the score. A binding mismatch fails
closed; it does not fall back to 0.5 or a legacy policy. `/score` and email triage
return redacted 502 failures, and proof creation cannot produce evidence under
the mismatched policy. In the default research mode, an explicit threshold opts out and
returns no policy ID, but the configured policy file must still be structurally
valid. Another detector uses its existing default behavior.

## Require reviewed policy decisions

Organizations that cannot admit research overrides can enable source-branch
operator enforcement after calibrating and approving the policy:

```bash
export LURESCOPE_POLICY_ENFORCEMENT=risk_controlled_bound
# LURESCOPE_POLICY_PATH and its independently approved SHA-256 must also be set.
lurescope policy --check-readiness
curl --fail http://127.0.0.1:8000/policy/readiness
```

Only three exact mode values are accepted. Unset or `off` retains research
behavior. `bound` requires a pinned v3 policy matching the portable detector;
`risk_controlled_bound` additionally requires its validated finite-sample FPR
evidence. Empty, misspelled, padded, or differently capitalized values fail closed.
Review the policy's target, confidence, validation population, and limitations;
the mode does not choose those requirements for your organization.

In either enforced mode, score and email-triage requests must leave `threshold`,
`engine`, and `model` unset or null and use the policy's detector. Even an explicitly supplied
threshold equal to the policy threshold is rejected. Rejections happen before
model construction or provider quota reservation. A missing pin, invalid policy,
or legacy downgrade cannot fall back to defaults, including on a warm worker.
The direct Python service applies the same decision admission rules.

Exploratory attacks and new LureProofs are disabled in enforced mode, including
proof-producing batch workflows. They perform extra evaluations beyond the
bound scoring contract. Keep a separate research worker for those operations;
verification of already-issued proofs remains available without inference.
HTTP request-policy violations return redacted `403` responses. Unavailable
required policy configuration returns `503`; a detector binding mismatch during
scoring retains the redacted `502` failure, with no decision.

`GET /policy/readiness` returns `200` only when enforcement is enabled, trusted
policy bytes satisfy the selected requirement, the actual detector binding
matches, and API security configuration/allowlists permit that detector. Otherwise
it returns `503` with a fixed reason code and `ready: false`. HTTP responses use
`Cache-Control: no-store` so compliant intermediaries do not reuse old readiness.
The CLI probe uses
the same checks and exits 0 or 1. It accepts neither a file argument nor
`--check-deployment`: it checks actual deployment configuration, not an arbitrary
artifact. The probe can load the data-only model but never predicts, constructs
provider clients, or reserves quota. It exposes no private paths or credentials.

Use this policy-specific probe for enforced scoring workers; a research worker
with enforcement off intentionally reports not ready here while `/health` can
remain healthy. A ready result is a point-in-time configuration check, not proof
of prediction success, capacity, authentication of a particular client, TLS,
email extraction validity, regulatory compliance, or future accuracy. Independent
sampling and deployment-monitoring obligations still apply.

Treat policy file, approved pin, enforcement mode, and installed code as trusted
administrative configuration. Deploy them together before starting workers and
use controlled rolling replacements. Each operation rechecks current admission;
this does not atomically update environment variables, cancel in-flight work,
or coordinate replicas. Browser-only JavaScript scoring is a research demo and
does not inherit server environment enforcement.

## Check configuration separately from statistical evidence

`lurescope policy FILE` validates the artifact without claiming a deployment
match: v3 status is `not_checked`, and `detector_configuration_verified` is false.
Add `--check-deployment` to compare against this installation; the command exits
0 only for a verified match, 1 for a mismatch/unbound/unconfigured policy, and
2 for invalid input. Legacy policies remain usable but cannot pass this check.

`GET /policy` performs the deployment comparison for v3. Clients should require
both `detector_binding_status: match` and the appropriate `assurance_status`.
A mismatch remains visible as a 200 status response with verification false;
unreadable or invalid configuration returns a redacted 503. Liveness at `/health`
is not statistical readiness. The first v3 status check can load the local model;
it never constructs provider clients or makes paid requests.

## Binding scope and renewal

The binding contains the profile `lurescope-portable-tfidf-exact-v1` and three
SHA-256 values:

- `artifact_sha256` covers the exact portable JSON bytes, not merely its embedded
  source-joblib digest. Loaded weights and metadata are immutable through the
  normal Python interface.
- `implementation_sha256` covers the installed portable inference source,
  captured at module import. Editing that source requires a restart and fresh
  validation; it is not a measurement of arbitrary live-process modifications.
- `runtime_sha256` covers the declared Python build/implementation, OS and release,
  machine architecture, libc version, Unicode version, floating-point profile,
  and byte order. It is cached per process. Different Python builds, operating
  systems, or implementations can therefore require recalibration even if
  measured scores happen to agree.

This is a strict configuration comparison, not hardware or process attestation.
It assumes trusted installed code and runtime; it does not defend against code
with arbitrary in-process mutation authority. It does not verify upstream email
extraction or preprocessing, training-data independence, labels, provider models,
or future deployment traffic. Cross-implementation equivalence is not inferred
from parity probes. Calibrate on the target runtime after a material change and
review new evidence rather than copying fingerprints into an old policy.

The [v3 schema](../spec/decision-policy-v3.schema.json) and full policy ID also
bind declared validation evidence and selected threshold. Both consumers retain
v1/v2 loading without rewriting historical policies. Re-verifying an old proof
does not rerun the historical model or attest its past runtime.
