# LureWatch: anytime-valid deployment monitoring

Pre-deployment evaluation answers whether a frozen detector met a risk target on
a frozen sample. It does not answer whether the same detector still meets that
target after deployment, after traffic changes, or after operators have checked
the dashboard every day for six months.

LureWatch turns adjudicated aggregate false-positive and false-negative counts
into a tamper-evident longitudinal evidence chain. Its alarm remains valid at
every submitted batch boundary. Looking after every batch does not create the
false-positive inflation produced by repeatedly applying ordinary fixed-sample
tests.

This directly addresses a methodological gap identified in
[NIST AI 800-4](https://doi.org/10.6028/NIST.AI.800-4): practitioners need trusted
monitoring methods, privacy-preserving logs, uncertainty, performance thresholds,
longitudinal tracking, and statistics designed for continuous rather than
one-time evaluation. LureWatch is one narrow implementation for binary detector
error rates. It is not a general solution to every monitoring category in that
report.

## What is different

| Ordinary dashboard | LureWatch |
|---|---|
| Shows a rolling empirical rate | Tests one immutable, predeclared risk limit |
| Repeated peeking silently increases false alarms | Alarm is valid over all submitted batch looks |
| Metrics can be added after seeing outcomes | Monitor family is fixed before the first batch |
| Often stores row-level telemetry | Stores confusion counts and optional source commitment only |
| Current chart can hide an earlier crossing | Maximum evidence and breach status are sticky |
| Mutable state is difficult to audit | Every entry and statement is hash-chained and recomputed |
| Authentication is ambiguous | Optional DSSE mode requires one externally trusted P-256 key |

No alarm means only that the configured test has not crossed. It is **not** proof
that risk is below the limit. A low-power stream, biased review sample, bad labels,
or changed population can all prevent a meaningful conclusion.

## Start an overall FPR/FNR monitor

Use a risk-controlled LureBench decision policy when one is available. The plan
then binds its exact bytes, detector, threshold, and policy identity:

```bash
lurescope monitor init \
  --out ./agency-lurewatch \
  --plan-id agency-email-fraud-v1 \
  --policy ./tfidf-1pct-fpr-95.json \
  --fnr-limit 0.10 \
  --family-alpha 0.05 \
  --sampling random_sample \
  --labeling-protocol dual-review-v1
```

Without `--policy`, declare the served detector and threshold directly:

```bash
lurescope monitor init --out ./agency-lurewatch \
  --plan-id agency-email-fraud-v1 \
  --detector tfidf-logreg --threshold 0.5 \
  --fpr-limit 0.01 --fnr-limit 0.10
```

The default family contains two monitors:

- `overall-fpr`: false positives divided by adjudicated actual-benign cases;
- `overall-fnr`: false negatives divided by adjudicated actual-fraud cases.

The 5% family false-alarm budget is divided across both predeclared monitors, so
each alarm threshold uses 2.5%. This is conservative Bonferroni control and does
not assume the two metrics are independent.

## Append one adjudicated batch

Do not count unlabeled, uncertain, missing, or delayed outcomes as correct. Submit
only the confusion matrix for cases covered by the registered sampling and
labeling protocol:

```bash
lurescope monitor append ./agency-lurewatch \
  --batch-id 2026-W35 \
  --true-positive 94 --false-negative 6 \
  --true-negative 298 --false-positive 2 \
  --observed-at 2026-08-30T23:59:59Z \
  --source-sha256 <sha256-of-private-adjudication-export>
```

Exit status `0` means the checkpoint was appended and the family has not crossed.
Exit status `1` means the append succeeded and at least one monitor has produced an
anytime-valid breach alarm. Exit status `2` means the input, bundle, chain, or
signature failed validation.

The optional source digest commits to evidence retained inside the organization's
approved boundary. It does not reveal that evidence, prove label quality, or
authenticate its owner.

## Authenticate every checkpoint

Generate a P-256 keypair with the existing offline command:

```bash
lurescope keygen --private-out monitor-private.pem --public-out monitor-public.pem

lurescope monitor init --out ./signed-lurewatch \
  --plan-id agency-email-fraud-v1 \
  --fpr-limit 0.01 --fnr-limit 0.10 \
  --signer-public-key monitor-public.pem

lurescope monitor append ./signed-lurewatch \
  --batch-id 2026-W35 \
  --true-positive 94 --false-negative 6 \
  --true-negative 298 --false-positive 2 \
  --signing-key monitor-private.pem

lurescope monitor verify ./signed-lurewatch --public-key monitor-public.pem
```

The plan stores only the public-key identity. Verification requires the public key
from an external trusted channel. Copying a public key from the evidence package
itself would verify mathematical possession without establishing issuer identity.
Protect the private key through the organization's normal key-management process;
the CLI accepts only an unencrypted PEM and does not provide HSM integration.

## Statistical contract

For one monitor, let `p0` be the predeclared maximum acceptable error probability,
and let `S_n` errors be observed among `n` eligible adjudicated outcomes. LureWatch
predeclares twelve alternatives

```text
q_k = p0 + (1 - p0) × 2^-k,  k = 1,...,12.
```

For every `q_k > p0`, it computes the Bernoulli likelihood ratio

```text
E_n(q_k) = (q_k / p0)^S_n × ((1 - q_k) / (1 - p0))^(n - S_n).
```

If the conditional error probability is at most `p0`, the next-step conditional
expectation of each ratio multiplier is at most one. Each component is therefore
a nonnegative supermartingale under the risk-limit null. The uniform finite
mixture

```text
E_n = (1 / 12) × sum_k E_n(q_k)
```

is also a nonnegative supermartingale. By Ville's inequality,

```text
P(any submitted look has E_n >= 1 / alpha_monitor) <= alpha_monitor.
```

LureWatch performs all calculations in log space and stores the current and
maximum log e-value. The maximum begins at zero (`E_0 = 1`), and a breach remains
recorded even when later favorable outcomes reduce the current e-value.

The implementation's exact path-enumeration test checks every Bernoulli sequence
through a finite horizon at the null boundary—no Monte Carlo tolerance is used.
The broader time-uniform basis is described by Howard et al.,
[*Time-uniform, nonparametric, nonasymptotic confidence sequences*](https://doi.org/10.1214/20-AOS1991).

### What the guarantee assumes

The alarm guarantee requires:

1. The detector, preprocessing, threshold, decision policy, event definition,
   population, monitor family, risk limits, and family alpha were fixed first.
2. Adjudicated outcomes are representative and conditionally independent under
   the declared sampling protocol, or satisfy a justified equivalent model.
3. Labels are trustworthy for the declared event and denominator.
4. Every submitted count covers disjoint eligible observations; batches are not
   replayed, selectively withheld based on their outcomes, or counted twice.
5. Operators inspect at submitted batch boundaries. Aggregate counts do not
   reveal whether the alarm crossed temporarily inside an unsubmitted batch.

Optional stopping based on earlier submitted evidence is allowed. Selective
labeling, post-hoc slices, silent model changes, and outcome-dependent batch
omission are not.

## Evidence package

```text
agency-lurewatch/
├── monitor-plan.json
├── entries/
│   ├── 00000001.json
│   └── 00000002.json
└── checkpoints/
    ├── 00000001.statement.json
    ├── 00000001.dsse.json        # signed plans only
    ├── 00000002.statement.json
    └── 00000002.dsse.json
```

Every entry binds the plan and predecessor entry by SHA-256. Every in-toto
checkpoint binds the plan, current entry, and predecessor statement. Strict
verification rejects unknown fields, duplicate JSON keys, non-finite numbers,
non-canonical JSON, gaps, duplicate batch IDs, altered counts, statistics that do
not recompute, unsafe permissions, symbolic links, unexpected files, mismatched
keys, and invalid DSSE payloads or signatures.

The chain detects mutation, insertion, and reordering. It cannot independently
detect deletion of the final entries if an attacker can replace the whole local
directory. Register or publish the latest statement SHA-256 in a separately
controlled system to make tail deletion externally detectable.

## Response protocol

Treat a breach as an investigation trigger, not an automatic blocking rule:

1. Preserve the bundle and externally checkpoint the latest statement digest.
2. Confirm the sampling frame, adjudication process, denominator, and source
   commitment before attributing the change to the detector.
3. Break down a new, separately predeclared investigation by language, channel,
   office, attack pattern, or upstream provider. Do not add a favorable slice to
   the existing family after seeing the alarm.
4. Compare model, policy, preprocessing, provider, and traffic changes.
5. Decide through the organization's incident, change-control, privacy, legal,
   and authorizing processes whether to retrain, recalibrate, roll back, add
   review capacity, or accept risk.
6. Start a new plan after any material control or population change. Preserve the
   old chain; do not reset it to make the breach disappear.

## Public-sector alignment

LureWatch emits evidence *relevant* to these outcomes; it does not establish
compliance with them:

- [NIST AI RMF](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
  Measure 2.4 and Manage 4.1 call for production monitoring and implemented
  post-deployment monitoring plans.
- [NIST SP 800-53 Rev. 5 CA-7](https://doi.org/10.6028/NIST.SP.800-53r5)
  calls for defined metrics, monitoring frequencies, analysis, and response.
- [OMB M-25-21](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-21-Accelerating-Federal-Use-of-AI-through-Innovation-Governance-and-Public-Trust.pdf)
  addresses ongoing real-world performance testing, continuous monitoring, and
  post-award evaluation for federal AI use.

These mappings are an aid for system owners and assessors. A LureWatch package is
not an authorization package, control-satisfaction finding, procurement approval,
incident report, or substitute for a qualified assessor.
