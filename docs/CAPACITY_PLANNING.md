# Review-capacity scenarios (unreleased)

Before deploying a detector, ask: **how many messages would people need to review?**
A high recall percentage alone does not answer that question. The classic
[base-rate analysis by Axelsson](https://profsandhu.com/cs6393_s21/Axelsson-2000.pdf)
explains why false alarms can dominate at low event prevalence. This tool applies
simple class-conditional scenario arithmetic, not that paper's experiments or a
new statistical guarantee.

## Offline workflow

The source-branch browser lab also includes a **Can your team review the alerts?**
panel (`#capacity`). It computes locally without transmitting counts or calling
a model. Enter all six outcome counts and three distinct prevalence assumptions.
Editing any input hides the previous results and disables their download until
you recalculate. Downloaded JSON includes the assumptions and limitations, not
just the displayed table. Initial values are explicitly synthetic, not measured
performance. Browser and Python arithmetic are tested for parity; this does not
validate the assumptions against an organization's traffic.

Export all six outcomes from a reviewed LureBench **fraud-task** cache. Both
commands below are source-branch additions, not features of PyPI 0.11.0:

```sh
lurebench cache-replay --dataset validation.jsonl --cache scores.json \
  --detector-name 'original-display-name' --task fraud --threshold 0.5 \
  --decision-counts > decision-counts.json
lurescope capacity-plan decision-counts.json --messages-per-period 1000000 \
  --prevalence 0.001 0.01 0.05 --review-minutes 5 --available-review-hours 1000
```

Supply the original cache namespace if required by the detector. Check the first
command's exit status before consuming its output. Cache replay does not construct
a provider or model, and capacity planning needs no messages, credentials,
downloads, or model runtime. Use the same period for volume and available hours
(for example, both daily or both monthly). Choose assumptions from your own
operation; the command does not infer prevalence from an artificially balanced
benchmark or infer staffing capacity from employee counts.

The input contract is [decision-counts.schema.json](../spec/decision-counts.schema.json):
version, task, declared detector, threshold, and `tp`, `fp`, `tn`, `fn`,
`abstained_positive`, `abstained_negative`. Both labeled classes must have at
least one observation. Missing abstention fields are errors, not implicit zeros.
The runtime additionally rejects coerced numeric types, nonfinite inputs, and
provenance-task counts. Count files must be bounded non-symlink regular files.

## Arithmetic and routing assumptions

For positive records, estimate the three rates using
`P = tp + fn + abstained_positive`. For negative records, use
`N = tn + fp + abstained_negative`. At volume `V` and assumed prevalence `p`,
each positive outcome's expectation is `V * p * count / P`; each negative
outcome's expectation is `V * (1-p) * count / N`.

Every flag and every abstention requires human review in this scenario. Review
hours are `(expected flags + expected abstentions) * minutes per case / 60`.
Abstained fraud is reported separately as pending review: it is neither credited
as a successful detection nor counted as an automated benign decision. The
planner never assumes that a human review is correct or prevents a loss.

**Synthetic illustration, not measured LureScope performance:** counts of
96 true positives / 4 false negatives and 2 false positives / 98 true negatives,
with no abstentions, imply at 0.1% prevalence and one million messages:

- 960 true-positive flags and 19,980 false-positive flags;
- 20,940 reviews, with roughly 4.6% of flags representing fraud;
- 1,745 review hours at five minutes per case—745 hours above a supplied
  1,000-hour capacity.

## Interpretation boundary

### Optional sampling envelope (CLI only)

Add `--confidence 0.95` to request simultaneous bounds on **expected review
demand**. The default command and browser panel still produce point scenarios
only. The optional output nests those point scenarios and adds a separate
`review_capacity_sampling_envelope` report. This is not a prediction interval
for tomorrow's actual message count or a guarantee about queueing delays.

For each labeled class, combine flags and abstentions into one binary review
event. With `n` independently sampled examples and observed review fraction `q`,
use radius `sqrt(log(4 / alpha) / (2*n))`, where `alpha = 1 - confidence`.
Clip `q ± radius` to `[0,1]`. This applies
[Hoeffding's bounded-independent-variable inequality](https://doi.org/10.1080/01621459.1963.10500830)
to four one-sided tails: two directions for each of two classes. Each tail has
error budget `alpha/4`; a union bound covers both class rates jointly. Cross-class
independence is not needed for that union bound.

For every prevalence `p`, multiply the positive-class endpoints by `V*p`, the
negative-class endpoints by `V*(1-p)`, and add. Nonnegative mixture weights imply
simultaneous coverage for all these prevalence mixtures from the same two
intervals; adding prevalence scenarios does not create additional tail tests.
Convert those review-count endpoints into hours using the supplied fixed review
time. The result distinguishes an interval entirely above capacity, entirely
within it, or straddling it. None of these labels means safe to deploy.

This requires a fixed classifier, threshold, routing rule, confidence level, and
sample sizes specified before examining validation outcomes, representative
independent sampling within each true class, correct labels, and stable
class-conditional rates. Reusing validation results to choose a model, repeated
peeking/optional stopping, correlated campaign duplicates, drift, or label error
invalidates the stated interpretation. No multiple-model correction is supplied.
The bounds can be very conservative, especially for rare events; zero observed
reviews still yields a nonzero upper bound. They do not quantify uncertainty in
prevalence, volume, review time, precision, loss, or reviewer accuracy. Input
counts and compliance with these assumptions are not authenticated.

### Default point scenarios

These are fractional **expected counts under supplied assumptions**, not incident
forecasts, confidence bounds, an observed staffing requirement, or a queueing
model. Class-conditional rates are assumed stable across scenarios. Sampling
uncertainty, label error, changes in attack mix, model drift, clustered messages,
arrival bursts, reviewer accuracy, and handling-time variation are not quantified.
Zero observed false positives is not evidence of zero population false positives.

Input counts and detector names are not authenticated. Aggregate counts are not
differential privacy and may need suppression before sharing. There is no claimed
dollar saving, fraud prevention, compliance finding, or authorization to deploy.
Use these scenarios to inform a preregistered [pilot gate](PILOT_GATE.md) and real
capacity measurements; do not automatically change thresholds to make a chart fit.

The CLI exits successfully when valid arithmetic shows overload; inspect each
scenario's `exceeds_review_capacity` and `review_hour_shortfall`. Invalid inputs
exit 2. Tests use exact rational reference calculations, mass conservation,
all-abstention cases, prevalence endpoints, and zero available review capacity.
