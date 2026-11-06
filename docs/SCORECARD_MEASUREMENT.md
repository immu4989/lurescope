# Scorecard outcome accounting (unreleased)

The character and cross-model research scripts now emit
`measurement_version: "scorecard-outcomes-v2"`. This is an aggregate measurement
contract, not a signed assurance receipt, a new provider experiment, or a claim
that a detector is safe to deploy. Historical scorecard files and caches have
not been rewritten.

The research CLIs also perform [whole-file corpus admission](SCORECARD_CORPUS.md)
and add an input/selection manifest. This identifies the consumed bytes and
selection policy, not label correctness or representativeness. Direct Python
aggregation of supplied observations does not imply file admission.

## Observations, abstentions and failures

A score is a finite non-boolean real number in `[0, 1]`, or `None` for an explicit
abstention. Numeric strings, booleans, non-finite/out-of-range values and missing
result entries are errors. They do not become zero, benign, evasion, or an
abstention. A valid score equal to the threshold is a detection.

Thresholds, nonempty panels/cohorts, and distinct detector/attack names are checked
before evaluation callbacks. Cross-model aggregates require every declared
detector, record position and variant exactly once. All supplied scores are
validated, including attacks on records not eligible for the final evasion rate.
Cached scores are validated before attacker/provider callbacks; invalid new
scores are not cached. This value validation does **not** authenticate a cache
or bind its legacy keys to prompts, parser versions, models or generation settings.
Review those identities independently before reusing historical observations.
The cross-model CLI now enforces a separate [versioned cache contract](SCORECARD_CACHE.md);
legacy caches are rejected, not automatically migrated or authenticated.

## Denominators and logical bounds

For `N` fraud records, `C` confirmed clean catches and `A` clean abstentions:

- `clean_recall = C/N` is the **observed detection fraction over all fraud records**,
  not recall conditional on the detector answering.
- `clean_recall_upper = (C+A)/N` is its logical completion upper bound.
- `clean_coverage = (N-A)/N`; `clean_scored` and `clean_abstain` give the counts.
- Only the `C` confirmed clean catches are eligible for attacked evaluation.
  Unknown clean outcomes are not silently promoted into that cohort.

For each attacked cohort, let `E` be confirmed evasions, `U` explicit abstentions,
and `S = C-U` scored outcomes:

| Status | Primary `evasion` | Bounds | Diagnostic observed-subset rate |
|---|---|---|---|
| `complete`: `C>0`, `U=0` | `E/C` | both `E/C` | `E/S` |
| `inconclusive`: `C>0`, `U>0` | `null` | `[E/C, (E+U)/C]` | `E/S`, or `null` if `S=0` |
| `no_eligible`: `C=0` | `null` | both `null` | `null` |

Each cell includes `n_eligible`, `n_scored`, `n_abstained`, `n_evaded`, `coverage`,
`evasion_lower`, `evasion_upper`, and `evasion_observed`. These exact logical bounds
enumerate what could happen if unknown binary outcomes were completed. They are
**not confidence intervals**, sampling uncertainty estimates or population-level
performance guarantees. All attacked abstentions produce `[0, 1]`, not 0% evasion.

For example, one evasion, one detection and one abstention among three clean
catches gives an inconclusive primary rate, bounds `[1/3, 2/3]`, coverage `2/3`,
and diagnostic observed-subset rate `1/2`. Reporting only 50% would hide which
observations were selected out of its denominator.

Character scorecards retain `evasion_raw` and `evasion_normalized` as the primary
point-rate keys, now nullable, and put full counts/bounds under `raw` and
`normalized`. Both use the same clean-catch cohort, but can have different
missingness. Cross-model cells retain `evasion` and `n_scored` and add the same
accounting fields. The former conditional rate is now explicitly
`evasion_observed`; consumers must not silently substitute it for a null primary
rate or rank detectors by dropping unknown rows.

## Reading generated reports

Markdown gives eligible/scored counts alongside rates or inconclusive bounds.
PNGs mask unresolved and ineligible cells in neutral gray and show counts/bounds;
gray is not zero. Clean recall is labelled observed. The renderer does not infer
baseline/judge categories from row positions. Generated prose no longer invents
normalization success, model superiority, independence, or semantic explanations
from detector/attack labels. Earlier published corrections remain in the generator.

No clean catches is not evidence of robustness. Different detectors may have
different clean-catch cohorts; even complete evasion rates are not direct rankings
of overall quality. Fraud-only scorecards do not measure false-positive cost,
human-review workload, representative prevalence, calibration or downstream harm.
Normalization comparisons with differing missingness do not establish improvement
merely because the observed-subset rate decreases. Use appropriately designed
paired comparisons, benign data and independently reviewed operational evidence.

## Historical evidence and reproduction

Unversioned aggregates render with a legacy/unverified-semantics notice; rendering
cannot recover counts or abstentions that were discarded. Unknown explicit
measurement versions are rejected. A version label is not authentication of an
arbitrary aggregate supplied by another party. Preserve previous files. Re-run
affected evaluations or re-aggregate complete, independently identified per-record
observations under the new contract; do not relabel an old aggregate as version 2.
Complete all-scored observations retain the same numerical evasion rate.

No paid calls are needed for the synthetic regression tests or bundled character
sample. The cross-model CLI still performs paid work when asked to generate fresh
observations; no such run was made for this change. The normal tests include
exhaustive small-cohort completion checks; the optional PNG cases require
`LURESCOPE_TEST_VIZ=1` and the reviewed `viz` extra (see CONTRIBUTING).

## Research context and limits

This work follows the existing LureBench missing-outcome semantics. NIST's
[AI RMF MEASURE discussion](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
calls for documented, rigorous measurement with uncertainty and limitations;
this implementation is not NIST endorsement or a compliance assessment.
Traub et al.'s [selective-classification evaluation study](https://arxiv.org/abs/2407.01032)
illustrates why rejection/coverage choices can alter metric rankings. We do not
claim to implement that paper's AUGRC metric. The bounds above follow directly
from counting known and unknown outcomes; they are not a new statistical estimator.
