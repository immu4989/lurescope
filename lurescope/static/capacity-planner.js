/* Pure local scenario arithmetic. No networking, persistence, or model access. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.LureScopeCapacity = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const fields = ["abstained_negative", "abstained_positive", "fn", "fp", "tn", "tp"];
  const positiveFields = new Set(["tp", "fn", "abstained_positive"]);
  const limitations = [
    "scenario_arithmetic_not_a_deployment_forecast_or_confidence_interval",
    "prevalences_volume_review_time_and_capacity_are_operator_assumptions",
    "class_conditional_outcome_rates_assumed_stable_across_scenarios",
    "sampling_uncertainty_label_error_and_distribution_shift_not_quantified",
    "reviewer_accuracy_queueing_delays_and_prevention_effect_not_modeled",
    "expected_counts_may_be_fractional_and_are_not_observed_incidents",
    "input_counts_and_detector_identity_are_not_authenticated",
    "aggregate_counts_are_not_differential_privacy",
    "no_automatic_threshold_change_or_authorization_to_deploy",
  ];
  function number(value, label, maximum) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > maximum) {
      throw new Error(`${label} must be a finite number between 0 and ${maximum}.`);
    }
    return value;
  }
  function exact(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value) ||
        Object.keys(value).sort().join("\n") !== [...keys].sort().join("\n")) {
      throw new Error("Input fields do not match the decision-count contract.");
    }
  }
  function plan(validation, options) {
    exact(options, ["messages_per_period", "prevalences", "review_minutes_per_case", "available_review_hours"]);
    exact(validation, ["schema_version", "task", "detector", "threshold", "counts"]);
    if (validation.schema_version !== 1 || validation.task !== "fraud") {
      throw new Error("Version 1 fraud-task counts are required.");
    }
    if (typeof validation.detector !== "string" || !validation.detector.length ||
        [...validation.detector].length > 256 || /[\u0000-\u001f\u007f]/.test(validation.detector)) {
      throw new Error("A bounded detector name without controls is required.");
    }
    number(validation.threshold, "Threshold", 1);
    exact(validation.counts, fields);
    const counts = {...validation.counts};
    for (const field of fields) {
      number(counts[field], "Outcome counts", 10000000);
      if (!Number.isInteger(counts[field])) throw new Error("Outcome counts must be integers.");
    }
    const positive = counts.tp + counts.fn + counts.abstained_positive;
    const negative = counts.tn + counts.fp + counts.abstained_negative;
    if (!positive || !negative) throw new Error("Both labeled classes need observations.");
    const volume = number(options.messages_per_period, "Messages per period", 1000000000);
    if (!Number.isInteger(volume) || !volume) throw new Error("Message volume must be a positive integer.");
    const minutes = number(options.review_minutes_per_case, "Review minutes", 1440);
    if (!minutes) throw new Error("Review minutes must be positive.");
    const hours = number(options.available_review_hours, "Available review hours", 1000000000);
    const points = options.prevalences;
    if (!Array.isArray(points) || !points.length || points.length > 32) {
      throw new Error("Supply one through 32 prevalence scenarios.");
    }
    points.forEach(p => number(p, "Prevalence", 1));
    if (new Set(points).size !== points.length) throw new Error("Prevalence scenarios must be unique.");
    const rates = Object.fromEntries(fields.map(k => [k, counts[k] / (positiveFields.has(k) ? positive : negative)]));
    const scenarios = points.map(p => {
      const expected = Object.fromEntries(fields.map(k => [k, rates[k] * (positiveFields.has(k) ? volume * p : volume * (1 - p))]));
      const flagged = expected.tp + expected.fp;
      const abstained = expected.abstained_positive + expected.abstained_negative;
      const review = flagged + abstained;
      const required = review * minutes / 60;
      return {fraud_prevalence: p, expected_outcomes: expected, expected_flagged: flagged,
        expected_abstained: abstained, expected_review_cases: review,
        fraud_share_among_flags: flagged ? expected.tp / flagged : null,
        fraud_classified_benign: expected.fn,
        fraud_abstained_pending_review: expected.abstained_positive,
        required_review_hours: required, exceeds_review_capacity: required > hours,
        review_hour_shortfall: Math.max(0, required - hours)};
    });
    return {schema_version: 1, analysis: "prevalence_capacity_scenarios",
      validation: {...validation, counts}, validation_class_sizes: {positive, negative},
      class_conditional_outcome_rates: rates, messages_per_period: volume,
      review_minutes_per_case: minutes, available_review_hours: hours,
      routing_assumption: "all_flags_and_abstentions_require_review", scenarios,
      limitations: [...limitations]};
  }
  return {plan};
});
