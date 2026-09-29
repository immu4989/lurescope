const test = require("node:test");
const assert = require("node:assert/strict");
const {plan} = require("../lurescope/static/capacity-planner.js");
const validation = {schema_version: 1, task: "fraud", detector: "synthetic", threshold: .5,
  counts: {tp: 96, fn: 4, fp: 2, tn: 98, abstained_positive: 0, abstained_negative: 0}};
const options = {messages_per_period: 1000000, prevalences: [.001, .01, .05],
  review_minutes_per_case: 5, available_review_hours: 1000};

test("rare event arithmetic exposes false-positive review demand", () => {
  const row = plan(validation, options).scenarios[0];
  assert.equal(row.expected_review_cases, 20940);
  assert.equal(row.required_review_hours, 1745);
  assert.equal(row.review_hour_shortfall, 745);
  assert.equal(row.exceeds_review_capacity, true);
});

test("no flags has undefined precision while abstentions still require review", () => {
  const allMissing = {...validation, counts: {tp: 0, fn: 0, fp: 0, tn: 0,
    abstained_positive: 5, abstained_negative: 5}};
  for (const row of plan(allMissing, options).scenarios) {
    assert.equal(row.fraud_share_among_flags, null);
    assert.equal(row.expected_review_cases, options.messages_per_period);
    assert.equal(row.fraud_classified_benign, 0);
  }
});

test("class counts and controls cannot be missing or coerced", () => {
  for (const bad of [true, "1", null, NaN, Infinity, -1, .5, 10000001]) {
    assert.throws(() => plan({...validation, counts: {...validation.counts, tp: bad}}, options));
  }
  assert.throws(() => plan({...validation, task: "provenance"}, options));
  assert.throws(() => plan({...validation, threshold: true}, options));
  assert.throws(() => plan(validation, {...options, prevalences: [.1, .1]}));
  assert.throws(() => plan(validation, {...options, prevalences: [null]}));
  assert.throws(() => plan(validation, {...options, messages_per_period: true}));
  assert.throws(() => plan(validation, {...options, review_minutes_per_case: 0}));
});

test("results do not mutate caller input or leak shared mutable defaults", () => {
  const original = JSON.stringify(validation);
  const result = plan(validation, options);
  result.validation.counts.tp = 0;
  result.limitations.length = 0;
  assert.equal(JSON.stringify(validation), original);
  assert.ok(plan(validation, options).limitations.length > 0);
});

test("prevalence endpoints conserve mass", () => {
  for (const p of [0, 1]) {
    const row = plan(validation, {...options, prevalences: [p]}).scenarios[0];
    assert.equal(Object.values(row.expected_outcomes).reduce((a, b) => a + b, 0), 1000000);
  }
});
