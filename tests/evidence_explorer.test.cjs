const test = require("node:test");
const assert = require("node:assert/strict");

const explorer = require("../lurescope/static/evidence-explorer.js");

const sha = character => character.repeat(64);
const receipt = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{name: "private-evaluation-cohort", digest: {sha256: sha("a")}}],
  predicateType: "https://github.com/immu4989/lurebench/spec/lureeval-receipt/v1",
  predicate: {
    cohort: {
      processed_count: 100,
      evaluated_count: 90,
      manifest_sha256: sha("b"),
      labels_sha256: sha("c"),
      plan_sha256: sha("d"),
      gate_sha256: sha("e"),
    },
    control: {detector_artifact_sha256: sha("f"), policy_sha256: null},
    outcome: {
      metrics: {
        recall_estimate: 0.9,
        recall_lower_bound: 0.8,
        false_positive_rate_estimate: 0.02,
        false_positive_rate_upper_bound: 0.05,
      },
      routing: {routed_rate: 0.2},
      resilience: {evasion_rate: 0.1},
      pilot_gate: {verdict: "pass", failed_checks: []},
    },
    privacy: {excluded_fields: ["message_content", "case_ids"]},
    limitations: ["representative_iid_sample_required"],
  },
};

test("LureEval receipt reveals metrics and bindings without raw records", () => {
  const summary = explorer.summarizeArtifact(receipt);

  assert.equal(summary.kind, "LureEval receipt");
  assert.equal(summary.status, "pass");
  assert.equal(summary.tone, "pass");
  assert.equal(summary.metrics.find(item => item.label === "Recall").value, "90.0%");
  assert.equal(summary.bindings.length, 5);
  assert.ok(summary.privacy.includes("message_content"));
  assert.match(summary.warnings[0], /unsigned/i);
});

test("DSSE is decoded but never misrepresented as authenticated", () => {
  const envelope = {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(receipt), "utf8").toString("base64"),
    signatures: [{keyid: sha("1"), sig: "AAAA"}],
  };
  const summary = explorer.parseArtifact(JSON.stringify(envelope));

  assert.equal(summary.signature.label, "1 DSSE signature present");
  assert.equal(summary.signature.authenticated, false);
  assert.match(summary.warnings[0], /not cryptographically authenticated/i);
});

test("Defender paired report compares only aggregate operational metrics", () => {
  const report = {
    schema: "https://github.com/immu4989/lurescope/spec/defender-report/v1",
    cohort: {
      messages: 25,
      matched_messages: 20,
      evaluated_matched_messages: 18,
    },
    native_attention: {performance: {
      recall_estimate: 0.75,
      recall_lower_bound: 0.6,
      false_positive_rate_estimate: 0.1,
      false_positive_rate_upper_bound: 0.2,
    }},
    lurescope_paired: {performance: {
      recall_estimate: 0.9,
      recall_lower_bound: 0.72,
      false_positive_rate_estimate: 0.05,
      false_positive_rate_upper_bound: 0.14,
    }},
    bindings: {
      defender_import_sha256: sha("2"),
      shadow_manifest_sha256: sha("3"),
      labels_sha256: sha("4"),
    },
    privacy: {excluded_fields: ["internet_message_ids", "recipient_addresses"]},
    limitations: ["unmatched_messages_excluded_from_paired_performance"],
  };
  const summary = explorer.summarizeArtifact(report);

  assert.equal(summary.kind, "Defender paired report");
  assert.equal(summary.status, "Paired evidence");
  assert.equal(summary.metrics.find(item => item.label === "Matched").value, "20 / 25");
  assert.equal(summary.bindings.length, 3);
});

test("LureWatch entry exposes aggregate e-process state and chain bindings", () => {
  const entry = {
    schema: "https://github.com/immu4989/lurescope/spec/lurewatch-entry/v1",
    sequence: 4,
    family_status: "breach",
    plan_sha256: sha("a"),
    previous_entry_sha256: sha("b"),
    batch: {source_commitment_sha256: sha("c")},
    states: [
      {
        monitor_id: "overall-fpr",
        empirical_rate: 0.08,
        log_e_value: 5.2,
        alarm_log_threshold: 3.69,
        status: "breach",
      },
    ],
    privacy: {
      contains_message_content: false,
      contains_case_identifiers: false,
      contains_per_message_scores: false,
    },
  };
  const summary = explorer.summarizeArtifact(entry);

  assert.equal(summary.kind, "LureWatch entry");
  assert.equal(summary.status, "breach");
  assert.equal(summary.tone, "fail");
  assert.equal(summary.metrics.find(item => item.label === "overall-fpr").value, "8.0%");
  assert.equal(summary.bindings.length, 3);
  assert.ok(summary.privacy.includes("no message_content"));
  assert.match(summary.warnings.join(" "), /No alarm is not proof/i);
});

test("signed LureWatch checkpoint is inspected without claiming authentication", () => {
  const checkpoint = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {name: "monitor-plan.json", digest: {sha256: sha("d")}},
      {name: "entries/00000001.json", digest: {sha256: sha("e")}},
    ],
    predicateType: "https://github.com/immu4989/lurescope/spec/lurewatch-checkpoint/v1",
    predicate: {
      sequence: 1,
      family_status: "monitoring",
      authentication_mode: "ecdsa-p256-dsse",
      previous_statement_sha256: null,
      limitations: ["no_alarm_is_not_proof_that_risk_is_below_the_limit"],
    },
  };
  const envelope = {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(checkpoint), "utf8").toString("base64"),
    signatures: [{keyid: sha("1"), sig: "AAAA"}],
  };
  const summary = explorer.summarizeArtifact(envelope);

  assert.equal(summary.kind, "LureWatch checkpoint");
  assert.equal(summary.status, "monitoring");
  assert.equal(summary.signature.authenticated, false);
  assert.match(summary.warnings[0], /not cryptographically authenticated/i);
});

test("LureBoundary evaluation shows containment metrics without event content", () => {
  const evaluation = {
    schema: "https://github.com/immu4989/lurebench/spec/agent-boundary-evaluation/v1",
    suite: {suite_sha256: sha("a")},
    monitor: {monitor_id: "boundary-monitor", artifact_sha256: sha("b")},
    summary: {
      total_trajectories: 14,
      trajectory_recall: 1,
      benign_false_positive_rate: 0,
      category_accuracy: 1,
      maximum_detection_delay_events: 0,
      verdict: "pass",
    },
    limitations: ["results_measure_the_declared_monitor_on_this_suite_not_deployment_containment"],
  };
  const summary = explorer.summarizeArtifact(evaluation);

  assert.equal(summary.kind, "LureBoundary evaluation");
  assert.equal(summary.status, "pass");
  assert.equal(summary.metrics.find(item => item.label === "Recall").value, "100.0%");
  assert.equal(summary.bindings.length, 2);
  assert.ok(summary.privacy.includes("no credentials"));
});

test("LureBoundary entry preserves sticky breach and response boundary", () => {
  const entry = {
    schema: "https://github.com/immu4989/lurescope/spec/lureboundary-entry/v1",
    sequence: 2,
    plan_sha256: sha("a"),
    previous_entry_sha256: sha("b"),
    evaluation: {
      sha256: sha("c"),
      suite_sha256: sha("d"),
      summary: {
        trajectory_recall: 1,
        benign_false_positive_rate: 0,
        maximum_detection_delay_events: 0,
      },
    },
    decision: {
      evaluation_status: "pass",
      boundary_status: "breach",
      required_action: "human_review_required",
    },
    privacy: {contains_prompts: false, contains_credentials: false},
  };
  const summary = explorer.summarizeArtifact(entry);

  assert.equal(summary.kind, "LureBoundary entry");
  assert.equal(summary.status, "breach");
  assert.equal(summary.tone, "fail");
  assert.equal(summary.metrics.find(item => item.label === "Required action").value, "human_review_required");
  assert.equal(summary.bindings.length, 4);
  assert.match(summary.warnings.join(" "), /not proof of deployment containment/i);
});

test("signed LureBoundary checkpoint never claims browser authentication", () => {
  const checkpoint = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {name: "boundary-plan.json", digest: {sha256: sha("d")}},
      {name: "evaluations/00000001.json", digest: {sha256: sha("e")}},
      {name: "entries/00000001.json", digest: {sha256: sha("f")}},
    ],
    predicateType: "https://github.com/immu4989/lurescope/spec/lureboundary-checkpoint/v1",
    predicate: {
      sequence: 1,
      boundary_status: "pass",
      required_action: "none",
      authentication_mode: "ecdsa-p256-dsse",
      previous_statement_sha256: null,
      limitations: ["synthetic_suite_performance_does_not_establish_deployment_containment"],
    },
  };
  const envelope = {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(checkpoint), "utf8").toString("base64"),
    signatures: [{keyid: sha("1"), sig: "AAAA"}],
  };
  const summary = explorer.summarizeArtifact(envelope);

  assert.equal(summary.kind, "LureBoundary checkpoint");
  assert.equal(summary.signature.authenticated, false);
  assert.match(summary.warnings[0], /not cryptographically authenticated/i);
});

test("LureCoverage and LureDelegation expose operational assurance metrics", () => {
  const coverage = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurebench/spec/agent-coverage-evaluation/v1",
    manifest: {manifest_sha256: sha("a")},
    canaries_sha256: sha("b"),
    summary: {
      route_coverage: 1,
      probe_delivery_rate: 0.95,
      duplicate_rate: 0.01,
      out_of_order_rate: 0,
      lineage_continuity: 0.99,
      maximum_delivery_delay_ms: 25,
      verdict: "pass",
    },
    limitations: ["coverage_applies_only_to_declared_routes"],
  });
  assert.equal(coverage.kind, "LureCoverage evaluation");
  assert.equal(coverage.status, "pass");
  assert.equal(coverage.metrics.find(item => item.label === "Probe delivery").value, "95.0%");
  assert.equal(coverage.bindings.length, 2);

  const delegation = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurebench/spec/agent-delegation-evaluation/v1",
    suite: {suite_sha256: sha("c")},
    summary: {
      total_scenarios: 14,
      recall: 1,
      benign_false_positive_rate: 0,
      category_accuracy: 1,
      maximum_detection_delay_events: 0,
      verdict: "pass",
    },
    limitations: ["synthetic_metadata_only"],
  });
  assert.equal(delegation.kind, "LureDelegation evaluation");
  assert.equal(delegation.metrics.find(item => item.label === "Scenarios").value, "14");
  assert.ok(delegation.privacy.includes("no tokens or credential values"));
});

test("combined portfolio and witness receipt stay explicit about browser trust", () => {
  const portfolio = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/agent-assurance-portfolio/v1",
    overall_status: "pass",
    boundary: {
      status: "pass",
      checkpoint_sequence: 2,
      plan_sha256: sha("a"),
      checkpoint_statement_sha256: sha("b"),
    },
    evidence: [
      {kind: "coverage", verdict: "pass", sha256: sha("c")},
      {kind: "delegation", verdict: "pass", sha256: sha("d")},
      {kind: "incident_response", verdict: "pass", sha256: sha("e")},
    ],
    limitations: ["passing_is_not_proof_of_containment"],
  });
  assert.equal(portfolio.kind, "Agent assurance portfolio");
  assert.equal(portfolio.status, "pass");
  assert.equal(portfolio.bindings.length, 5);

  const receipt = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/checkpoint-witness-receipt/v1",
    witness: {witness_id: "auditor-a", key_id: sha("f")},
    statement: {
      predicate: {
        bundle_kind: "lureboundary",
        checkpoint_sequence: 2,
        status: "pass",
        request_sha256: sha("1"),
        checkpoint_statement_sha256: sha("2"),
      },
    },
    dsse: {payloadType: "application/vnd.in-toto+json", payload: "", signatures: []},
    limitations: ["receipt_proves_observation_by_a_key"],
  });
  assert.equal(receipt.kind, "Checkpoint witness receipt");
  assert.match(receipt.signature.label, /DSSE signature present/i);
  assert.equal(receipt.signature.authenticated, false);
  assert.match(receipt.warnings[0], /unsigned|not authenticated/i);
});

test("unsupported, malformed, and oversized evidence fails closed", () => {
  assert.throws(() => explorer.parseArtifact("not-json"), /not valid JSON/i);
  assert.throws(() => explorer.summarizeArtifact({schema: "unknown"}), /Unsupported evidence/);
  assert.throws(() => explorer.summarizeArtifact({
    payloadType: "application/vnd.in-toto+json",
    payload: "%%%not-base64%%%",
    signatures: [{sig: "x"}],
  }), /base64|oversized/i);
  assert.throws(
    () => explorer.parseArtifact(" ".repeat(explorer.MAX_ARTIFACT_BYTES + 1)),
    /8 MB safety limit/i,
  );
});
