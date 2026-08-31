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

test("LureRange evaluation exposes permit controls and exact bindings", () => {
  const evaluation = {
    schema: "https://github.com/immu4989/lurebench/spec/lurerange-evaluation-v1",
    engine: {engine_id: "policy-gateway", engine_version: "2.0.0", artifact_sha256: sha("c")},
    inputs: {permit_sha256: sha("a"), range_suite_sha256: sha("b")},
    summary: {
      total_scenarios: 21,
      violation_control_rate: 1,
      benign_allow_rate: 1,
      reason_accuracy: 1,
      safe_stop_recall: 1,
      verdict: "pass",
    },
    limitations: ["passing_is_not_containment_safety_compliance_certification_or_deployment_authorization"],
  };
  const summary = explorer.summarizeArtifact(evaluation);

  assert.equal(summary.kind, "LureRange evaluation");
  assert.equal(summary.status, "pass");
  assert.equal(summary.metrics.find(item => item.label === "Safe-stop recall").value, "100.0%");
  assert.equal(summary.bindings.length, 3);
  assert.match(summary.privacy.join(" "), /no targets/i);
  assert.deepEqual(evaluation.limitations, ["passing_is_not_containment_safety_compliance_certification_or_deployment_authorization"]);
});

test("LureRange bundle and comparison expose verification boundaries", () => {
  const bundle = {
    schema: "https://github.com/immu4989/lurescope/spec/lurerange-evidence-bundle/v1",
    bundle_id: "range-1",
    system: {system_id: "system-a", environment: "evaluation"},
    engine: {engine_id: "policy-gateway", engine_version: "2.0.0", artifact_sha256: sha("e")},
    evidence: {sha256: sha("a"), permit_sha256: sha("b"), range_suite_sha256: sha("c")},
    overall_status: "pass",
    authentication: {mode: "ecdsa-p256-dsse", signer_key_id: sha("d")},
    limitations: ["source_engine_not_attested"],
  };
  const bundleSummary = explorer.summarizeArtifact(bundle);
  assert.equal(bundleSummary.kind, "LureRange evidence bundle");
  assert.equal(bundleSummary.status, "pass");
  assert.match(bundleSummary.warnings.join(" "), /lurescope range verify/);
  assert.deepEqual(bundle.limitations, ["source_engine_not_attested"]);

  const comparison = {
    schema: "https://github.com/immu4989/lurescope/spec/lurerange-remediation-comparison/v1",
    contract: {permit_sha256: sha("a"), range_suite_sha256: sha("b"), engine_id: "policy-gateway"},
    before: {manifest_sha256: sha("c"), overall_status: "fail"},
    after: {manifest_sha256: sha("d"), overall_status: "pass"},
    summary: {resolved: 3, persistent: 0, new: 0, status: "effective"},
    limitations: ["causality_not_proven"],
  };
  const comparisonSummary = explorer.summarizeArtifact(comparison);
  assert.equal(comparisonSummary.kind, "LureRange remediation comparison");
  assert.equal(comparisonSummary.status, "effective");
  assert.match(comparisonSummary.warnings.join(" "), /verify-comparison/);
  assert.deepEqual(comparison.limitations, ["causality_not_proven"]);
});

test("signed LureRange checkpoint remains unauthenticated in browser inspection", () => {
  const checkpoint = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {name: "bundle.json", digest: {sha256: sha("a")}},
      {name: "evidence/lurerange-evaluation.json", digest: {sha256: sha("b")}},
    ],
    predicateType: "https://github.com/immu4989/lurescope/spec/lurerange-evidence-checkpoint/v1",
    predicate: {
      bundle_id: "range-1",
      engine_id: "policy-gateway",
      overall_status: "pass",
      authentication_mode: "ecdsa-p256-dsse",
      permit_sha256: sha("c"),
      range_suite_sha256: sha("d"),
      limitations: ["source_engine_not_attested"],
    },
  };
  const envelope = {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(checkpoint), "utf8").toString("base64"),
    signatures: [{keyid: sha("1"), sig: "AAAA"}],
  };
  const summary = explorer.summarizeArtifact(envelope);

  assert.equal(summary.kind, "LureRange checkpoint");
  assert.equal(summary.status, "pass");
  assert.equal(summary.signature.authenticated, false);
  assert.match(summary.warnings[0], /not cryptographically authenticated/i);
});

test("runtime mediation artifacts expose coverage, bypasses, and verification boundaries", () => {
  const evaluation = {
    schema: "https://github.com/immu4989/lurebench/spec/lurepermit-runtime-evaluation-v1",
    trace_sha256: sha("a"),
    trace: {profile_sha256: sha("b"), profile: {permit_sha256: sha("c")}},
    summary: {total_requests: 11, decision_accuracy: 1, reason_accuracy: 1, mediation_coverage_rate: 1, mediation_point_coverage_rate: 1, control_bypass_count: 0, unmediated_count: 0, unknown_count: 0, verdict: "pass"},
    limitations: ["sensor_completeness_not_proven"],
  };
  const evaluationSummary = explorer.summarizeArtifact(evaluation);
  assert.equal(evaluationSummary.kind, "Runtime mediation evaluation");
  assert.equal(evaluationSummary.status, "pass");
  assert.equal(evaluationSummary.metrics.find(item => item.label === "Point coverage").value, "100.0%");
  assert.equal(evaluationSummary.metrics.find(item => item.label === "Decision accuracy").value, "100.0%");
  assert.equal(evaluationSummary.bindings.length, 3);

  const bundle = {
    schema: "https://github.com/immu4989/lurescope/spec/runtime-mediation-evidence-bundle/v1",
    bundle_id: "runtime-1",
    system: {system_id: "system-a", environment: "production"},
    profile: {profile_sha256: sha("a"), permit_sha256: sha("b")},
    policy: {engine_id: "policy-gateway", engine_version: "2.0.0"},
    evidence: {sha256: sha("c"), trace_sha256: sha("d")},
    overall_status: "fail",
    authentication: {mode: "unsigned", signer_key_id: null},
    limitations: ["complete_observation_not_proven"],
  };
  const bundleSummary = explorer.summarizeArtifact(bundle);
  assert.equal(bundleSummary.kind, "Runtime mediation evidence bundle");
  assert.equal(bundleSummary.status, "fail");
  assert.match(bundleSummary.warnings.join(" "), /lurescope runtime verify/);

  const comparison = {
    schema: "https://github.com/immu4989/lurescope/spec/runtime-mediation-remediation-comparison/v1",
    contract: {profile_sha256: sha("a"), permit_sha256: sha("b"), policy_engine_id: "policy-gateway"},
    before: {manifest_sha256: sha("c"), overall_status: "fail"},
    after: {manifest_sha256: sha("d"), overall_status: "pass"},
    summary: {resolved: 2, persistent: 0, new: 0, status: "effective"},
    limitations: ["causality_not_proven"],
  };
  const comparisonSummary = explorer.summarizeArtifact(comparison);
  assert.equal(comparisonSummary.kind, "Runtime mediation remediation comparison");
  assert.equal(comparisonSummary.status, "effective");
  assert.match(comparisonSummary.warnings.join(" "), /verify-comparison/);
});

test("signed runtime checkpoint remains unauthenticated in browser inspection", () => {
  const checkpoint = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {name: "bundle.json", digest: {sha256: sha("a")}},
      {name: "evidence/runtime-evaluation.json", digest: {sha256: sha("b")}},
    ],
    predicateType: "https://github.com/immu4989/lurescope/spec/runtime-mediation-evidence-checkpoint/v1",
    predicate: {
      bundle_id: "runtime-1",
      policy_engine_id: "policy-gateway",
      overall_status: "pass",
      authentication_mode: "ecdsa-p256-dsse",
      profile_sha256: sha("c"),
      permit_sha256: sha("d"),
      trace_sha256: sha("e"),
      limitations: ["sensor_truth_not_proven"],
    },
  };
  const envelope = {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(checkpoint), "utf8").toString("base64"),
    signatures: [{keyid: sha("1"), sig: "AAAA"}],
  };
  const summary = explorer.summarizeArtifact(envelope);
  assert.equal(summary.kind, "Runtime mediation checkpoint");
  assert.equal(summary.signature.authenticated, false);
  assert.equal(summary.bindings.length, 5);
});

test("LureRevoke artifacts expose convergence and independent verification boundaries", () => {
  const evaluation = {
    schema: "https://github.com/immu4989/lurebench/spec/lurerevoke-evaluation-v1",
    plan_sha256: sha("a"),
    run_sha256: sha("b"),
    run: {implementation: {name: "receiver-a", artifact_sha256: sha("c")}},
    summary: {
      delivery_coverage_rate: 1,
      p95_convergence_ms: 350,
      maximum_convergence_ms: 400,
      deadline_miss_count: 0,
      post_deadline_allow_count: 0,
      collateral_block_count: 0,
      revoked_block_recall: 1,
      verdict: "pass",
    },
    limitations: ["complete_delivery_not_proven"],
  };
  const evaluationSummary = explorer.summarizeArtifact(evaluation);
  assert.equal(evaluationSummary.kind, "LureRevoke evaluation");
  assert.equal(evaluationSummary.status, "pass");
  assert.equal(evaluationSummary.metrics.find(item => item.label === "p95 convergence").value, "350 ms");
  assert.equal(evaluationSummary.bindings.length, 3);

  const bundle = {
    schema: "https://github.com/immu4989/lurescope/spec/lurerevoke-evidence-bundle/v1",
    bundle_id: "revoke-1",
    plan: {plan_sha256: sha("a")},
    receiver: {name: "receiver-a", artifact_sha256: sha("b")},
    evidence: {sha256: sha("c"), run_sha256: sha("d")},
    summary: {
      delivery_coverage_rate: 0.75,
      p95_convergence_ms: 700,
      deadline_miss_count: 1,
      post_deadline_allow_count: 1,
    },
    overall_status: "fail",
    authentication: {mode: "unsigned", signer_key_id: null},
    limitations: ["receiver_authenticity_not_proven"],
  };
  const bundleSummary = explorer.summarizeArtifact(bundle);
  assert.equal(bundleSummary.kind, "LureRevoke evidence bundle");
  assert.equal(bundleSummary.status, "fail");
  assert.match(bundleSummary.warnings.join(" "), /lurescope revoke verify/);

  const comparison = {
    schema: "https://github.com/immu4989/lurescope/spec/lurerevoke-remediation-comparison/v1",
    contract: {plan_sha256: sha("e"), receiver_name: "receiver-a"},
    before: {overall_status: "fail", manifest_sha256: sha("f"), statement_sha256: sha("1")},
    after: {overall_status: "pass", manifest_sha256: sha("2"), statement_sha256: sha("3")},
    metric_deltas: {delivery_coverage_rate_delta: 0.25, p95_convergence_ms_delta: -350},
    summary: {resolved: 2, persistent: 0, new: 0, status: "effective"},
    limitations: ["configuration_change_causality_is_not_proven"],
  };
  const comparisonSummary = explorer.summarizeArtifact(comparison);
  assert.equal(comparisonSummary.kind, "LureRevoke remediation comparison");
  assert.equal(comparisonSummary.status, "effective");
  assert.equal(comparisonSummary.bindings.length, 5);
  assert.match(comparisonSummary.warnings.join(" "), /verify-comparison/i);
});

test("signed LureRevoke checkpoint remains unauthenticated in browser inspection", () => {
  const checkpoint = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {name: "bundle.json", digest: {sha256: sha("a")}},
      {name: "evidence/revocation-evaluation.json", digest: {sha256: sha("b")}},
    ],
    predicateType: "https://github.com/immu4989/lurescope/spec/lurerevoke-evidence-checkpoint/v1",
    predicate: {
      bundle_id: "revoke-1",
      receiver_name: "receiver-a",
      overall_status: "pass",
      authentication_mode: "ecdsa-p256-dsse",
      plan_sha256: sha("c"),
      run_sha256: sha("d"),
      limitations: ["receiver_authenticity_not_proven"],
    },
  };
  const envelope = {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(checkpoint), "utf8").toString("base64"),
    signatures: [{keyid: sha("1"), sig: "AAAA"}],
  };
  const summary = explorer.summarizeArtifact(envelope);
  assert.equal(summary.kind, "LureRevoke checkpoint");
  assert.equal(summary.signature.authenticated, false);
  assert.equal(summary.bindings.length, 4);
});

test("LureRevoke registry artifacts expose Merkle bindings without claiming verification", () => {
  const registry = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/lurerevoke-registry/v1",
    registry_id: "agency-history",
    registration_policy: {
      system_id: "agent-platform",
      environment: "production",
      receiver_name: "caep-receiver",
      require_authenticated_bundle: true,
    },
    hash_profile: "rfc9162-sha256-merkle-tree",
    signer_key_id: sha("a"),
    limitations: ["tail_deletion_requires_a_retained_head"],
  });
  assert.equal(registry.kind, "LureRevoke registry");
  assert.equal(registry.bindings.length, 1);
  assert.match(registry.warnings.join(" "), /registry-verify/i);

  const entry = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-entry/v1",
    sequence: 2,
    registered_at: "2026-08-30T12:00:00Z",
    previous_entry_sha256: sha("b"),
    receiver: {
      name: "caep-receiver",
      version: "1.1.0",
      bundle_signer_key_id: sha("c"),
    },
    evidence: {
      overall_status: "pass",
      manifest_sha256: sha("d"),
      checkpoint_sha256: sha("e"),
      plan_sha256: sha("f"),
      run_sha256: sha("1"),
    },
    limitations: ["registration_is_not_enforcement_proof"],
  });
  assert.equal(entry.kind, "LureRevoke registry entry");
  assert.equal(entry.status, "pass");
  assert.equal(entry.bindings.length, 6);

  const head = explorer.summarizeArtifact({
    _type: "https://in-toto.io/Statement/v1",
    subject: [{name: "entry.json", digest: {sha256: sha("2")}}],
    predicateType: "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-tree-head/v1",
    predicate: {
      registry_id: "agency-history",
      tree_size: 2,
      hash_profile: "rfc9162-sha256-merkle-tree",
      registered_at: "2026-08-30T12:00:00Z",
      root_sha256: sha("3"),
      latest_entry_sha256: sha("4"),
      previous_tree_head_sha256: sha("5"),
      config_sha256: sha("6"),
      signer_key_id: sha("7"),
      limitations: ["tail_deletion_requires_a_retained_head"],
    },
  });
  assert.equal(head.kind, "LureRevoke registry tree head");
  assert.equal(head.bindings.length, 6);
  assert.match(head.warnings.join(" "), /does not authenticate DSSE/i);
});

test("LureRevoke inclusion proof exposes portable membership without claiming browser verification", () => {
  const summary = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-inclusion-proof/v1",
    registry_config: {registry_id: "agency-history", signer_key_id: sha("a")},
    tree_size: 9,
    sequence: 4,
    leaf_index: 3,
    entry_sha256: sha("b"),
    leaf_sha256: sha("c"),
    root_sha256: sha("d"),
    inclusion_path_sha256: [sha("e"), sha("f"), sha("1"), sha("2")],
    entry: {
      receiver: {name: "caep-receiver"},
      evidence: {
        overall_status: "pass",
        manifest_sha256: sha("3"),
        checkpoint_sha256: sha("4"),
      },
    },
    limitations: ["proof_does_not_establish_global_non_equivocation"],
  });
  assert.equal(summary.kind, "LureRevoke registry inclusion proof");
  assert.equal(summary.metrics[3].value, "4");
  assert.equal(summary.bindings.length, 6);
  assert.match(summary.warnings.join(" "), /registry-verify-inclusion/i);
});

test("LureRevoke consistency proof exposes append-only evidence without claiming verification", () => {
  const summary = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-consistency-proof/v1",
    registry_config: {registry_id: "agency-history", signer_key_id: sha("a")},
    first_tree_size: 8,
    first_root_sha256: sha("b"),
    second_tree_size: 13,
    second_root_sha256: sha("c"),
    consistency_path_sha256: [sha("d"), sha("e"), sha("f")],
    limitations: ["proof_does_not_establish_global_non_equivocation"],
  });
  assert.equal(summary.kind, "LureRevoke registry consistency proof");
  assert.equal(summary.metrics[3].value, "5");
  assert.equal(summary.bindings.length, 3);
  assert.match(summary.warnings.join(" "), /registry-verify-consistency/i);
});

test("LureRevoke head comparison makes same-size equivocation visible", () => {
  const summary = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-head-comparison/v1",
    registry_config: {registry_id: "agency-history", signer_key_id: sha("a")},
    summary: {
      first_tree_size: 12,
      first_root_sha256: sha("b"),
      first_statement_sha256: sha("c"),
      second_tree_size: 12,
      second_root_sha256: sha("d"),
      second_statement_sha256: sha("e"),
      same_tree_size: true,
      same_root: false,
      same_statement: false,
      status: "equivocation",
    },
    limitations: ["unpresented_conflicting_heads_are_not_established"],
  });
  assert.equal(summary.kind, "LureRevoke registry head comparison");
  assert.equal(summary.status, "equivocation");
  assert.equal(summary.tone, "fail");
  assert.equal(summary.bindings.length, 5);
  assert.match(summary.warnings.join(" "), /verify-head-comparison/i);
});

test("LureRevoke topology audit exposes declared scope and exact input bindings", () => {
  const summary = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurebench/spec/lurerevoke-topology-audit/v1",
    inputs: {
      revocation_plan_sha256: sha("a"),
      runtime_profile_sha256: sha("b"),
    },
    summary: {
      required_mediation_point_count: 9,
      covered_mediation_point_count: 8,
      missing_mediation_point_count: 1,
      unmapped_node_count: 0,
      mediation_point_coverage_rate: 8 / 9,
      verdict: "fail",
    },
    limitations: ["a_pass_does_not_prove_discovery_completeness"],
  });
  assert.equal(summary.kind, "LureRevoke topology audit");
  assert.equal(summary.status, "fail");
  assert.equal(summary.bindings.length, 2);
  assert.match(summary.warnings.join(" "), /verify-topology/i);
});

test("LureRevoke OpenTelemetry projection exposes bindings and clock boundary", () => {
  const summary = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurebench/spec/lurerevoke-otel-projection/v1",
    inputs: {
      revocation_plan_sha256: sha("a"),
      otel_log_export_sha256: sha("b"),
      otel_log_export: {
        receiver: {name: "caep-receiver"},
        records: [{EventName: "signal"}, {EventName: "access"}],
      },
    },
    run: {signal_observations: [{}], access_observations: [{}]},
    run_sha256: sha("c"),
    clock_boundary: {
      benchmark_time_field: "Timestamp",
      observed_timestamp_used_for_benchmark_timing: false,
    },
    limitations: ["projection_does_not_prove_telemetry_completeness"],
  });
  assert.equal(summary.kind, "LureRevoke OpenTelemetry projection");
  assert.equal(summary.metrics[0].value, "2");
  assert.equal(summary.metrics[5].value, "no");
  assert.equal(summary.bindings.length, 3);
  assert.match(summary.warnings.join(" "), /verify-otel/i);
});

test("LureRevoke deployment gate exposes exact cross-artifact bindings", () => {
  const summary = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/lurerevoke-deployment-gate/v1",
    system: {system_id: "agent-platform", environment: "production"},
    policy: {
      maximum_allowed_convergence_ms: 750,
      declared_convergence_ms: 500,
      minimum_run_generated_at: "2026-08-30T00:00:00Z",
      expected_system_id: "agent-platform",
      expected_environment: "production",
      expected_receiver_name: "caep-receiver",
      expected_receiver_artifact_sha256: sha("3"),
    },
    contract: {plan_sha256: sha("a"), run_sha256: sha("b")},
    sources: {
      topology_audit: {
        sha256: sha("c"),
        verdict: "pass",
        covered_mediation_point_count: 9,
        required_mediation_point_count: 9,
      },
      otel_projection: {
        sha256: sha("d"),
        source_export_sha256: sha("e"),
        record_count: 80,
      },
      revocation_evidence: {
        manifest_sha256: sha("f"),
        checkpoint_sha256: sha("1"),
        signer_key_id: sha("2"),
        overall_status: "pass",
      },
    },
    checks: [
      {check_id: "declared_topology_complete", status: "pass"},
      {check_id: "runtime_topology_preregistered", status: "pass"},
      {check_id: "probe_phase_coverage_complete", status: "pass"},
      {check_id: "strict_acceptance_thresholds", status: "pass"},
      {check_id: "convergence_deadline_within_policy", status: "pass"},
      {check_id: "run_freshness_matches_policy", status: "pass"},
      {check_id: "deployment_identity_matches_policy", status: "pass"},
      {check_id: "telemetry_projection_recomputed", status: "pass"},
      {check_id: "source_bundle_authenticated", status: "pass"},
      {check_id: "revocation_acceptance_met", status: "pass"},
    ],
    overall_status: "pass",
    limitations: ["a_pass_does_not_prove_enforcement"],
  });
  assert.equal(summary.kind, "LureRevoke deployment gate");
  assert.equal(summary.status, "pass");
  assert.equal(summary.metrics.find(item => item.label === "Coverage").value, "9 / 9");
  assert.equal(summary.metrics.find(item => item.label === "Convergence").value, "500 / 750 ms");
  assert.equal(
    summary.metrics.find(item => item.label === "Run accepted from").value,
    "2026-08-30T00:00:00Z",
  );
  assert.equal(summary.bindings.length, 9);
  assert.match(summary.warnings.join(" "), /verify-gate/i);
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

test("LureInvariant plan and evaluation expose bounded graph evidence", () => {
  const plan = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurebench/spec/agent-invariant-plan/v1",
    nodes: [{node_id: "agent"}, {node_id: "network"}],
    edges: [{edge_id: "agent-network"}],
    invariants: [{invariant_id: "no-egress"}],
    sources: [{source_id: "topology"}],
    acceptance: {maximum_violations: 0, allow_insufficient_evidence: false},
    limitations: ["declared_inventory_and_operator_observations_only"],
  });
  assert.equal(plan.kind, "LureInvariant plan");
  assert.equal(plan.metrics.find(item => item.label === "Invariants").value, "1");

  const evaluation = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurebench/spec/agent-invariant-evaluation/v1",
    plan: {plan_sha256: sha("a")},
    observations: {observations_sha256: sha("b")},
    summary: {
      total_invariants: 4,
      violated: 1,
      not_observed_within_declared_boundary: 2,
      insufficient_evidence: 1,
      source_coverage: 0.5,
      unknown_edges: 1,
      verdict: "fail",
    },
    limitations: ["incomplete_sources_produce_insufficient_evidence"],
  });
  assert.equal(evaluation.kind, "LureInvariant evaluation");
  assert.equal(evaluation.status, "fail");
  assert.equal(evaluation.tone, "fail");
  assert.equal(evaluation.metrics.find(item => item.label === "Source coverage").value, "50.0%");
  assert.equal(evaluation.bindings.length, 2);
});

test("LureInvariant bundle and comparison retain claims boundaries", () => {
  const bundle = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/invariant-evidence-bundle/v1",
    bundle_id: "after-1",
    system: {environment: "evaluation"},
    overall_status: "pass",
    authentication: {mode: "ecdsa-p256-dsse", signer_key_id: sha("1")},
    evidence: [
      {kind: "plan", file: "evidence/plan.json", sha256: sha("a"), verdict: "not_applicable"},
      {kind: "observations", file: "evidence/observations.json", sha256: sha("b"), verdict: "not_applicable"},
      {kind: "evaluation", file: "evidence/evaluation.json", sha256: sha("c"), verdict: "pass"},
    ],
    limitations: ["passing_is_not_proof_of_containment"],
  });
  assert.equal(bundle.kind, "LureInvariant evidence bundle");
  assert.equal(bundle.status, "pass");
  assert.equal(bundle.bindings.length, 4);
  assert.match(bundle.warnings.join(" "), /trusted public key/i);

  const comparison = explorer.summarizeArtifact({
    schema: "https://github.com/immu4989/lurescope/spec/invariant-remediation-comparison/v1",
    contract_sha256: sha("d"),
    before: {overall_status: "fail", manifest_sha256: sha("e"), statement_sha256: sha("f")},
    after: {overall_status: "pass", manifest_sha256: sha("2"), statement_sha256: sha("3")},
    summary: {resolved: 4, persistent: 0, new: 0, insufficient_after: 0, status: "effective"},
    limitations: ["configuration_change_causality_is_not_proven"],
  });
  assert.equal(comparison.kind, "LureInvariant remediation comparison");
  assert.equal(comparison.status, "effective");
  assert.equal(comparison.tone, "warn");
  assert.equal(comparison.bindings.length, 5);
  assert.match(comparison.warnings.join(" "), /verify-comparison/i);
});

test("signed LureInvariant checkpoint never claims browser authentication", () => {
  const checkpoint = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {name: "bundle.json", digest: {sha256: sha("a")}},
      {name: "evidence/plan.json", digest: {sha256: sha("b")}},
      {name: "evidence/observations.json", digest: {sha256: sha("c")}},
      {name: "evidence/evaluation.json", digest: {sha256: sha("d")}},
    ],
    predicateType: "https://github.com/immu4989/lurescope/spec/invariant-evidence-checkpoint/v1",
    predicate: {
      bundle_id: "after-1",
      overall_status: "pass",
      authentication_mode: "ecdsa-p256-dsse",
      limitations: ["signed_evidence_authenticates_a_key_not_an_organization"],
    },
  };
  const envelope = {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(checkpoint), "utf8").toString("base64"),
    signatures: [{keyid: sha("1"), sig: "AAAA"}],
  };
  const summary = explorer.summarizeArtifact(envelope);
  assert.equal(summary.kind, "LureInvariant checkpoint");
  assert.equal(summary.status, "pass");
  assert.equal(summary.signature.authenticated, false);
  assert.match(summary.warnings[0], /not cryptographically authenticated/i);
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
