(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.LureScopeEvidence = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
  const RECEIPT = "https://github.com/immu4989/lurebench/spec/lureeval-receipt/v1";
  const AGGREGATE = "https://github.com/immu4989/lurebench/spec/lureeval-aggregate/v1";
  const LUREPROOF = "https://github.com/immu4989/lurescope/spec/lureproof/v0.2";
  const COMBINED = "https://github.com/immu4989/lurescope/spec/combined-email-assurance/v1";
  const DRIFT = "https://github.com/immu4989/lurescope/spec/scuba-assurance-drift-statement/v1";
  const PILOT_GATE = "https://github.com/immu4989/lurescope/spec/pilot-gate/v1";
  const SHADOW_REPORT = "https://github.com/immu4989/lurescope/spec/shadow-report/v1";
  const DEFENDER_REPORT = "https://github.com/immu4989/lurescope/spec/defender-report/v1";
  const LUREWATCH_ENTRY = "https://github.com/immu4989/lurescope/spec/lurewatch-entry/v1";
  const LUREWATCH_CHECKPOINT = "https://github.com/immu4989/lurescope/spec/lurewatch-checkpoint/v1";
  const LUREBOUNDARY_EVALUATION = "https://github.com/immu4989/lurebench/spec/agent-boundary-evaluation/v1";
  const LUREBOUNDARY_PLAN = "https://github.com/immu4989/lurescope/spec/lureboundary-plan/v1";
  const LUREBOUNDARY_ENTRY = "https://github.com/immu4989/lurescope/spec/lureboundary-entry/v1";
  const LUREBOUNDARY_CHECKPOINT = "https://github.com/immu4989/lurescope/spec/lureboundary-checkpoint/v1";
  const COVERAGE_EVALUATION = "https://github.com/immu4989/lurebench/spec/agent-coverage-evaluation/v1";
  const DELEGATION_EVALUATION = "https://github.com/immu4989/lurebench/spec/agent-delegation-evaluation/v1";
  const IR_EVALUATION = "https://github.com/immu4989/lurebench/spec/lureir-evaluation/v1";
  const AGENT_PORTFOLIO = "https://github.com/immu4989/lurescope/spec/agent-assurance-portfolio/v1";
  const AGENT_CHECKPOINT = "https://github.com/immu4989/lurescope/spec/agent-assurance-checkpoint/v1";
  const WITNESS_REQUEST = "https://github.com/immu4989/lurescope/spec/checkpoint-witness-request/v1";
  const WITNESS_RECEIPT = "https://github.com/immu4989/lurescope/spec/checkpoint-witness-receipt/v1";
  const INVARIANT_PLAN = "https://github.com/immu4989/lurebench/spec/agent-invariant-plan/v1";
  const INVARIANT_EVALUATION = "https://github.com/immu4989/lurebench/spec/agent-invariant-evaluation/v1";
  const INVARIANT_BUNDLE = "https://github.com/immu4989/lurescope/spec/invariant-evidence-bundle/v1";
  const INVARIANT_COMPARISON = "https://github.com/immu4989/lurescope/spec/invariant-remediation-comparison/v1";
  const INVARIANT_CHECKPOINT = "https://github.com/immu4989/lurescope/spec/invariant-evidence-checkpoint/v1";
  const RANGE_EVALUATION = "https://github.com/immu4989/lurebench/spec/lurerange-evaluation-v1";
  const RANGE_BUNDLE = "https://github.com/immu4989/lurescope/spec/lurerange-evidence-bundle/v1";
  const RANGE_COMPARISON = "https://github.com/immu4989/lurescope/spec/lurerange-remediation-comparison/v1";
  const RANGE_CHECKPOINT = "https://github.com/immu4989/lurescope/spec/lurerange-evidence-checkpoint/v1";
  const RUNTIME_EVALUATION = "https://github.com/immu4989/lurebench/spec/lurepermit-runtime-evaluation-v1";
  const RUNTIME_BUNDLE = "https://github.com/immu4989/lurescope/spec/runtime-mediation-evidence-bundle/v1";
  const RUNTIME_COMPARISON = "https://github.com/immu4989/lurescope/spec/runtime-mediation-remediation-comparison/v1";
  const RUNTIME_CHECKPOINT = "https://github.com/immu4989/lurescope/spec/runtime-mediation-evidence-checkpoint/v1";
  const REVOKE_EVALUATION = "https://github.com/immu4989/lurebench/spec/lurerevoke-evaluation-v1";
  const REVOKE_BUNDLE = "https://github.com/immu4989/lurescope/spec/lurerevoke-evidence-bundle/v1";
  const REVOKE_COMPARISON = "https://github.com/immu4989/lurescope/spec/lurerevoke-remediation-comparison/v1";
  const REVOKE_CHECKPOINT = "https://github.com/immu4989/lurescope/spec/lurerevoke-evidence-checkpoint/v1";
  const REVOKE_REGISTRY = "https://github.com/immu4989/lurescope/spec/lurerevoke-registry/v1";
  const REVOKE_REGISTRY_ENTRY = "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-entry/v1";
  const REVOKE_REGISTRY_HEAD = "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-tree-head/v1";
  const REVOKE_REGISTRY_INCLUSION = "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-inclusion-proof/v1";
  const REVOKE_REGISTRY_CONSISTENCY = "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-consistency-proof/v1";
  const REVOKE_REGISTRY_HEAD_COMPARISON = "https://github.com/immu4989/lurescope/spec/lurerevoke-registry-head-comparison/v1";
  const REVOKE_TOPOLOGY_AUDIT = "https://github.com/immu4989/lurebench/spec/lurerevoke-topology-audit/v1";
  const REVOKE_OTEL_PROJECTION = "https://github.com/immu4989/lurebench/spec/lurerevoke-otel-projection/v1";
  const REVOKE_DEPLOYMENT_GATE = "https://github.com/immu4989/lurescope/spec/lurerevoke-deployment-gate/v1";

  function object(value, field) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`${field} must be a JSON object`);
    }
    return value;
  }

  function decodeBase64(value) {
    if (typeof value !== "string" || value.length > MAX_ARTIFACT_BYTES * 2 ||
        value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
      throw new Error("DSSE payload is missing or oversized");
    }
    try {
      if (typeof Buffer !== "undefined") return Buffer.from(value, "base64").toString("utf8");
      const binary = atob(value);
      const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
      return new TextDecoder("utf-8", {fatal: true}).decode(bytes);
    } catch (error) {
      throw new Error("DSSE payload is not valid base64 UTF-8");
    }
  }

  function unwrap(value) {
    const artifact = object(value, "artifact");
    const envelopeKeys = ["payloadType", "payload", "signatures"];
    const isEnvelope = envelopeKeys.every(key => Object.hasOwn(artifact, key));
    if (!isEnvelope) return {statement: artifact, signed: false, signatureCount: 0};
    if (Object.keys(artifact).some(key => !envelopeKeys.includes(key))) {
      throw new Error("DSSE envelope contains unsupported fields");
    }
    if (artifact.payloadType !== "application/vnd.in-toto+json") {
      throw new Error("Unsupported DSSE payload type");
    }
    if (!Array.isArray(artifact.signatures) || artifact.signatures.length < 1 || artifact.signatures.length > 16) {
      throw new Error("DSSE envelope has an invalid signature list");
    }
    let statement;
    try {
      statement = JSON.parse(decodeBase64(artifact.payload));
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error("DSSE payload is not JSON");
      throw error;
    }
    return {statement: object(statement, "DSSE statement"), signed: true, signatureCount: artifact.signatures.length};
  }

  function ratio(value) {
    return value === null || value === undefined ? "Not measurable" : `${(Number(value) * 100).toFixed(1)}%`;
  }

  function count(value) {
    return Number(value || 0).toLocaleString("en-US");
  }

  function digest(value) {
    return typeof value === "string" && /^[a-f0-9]{64}$/.test(value) ? value : null;
  }

  function binding(label, value) {
    const checked = digest(value);
    return checked ? {label, value: `sha256:${checked}`} : null;
  }

  function signatureSummary(meta) {
    return meta.signed
      ? {label: `${meta.signatureCount} DSSE signature${meta.signatureCount === 1 ? "" : "s"} present`, authenticated: false}
      : {label: "Unsigned statement", authenticated: false};
  }

  function base(kind, title, description, meta) {
    return {
      kind,
      title,
      description,
      status: "Inspected",
      tone: "neutral",
      metrics: [],
      bindings: [],
      privacy: [],
      warnings: [],
      signature: signatureSummary(meta),
    };
  }

  function gateStatus(summary, verdict) {
    const normalized = String(verdict || "unknown");
    summary.status = normalized.replaceAll("_", " ");
    summary.tone = normalized === "pass"
      ? "pass" : ["fail", "breach"].includes(normalized) ? "fail" : "warn";
  }

  function receiptSummary(statement, meta) {
    const predicate = object(statement.predicate, "receipt predicate");
    const cohort = object(predicate.cohort, "receipt cohort");
    const outcome = object(predicate.outcome, "receipt outcome");
    const metrics = object(outcome.metrics, "receipt metrics");
    const gate = object(outcome.pilot_gate, "receipt Pilot Gate");
    const summary = base("LureEval receipt", "Private operational evaluation", "One aggregate-only, protocol-bound detector evaluation cohort.", meta);
    gateStatus(summary, gate.verdict);
    summary.metrics = [
      {label: "Processed", value: count(cohort.processed_count)},
      {label: "Evaluated", value: count(cohort.evaluated_count)},
      {label: "Recall", value: ratio(metrics.recall_estimate), note: `lower ${ratio(metrics.recall_lower_bound)}`},
      {label: "False-positive rate", value: ratio(metrics.false_positive_rate_estimate), note: `upper ${ratio(metrics.false_positive_rate_upper_bound)}`},
      {label: "Routed", value: ratio(outcome.routing && outcome.routing.routed_rate)},
      {label: "Evasion", value: ratio(outcome.resilience && outcome.resilience.evasion_rate)},
    ];
    summary.bindings = [
      binding("Manifest", cohort.manifest_sha256), binding("Labels", cohort.labels_sha256),
      binding("Plan", cohort.plan_sha256), binding("Gate", cohort.gate_sha256),
      binding("Detector", predicate.control && predicate.control.detector_artifact_sha256),
      binding("Policy", predicate.control && predicate.control.policy_sha256),
    ].filter(Boolean);
    summary.privacy = predicate.privacy && Array.isArray(predicate.privacy.excluded_fields)
      ? predicate.privacy.excluded_fields : [];
    summary.warnings = Array.isArray(predicate.limitations) ? predicate.limitations : [];
    return summary;
  }

  function aggregateSummary(statement, meta) {
    const predicate = object(statement.predicate, "aggregate predicate");
    const pooled = object(predicate.pooled, "pooled evidence");
    const metrics = object(pooled.metrics, "pooled metrics");
    const summary = base("LureEval aggregate", "Compatible multi-site evidence", "Pooled counts recomputed from compatible private evaluation receipts.", meta);
    summary.status = predicate.source_authentication_required && predicate.authenticated_source_count !== predicate.source_receipt_count ? "Authentication incomplete" : "Compatible pool";
    summary.tone = summary.status === "Compatible pool" ? "pass" : "warn";
    summary.metrics = [
      {label: "Receipts", value: count(predicate.source_receipt_count)},
      {label: "Authenticated", value: `${count(predicate.authenticated_source_count)} / ${count(predicate.source_receipt_count)}`},
      {label: "Processed", value: count(pooled.processed_count)},
      {label: "Recall", value: ratio(metrics.recall_estimate), note: `lower ${ratio(metrics.recall_lower_bound)}`},
      {label: "False-positive rate", value: ratio(metrics.false_positive_rate_estimate), note: `upper ${ratio(metrics.false_positive_rate_upper_bound)}`},
      {label: "Routed", value: ratio(pooled.routing && pooled.routing.routed_rate)},
    ];
    summary.bindings = Array.isArray(statement.subject)
      ? statement.subject.map((item, index) => binding(`Receipt ${index + 1}`, item && item.digest && item.digest.sha256)).filter(Boolean)
      : [];
    summary.warnings = Array.isArray(predicate.limitations) ? predicate.limitations : [];
    summary.privacy = ["messages remain at source", "counts only", "small-cell suppression"];
    return summary;
  }

  function pilotGateSummary(value, meta) {
    const metrics = object(value.metrics, "Pilot Gate metrics");
    const summary = base("Pilot Gate", "Pre-registered deployment decision", "Exact one-sided evidence checks against a registered acceptance plan.", meta);
    gateStatus(summary, value.verdict);
    summary.metrics = [
      {label: "Processed", value: count(metrics.processed_count)},
      {label: "Label coverage", value: ratio(metrics.label_coverage)},
      {label: "Recall", value: ratio(metrics.routing_recall_estimate), note: `lower ${ratio(metrics.routing_recall_lower_bound)}`},
      {label: "False-positive rate", value: ratio(metrics.routing_false_positive_rate_estimate), note: `upper ${ratio(metrics.routing_false_positive_rate_upper_bound)}`},
      {label: "Routed", value: ratio(metrics.routed_rate)},
      {label: "Failed checks", value: count(Array.isArray(value.failed_checks) ? value.failed_checks.length : 0)},
    ];
    summary.bindings = [
      binding("Plan", value.plan_binding && value.plan_binding.sha256),
      binding("Manifest", value.run_binding && value.run_binding.manifest_sha256),
      binding("Labels", value.run_binding && value.run_binding.labels_sha256),
    ].filter(Boolean);
    summary.privacy = ["aggregate only", "no case identifiers", "no message content"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function defenderSummary(value, meta) {
    const cohort = object(value.cohort, "Defender cohort");
    const nativePerformance = object(value.native_attention && value.native_attention.performance, "Defender performance");
    const scopePerformance = object(value.lurescope_paired && value.lurescope_paired.performance, "LureScope paired performance");
    const summary = base("Defender paired report", "LureScope × Microsoft Defender", "Offline, analyst-labeled comparison over messages matched in memory.", meta);
    summary.status = cohort.evaluated_matched_messages ? "Paired evidence" : "Awaiting labels";
    summary.tone = cohort.evaluated_matched_messages ? "pass" : "warn";
    summary.metrics = [
      {label: "Matched", value: `${count(cohort.matched_messages)} / ${count(cohort.messages)}`},
      {label: "Evaluated", value: count(cohort.evaluated_matched_messages)},
      {label: "Defender recall", value: ratio(nativePerformance.recall_estimate), note: `lower ${ratio(nativePerformance.recall_lower_bound)}`},
      {label: "LureScope recall", value: ratio(scopePerformance.recall_estimate), note: `lower ${ratio(scopePerformance.recall_lower_bound)}`},
      {label: "Defender FPR", value: ratio(nativePerformance.false_positive_rate_estimate), note: `upper ${ratio(nativePerformance.false_positive_rate_upper_bound)}`},
      {label: "LureScope FPR", value: ratio(scopePerformance.false_positive_rate_estimate), note: `upper ${ratio(scopePerformance.false_positive_rate_upper_bound)}`},
    ];
    summary.bindings = [
      binding("Defender import", value.bindings && value.bindings.defender_import_sha256),
      binding("Manifest", value.bindings && value.bindings.shadow_manifest_sha256),
      binding("Labels", value.bindings && value.bindings.labels_sha256),
    ].filter(Boolean);
    summary.privacy = value.privacy && Array.isArray(value.privacy.excluded_fields) ? value.privacy.excluded_fields : [];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function shadowSummary(value, meta) {
    const review = object(value.analyst_review, "Shadow analyst review");
    const summary = base("Shadow Inbox report", "Offline mailbox pilot", "Aggregate workload, routing, review, and resilience evidence.", meta);
    summary.status = review.latest_label_count ? "Review in progress" : "Awaiting labels";
    summary.tone = review.coverage === 1 ? "pass" : "warn";
    summary.metrics = [
      {label: "Processed", value: count(value.volume && value.volume.processed_count)},
      {label: "Label coverage", value: ratio(review.coverage)},
      {label: "Recall", value: ratio(review.routing_recall)},
      {label: "False-positive rate", value: ratio(review.routing_false_positive_rate)},
      {label: "Routed", value: ratio(value.routing && value.routing.routed_rate)},
      {label: "Evasion", value: ratio(value.resilience && value.resilience.evasion_rate)},
    ];
    summary.privacy = value.privacy && Array.isArray(value.privacy.excluded_fields) ? value.privacy.excluded_fields : [];
    return summary;
  }

  function lurewatchEntrySummary(value, meta) {
    if (!Array.isArray(value.states) || value.states.length < 1) {
      throw new Error("LureWatch entry must contain monitor states");
    }
    const summary = base(
      "LureWatch entry",
      "Anytime-valid deployment risk",
      "One aggregate-only batch boundary in a predeclared FPR/FNR e-process.",
      meta,
    );
    gateStatus(summary, value.family_status);
    summary.metrics = value.states.slice(0, 6).map(state => {
      const item = object(state, "LureWatch monitor state");
      const empirical = item.empirical_rate === null || item.empirical_rate === undefined
        ? "Not measurable" : ratio(item.empirical_rate);
      return {
        label: String(item.monitor_id || "monitor"),
        value: empirical,
        note: `log(e) ${Number(item.log_e_value).toFixed(2)} · alarm ${Number(item.alarm_log_threshold).toFixed(2)} · ${item.status}`,
      };
    });
    summary.metrics.unshift({label: "Sequence", value: count(value.sequence)});
    summary.bindings = [
      binding("Plan", value.plan_sha256),
      binding("Previous entry", value.previous_entry_sha256),
      binding("Private source", value.batch && value.batch.source_commitment_sha256),
    ].filter(Boolean);
    summary.privacy = value.privacy
      ? Object.entries(value.privacy).filter(([, present]) => present === false).map(([name]) => name.replace("contains_", "no "))
      : [];
    summary.warnings = [
      "No alarm is not proof that risk is below the limit.",
      "The browser recomputes no e-process or chain links; use `lurescope monitor verify`.",
    ];
    return summary;
  }

  function boundaryEvaluationSummary(value, meta) {
    const metrics = object(value.summary, "LureBoundary evaluation summary");
    const suite = object(value.suite, "LureBoundary suite binding");
    const monitor = object(value.monitor, "LureBoundary monitor binding");
    const summary = base(
      "LureBoundary evaluation",
      "Synthetic agent-boundary monitor test",
      "Typed, content-free trajectories measuring recall, benign alarms, category accuracy, and alert delay.",
      meta,
    );
    gateStatus(summary, metrics.verdict);
    summary.metrics = [
      {label: "Trajectories", value: count(metrics.total_trajectories)},
      {label: "Recall", value: ratio(metrics.trajectory_recall)},
      {label: "Benign FPR", value: ratio(metrics.benign_false_positive_rate)},
      {label: "Category accuracy", value: ratio(metrics.category_accuracy)},
      {label: "Max delay", value: `${count(metrics.maximum_detection_delay_events)} event(s)`},
      {label: "Monitor", value: String(monitor.monitor_id || "unknown")},
    ];
    summary.bindings = [
      binding("Suite", suite.suite_sha256),
      binding("Monitor", monitor.artifact_sha256),
    ].filter(Boolean);
    summary.privacy = ["synthetic metadata only", "no prompts", "no commands or payloads", "no credentials", "no hosts or URLs", "no model reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function boundaryPlanSummary(value, meta) {
    const benchmark = object(value.benchmark, "LureBoundary benchmark binding");
    const control = object(value.control, "LureBoundary control binding");
    const response = object(value.response, "LureBoundary response binding");
    const summary = base(
      "LureBoundary plan",
      "Preregistered agent assurance boundary",
      "Immutable system, benchmark, monitor, threshold, response-authority, and signer declarations.",
      meta,
    );
    summary.status = "Preregistered";
    summary.tone = "neutral";
    summary.metrics = [
      {label: "Environment", value: String(value.system && value.system.environment || "unknown")},
      {label: "Min recall", value: ratio(benchmark.minimum_trajectory_recall)},
      {label: "Max benign FPR", value: ratio(benchmark.maximum_benign_false_positive_rate)},
      {label: "Max delay", value: `${count(benchmark.maximum_detection_delay_events)} event(s)`},
      {label: "Monitor", value: String(control.monitor_id || "unknown")},
      {label: "Breach response", value: String(response.critical_action || "unknown")},
    ];
    summary.bindings = [
      binding("Suite", benchmark.suite_sha256), binding("Model", value.system && value.system.model_sha256),
      binding("Monitor", control.monitor_artifact_sha256), binding("Policy", control.policy_sha256),
      binding("Controller", control.controller_sha256), binding("Signer", value.authentication && value.authentication.signer_key_id),
    ].filter(Boolean);
    summary.privacy = value.privacy
      ? Object.entries(value.privacy).filter(([, present]) => present === false).map(([name]) => name.replace("contains_", "no "))
      : [];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function boundaryEntrySummary(value, meta) {
    const decision = object(value.decision, "LureBoundary decision");
    const evaluation = object(value.evaluation, "LureBoundary evaluation binding");
    const metrics = object(evaluation.summary, "LureBoundary metrics");
    const summary = base(
      "LureBoundary entry",
      "Append-only agent assurance evidence",
      "One validated evaluation bound to its preregistered plan and predecessor checkpoint.",
      meta,
    );
    gateStatus(summary, decision.boundary_status);
    summary.metrics = [
      {label: "Sequence", value: count(value.sequence)},
      {label: "Evaluation", value: String(decision.evaluation_status || "unknown")},
      {label: "Recall", value: ratio(metrics.trajectory_recall)},
      {label: "Benign FPR", value: ratio(metrics.benign_false_positive_rate)},
      {label: "Max delay", value: `${count(metrics.maximum_detection_delay_events)} event(s)`},
      {label: "Required action", value: String(decision.required_action || "unknown")},
    ];
    summary.bindings = [
      binding("Plan", value.plan_sha256), binding("Previous entry", value.previous_entry_sha256),
      binding("Evaluation", evaluation.sha256), binding("Suite", evaluation.suite_sha256),
    ].filter(Boolean);
    summary.privacy = value.privacy
      ? Object.entries(value.privacy).filter(([, present]) => present === false).map(([name]) => name.replace("contains_", "no "))
      : [];
    summary.warnings = [
      "A pass measures the declared monitor on the bound synthetic suite; it is not proof of deployment containment.",
      "The browser does not recompute metrics, chain links, or signatures; use `lurescope boundary verify`.",
    ];
    return summary;
  }

  function coverageSummary(value, meta) {
    const metrics = object(value.summary, "LureCoverage summary");
    const manifest = object(value.manifest, "LureCoverage manifest binding");
    const summary = base(
      "LureCoverage evaluation",
      "Boundary telemetry coverage",
      "Payload-free canaries measuring delivery, duplication, ordering, lineage, and delay.",
      meta,
    );
    gateStatus(summary, metrics.verdict);
    summary.metrics = [
      {label: "Route coverage", value: ratio(metrics.route_coverage)},
      {label: "Probe delivery", value: ratio(metrics.probe_delivery_rate)},
      {label: "Duplicate rate", value: ratio(metrics.duplicate_rate)},
      {label: "Out-of-order", value: ratio(metrics.out_of_order_rate)},
      {label: "Lineage continuity", value: ratio(metrics.lineage_continuity)},
      {label: "Max delay", value: `${count(metrics.maximum_delivery_delay_ms)} ms`},
    ];
    summary.bindings = [
      binding("Manifest", manifest.manifest_sha256),
      binding("Canaries", value.canaries_sha256),
    ].filter(Boolean);
    summary.privacy = ["typed metadata only", "canaries execute no agent action", "no event content or secrets"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function delegationSummary(value, meta) {
    const metrics = object(value.summary, "LureDelegation summary");
    const suite = object(value.suite, "LureDelegation suite binding");
    const summary = base(
      "LureDelegation evaluation",
      "Agent identity and capability graph",
      "Synthetic issuer, audience, scope, expiry, replay, tenant, subagent, and peer-trust scenarios.",
      meta,
    );
    gateStatus(summary, metrics.verdict);
    summary.metrics = [
      {label: "Scenarios", value: count(metrics.total_scenarios)},
      {label: "Recall", value: ratio(metrics.recall)},
      {label: "Benign FPR", value: ratio(metrics.benign_false_positive_rate)},
      {label: "Category accuracy", value: ratio(metrics.category_accuracy)},
      {label: "Max delay", value: `${count(metrics.maximum_detection_delay_events)} event(s)`},
    ];
    summary.bindings = [binding("Suite", suite.suite_sha256)].filter(Boolean);
    summary.privacy = ["synthetic identity metadata", "no tokens or credential values", "no prompts or payloads"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function irSummary(value, meta) {
    const metrics = object(value.summary, "LureIR summary");
    const suite = object(value.suite, "LureIR suite binding");
    const responder = object(value.responder, "LureIR responder binding");
    const summary = base(
      "LureIR evaluation",
      "Defanged incident-response readiness",
      "Structured findings, evidence, timeline, containment-choice, and escalation scoring.",
      meta,
    );
    gateStatus(summary, metrics.verdict);
    summary.metrics = [
      {label: "Cases", value: count(metrics.case_count)},
      {label: "Fact recall", value: ratio(metrics.fact_recall)},
      {label: "Fact precision", value: ratio(metrics.fact_precision)},
      {label: "Evidence support", value: ratio(metrics.evidence_support_rate)},
      {label: "Containment recall", value: ratio(metrics.containment_action_recall)},
      {label: "Unsafe actions", value: ratio(metrics.unsafe_action_rate)},
      {label: "Escalation", value: ratio(metrics.escalation_accuracy)},
    ];
    summary.bindings = [
      binding("Suite", suite.suite_sha256),
      binding("Response", responder.response_sha256),
    ].filter(Boolean);
    summary.privacy = ["defanged event codes", "no exploit payloads", "containment codes are not executed"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function invariantPlanSummary(value, meta) {
    if (!Array.isArray(value.nodes) || !Array.isArray(value.edges) || !Array.isArray(value.invariants)) {
      throw new Error("LureInvariant plan must contain nodes, edges, and invariants");
    }
    const acceptance = object(value.acceptance, "LureInvariant acceptance contract");
    const summary = base(
      "LureInvariant plan",
      "Cross-layer graph and temporal contract",
      "Typed reachability, mediation, shutdown, and post-trigger assertions over a declared evidence boundary.",
      meta,
    );
    summary.status = "Declared contract";
    summary.metrics = [
      {label: "Nodes", value: count(value.nodes.length)},
      {label: "Edges", value: count(value.edges.length)},
      {label: "Invariants", value: count(value.invariants.length)},
      {label: "Sources", value: count(Array.isArray(value.sources) ? value.sources.length : 0)},
      {label: "Allowed violations", value: count(acceptance.maximum_violations)},
      {label: "Insufficient allowed", value: String(Boolean(acceptance.allow_insufficient_evidence))},
    ];
    summary.privacy = ["typed metadata only", "no targets, payloads, credentials, prompts, commands, or reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function invariantEvaluationSummary(value, meta) {
    const metrics = object(value.summary, "LureInvariant evaluation summary");
    const plan = object(value.plan, "LureInvariant plan binding");
    const observations = object(value.observations, "LureInvariant observation binding");
    const summary = base(
      "LureInvariant evaluation",
      "Graph and temporal invariant evidence",
      "Deterministic results over exact plan and observation bytes with explicit unknown and incomplete states.",
      meta,
    );
    gateStatus(summary, metrics.verdict);
    summary.metrics = [
      {label: "Invariants", value: count(metrics.total_invariants)},
      {label: "Violated", value: count(metrics.violated)},
      {label: "Not observed", value: count(metrics.not_observed_within_declared_boundary)},
      {label: "Insufficient", value: count(metrics.insufficient_evidence)},
      {label: "Source coverage", value: ratio(metrics.source_coverage)},
      {label: "Unknown edges", value: count(metrics.unknown_edges)},
    ];
    summary.bindings = [
      binding("Plan", plan.plan_sha256),
      binding("Observations", observations.observations_sha256),
    ].filter(Boolean);
    summary.privacy = ["typed identifiers and outcomes only", "paths do not contain live targets or exploit instructions"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function invariantBundleSummary(value, meta) {
    if (!Array.isArray(value.evidence) || value.evidence.length !== 3) {
      throw new Error("LureInvariant bundle must bind exactly three evidence artifacts");
    }
    const authentication = object(value.authentication, "LureInvariant authentication declaration");
    const summary = base(
      "LureInvariant evidence bundle",
      "Tamper-evident invariant checkpoint",
      "Exact plan, observations, and independently recomputable evaluation bindings.",
      meta,
    );
    gateStatus(summary, value.overall_status);
    summary.metrics = [
      {label: "Bundle", value: String(value.bundle_id || "unknown")},
      {label: "Environment", value: String(value.system && value.system.environment || "unknown")},
      {label: "Authentication", value: String(authentication.mode || "unknown")},
      ...value.evidence.map(item => ({
        label: String(item.kind || "evidence"),
        value: String(item.verdict || "unknown"),
      })),
    ];
    summary.bindings = value.evidence
      .map(item => binding(String(item.file || item.kind || "Evidence"), item.sha256))
      .filter(Boolean);
    const signer = binding("Declared signer", authentication.signer_key_id);
    if (signer) summary.bindings.push(signer);
    summary.privacy = ["typed graph and event metadata", "no live actions or hidden reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    summary.warnings.push("Use `lurescope invariant verify` with a trusted public key to authenticate and recompute this bundle.");
    return summary;
  }

  function invariantComparisonSummary(value, meta) {
    const metrics = object(value.summary, "LureInvariant comparison summary");
    const summary = base(
      "LureInvariant remediation comparison",
      "Before/after invariant evidence",
      "A strict comparison that rejects changed invariants, acceptance thresholds, and evidence-source contracts.",
      meta,
    );
    gateStatus(summary, metrics.status);
    summary.metrics = [
      {label: "Resolved", value: count(metrics.resolved)},
      {label: "Persistent", value: count(metrics.persistent)},
      {label: "New", value: count(metrics.new)},
      {label: "Insufficient after", value: count(metrics.insufficient_after)},
      {label: "Before", value: String(value.before && value.before.overall_status || "unknown")},
      {label: "After", value: String(value.after && value.after.overall_status || "unknown")},
    ];
    summary.bindings = [
      binding("Invariant contract", value.contract_sha256),
      binding("Before manifest", value.before && value.before.manifest_sha256),
      binding("Before checkpoint", value.before && value.before.statement_sha256),
      binding("After manifest", value.after && value.after.manifest_sha256),
      binding("After checkpoint", value.after && value.after.statement_sha256),
    ].filter(Boolean);
    summary.privacy = ["comparison contains identifiers, statuses, counts, and digests only"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    summary.warnings.push("Use `lurescope invariant verify-comparison` to recompute this result from both bundles.");
    return summary;
  }

  function rangeEvaluationSummary(value, meta) {
    const metrics = object(value.summary, "LureRange evaluation summary");
    const inputs = object(value.inputs, "LureRange input bindings");
    const engine = object(value.engine, "LureRange engine declaration");
    const summary = base(
      "LureRange evaluation",
      "Agent permit conformance",
      "Offline policy decisions for authorization, isolation, credential, monitoring, and safe-stop controls.",
      meta,
    );
    gateStatus(summary, metrics.verdict);
    summary.metrics = [
      {label: "Scenarios", value: count(metrics.total_scenarios)},
      {label: "Violation control", value: ratio(metrics.violation_control_rate)},
      {label: "Benign allow", value: ratio(metrics.benign_allow_rate)},
      {label: "Reason accuracy", value: ratio(metrics.reason_accuracy)},
      {label: "Safe-stop recall", value: ratio(metrics.safe_stop_recall)},
      {label: "Engine", value: String(engine.engine_id || "unknown")},
    ];
    summary.bindings = [
      binding("Permit", inputs.permit_sha256),
      binding("Range suite", inputs.range_suite_sha256),
      binding("Engine artifact", engine.artifact_sha256),
    ].filter(Boolean);
    summary.privacy = ["typed synthetic metadata only", "no targets, URLs, payloads, credentials, prompts, commands, or reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    return summary;
  }

  function rangeBundleSummary(value, meta) {
    const evidence = object(value.evidence, "LureRange evidence binding");
    const authentication = object(value.authentication, "LureRange authentication declaration");
    const engine = object(value.engine, "LureRange engine declaration");
    const summary = base(
      "LureRange evidence bundle",
      "Tamper-evident permit checkpoint",
      "Exact evaluation bytes with independently recomputable permit, suite, and metric bindings.",
      meta,
    );
    gateStatus(summary, value.overall_status);
    summary.metrics = [
      {label: "Bundle", value: String(value.bundle_id || "unknown")},
      {label: "Environment", value: String(value.system && value.system.environment || "unknown")},
      {label: "Engine", value: String(engine.engine_id || "unknown")},
      {label: "Engine version", value: String(engine.engine_version || "unknown")},
      {label: "Authentication", value: String(authentication.mode || "unknown")},
    ];
    summary.bindings = [
      binding("Evaluation", evidence.sha256),
      binding("Permit", evidence.permit_sha256),
      binding("Range suite", evidence.range_suite_sha256),
      binding("Engine artifact", engine.artifact_sha256),
      binding("Declared signer", authentication.signer_key_id),
    ].filter(Boolean);
    summary.privacy = ["typed synthetic policy metadata", "no live actions or model reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope range verify` with a trusted public key to authenticate and recompute this bundle.");
    return summary;
  }

  function rangeComparisonSummary(value, meta) {
    const metrics = object(value.summary, "LureRange comparison summary");
    const contract = object(value.contract, "LureRange comparison contract");
    const summary = base(
      "LureRange remediation comparison",
      "Before/after permit conformance",
      "A strict comparison under an unchanged permit, range suite, acceptance contract, and engine identity.",
      meta,
    );
    gateStatus(summary, metrics.status);
    summary.metrics = [
      {label: "Resolved", value: count(metrics.resolved)},
      {label: "Persistent", value: count(metrics.persistent)},
      {label: "New", value: count(metrics.new)},
      {label: "Before", value: String(value.before && value.before.overall_status || "unknown")},
      {label: "After", value: String(value.after && value.after.overall_status || "unknown")},
      {label: "Engine", value: String(contract.engine_id || "unknown")},
    ];
    summary.bindings = [
      binding("Permit", contract.permit_sha256),
      binding("Range suite", contract.range_suite_sha256),
      binding("Before manifest", value.before && value.before.manifest_sha256),
      binding("After manifest", value.after && value.after.manifest_sha256),
    ].filter(Boolean);
    summary.privacy = ["scenario identifiers, statuses, counts, and digests only"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope range verify-comparison` to recompute this result from both bundles.");
    return summary;
  }

  function runtimeEvaluationSummary(value, meta) {
    const metrics = object(value.summary, "runtime mediation summary");
    const trace = object(value.trace, "runtime trace");
    const summary = base(
      "Runtime mediation evaluation",
      "Receipt × sensor reconciliation",
      "Typed authorization receipts reconciled with independently submitted effect observations.",
      meta,
    );
    gateStatus(summary, metrics.verdict);
    summary.metrics = [
      {label: "Requests", value: count(metrics.total_requests)},
      {label: "Decision accuracy", value: ratio(metrics.decision_accuracy)},
      {label: "Reason accuracy", value: ratio(metrics.reason_accuracy)},
      {label: "Receipt coverage", value: ratio(metrics.mediation_coverage_rate)},
      {label: "Point coverage", value: ratio(metrics.mediation_point_coverage_rate)},
      {label: "Control bypass", value: count(metrics.control_bypass_count)},
      {label: "Unmediated", value: count(metrics.unmediated_count)},
      {label: "Unknown", value: count(metrics.unknown_count)},
    ];
    summary.bindings = [
      binding("Trace", value.trace_sha256),
      binding("Runtime profile", trace.profile_sha256),
      binding("Permit", trace.profile && trace.profile.permit_sha256),
    ].filter(Boolean);
    summary.privacy = ["typed metadata only", "no action content, tokens, credentials, prompts, commands, URLs, or reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    return summary;
  }

  function runtimeBundleSummary(value, meta) {
    const evidence = object(value.evidence, "runtime evidence binding");
    const authentication = object(value.authentication, "runtime authentication declaration");
    const policy = object(value.policy, "runtime policy identity");
    const profile = object(value.profile, "runtime profile binding");
    const summary = base(
      "Runtime mediation evidence bundle",
      "Tamper-evident runtime checkpoint",
      "Independent receipt-chain, sensor-binding, and reconciliation evidence over exact bytes.",
      meta,
    );
    gateStatus(summary, value.overall_status);
    summary.metrics = [
      {label: "Bundle", value: String(value.bundle_id || "unknown")},
      {label: "Environment", value: String(value.system && value.system.environment || "unknown")},
      {label: "Policy engine", value: String(policy.engine_id || "unknown")},
      {label: "Policy version", value: String(policy.engine_version || "unknown")},
      {label: "Authentication", value: String(authentication.mode || "unknown")},
    ];
    summary.bindings = [
      binding("Evaluation", evidence.sha256),
      binding("Trace", evidence.trace_sha256),
      binding("Runtime profile", profile.profile_sha256),
      binding("Permit", profile.permit_sha256),
      binding("Declared signer", authentication.signer_key_id),
    ].filter(Boolean);
    summary.privacy = ["typed runtime metadata", "no action content or secret values"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope runtime verify` with a trusted public key to authenticate and recompute this bundle.");
    return summary;
  }

  function runtimeComparisonSummary(value, meta) {
    const metrics = object(value.summary, "runtime comparison summary");
    const contract = object(value.contract, "runtime comparison contract");
    const summary = base(
      "Runtime mediation remediation comparison",
      "Before/after runtime evidence",
      "A strict comparison under an unchanged profile, permit, acceptance contract, system, and policy engine identity.",
      meta,
    );
    gateStatus(summary, metrics.status);
    summary.metrics = [
      {label: "Resolved", value: count(metrics.resolved)},
      {label: "Persistent", value: count(metrics.persistent)},
      {label: "New", value: count(metrics.new)},
      {label: "Before", value: String(value.before && value.before.overall_status || "unknown")},
      {label: "After", value: String(value.after && value.after.overall_status || "unknown")},
      {label: "Policy engine", value: String(contract.policy_engine_id || "unknown")},
    ];
    summary.bindings = [
      binding("Runtime profile", contract.profile_sha256),
      binding("Permit", contract.permit_sha256),
      binding("Before manifest", value.before && value.before.manifest_sha256),
      binding("After manifest", value.after && value.after.manifest_sha256),
    ].filter(Boolean);
    summary.privacy = ["correlation identifiers, statuses, counts, and digests only"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope runtime verify-comparison` to recompute this result from both bundles.");
    return summary;
  }

  function revocationEvaluationSummary(value, meta) {
    const metrics = object(value.summary, "LureRevoke evaluation summary");
    const run = object(value.run, "LureRevoke receiver run");
    const receiver = object(run.implementation, "LureRevoke receiver identity");
    const summary = base(
      "LureRevoke evaluation",
      "Distributed revocation convergence",
      "Typed continuous-access signal delivery and access attenuation across declared policy nodes.",
      meta,
    );
    gateStatus(summary, metrics.verdict);
    summary.metrics = [
      {label: "Delivery coverage", value: ratio(metrics.delivery_coverage_rate)},
      {label: "p95 convergence", value: `${count(metrics.p95_convergence_ms)} ms`},
      {label: "Maximum convergence", value: `${count(metrics.maximum_convergence_ms)} ms`},
      {label: "Deadline misses", value: count(metrics.deadline_miss_count)},
      {label: "Post-deadline allows", value: count(metrics.post_deadline_allow_count)},
      {label: "Collateral blocks", value: count(metrics.collateral_block_count)},
      {label: "Revoked block recall", value: ratio(metrics.revoked_block_recall)},
      {label: "Receiver", value: String(receiver.name || "unknown")},
    ];
    summary.bindings = [
      binding("Plan", value.plan_sha256),
      binding("Receiver run", value.run_sha256),
      binding("Receiver artifact", receiver.artifact_sha256),
    ].filter(Boolean);
    summary.privacy = ["opaque subjects and relative timing", "no SETs, tokens, credentials, targets, payloads, prompts, URLs, or reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    return summary;
  }

  function revocationBundleSummary(value, meta) {
    const evidence = object(value.evidence, "LureRevoke evidence binding");
    const authentication = object(value.authentication, "LureRevoke authentication declaration");
    const receiver = object(value.receiver, "LureRevoke receiver identity");
    const metrics = object(value.summary, "LureRevoke bound summary");
    const summary = base(
      "LureRevoke evidence bundle",
      "Tamper-evident convergence checkpoint",
      "Exact independently recomputable revocation evidence with an optional external-key signature.",
      meta,
    );
    gateStatus(summary, value.overall_status);
    summary.metrics = [
      {label: "Delivery coverage", value: ratio(metrics.delivery_coverage_rate)},
      {label: "p95 convergence", value: `${count(metrics.p95_convergence_ms)} ms`},
      {label: "Deadline misses", value: count(metrics.deadline_miss_count)},
      {label: "Post-deadline allows", value: count(metrics.post_deadline_allow_count)},
      {label: "Receiver", value: String(receiver.name || "unknown")},
      {label: "Authentication", value: String(authentication.mode || "unknown")},
    ];
    summary.bindings = [
      binding("Evaluation", evidence.sha256),
      binding("Receiver run", evidence.run_sha256),
      binding("Plan", value.plan && value.plan.plan_sha256),
      binding("Receiver artifact", receiver.artifact_sha256),
      binding("Declared signer", authentication.signer_key_id),
    ].filter(Boolean);
    summary.privacy = ["opaque subjects and aggregate metrics", "no security tokens or action content"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope revoke verify` with a trusted public key to authenticate and independently recompute this bundle.");
    return summary;
  }

  function revocationComparisonSummary(value, meta) {
    const metrics = object(value.summary, "LureRevoke comparison summary");
    const contract = object(value.contract, "LureRevoke comparison contract");
    const deltas = object(value.metric_deltas, "LureRevoke metric deltas");
    const summary = base(
      "LureRevoke remediation comparison",
      "Before/after revocation convergence",
      "A strict comparison under an unchanged plan, system, environment, and receiver identity.",
      meta,
    );
    gateStatus(summary, metrics.status);
    summary.metrics = [
      {label: "Resolved", value: count(metrics.resolved)},
      {label: "Persistent", value: count(metrics.persistent)},
      {label: "New", value: count(metrics.new)},
      {label: "Before", value: String(value.before && value.before.overall_status || "unknown")},
      {label: "After", value: String(value.after && value.after.overall_status || "unknown")},
      {label: "Coverage Δ", value: ratio(deltas.delivery_coverage_rate_delta)},
      {label: "p95 convergence Δ", value: deltas.p95_convergence_ms_delta === null ? "Not comparable" : `${count(deltas.p95_convergence_ms_delta)} ms`},
      {label: "Receiver", value: String(contract.receiver_name || "unknown")},
    ];
    summary.bindings = [
      binding("Plan", contract.plan_sha256),
      binding("Before manifest", value.before && value.before.manifest_sha256),
      binding("Before checkpoint", value.before && value.before.statement_sha256),
      binding("After manifest", value.after && value.after.manifest_sha256),
      binding("After checkpoint", value.after && value.after.statement_sha256),
    ].filter(Boolean);
    summary.privacy = ["opaque failure identifiers, aggregate deltas, statuses, and digests only"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope revoke verify-comparison` with both source bundles and trusted public keys before relying on this result.");
    return summary;
  }

  function revocationRegistrySummary(value, meta) {
    const policy = object(value.registration_policy, "LureRevoke registry policy");
    const summary = base(
      "LureRevoke registry",
      "Append-only revocation evidence policy",
      "A fixed admission policy and external-key identity for a signed privacy-minimized Merkle history.",
      meta,
    );
    summary.status = "Policy inspected";
    summary.metrics = [
      {label: "Registry", value: String(value.registry_id || "unknown")},
      {label: "System", value: String(policy.system_id || "unknown")},
      {label: "Environment", value: String(policy.environment || "unknown")},
      {label: "Receiver", value: String(policy.receiver_name || "unknown")},
      {label: "Authenticated bundles", value: policy.require_authenticated_bundle === true ? "required" : "not declared"},
      {label: "Hash profile", value: String(value.hash_profile || "unknown")},
    ];
    summary.bindings = [binding("Registry signer", value.signer_key_id)].filter(Boolean);
    summary.privacy = ["registration policy and key digest only"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope revoke registry-verify` with the external public key; this browser does not inspect registry entries or signatures.");
    return summary;
  }

  function revocationRegistryEntrySummary(value, meta) {
    const receiver = object(value.receiver, "LureRevoke registry receiver");
    const evidence = object(value.evidence, "LureRevoke registered evidence");
    const summary = base(
      "LureRevoke registry entry",
      "Privacy-minimized checkpoint registration",
      "One ordered digest-only registration from a signed revocation evidence bundle.",
      meta,
    );
    gateStatus(summary, evidence.overall_status);
    summary.metrics = [
      {label: "Sequence", value: count(value.sequence)},
      {label: "Receiver", value: String(receiver.name || "unknown")},
      {label: "Receiver version", value: String(receiver.version || "unknown")},
      {label: "Evidence status", value: String(evidence.overall_status || "unknown")},
      {label: "Registered", value: String(value.registered_at || "unknown")},
    ];
    summary.bindings = [
      binding("Previous entry", value.previous_entry_sha256),
      binding("Manifest", evidence.manifest_sha256),
      binding("Checkpoint", evidence.checkpoint_sha256),
      binding("Plan", evidence.plan_sha256),
      binding("Receiver run", evidence.run_sha256),
      binding("Bundle signer", receiver.bundle_signer_key_id),
    ].filter(Boolean);
    summary.privacy = ["digests, status, time, and receiver version only", "no revocation evaluation, subjects, events, or observations"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    return summary;
  }

  function revocationRegistryInclusionSummary(value, meta) {
    const config = object(value.registry_config, "LureRevoke inclusion-proof registry config");
    const entry = object(value.entry, "LureRevoke inclusion-proof entry");
    const evidence = object(entry.evidence, "LureRevoke inclusion-proof evidence");
    const receiver = object(entry.receiver, "LureRevoke inclusion-proof receiver");
    const path = Array.isArray(value.inclusion_path_sha256)
      ? value.inclusion_path_sha256 : [];
    const summary = base(
      "LureRevoke registry inclusion proof",
      "Portable authenticated registry membership",
      "One privacy-minimized registration, its RFC 9162-style audit path, and the signed tree head it resolves to.",
      meta,
    );
    summary.status = "Proof inspected";
    summary.metrics = [
      {label: "Registry", value: String(config.registry_id || "unknown")},
      {label: "Sequence", value: count(value.sequence)},
      {label: "Tree size", value: count(value.tree_size)},
      {label: "Path nodes", value: count(path.length)},
      {label: "Receiver", value: String(receiver.name || "unknown")},
      {label: "Evidence status", value: String(evidence.overall_status || "unknown")},
    ];
    summary.bindings = [
      binding("Entry", value.entry_sha256),
      binding("Leaf", value.leaf_sha256),
      binding("Merkle root", value.root_sha256),
      binding("Registry signer", config.signer_key_id),
      binding("Manifest", evidence.manifest_sha256),
      binding("Checkpoint", evidence.checkpoint_sha256),
    ].filter(Boolean);
    summary.privacy = ["one digest-only registry entry", "no revocation evaluation, subjects, events, observations, or sibling entries"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope revoke registry-verify-inclusion` with the external public key; this browser does not authenticate the embedded DSSE or recompute the audit path.");
    return summary;
  }

  function revocationRegistryConsistencySummary(value, meta) {
    const config = object(value.registry_config, "LureRevoke consistency-proof registry config");
    const path = Array.isArray(value.consistency_path_sha256)
      ? value.consistency_path_sha256 : [];
    const summary = base(
      "LureRevoke registry consistency proof",
      "Portable authenticated append-only evidence",
      "Two signed tree heads and the RFC 9162-style Merkle path linking the earlier prefix to the later tree.",
      meta,
    );
    summary.status = "Proof inspected";
    summary.metrics = [
      {label: "Registry", value: String(config.registry_id || "unknown")},
      {label: "First tree", value: count(value.first_tree_size)},
      {label: "Second tree", value: count(value.second_tree_size)},
      {label: "New leaves", value: count(Number(value.second_tree_size || 0) - Number(value.first_tree_size || 0))},
      {label: "Path nodes", value: count(path.length)},
    ];
    summary.bindings = [
      binding("First Merkle root", value.first_root_sha256),
      binding("Second Merkle root", value.second_root_sha256),
      binding("Registry signer", config.signer_key_id),
    ].filter(Boolean);
    summary.privacy = ["Merkle nodes and signed tree heads only", "no registry entries, revocation evaluations, subjects, events, or observations"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope revoke registry-verify-consistency` with the external public key; this browser does not authenticate either DSSE or recompute the consistency path.");
    return summary;
  }

  function revocationRegistryHeadComparisonSummary(value, meta) {
    const config = object(value.registry_config, "LureRevoke head-comparison registry config");
    const result = object(value.summary, "LureRevoke head-comparison summary");
    const summary = base(
      "LureRevoke registry head comparison",
      "Authenticated split-view check",
      "Two exchanged signed tree heads compared for identity, same-size conflict, or a required consistency proof.",
      meta,
    );
    summary.status = String(result.status || "unknown").replaceAll("_", " ");
    summary.tone = result.status === "identical"
      ? "pass" : result.status === "equivocation" ? "fail" : "warn";
    summary.metrics = [
      {label: "Registry", value: String(config.registry_id || "unknown")},
      {label: "First tree", value: count(result.first_tree_size)},
      {label: "Second tree", value: count(result.second_tree_size)},
      {label: "Same size", value: String(Boolean(result.same_tree_size))},
      {label: "Same root", value: String(Boolean(result.same_root))},
      {label: "Same statement", value: String(Boolean(result.same_statement))},
    ];
    summary.bindings = [
      binding("First Merkle root", result.first_root_sha256),
      binding("First statement", result.first_statement_sha256),
      binding("Second Merkle root", result.second_root_sha256),
      binding("Second statement", result.second_statement_sha256),
      binding("Registry signer", config.signer_key_id),
    ].filter(Boolean);
    summary.privacy = ["signed tree-head metadata and digests only", "no registry entries or revocation evaluations"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope revoke registry-verify-head-comparison`; this browser does not authenticate either signature or establish global non-equivocation.");
    return summary;
  }

  function revocationTopologySummary(value, meta) {
    const metrics = object(value.summary, "LureRevoke topology summary");
    const inputs = object(value.inputs, "LureRevoke topology inputs");
    const summary = base(
      "LureRevoke topology audit",
      "Declared revocation-surface coverage",
      "An independently recomputable mapping from revocation nodes to every declared runtime mediation point.",
      meta,
    );
    gateStatus(summary, metrics.verdict);
    summary.metrics = [
      {label: "Point coverage", value: ratio(metrics.mediation_point_coverage_rate)},
      {label: "Covered", value: `${count(metrics.covered_mediation_point_count)} / ${count(metrics.required_mediation_point_count)}`},
      {label: "Missing", value: count(metrics.missing_mediation_point_count)},
      {label: "Unmapped nodes", value: count(metrics.unmapped_node_count)},
    ];
    summary.bindings = [
      binding("Revocation plan", inputs.revocation_plan_sha256),
      binding("Runtime profile", inputs.runtime_profile_sha256),
    ].filter(Boolean);
    summary.privacy = ["declared node, action, and sensor identifiers plus exact input digests"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope revoke verify-topology`; this browser does not recompute either input contract or the mapping.");
    return summary;
  }

  function revocationOtelProjectionSummary(value, meta) {
    const inputs = object(value.inputs, "LureRevoke OpenTelemetry inputs");
    const source = object(inputs.otel_log_export, "LureRevoke OpenTelemetry source export");
    const run = object(value.run, "LureRevoke OpenTelemetry projected run");
    const clock = object(value.clock_boundary, "LureRevoke OpenTelemetry clock boundary");
    const summary = base(
      "LureRevoke OpenTelemetry projection",
      "Body-free operational telemetry bridge",
      "An independently recomputable projection from strict OpenTelemetry log-model records to a LureRevoke run.",
      meta,
    );
    summary.status = "Projection inspected";
    summary.metrics = [
      {label: "Records", value: count(Array.isArray(source.records) ? source.records.length : 0)},
      {label: "Signals", value: count(Array.isArray(run.signal_observations) ? run.signal_observations.length : 0)},
      {label: "Access decisions", value: count(Array.isArray(run.access_observations) ? run.access_observations.length : 0)},
      {label: "Receiver", value: String(source.receiver && source.receiver.name || "unknown")},
      {label: "Benchmark clock", value: String(clock.benchmark_time_field || "unknown")},
      {label: "Collector time scored", value: clock.observed_timestamp_used_for_benchmark_timing === false ? "no" : "unknown"},
    ];
    summary.bindings = [
      binding("Revocation plan", inputs.revocation_plan_sha256),
      binding("OTel source export", inputs.otel_log_export_sha256),
      binding("Projected run", value.run_sha256),
    ].filter(Boolean);
    summary.privacy = ["no log Body", "opaque declared identifiers and digests only", "no raw subjects, tokens, credentials, prompts, payloads, or targets"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope revoke verify-otel`; this browser does not recompute the source projection or establish telemetry completeness, clock synchronization, or causality.");
    return summary;
  }

  function revocationDeploymentGateSummary(value, meta) {
    const system = object(value.system, "LureRevoke deployment-gate system");
    const contract = object(value.contract, "LureRevoke deployment-gate contract");
    const policy = object(value.policy, "LureRevoke deployment-gate policy");
    const sources = object(value.sources, "LureRevoke deployment-gate sources");
    const topology = object(sources.topology_audit, "LureRevoke topology source");
    const projection = object(sources.otel_projection, "LureRevoke telemetry source");
    const evidence = object(sources.revocation_evidence, "LureRevoke signed evidence source");
    if (!Array.isArray(value.checks) || value.checks.length !== 10) {
      throw new Error("LureRevoke deployment gate must contain ten checks");
    }
    const summary = base(
      "LureRevoke deployment gate",
      "Cross-artifact revocation release decision",
      "One recomputable decision binding declared topology coverage, body-free telemetry, and authenticated convergence evidence to the same exact contract.",
      meta,
    );
    gateStatus(summary, value.overall_status);
    summary.metrics = [
      {label: "System", value: String(system.system_id || "unknown")},
      {label: "Environment", value: String(system.environment || "unknown")},
      {label: "Topology", value: String(topology.verdict || "unknown")},
      {label: "Coverage", value: `${count(topology.covered_mediation_point_count)} / ${count(topology.required_mediation_point_count)}`},
      {label: "Telemetry records", value: count(projection.record_count)},
      {label: "Signed evaluation", value: String(evidence.overall_status || "unknown")},
      {label: "Convergence", value: `${count(policy.declared_convergence_ms)} / ${count(policy.maximum_allowed_convergence_ms)} ms`},
      {label: "Run accepted from", value: String(policy.minimum_run_generated_at || "unknown")},
      {label: "Expected receiver", value: String(policy.expected_receiver_name || "unknown")},
    ];
    summary.bindings = [
      binding("Revocation plan", contract.plan_sha256),
      binding("Receiver run", contract.run_sha256),
      binding("Topology audit", topology.sha256),
      binding("Telemetry projection", projection.sha256),
      binding("Telemetry source", projection.source_export_sha256),
      binding("Evidence manifest", evidence.manifest_sha256),
      binding("Evidence checkpoint", evidence.checkpoint_sha256),
      binding("Evidence signer", evidence.signer_key_id),
      binding("Expected receiver artifact", policy.expected_receiver_artifact_sha256),
    ].filter(Boolean);
    summary.privacy = ["body-free telemetry projection", "opaque identifiers and exact digests only", "no raw subjects, credentials, prompts, payloads, targets, or reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? [...value.limitations] : [];
    summary.warnings.push("Use `lurescope revoke verify-gate` with all three exact sources and a trusted public key; this browser does not recompute the gate or authenticate its evidence bundle.");
    return summary;
  }

  function portfolioSummary(value, meta) {
    const boundary = object(value.boundary, "portfolio boundary binding");
    if (!Array.isArray(value.evidence) || value.evidence.length !== 3) {
      throw new Error("Agent assurance portfolio must bind three evidence reports");
    }
    const summary = base(
      "Agent assurance portfolio",
      "Cross-bound agent assurance evidence",
      "Boundary, coverage, delegation, and incident-response evidence bound into one checkpoint.",
      meta,
    );
    gateStatus(summary, value.overall_status);
    summary.metrics = [
      {label: "Boundary", value: String(boundary.status || "unknown")},
      ...value.evidence.map(item => ({
        label: String(item.kind || "evidence").replaceAll("_", " "),
        value: String(item.verdict || "unknown"),
      })),
      {label: "Boundary checkpoint", value: count(boundary.checkpoint_sequence)},
    ];
    summary.bindings = [
      binding("Boundary plan", boundary.plan_sha256),
      binding("Boundary checkpoint", boundary.checkpoint_statement_sha256),
      ...value.evidence.map(item => binding(String(item.kind || "Evidence"), item.sha256)),
    ].filter(Boolean);
    summary.privacy = ["privacy-minimized reports only", "no event content", "no prompts, commands, credentials, or reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function witnessRequestSummary(value, meta) {
    const summary = base(
      "Checkpoint witness request",
      "External observation request",
      "Digest-only request for an independent key to witness a chain checkpoint.",
      meta,
    );
    summary.status = String(value.status || "unknown");
    summary.tone = value.status === "breach" ? "fail" : "neutral";
    summary.metrics = [
      {label: "Bundle", value: String(value.bundle_kind || "unknown")},
      {label: "Sequence", value: count(value.checkpoint_sequence)},
      {label: "Request", value: String(value.request_id || "unknown")},
    ];
    summary.bindings = [
      binding("Plan", value.plan_sha256),
      binding("Checkpoint", value.checkpoint_statement_sha256),
    ].filter(Boolean);
    summary.privacy = ["checkpoint digest only", "no event content", "no secrets or model reasoning"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    return summary;
  }

  function witnessReceiptSummary(value, meta) {
    const witness = object(value.witness, "witness identity");
    const statement = object(value.statement, "witness statement");
    const predicate = object(statement.predicate, "witness predicate");
    const summary = base(
      "Checkpoint witness receipt",
      "Independent checkpoint observation",
      "An offline DSSE-authenticated in-toto receipt for one checkpoint digest.",
      meta,
    );
    summary.status = "Receipt present";
    summary.metrics = [
      {label: "Witness", value: String(witness.witness_id || "unknown")},
      {label: "Bundle", value: String(predicate.bundle_kind || "unknown")},
      {label: "Sequence", value: count(predicate.checkpoint_sequence)},
      {label: "Observed status", value: String(predicate.status || "unknown")},
    ];
    summary.bindings = [
      binding("Witness key", witness.key_id),
      binding("Request", predicate.request_sha256),
      binding("Checkpoint", predicate.checkpoint_statement_sha256),
    ].filter(Boolean);
    summary.privacy = ["checkpoint digest only", "no event content"];
    summary.warnings = Array.isArray(value.limitations) ? value.limitations : [];
    summary.signature = {label: "Embedded DSSE signature present", authenticated: false};
    return summary;
  }

  function statementSummary(statement, meta) {
    if (statement.predicateType === RECEIPT) return receiptSummary(statement, meta);
    if (statement.predicateType === AGGREGATE) return aggregateSummary(statement, meta);
    if (statement.predicateType === LUREPROOF) {
      const predicate = object(statement.predicate, "LureProof predicate");
      const assessment = object(predicate.assessment, "LureProof assessment");
      const summary = base("LureProof", "Per-message resilience evidence", "Privacy-minimized detector and adversarial-resilience statement.", meta);
      summary.status = String(assessment.risk_tier || assessment.label || "inspected");
      summary.tone = assessment.risk_tier === "low" ? "pass" : assessment.risk_tier === "high" ? "fail" : "warn";
      summary.metrics = [
        {label: "Fraud probability", value: ratio(assessment.fraud_probability)},
        {label: "Threshold", value: ratio(assessment.threshold)},
        {label: "Attacks", value: count(predicate.resilience && predicate.resilience.attack_count)},
        {label: "Evasions", value: count(predicate.resilience && predicate.resilience.evasion_count)},
        {label: "Recoveries", value: count(predicate.resilience && predicate.resilience.defense_recovery_count)},
      ];
      summary.bindings = Array.isArray(statement.subject) ? statement.subject.map(item => binding("Subject", item && item.digest && item.digest.sha256)).filter(Boolean) : [];
      summary.privacy = predicate.privacy ? Object.keys(predicate.privacy).filter(key => Boolean(predicate.privacy[key])) : [];
      summary.warnings = Array.isArray(predicate.limitations) ? predicate.limitations : [];
      return summary;
    }
    if (statement.predicateType === COMBINED) {
      const predicate = object(statement.predicate, "combined assurance predicate");
      const outcome = object(predicate.outcome, "combined assurance outcome");
      const summary = base("Combined email assurance", "SCuBA controls × operational pilot", "Configuration posture and measured routing evidence bound in one statement.", meta);
      gateStatus(summary, outcome.pilot_gate_verdict);
      summary.metrics = [
        {label: "SCuBA controls", value: count(outcome.scuba_control_count)},
        {label: "Candidate POA&M", value: count(outcome.candidate_poam_count)},
      ];
      summary.bindings = Array.isArray(statement.subject) ? statement.subject.map(item => binding(item.name || "Subject", item && item.digest && item.digest.sha256)).filter(Boolean) : [];
      summary.warnings = Array.isArray(predicate.limitations) ? predicate.limitations : [];
      return summary;
    }
    if (statement.predicateType === DRIFT) {
      const predicate = object(statement.predicate, "drift predicate");
      const summary = base("SCuBA drift ledger", "Longitudinal assurance change", "A chainable comparison of two compatible combined-assurance snapshots.", meta);
      summary.status = "Drift evidence";
      summary.tone = "neutral";
      const drift = predicate.summary || {};
      summary.metrics = Object.entries(drift).slice(0, 6).map(([label, value]) => ({label: label.replaceAll("_", " "), value: count(value)}));
      summary.bindings = [
        binding("Before", predicate.before_combined_statement_sha256),
        binding("After", predicate.after_combined_statement_sha256),
        binding("Previous ledger", predicate.previous_ledger_statement_sha256),
      ].filter(Boolean);
      summary.warnings = Array.isArray(predicate.limitations) ? predicate.limitations : [];
      return summary;
    }
    if (statement.predicateType === LUREWATCH_CHECKPOINT) {
      const predicate = object(statement.predicate, "LureWatch checkpoint predicate");
      const summary = base(
        "LureWatch checkpoint",
        "Chain-bound deployment monitor",
        "An in-toto checkpoint binding one aggregate monitor entry to its immutable plan and predecessor.",
        meta,
      );
      gateStatus(summary, predicate.family_status);
      summary.metrics = [
        {label: "Sequence", value: count(predicate.sequence)},
        {label: "Authentication mode", value: String(predicate.authentication_mode || "unknown")},
      ];
      summary.bindings = Array.isArray(statement.subject)
        ? statement.subject.map(item => binding(item.name || "Subject", item && item.digest && item.digest.sha256)).filter(Boolean)
        : [];
      const previous = binding("Previous checkpoint", predicate.previous_statement_sha256);
      if (previous) summary.bindings.push(previous);
      summary.privacy = ["aggregate entry", "no message content", "no case identifiers", "no per-message labels or scores"];
      summary.warnings = Array.isArray(predicate.limitations) ? predicate.limitations : [];
      return summary;
    }
    if (statement.predicateType === LUREBOUNDARY_CHECKPOINT) {
      const predicate = object(statement.predicate, "LureBoundary checkpoint predicate");
      const summary = base(
        "LureBoundary checkpoint",
        "Chain-bound agent assurance",
        "An in-toto checkpoint binding a plan, exact evaluation, entry, and predecessor statement.",
        meta,
      );
      gateStatus(summary, predicate.boundary_status);
      summary.metrics = [
        {label: "Sequence", value: count(predicate.sequence)},
        {label: "Required action", value: String(predicate.required_action || "unknown")},
        {label: "Authentication mode", value: String(predicate.authentication_mode || "unknown")},
      ];
      summary.bindings = Array.isArray(statement.subject)
        ? statement.subject.map(item => binding(item.name || "Subject", item && item.digest && item.digest.sha256)).filter(Boolean)
        : [];
      const previous = binding("Previous checkpoint", predicate.previous_statement_sha256);
      if (previous) summary.bindings.push(previous);
      summary.privacy = ["synthetic metadata only", "no prompts, commands, payloads, credentials, hosts, URLs, or reasoning"];
      summary.warnings = Array.isArray(predicate.limitations) ? predicate.limitations : [];
      return summary;
    }
    if (statement.predicateType === AGENT_CHECKPOINT) {
      const predicate = object(statement.predicate, "agent assurance checkpoint predicate");
      const summary = base(
        "Agent assurance checkpoint",
        "Combined assurance statement",
        "An in-toto checkpoint binding the portfolio and three exact evidence reports.",
        meta,
      );
      gateStatus(summary, predicate.overall_status);
      summary.metrics = [
        {label: "Portfolio", value: String(predicate.portfolio_id || "unknown")},
        {label: "Authentication", value: String(predicate.authentication_mode || "unknown")},
      ];
      summary.bindings = Array.isArray(statement.subject)
        ? statement.subject.map(item => binding(item.name || "Subject", item && item.digest && item.digest.sha256)).filter(Boolean)
        : [];
      const boundary = binding("Boundary checkpoint", predicate.boundary_checkpoint_statement_sha256);
      if (boundary) summary.bindings.push(boundary);
      summary.privacy = ["privacy-minimized evidence only", "no event content"];
      summary.warnings = Array.isArray(predicate.limitations) ? predicate.limitations : [];
      return summary;
    }
    if (statement.predicateType === INVARIANT_CHECKPOINT) {
      const predicate = object(statement.predicate, "LureInvariant checkpoint predicate");
      const summary = base(
        "LureInvariant checkpoint",
        "Exact invariant evidence binding",
        "An in-toto checkpoint binding the manifest, plan, observations, and evaluation.",
        meta,
      );
      gateStatus(summary, predicate.overall_status);
      summary.metrics = [
        {label: "Bundle", value: String(predicate.bundle_id || "unknown")},
        {label: "Authentication", value: String(predicate.authentication_mode || "unknown")},
      ];
      summary.bindings = Array.isArray(statement.subject)
        ? statement.subject.map(item => binding(item.name || "Subject", item && item.digest && item.digest.sha256)).filter(Boolean)
        : [];
      summary.privacy = ["typed metadata only", "no targets, payloads, credentials, prompts, commands, or reasoning"];
      summary.warnings = Array.isArray(predicate.limitations) ? predicate.limitations : [];
      return summary;
    }
    if (statement.predicateType === RANGE_CHECKPOINT) {
      const predicate = object(statement.predicate, "LureRange checkpoint predicate");
      const summary = base(
        "LureRange checkpoint",
        "Exact permit-conformance evidence binding",
        "An in-toto checkpoint binding a LureRange manifest and evaluation report.",
        meta,
      );
      gateStatus(summary, predicate.overall_status);
      summary.metrics = [
        {label: "Bundle", value: String(predicate.bundle_id || "unknown")},
        {label: "Engine", value: String(predicate.engine_id || "unknown")},
        {label: "Authentication", value: String(predicate.authentication_mode || "unknown")},
      ];
      summary.bindings = [
        ...(Array.isArray(statement.subject)
          ? statement.subject.map(item => binding(item.name || "Subject", item && item.digest && item.digest.sha256))
          : []),
        binding("Permit", predicate.permit_sha256),
        binding("Range suite", predicate.range_suite_sha256),
      ].filter(Boolean);
      summary.privacy = ["typed synthetic policy metadata", "no live actions, targets, credentials, or reasoning"];
      summary.warnings = Array.isArray(predicate.limitations) ? [...predicate.limitations] : [];
      return summary;
    }
    if (statement.predicateType === RUNTIME_CHECKPOINT) {
      const predicate = object(statement.predicate, "runtime mediation checkpoint predicate");
      const summary = base(
        "Runtime mediation checkpoint",
        "Exact runtime evidence binding",
        "An in-toto checkpoint binding a runtime manifest, exact evaluation, profile, permit, and policy identity.",
        meta,
      );
      gateStatus(summary, predicate.overall_status);
      summary.metrics = [
        {label: "Bundle", value: String(predicate.bundle_id || "unknown")},
        {label: "Policy engine", value: String(predicate.policy_engine_id || "unknown")},
        {label: "Authentication", value: String(predicate.authentication_mode || "unknown")},
      ];
      summary.bindings = [
        ...(Array.isArray(statement.subject)
          ? statement.subject.map(item => binding(item.name || "Subject", item && item.digest && item.digest.sha256))
          : []),
        binding("Runtime profile", predicate.profile_sha256),
        binding("Permit", predicate.permit_sha256),
        binding("Trace", predicate.trace_sha256),
      ].filter(Boolean);
      summary.privacy = ["typed runtime metadata", "no action content, tokens, secrets, or reasoning"];
      summary.warnings = Array.isArray(predicate.limitations) ? [...predicate.limitations] : [];
      return summary;
    }
    if (statement.predicateType === REVOKE_CHECKPOINT) {
      const predicate = object(statement.predicate, "LureRevoke checkpoint predicate");
      const summary = base(
        "LureRevoke checkpoint",
        "Exact revocation evidence binding",
        "An in-toto checkpoint binding a revocation manifest, evaluation, plan, run, and receiver identity.",
        meta,
      );
      gateStatus(summary, predicate.overall_status);
      summary.metrics = [
        {label: "Bundle", value: String(predicate.bundle_id || "unknown")},
        {label: "Receiver", value: String(predicate.receiver_name || "unknown")},
        {label: "Authentication", value: String(predicate.authentication_mode || "unknown")},
      ];
      summary.bindings = [
        ...(Array.isArray(statement.subject)
          ? statement.subject.map(item => binding(item.name || "Subject", item && item.digest && item.digest.sha256))
          : []),
        binding("Plan", predicate.plan_sha256),
        binding("Receiver run", predicate.run_sha256),
      ].filter(Boolean);
      summary.privacy = ["opaque subjects, relative timing, statuses, counts, and digests only"];
      summary.warnings = Array.isArray(predicate.limitations) ? [...predicate.limitations] : [];
      return summary;
    }
    if (statement.predicateType === REVOKE_REGISTRY_HEAD) {
      const predicate = object(statement.predicate, "LureRevoke registry tree-head predicate");
      const summary = base(
        "LureRevoke registry tree head",
        "Authenticated Merkle-history commitment",
        "An in-toto statement committing one complete ordered registry prefix to a Merkle root.",
        meta,
      );
      summary.status = "Tree head inspected";
      summary.metrics = [
        {label: "Registry", value: String(predicate.registry_id || "unknown")},
        {label: "Tree size", value: count(predicate.tree_size)},
        {label: "Hash profile", value: String(predicate.hash_profile || "unknown")},
        {label: "Registered", value: String(predicate.registered_at || "unknown")},
      ];
      summary.bindings = [
        ...(Array.isArray(statement.subject)
          ? statement.subject.map(item => binding(item.name || "Subject", item && item.digest && item.digest.sha256))
          : []),
        binding("Merkle root", predicate.root_sha256),
        binding("Latest entry", predicate.latest_entry_sha256),
        binding("Previous tree head", predicate.previous_tree_head_sha256),
        binding("Registry config", predicate.config_sha256),
        binding("Registry signer", predicate.signer_key_id),
      ].filter(Boolean);
      summary.privacy = ["Merkle and artifact digests, sequence, and time only"];
      summary.warnings = Array.isArray(predicate.limitations) ? [...predicate.limitations] : [];
      summary.warnings.push("The browser does not authenticate DSSE, recompute the Merkle tree, or detect rollback. Use the registry verifier and a retained head.");
      return summary;
    }
    throw new Error("Unsupported in-toto evidence predicate");
  }

  function summarizeArtifact(value) {
    const meta = unwrap(value);
    const statement = meta.statement;
    let summary;
    if (statement.predicateType) summary = statementSummary(statement, meta);
    else if (statement.schema === PILOT_GATE) summary = pilotGateSummary(statement, meta);
    else if (statement.schema === DEFENDER_REPORT) summary = defenderSummary(statement, meta);
    else if (statement.schema === SHADOW_REPORT) summary = shadowSummary(statement, meta);
    else if (statement.schema === LUREWATCH_ENTRY) summary = lurewatchEntrySummary(statement, meta);
    else if (statement.schema === LUREBOUNDARY_EVALUATION) summary = boundaryEvaluationSummary(statement, meta);
    else if (statement.schema === LUREBOUNDARY_PLAN) summary = boundaryPlanSummary(statement, meta);
    else if (statement.schema === LUREBOUNDARY_ENTRY) summary = boundaryEntrySummary(statement, meta);
    else if (statement.schema === COVERAGE_EVALUATION) summary = coverageSummary(statement, meta);
    else if (statement.schema === DELEGATION_EVALUATION) summary = delegationSummary(statement, meta);
    else if (statement.schema === IR_EVALUATION) summary = irSummary(statement, meta);
    else if (statement.schema === AGENT_PORTFOLIO) summary = portfolioSummary(statement, meta);
    else if (statement.schema === WITNESS_REQUEST) summary = witnessRequestSummary(statement, meta);
    else if (statement.schema === WITNESS_RECEIPT) summary = witnessReceiptSummary(statement, meta);
    else if (statement.schema === INVARIANT_PLAN) summary = invariantPlanSummary(statement, meta);
    else if (statement.schema === INVARIANT_EVALUATION) summary = invariantEvaluationSummary(statement, meta);
    else if (statement.schema === INVARIANT_BUNDLE) summary = invariantBundleSummary(statement, meta);
    else if (statement.schema === INVARIANT_COMPARISON) summary = invariantComparisonSummary(statement, meta);
    else if (statement.schema === RANGE_EVALUATION) summary = rangeEvaluationSummary(statement, meta);
    else if (statement.schema === RANGE_BUNDLE) summary = rangeBundleSummary(statement, meta);
    else if (statement.schema === RANGE_COMPARISON) summary = rangeComparisonSummary(statement, meta);
    else if (statement.schema === RUNTIME_EVALUATION) summary = runtimeEvaluationSummary(statement, meta);
    else if (statement.schema === RUNTIME_BUNDLE) summary = runtimeBundleSummary(statement, meta);
    else if (statement.schema === RUNTIME_COMPARISON) summary = runtimeComparisonSummary(statement, meta);
    else if (statement.schema === REVOKE_EVALUATION) summary = revocationEvaluationSummary(statement, meta);
    else if (statement.schema === REVOKE_BUNDLE) summary = revocationBundleSummary(statement, meta);
    else if (statement.schema === REVOKE_COMPARISON) summary = revocationComparisonSummary(statement, meta);
    else if (statement.schema === REVOKE_REGISTRY) summary = revocationRegistrySummary(statement, meta);
    else if (statement.schema === REVOKE_REGISTRY_ENTRY) summary = revocationRegistryEntrySummary(statement, meta);
    else if (statement.schema === REVOKE_REGISTRY_INCLUSION) summary = revocationRegistryInclusionSummary(statement, meta);
    else if (statement.schema === REVOKE_REGISTRY_CONSISTENCY) summary = revocationRegistryConsistencySummary(statement, meta);
    else if (statement.schema === REVOKE_REGISTRY_HEAD_COMPARISON) summary = revocationRegistryHeadComparisonSummary(statement, meta);
    else if (statement.schema === REVOKE_TOPOLOGY_AUDIT) summary = revocationTopologySummary(statement, meta);
    else if (statement.schema === REVOKE_OTEL_PROJECTION) summary = revocationOtelProjectionSummary(statement, meta);
    else if (statement.schema === REVOKE_DEPLOYMENT_GATE) summary = revocationDeploymentGateSummary(statement, meta);
    else throw new Error("Unsupported evidence artifact. Choose a LureEval, Pilot Gate, Defender, Shadow, LureProof, SCuBA, LureWatch, LureBoundary, LureInvariant, LureRange, runtime mediation, LureRevoke, coverage, delegation, LureIR, portfolio, or witness artifact.");
    if (meta.signed) summary.warnings.unshift("A DSSE signature is present but is not cryptographically authenticated by this browser view. Verify it with the CLI and a trusted public key.");
    else summary.warnings.unshift("This artifact is unsigned or was supplied without an envelope; issuer identity is not authenticated.");
    return summary;
  }

  function parseArtifact(text) {
    if (typeof text !== "string" || new TextEncoder().encode(text).length > MAX_ARTIFACT_BYTES) {
      throw new Error("Evidence file exceeds the 8 MB safety limit");
    }
    let value;
    try { value = JSON.parse(text); }
    catch (error) { throw new Error("Evidence file is not valid JSON"); }
    return summarizeArtifact(value);
  }

  return {MAX_ARTIFACT_BYTES, parseArtifact, summarizeArtifact, unwrap};
});
