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
    else throw new Error("Unsupported evidence artifact. Choose a LureEval, Pilot Gate, Defender, Shadow, LureProof, SCuBA, or LureWatch artifact.");
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
