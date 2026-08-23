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
