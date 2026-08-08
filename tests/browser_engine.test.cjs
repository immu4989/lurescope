const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const engine = require("../lurescope/static/browser-engine.js");
const model = JSON.parse(fs.readFileSync(path.join(__dirname, "../space/model.json"), "utf8"));
engine.setModel(model);

const phishing = "Dear customer, verify your account within 24 hours or it will be suspended. Confirm now at https://example.test/login.";
const benign = "Hi team, the design review moved to Thursday at 2 PM. Please add comments to the shared project folder.";

test("browser TF-IDF model ranks the phishing sample above the benign sample", () => {
  const fraud = engine.scoreMessage(phishing, "tfidf-logreg");
  const normal = engine.scoreMessage(benign, "tfidf-logreg");

  assert.ok(fraud.fraud_probability > normal.fraud_probability);
  assert.equal(fraud.threshold_source, "browser-default");
  assert.ok(fraud.signals.length > 0);
});

test("homoglyph normalization restores the original heuristic score", () => {
  const result = engine.attackMessage(phishing, "homoglyph", "heuristic-v0", "normalize");

  assert.notEqual(result.attacked, result.original);
  assert.equal(result.defended_text, result.original);
  assert.ok(Math.abs(result.defended_probability - result.clean_probability) < 1e-12);
  assert.equal(result.defense_recovered, result.evaded);
});

test("bounded email preview separates model output from deterministic context", () => {
  const raw = [
    "From: Billing <billing@example.com>",
    "Reply-To: collect@lookalike.example",
    "To: user@example.net",
    "Subject: Urgent invoice payment",
    "Message-ID: <preview-1@example.com>",
    "Authentication-Results: gateway.example; spf=fail; dkim=fail; dmarc=fail",
    "Content-Type: multipart/mixed; boundary=boundary-1",
    "",
    "--boundary-1",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Please process the attached invoice and sign in at http://192.0.2.7/login.",
    "--boundary-1",
    "Content-Type: application/octet-stream; name=invoice.exe",
    "Content-Disposition: attachment; filename=invoice.exe",
    "",
    "not-opened",
    "--boundary-1--",
  ].join("\r\n");

  const result = engine.triageEmail(raw, "heuristic-v0");
  const codes = new Set(result.evidence.map((item) => item.code));

  assert.equal(result.browser_preview, true);
  assert.equal(result.risk_tier, "high");
  assert.ok(codes.has("reply_to_domain_mismatch"));
  assert.ok(codes.has("email_authentication_failed"));
  assert.ok(codes.has("ip_literal_url"));
  assert.ok(codes.has("executable_attachment"));
  assert.deepEqual(result.attachments, ["invoice.exe"]);
});

test("oversized and content-free email inputs fail closed", () => {
  assert.throws(() => engine.triageEmail("From: a@example.test\r\n\r\n"), /no subject or readable text/i);
  assert.throws(() => engine.scoreMessage("x".repeat(engine.MAX_TEXT + 1)), /character limit/i);
});
