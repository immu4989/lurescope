/* Run against an installed trusted wheel, not the source checkout. No network. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

if (process.argv.length !== 3) throw new Error("Usage: node check_installed_browser.cjs INSTALLED_ROOT");
const root = fs.realpathSync(process.argv[2]);
const checkout = fs.realpathSync(path.join(__dirname, ".."));
const cwd = fs.realpathSync(process.cwd());
if (cwd === checkout || cwd.startsWith(checkout + path.sep)) throw new Error("Run outside the source checkout");
if (root === checkout || root.startsWith(checkout + path.sep)) throw new Error("Use an isolated installation");
const assets = path.join(root, "lurescope/static");
const model = JSON.parse(fs.readFileSync(path.join(assets, "model.json"), "utf8"));
const engine = require(path.join(assets, "browser-engine.js"));
engine.setModel(model);
const result = engine.scoreMessage("Please verify your bank account");
assert.ok(Math.abs(result.fraud_probability - 0.8944714598915419) < 1e-5);
assert.equal(result.label, "fraud");
assert.ok(Number.isFinite(engine.scoreMessage("__proto__ constructor").fraud_probability));
for (const filename of ["index.html", "evidence-explorer.js", "capacity-planner.js", "capacity-ui.js"]) {
  assert.ok(fs.statSync(path.join(assets, filename)).size > 0, `Missing browser asset: ${filename}`);
}
const evidence = require(path.join(assets, "evidence-explorer.js"));
const fixture = fs.readFileSync(path.join(__dirname, "../tests/fixtures/cluster-uncertainty.json"), "utf8");
const uncertainty = evidence.parseArtifact(fixture);
assert.equal(uncertainty.kind, "LureBench detector uncertainty");
assert.equal(uncertainty.status, "Uncertainty only");
assert.equal(uncertainty.signature.authenticated, false);
assert.ok(uncertainty.metrics.some(m => m.label === "Records / resampling units" && m.value === "6 / 3"));
assert.ok(uncertainty.warnings.some(w => w.includes("verify-uncertainty")));
const altered = JSON.parse(fixture);
altered.metrics.recall.lower = -1;
assert.throws(() => evidence.summarizeArtifact(altered), /Invalid detector uncertainty report/);
console.log("PASS installed browser model, dictionary scoring, assets, and grouped uncertainty view");
