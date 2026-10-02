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
console.log("PASS installed browser model, safe dictionary scoring, and workbench assets");
