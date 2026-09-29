/* Form adapter: aggregate counts stay in this tab; invalid edits hide stale results. */
(function () {
  "use strict";
  const form = document.getElementById("capacityForm");
  if (!form || !globalThis.LureScopeCapacity) return;
  const byId = id => document.getElementById(id);
  const output = byId("capacityResult");
  const error = byId("capacityError");
  const download = byId("capacityDownload");
  // Significant digits keep rare-event assumptions and tiny shortfalls nonzero.
  const formatter = new Intl.NumberFormat(undefined, {maximumSignificantDigits: 6});
  let current = null;
  function numeric(id) {
    const raw = byId(id).value.trim();
    if (!raw) throw new Error("Every numeric assumption and outcome count is required.");
    return Number(raw);
  }
  function resetOutput() {
    current = null;
    output.hidden = true;
    download.disabled = true;
  }
  form.addEventListener("input", () => {
    resetOutput();
    error.textContent = "Inputs changed. Recalculate to update the scenarios.";
    byId("capacitySource").textContent = "Operator-entered counts and assumptions — not independently verified.";
  });
  function calculate(event) {
    if (event) event.preventDefault();
    resetOutput();
    error.textContent = "";
    try {
      const counts = {};
      for (const key of ["tp", "fp", "tn", "fn", "abstained_positive", "abstained_negative"]) {
        counts[key] = numeric(`capacity_${key}`);
      }
      current = globalThis.LureScopeCapacity.plan({schema_version: 1, task: "fraud",
        detector: byId("capacityDetector").value, threshold: numeric("capacityThreshold"), counts},
      {messages_per_period: numeric("capacityVolume"), review_minutes_per_case: numeric("capacityMinutes"),
        available_review_hours: numeric("capacityHours"),
        prevalences: ["capacityLow", "capacityMiddle", "capacityHigh"].map(id => numeric(id) / 100)});
      const body = byId("capacityRows");
      body.replaceChildren();
      for (const scenario of current.scenarios) {
        const row = document.createElement("tr");
        const values = [formatter.format(scenario.fraud_prevalence * 100) + "%",
          formatter.format(scenario.expected_review_cases),
          scenario.fraud_share_among_flags === null ? "Undefined (no flags)" :
            formatter.format(scenario.fraud_share_among_flags * 100) + "%",
          formatter.format(scenario.required_review_hours),
          scenario.exceeds_review_capacity ? `${formatter.format(scenario.review_hour_shortfall)} hours short` :
            "Within supplied hours"];
        for (const [i, value] of values.entries()) {
          const cell = document.createElement(i === 0 ? "th" : "td");
          if (i === 0) cell.scope = "row";
          cell.textContent = value;
          if (i === 4 && scenario.exceeds_review_capacity) cell.className = "capacity-over";
          row.appendChild(cell);
        }
        body.appendChild(row);
      }
      output.hidden = false;
      download.disabled = false;
    } catch (failure) {
      resetOutput();
      error.textContent = failure.message;
    }
  }
  form.addEventListener("submit", calculate);
  download.addEventListener("click", () => {
    if (!current) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(current, null, 2) + "\n"], {type: "application/json"}));
    const link = document.createElement("a");
    link.href = url;
    link.download = "capacity-scenarios.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  calculate();
})();
