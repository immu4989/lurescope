# Local verification and handoff — 2026-09-29

Unreleased, uncommitted, unpushed changes on `feat/lurepermit-lurerange`.
Stopped new work at the usage check reporting 9% remaining, near the requested
10% boundary. No paid/provider calls or production changes were made.

- Final LureScope suite: **912 passed**, 16 dependency warnings; lint and tracked
  whitespace checks passed. Same count also passed against adjacent LureBench.
- Final LureBench suite: **1,290 passed, 39 skipped**, 9 dependency warnings.
- **62 Node tests passed**, including capacity arithmetic and form invalidation.
  Python/JavaScript outputs matched for 80 synthetic configurations, seven
  prevalence scenarios each. These are correctness checks, not measured accuracy.
- Synthetic capacity/policy interoperability checks passed; 26 pinned producer
  contracts and 10 independent authority artifacts verified.
- Earlier wheels built and passed isolated installation checks, including the
  data-only default model with executable-model frameworks blocked. These builds
  predate the final inbox/policy/uncertainty/lineage changes: **rebuild and rerun
  installed-package checks before release**.

New work includes strict bounded HTTP/JSON intake, proof/key validation, safe
inbox reads, a browser/CLI capacity planner, and optional simultaneous sampling
bounds on expected review workload. Read [capacity assumptions](CAPACITY_PLANNING.md)
and [migration guidance](HARDENING_MIGRATION.md) before use.

Browser visual QA remains incomplete because the browser tool blocked access to
its failed-navigation page. The temporary localhost server was stopped. Automated
form tests do not substitute for desktop/mobile layout and interaction checks.

Next: review both local diffs; rebuild final wheels and rerun installed and
cross-repository checks; complete browser visual QA; then request push/release
authorization. Passing these checks does not establish government certification,
compliance, deployment safety, or operational detection performance.
