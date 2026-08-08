# Changelog

## 0.5.0 — 2026-08-08

### Added
- **LureProof 0.1**, an experimental, vendor-neutral resilience passport for a
  suspicious email: minimized message identity, detector and threshold provenance,
  deterministic attack/defense outcomes, implementation provenance, limitations,
  and independently recomputable integrity.
- `lurescope proof`, `lurescope verify`, `POST /proof/email`, and
  `POST /proof/verify` workflows.
- A public JSON Schema, design and standards-landscape document, privacy regression
  tests, deterministic reproduction test, tamper test, CLI test, and API test.

## 0.4.0 — 2026-08-08

### Added
- Privacy-first `.eml` triage through the web lab, `lurescope triage`, and
  `POST /triage/email`, including directory batches and JSONL output.
- Safe standard-library email parsing that never fetches links or opens attachment
  contents; HTML active content is excluded from scored visible text.
- Transparent context evidence for Reply-To domain mismatch, explicit email-auth
  failures, punycode/IP links, executable and archive attachment names.
- Stable triage schema, risk routing, recommended human actions, defanged example,
  and a real-world workflow guide with explicit safety boundaries.

## 0.3.0 — 2026-08-05

### Added
- A complete visual redesign for both the API-backed demo and zero-backend Space:
  forensic-console identity, guided score/attack/defend flow, responsive layouts,
  visible threshold provenance, keyboard focus states, and reduced-motion support.
- A coordinated repository hero graphic shared with the LureBench visual system.
- Strict loading of versioned decision policies exported by LureBench 0.9 through
  `LURESCOPE_POLICY_PATH`. Policies must carry a validation row count and SHA-256
  provenance digest and must target fraud detection.
- `/score` now reports `policy_id` and `threshold_source`, distinguishing a
  validation-selected policy from a caller override or the legacy 0.5 default.

### Changed
- Omitting `/score.threshold` uses a configured policy when its detector matches.
  Explicit thresholds remain fully backward compatible and always take priority.

## 0.2.1 — 2026-07-30

### Fixed
- **The cross-model scorecard measured a smaller sample than it reported.**
  `scripts/llm_scorecard.py` keyed its per-record maps by `rec["id"]`, and
  LureBench shipped roughly 500 generated records whose ids collided across
  generators. Colliding records overwrote each other, so the table headed
  *120 fraud lures* was computed over 73 distinct records, 25 of them counted two
  or three times. The maps are now keyed by position, which cannot collide, and
  the ids themselves are fixed upstream in LureBench 0.8.0.

  The effect was not uniform, because the collided records were mostly the harder
  BEC lures: judge clean recall was understated by 4 to 10 points, and
  `deepseek-v4-flash` paraphrase evasion moved from 27% to 16% while
  `qwen-2.5-7b` moved from 21% to 29%. `LLM_SCORECARD.md` and the README are
  regenerated and corrected.

  One claim does not survive: the best-recall judge is no longer the most
  paraphrase-evadable. `qwen-2.5-7b` now holds that position and has among the
  lowest recall.

- **Corrections are no longer deleted by regeneration.** The 2026-07-26
  calibration correction had been written into `LLM_SCORECARD.md` by hand and was
  silently removed the next time the script rebuilt the file. Both corrections now
  live in the generator and survive a rerun.

- `ruff` is pinned in the `dev` extra. An unpinned linter installs a newer default
  rule set in CI than the one used locally, which is how LureBench's CI went red
  on a green commit.

### Added
- A regression test that runs three distinct texts sharing one record id and
  asserts none are dropped. It fails against the previous id-keyed implementation.


## 0.2.0 — 2026-07-27

Adds a defense, exposes the detectors teams actually deploy, and publishes two
corpus-level scorecards. One entry below is a correction to a result this project
previously published.

### Added
- **`normalize` defense** (`lurescope/defense.py`) and a `defense` field on
  `/attack`, so one call shows the full loop: clean score, attacked score, then
  the score after input normalization. It strips invisible format characters,
  folds confusable Cyrillic and Greek back to Latin, and undoes in-word leet.
  `defense_recovered` and `defended_evaded` report whether the defense turned an
  evasion back into a catch.
- **Extended detectors.** `/capabilities` now advertises all six LureBench
  detectors rather than two. `llm-judge`, `openai-moderation`, `llama-guard-3`
  and `binoculars` are key- or dependency-gated; requesting one without its
  requirement returns a clear `400` naming what is missing, never a `500`.
- **Robustness scorecard** (`scripts/robustness_scorecard.py`, `SCORECARD.md`):
  detector by attack evasion rates over a corpus, raw and after the defense.
  Normalization drives homoglyph and zero-width evasion to 0% for both baseline
  detectors, leaves a 16% leet residue, and does nothing for whitespace.
- **Cross-model scorecard** (`scripts/llm_scorecard.py`, `LLM_SCORECARD.md`):
  the LLM-judge detector across five models via one OpenRouter key, against the
  four character attacks and an LLM paraphrase.
- The browser demo and the Hugging Face Space both gained the defense, with the
  JavaScript port verified byte-for-byte against Python across every attack.
- Community infrastructure: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, `CITATION.cff`, issue and PR templates, Dependabot, pre-commit.

### Changed
- README reframed around the three-move story: score, evade, defend.

### Fixed
- **Corrected the recall claim.** The cross-model scorecard originally read the
  judges' low clean recall as a capability trade-off, "immunity to character
  attacks bought with recall". Re-measured over the full 2,056-record LureBench
  `core/test` set with threshold-free metrics, that was wrong: the judges post an
  AUC of 0.89 to 0.94 and are simply miscalibrated at the 0.50 cutoff. Dropping
  `deepseek-v4-flash` to a 0.10 threshold lifts recall from 0.750 to 0.856 at a
  2.5% false-positive rate. The character-attack immunity and the paraphrase
  weakness both stand; the recall trade-off does not.

## 0.1.0 — 2026-07-13

Initial release.

### Added
- FastAPI service with `/health`, `/capabilities`, `/score`, `/attack`, and a
  self-contained browser demo at `/`.
- `tfidf-logreg` (bundled trained model) and `heuristic-v0` detectors, reusing
  LureBench so the served and benchmarked models cannot drift.
- Four character attacks and two LLM-driven attacks.
- Zero-backend Hugging Face Space that replicates scikit-learn's TfidfVectorizer
  transform in JavaScript, verified to match the Python service to four decimals.
- Dockerfile, CI across Python 3.9 / 3.11 / 3.12.
