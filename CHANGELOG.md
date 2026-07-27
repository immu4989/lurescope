# Changelog

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
