# Cross-model robustness scorecard

Evasion rate = of the fraud lures a detector caught on clean text, the fraction that fall below the 0.50 threshold after the attack. Lower is more robust. `paraphrase` is an LLM rewrite (attacker: `deepseek/deepseek-v4-flash`); the other four are dependency-free character attacks. Judge abstentions are excluded from each rate, not counted as evasions.

**Corpus:** LureBench core/test · 120 fraud lures. **Judges via OpenRouter:** openai/gpt-5-nano, google/gemini-2.5-flash-lite, deepseek/deepseek-v4-flash, qwen/qwen-2.5-7b-instruct, meta-llama/llama-3.1-8b-instruct.

| Detector | Clean recall | homoglyph | leet | zero-width | whitespace | paraphrase |
|---|---|---|---|---|---|---|
| `tfidf-logreg` | 97% (116) | 47% | 16% | 3% | 1% | 3% |
| `heuristic-v0` | 29% (35) | 100% | 100% | 100% | 63% | 20% |
| `judge:openai/gpt-5-nano` | 36% (43) | 0% | 0% | 0% | 0% | 3% |
| `judge:google/gemini-2.5-flash-lite` | 53% (64) | 5% | 0% | 2% | 2% | 6% |
| `judge:deepseek/deepseek-v4-flash` | 68% (82) | 1% | 1% | 7% | 10% | 16% |
| `judge:qwen/qwen-2.5-7b-instruct` | 29% (35) | 9% | 6% | 20% | 9% | 29% |
| `judge:meta-llama/llama-3.1-8b-instruct` | 44% (53) | 13% | 9% | 23% | 19% | 21% |

## Corrections to earlier versions of this table

**2026-07-30 - the sample was smaller than stated.** This script keyed its per-record maps by `rec["id"]`, and LureBench shipped roughly 500 generated records whose ids collided across generators (`gen-bec-000006` existed once per model, with different text each time). Colliding records overwrote each other, so the table headed *120 fraud lures* was computed over **73 distinct records**, 25 of them counted two or three times. The maps are now keyed by position and the ids themselves are fixed upstream.

The effect was not uniform, because the collided records were mostly the harder BEC lures: judge clean recall was understated by 4 to 10 points, and `deepseek-v4-flash` paraphrase evasion moved from 27% to 16% while `qwen-2.5-7b` moved from 21% to 29%. One claim built on the old numbers - that the best-recall judge was also the most paraphrase-evadable - does not survive: `qwen-2.5-7b` is now the most paraphrase-evadable and has among the lowest recall.

**2026-07-26 - low clean recall was mostly a threshold artifact.** An earlier version read the judges' low clean recall as a capability trade-off, "immunity to character attacks bought with recall". Measured threshold-free over the full 2,056-record `core/test` set, the judges post an AUC of 0.89 to 0.94: they rank fraud above benign well and are simply miscalibrated at the 0.50 cutoff this table uses. Dropping `deepseek-v4-flash` to a 0.10 threshold lifts recall from 0.750 to 0.856 at a 2.5% false-positive rate. Calibrate on your own data rather than assuming 0.50.


Three things to read here. First, the token detectors (`tfidf-logreg`, `heuristic-v0`) collapse under character attacks while the stronger LLM judges are essentially immune to them — they read the meaning through the homoglyphs. Second, that immunity is bought with recall: the judges catch far fewer of these lures on clean text than the TF-IDF baseline does, so they miss a great deal of fraud before any attack is applied (this sample is weighted toward the subtle romance / BEC / pig-butchering typologies). Third, `paraphrase` — the only attack that changes meaning rather than spelling — is where the judges are most evadable, and the small judges are weak on every axis at once. No single detector is robust down all of them.

Caveat: the paraphrase attacker (`deepseek/deepseek-v4-flash`) is itself one of the judged model families, so read that judge's `paraphrase` cell with the coupling in mind. Evasion is conditioned on a clean catch, so low-recall rows rest on fewer lures.
