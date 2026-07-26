# Cross-model robustness scorecard

Evasion rate = of the fraud lures a detector caught on clean text, the fraction that fall below the 0.50 threshold after the attack. Lower is more robust. `paraphrase` is an LLM rewrite (attacker: `deepseek/deepseek-v4-flash`); the other four are dependency-free character attacks. Judge abstentions are excluded from each rate, not counted as evasions.

**Corpus:** LureBench core/test · 120 fraud lures. **Judges via OpenRouter:** openai/gpt-5-nano, google/gemini-2.5-flash-lite, deepseek/deepseek-v4-flash, qwen/qwen-2.5-7b-instruct, meta-llama/llama-3.1-8b-instruct.

| Detector | Clean recall | homoglyph | leet | zero-width | whitespace | paraphrase |
|---|---|---|---|---|---|---|
| `tfidf-logreg` | 96% (115) | 52% | 19% | 2% | 0% | 1% |
| `heuristic-v0` | 30% (36) | 100% | 100% | 100% | 56% | 19% |
| `judge:openai/gpt-5-nano` | 27% (32) | 0% | 0% | 0% | 0% | 4% |
| `judge:google/gemini-2.5-flash-lite` | 43% (52) | 4% | 0% | 4% | 4% | 6% |
| `judge:deepseek/deepseek-v4-flash` | 65% (78) | 3% | 4% | 6% | 5% | 27% |
| `judge:qwen/qwen-2.5-7b-instruct` | 28% (34) | 18% | 15% | 24% | 15% | 21% |
| `judge:meta-llama/llama-3.1-8b-instruct` | 40% (48) | 12% | 12% | 12% | 19% | 15% |

Three things to read here. First, the token detectors (`tfidf-logreg`, `heuristic-v0`) collapse under character attacks while the stronger LLM judges are essentially immune to them — they read the meaning through the homoglyphs. Second, the judges' clean recall in this table is much lower than the TF-IDF baseline's — but see the correction below before reading that as a capability gap. Third, `paraphrase` — the only attack that changes meaning rather than spelling — is where the judges are most evadable, and the small judges are weak on every axis at once. No single detector is robust down all of them.

Caveat: the paraphrase attacker (`deepseek/deepseek-v4-flash`) is itself one of the judged model families, so read that judge's `paraphrase` cell with the coupling in mind. Evasion is conditioned on a clean catch, so low-recall rows rest on fewer lures.

## Correction (2026-07-26): the low clean recall is mostly a threshold artifact

The first version of this page read the judges' clean-recall column as a capability trade-off — "immunity to character attacks is bought with recall." A follow-up run over the full 2,056-record `core/test` set, with threshold-free metrics, shows that reading was wrong.

The judges rank fraud above benign well. What they do badly is land on the 0.50 cut this table uses:

| Judge | AUC | TPR @ 0.50 | best-F1 threshold | TPR there | FPR there |
|---|---|---|---|---|---|
| `deepseek/deepseek-v4-flash` | 0.940 | 0.750 | 0.10 | 0.856 | 0.025 |
| `google/gemini-2.5-flash-lite` | 0.937 | 0.726 | 0.05 | 0.870 | 0.049 |
| `qwen/qwen-2.5-7b-instruct` | 0.889 | 0.576 | 0.20 | 0.832 | 0.143 |

An AUC of 0.89–0.94 is not a detector that "misses a great deal of fraud." It is a detector whose scores are compressed toward zero, so a 0.50 cut throws away recall that a lower threshold recovers at a low false-positive cost. The remaining gap against `tfidf-logreg` is real but much smaller than this table implies, and part of what is left comes from the 120-lure sample here being deliberately weighted toward the subtle romance / BEC / pig-butchering typologies rather than phishing.

What survives unchanged: the character-attack immunity, and paraphrase as the attack that actually erodes the judges. What does not: the claim that the immunity is paid for in recall. If you deploy an LLM judge, calibrate its threshold on your own data instead of assuming 0.50.

Full leaderboard with threshold-free metrics: [LureBench `docs/leaderboard.md`](https://github.com/immu4989/lurebench/blob/main/docs/leaderboard.md).
