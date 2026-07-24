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

Three things to read here. First, the token detectors (`tfidf-logreg`, `heuristic-v0`) collapse under character attacks while the stronger LLM judges are essentially immune to them — they read the meaning through the homoglyphs. Second, that immunity is bought with recall: the judges catch far fewer of these lures on clean text than the TF-IDF baseline does, so they miss a great deal of fraud before any attack is applied (this sample is weighted toward the subtle romance / BEC / pig-butchering typologies). Third, `paraphrase` — the only attack that changes meaning rather than spelling — is where the judges are most evadable, and the small judges are weak on every axis at once. No single detector is robust down all of them.

Caveat: the paraphrase attacker (`deepseek/deepseek-v4-flash`) is itself one of the judged model families, so read that judge's `paraphrase` cell with the coupling in mind. Evasion is conditioned on a clean catch, so low-recall rows rest on fewer lures.
