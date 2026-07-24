---
title: LureScope
emoji: 🔬
colorFrom: blue
colorTo: green
sdk: static
pinned: false
license: apache-2.0
short_description: Fraud-lure scoring with a live attack-and-defense demo
---

# 🔬 LureScope

Deployable fraud-lure scoring with a **live attack-and-defense demo**. Paste a message, score it for fraud, apply an attack a real fraudster would run (homoglyph, leet, zero-width, whitespace), then turn on a defense and see whether the detector recovers.

- **`tfidf-logreg`** (trained baseline) catches a phishing lure strongly and degrades gracefully under attack.
- **`heuristic-v0`** (keyword rules) catches it too, then a single homoglyph swap makes it evade detection.
- **`normalize` defense** folds the attacked text back to plain ASCII before re-scoring. It reverses homoglyph and zero-width losslessly and the keyword detector recovers — but a semantic paraphrase would slip through untouched, because that attack changed the meaning, not the spelling.

Same message, opposite outcomes, and a defense that closes the typographic gap while leaving the semantic one exposed: clean-data accuracy is not deployment accuracy.

This Static Space runs both detectors, all four attacks, and the normalization defense **entirely in your browser** — no server, no data leaves the page. It uses the exact trained model from the [LureBench](https://github.com/immu4989/lurebench) benchmark, exported to JSON.

## What happens with real LLM detectors

The two detectors here are token-based, which is why a homoglyph swap breaks them. Running the same attacks against an LLM-as-classifier across five models (measured offline over 120 fraud lures, not in this browser demo) gives a sharper picture:

- Strong LLM judges are **essentially immune to the character attacks**: 0-6% evasion, where the keyword detector above hits 100%. They read the meaning straight through the homoglyphs.
- That immunity is **paid for in recall**. The judges catch only 27-65% of these lures on clean text, against 96% for the trained TF-IDF baseline, so they miss a lot of fraud before any attack is applied.
- **Paraphrase is the crack.** It is the attack that most erodes the judges, and the best-recall judge is also the most paraphrase-evadable.

No single detector is robust on every axis. Full numbers and caveats: [LLM_SCORECARD.md](https://github.com/immu4989/lurescope/blob/main/LLM_SCORECARD.md).

Full REST API (with the real content-safety detectors and LLM-based attacks) and source: **[github.com/immu4989/lurescope](https://github.com/immu4989/lurescope)**. Background and the corpus-level robustness numbers: **[the scorecard writeup](https://github.com/immu4989/lurescope/blob/main/blog/2026-07-23-robustness-gap-fraud-detection.md)**.
