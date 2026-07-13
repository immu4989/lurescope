---
title: LureScope
emoji: 🔬
colorFrom: blue
colorTo: green
sdk: static
pinned: false
license: apache-2.0
short_description: Fraud-lure scoring with a live adversarial-evasion demo
---

# 🔬 LureScope

Deployable fraud-lure scoring with a **live adversarial-evasion demo**. Paste a message, score it for fraud, then apply an attack a real fraudster would run (homoglyph, leet, zero-width, whitespace) and watch whether the detector still catches it.

- **`tfidf-logreg`** (trained baseline) catches a phishing lure strongly and degrades gracefully under attack.
- **`heuristic-v0`** (keyword rules) catches it too, then a single homoglyph swap makes it evade detection.

Same message, same attack, opposite outcomes: clean-data accuracy is not deployment accuracy.

This Static Space runs both detectors and the attacks **entirely in your browser** — no server, no data leaves the page. It uses the exact trained model from the [LureBench](https://github.com/immu4989/lurebench) benchmark, exported to JSON.

Full REST API (with LLM-based attacks) and source: **[github.com/immu4989/lurescope](https://github.com/immu4989/lurescope)**.
