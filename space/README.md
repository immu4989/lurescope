---
title: LureScope
emoji: 🔬
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
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

This Docker Space serves a **static, browser-only lab**: both detectors, all four
attacks, email preview, and the normalization defense execute inside your browser.
No scoring or message-content endpoint exists in the container, so pasted text and
uploaded email stay in the tab.

The image build installs the exact `lurescope==0.7.1` wheel from
[PyPI](https://pypi.org/project/lurescope/0.7.1/) with its SHA-256 pinned, then
extracts the wheel's packaged web interface. The trained LureBench model remains a
checked-in, client-side JSON artifact. This makes the public Space a deployment
test of the released package without weakening its privacy boundary.

## What happens with real LLM detectors

The two detectors here are token-based, which is why a homoglyph swap breaks them. Running the same attacks against an LLM-as-classifier across five models (measured offline over 120 fraud lures, not in this browser demo) gives a sharper picture:

- Strong LLM judges are **essentially immune to the character attacks**: 0-6% evasion, where the keyword detector above hits 100%. They read the meaning straight through the homoglyphs.
- Their lower recall at the default 0.50 threshold is mostly a **calibration artifact**, not a capability trade-off. Threshold-free AUC is 0.89–0.94 on the full test set; deployments must select an operating point on validation data.
- **Paraphrase is the crack.** It is the attack that most erodes the judges, and the best-recall judge is also the most paraphrase-evadable.

No single detector is robust on every axis. Full numbers, corrections, and caveats: [LLM_SCORECARD.md](https://github.com/immu4989/lurescope/blob/main/LLM_SCORECARD.md).

Full REST API (with the real content-safety detectors and LLM-based attacks) and source: **[github.com/immu4989/lurescope](https://github.com/immu4989/lurescope)**. Background and the corpus-level robustness numbers: **[the scorecard writeup](https://github.com/immu4989/lurescope/blob/main/blog/2026-07-23-robustness-gap-fraud-detection.md)**.
