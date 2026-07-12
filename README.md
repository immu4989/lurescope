<div align="center">

# 🔬 LureScope

### Score a message for fraud — then watch an attacker try to evade the detector, live

A deployable API and demo for AI-generated fraud-lure detection. The serving companion to [LureBench](https://github.com/immu4989/lurebench).

[![CI](https://github.com/immu4989/lurescope/actions/workflows/ci.yml/badge.svg)](https://github.com/immu4989/lurescope/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-0.1.0-4a3aa7)
![License](https://img.shields.io/badge/license-Apache_2.0-2a78d6)
![Python](https://img.shields.io/badge/python-3.9%2B-1baf7a)
![API](https://img.shields.io/badge/API-FastAPI-009485)

</div>

---

Most fraud-scoring demos stop at "is this phishing? — 94%." That number is the easy part, and it hides the question that actually matters in production: **does the detector survive an attacker who perturbs the message?** LureScope answers both. Paste a message, get a fraud score, then apply an attack a real fraudster would run (`homoglyph`, `leet`, paraphrase) and see whether the detector still catches it.

<p align="center">
  <img src="docs/assets/demo.png" width="720" alt="LureScope demo: a phishing message scored 90% fraud by the trained detector; after a homoglyph attack the keyword detector's score drops from 69% to 17% and the message evades detection.">
</p>

## Why this exists

A detector's clean-data accuracy is not its deployment accuracy. LureScope makes that gap visible and interactive:

- **`heuristic-v0`** (keyword rules) catches the clean lure at 69%, then a single homoglyph substitution (`vеrifу` with a Cyrillic `е`) drops it to 17% — the message walks straight through.
- **`tfidf-logreg`** (trained baseline) catches the same lure at 90% and degrades gracefully under the same attack.

Same message, same attack, opposite outcomes. That is the story a security team needs before trusting a score, and LureScope lets them see it in ten seconds.

## Quickstart

```bash
git clone https://github.com/immu4989/lurescope && cd lurescope
pip install .
lurescope            # serves the API + demo at http://127.0.0.1:8000
```

Open the demo in a browser, or call the API directly:

```bash
# Score a message
curl -s localhost:8000/score -H 'content-type: application/json' \
  -d '{"text":"Verify your account within 24 hours or it will be suspended."}'
# -> {"fraud_probability":0.90,"label":"fraud","signals":["your","account","within","hours"], ...}

# Attack it: does the detector still catch it after a homoglyph swap?
curl -s localhost:8000/attack -H 'content-type: application/json' \
  -d '{"text":"Verify your account within 24 hours or it will be suspended.","attack":"homoglyph","detector":"heuristic-v0"}'
# -> {"clean_probability":0.69,"attacked_probability":0.17,"evaded":true, ...}
```

Run it in a container instead:

```bash
docker build -t lurescope . && docker run -p 8000:8000 lurescope
```

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `GET` | `/capabilities` | Available detectors and attacks |
| `POST` | `/score` | Fraud-lure probability + the words the detector keys on |
| `POST` | `/attack` | Apply an attack and report whether the detector now misses it |
| `GET` | `/` | Interactive demo (single self-contained page) |

Interactive OpenAPI docs are served at `/docs`.

**Detectors:** `tfidf-logreg` (trained baseline, bundled and strong; the default) and `heuristic-v0` (dependency-free keyword rules, kept because its collapse under attack is the clearest illustration of the robustness gap).

**Attacks:** four instant, dependency-free character attacks (`homoglyph`, `leet`, `zero-width`, `whitespace`) and two LLM-driven attacks (`llm-paraphrase`, `llm-keyword-evasion`). The LLM attacks use any OpenAI-compatible provider by name with your own key — set `LURESCOPE_LLM_ENGINE` (e.g. `deepseek`) and that provider's API key in the environment. They never call api.openai.com or api.anthropic.com.

## How it relates to LureBench

LureScope reuses [LureBench](https://github.com/immu4989/lurebench)'s detectors and attacks directly (it installs `lurebench` as a dependency), so the served model and the benchmarked model are the same code — they cannot drift. LureBench is where you *measure* detectors across a corpus; LureScope is where you *serve* one and probe it on a single message.

## Responsible use

This is a defensive research tool. It scores text you supply and demonstrates evasion against your own detectors; it does not generate deliverable lures, personalize to real targets, or embed working links or payment rails. See [LureBench's DATA.md](https://github.com/immu4989/lurebench/blob/main/DATA.md) for the data and generation ethics that underpin the bundled model.

## License

Apache-2.0.
