# Contributing to LureScope

Thanks for helping make fraud-detector robustness something people can see rather
than take on trust.

## Ground rules

LureScope is a defensive project. Contributions must serve detection, evaluation,
or defense. We do not accept tooling to generate, personalize, or deliver fraud
campaigns, live malicious infrastructure, or real personal data. The service
deliberately does not produce deliverable lures, personalize to real targets, or
embed working links or payment rails, and it should stay that way.

Attacks are welcome. A new evasion technique that beats the current detectors is a
contribution, not a problem: measuring where detection fails is the point of the
project. See [SECURITY.md](SECURITY.md) for where that line sits.

## Ways to contribute

- **Defenses.** Add a function to `lurescope/defense.py` and register it in
  `DEFENSES`. Be honest in the docstring about what it cannot reverse. The
  existing `normalize` deliberately leaves word-splitting and paraphrase alone,
  because neither can be undone without corrupting legitimate text, and saying so
  is more useful than quietly under-performing.
- **Detectors and attacks.** These live upstream in
  [LureBench](https://github.com/immu4989/lurebench) so the served model and the
  benchmarked model cannot drift. Add them there and they appear here.
- **The demo.** `lurescope/static/index.html` is the API-backed page;
  `space/index.html` is the zero-backend build for the Hugging Face Space. If you
  change scoring or defense logic in one, port it to the other and verify parity
  against Python (see below).
- **Docs and results.** Corrections to published numbers are especially welcome.

## Keeping the browser build honest

The Space runs detectors, attacks, and the normalization defense entirely
client-side, which means the same logic exists twice: once in Python and once in
JavaScript. Any change to that logic has to be verified in both.

The bar used so far is byte-for-byte agreement across every attack. When
`normalize` was ported, it was checked on 5 messages by 4 attacks, 20 of 20
matching Python exactly. Please do something equivalent and say so in the PR.

## Development

```bash
git clone https://github.com/immu4989/lurescope && cd lurescope
pip install -e ".[dev]"
pytest -q
ruff check lurescope tests scripts
```

Optional but recommended:

```bash
pip install pre-commit && pre-commit install
```

The scorecard scripts need no keys for the character attacks. The cross-model
scorecard needs `OPENROUTER_API_KEY`; it caches every score to disk, so a rerun
costs nothing.

## Pull requests

- Add a test for new behaviour. The offline tests stub providers and detectors, so
  most things can be tested without a key.
- If a change moves a published number, say which one and by how much in the PR
  body, and update the affected doc in the same PR. A result that changed silently
  is worse than one that changed loudly.
- Keep `ruff check` and `pytest` green.
- Line length is 100. Targeting Python 3.9, so `typing.Optional` and `List` rather
  than the 3.10+ syntax.

## Reporting problems

Bugs and questions go in [issues](https://github.com/immu4989/lurescope/issues).
Security vulnerabilities go by email, not in public: see
[SECURITY.md](SECURITY.md).
