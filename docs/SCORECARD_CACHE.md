# Cross-model cache identity and replay (unreleased)

The research scorecard now uses `lurescope-scorecard-cache-v1` envelopes for
scores and paraphrases. Legacy flat caches are rejected before model construction
or paid work, including empty legacy JSON objects. Preserve them; do not relabel
their entries as new observations or overwrite them to force a rerun.

The configuration commitment binds the ordered judge panel, attacker model,
OpenRouter endpoint, generation/retry defaults, prompts, parser implementation,
bundled portable model, selected first-party implementation files and declared
Python/portable runtime. `--experiment-context` adds an operator-chosen provider
epoch or run label. Credentials are not read into this commitment. The same
context binds both cache kinds; changing the panel or attacker conservatively
requires fresh paths. Text keys use domain-separated, JSON-framed SHA-256.

## Replay without paid work

From the source checkout, using matching caches produced by this version:

```bash
python scripts/llm_scorecard.py --data /path/to/corpus.jsonl \
  --judges vendor/judge --attacker vendor/attacker \
  --cache /path/to/scores-v1.json --para-cache /path/to/paraphrases-v1.json \
  --experiment-context reviewed-run --cache-only --out-json replay.json
```

Use the same models and experiment context as the original run. Cache-only mode
requires no API key, constructs no detectors or provider generators, never calls
providers and never writes cache files. It still imports trusted code, validates
the full corpus/cache files, constructs deterministic character variants and can
write requested reports. Missing entries stop rather than falling back to live
work. `--validate-corpus` is separate: it checks input selection only, without
reading caches. Removing `--cache-only` permits fresh paid work and needs a key.

JSON reports include the configuration and its digest plus `replay_only`;
Markdown identifies the mode and commitment. A normal evaluation can contain
both cached and fresh observations; it does not claim every observation is new.
Thresholds and cohort limits do not invalidate raw-score caches, but their input
selection and outcome semantics remain explicit in each generated report.

## Admission, concurrency and persistence

Both complete cache files are validated before callbacks, including unused entries.
Scores must be finite non-boolean probabilities or explicit abstentions. Paraphrases
must be nonempty UTF-8 text within 1 MiB. Failed or empty generation is an error,
not a fallback to the original message and a claimed successful defense.
The built-in TF-IDF baseline uses the pinned data-only JSON loader, not joblib.

Repeated input text shares one paraphrase and each distinct detector/text key
shares one score per run. Positional records remain separate in the aggregate;
repeated cached draws are not independent stochastic samples. Worker count is
bounded to 1–128, with at most that many outstanding tasks. Failure stops new
admission, cancels queued work where possible and awaits in-flight callbacks;
already-started provider calls are not cancelled or refunded. This is not a
monetary budget or provider-request limit (provider retries can add requests).

Successful caches are serialized as strict bounded JSON (64 MiB), staged in
private temporary files, flushed and atomically replaced individually. Failed
evaluations do not checkpoint partial work. Publication rejects observed changes
since initial cache admission and refuses input/cache/output path aliases.
Errors leave earlier files in place when failure occurs before replacement.
Trusted parent directories and one writer are required: the final check/replace
is not a cross-process compare-and-swap, a two-cache transaction, or a crash-proof
durability guarantee. One cache can publish before the second fails; no report is
published after that failure. Preserve valid observations and investigate errors.

Direct Python `run()` calls with empty dictionaries and no `cache_context` are
ephemeral and leave those dictionaries empty. Reuse requires an explicit trusted
configuration digest and valid envelopes; caller-supplied digests are assertions,
not automatic introspection/authentication of custom Python callbacks.

## Limits and migration

The commitment describes selected source/configuration, not the complete software
supply chain, live-process attestation or the provider's actual backend weights.
An upstream backend can change while keeping its model ID. Account-side routing
is not captured; use a reviewed new experiment context when that changes. Even
temperature zero is not proof of determinism. A cached response replays an earlier
draw, and independent replicates require separate fresh observations.

Caches contain sensitive generated text and unsalted text commitments. Do not
publish them as anonymized evidence, and do not put secrets in experiment labels.
Hashes do not authenticate cache producers or establish label quality. No legacy
cache, published benchmark or provider result was migrated or recomputed here.
See [outcome accounting](SCORECARD_MEASUREMENT.md) and
[corpus admission](SCORECARD_CORPUS.md) for the separate measurement contracts.
