"""Cross-model robustness scorecard: token detectors vs LLM detectors, character
attacks vs semantic paraphrase.

The character-attack scorecard (``robustness_scorecard.py``) shows token detectors
collapsing under homoglyph/zero-width edits and a normalization defense closing that
gap. It leaves two claims unmeasured: that an LLM-as-classifier reads *through*
those same character attacks (it judges meaning, not tokens), and that a semantic
paraphrase is the attack that actually evades a strong detector. This script
measures both by running the LLM-judge detector across several models — via one
OpenRouter key — against the four character attacks and an LLM paraphrase.

Each cell describes the confirmed clean-catch cohort, with missingness made explicit.
Versioned caches bind the declared panel, attacker, provider configuration, code,
prompts and runtime. A complete matching cache can be replayed with --cache-only
without keys or model construction. Legacy/mismatched caches stop before paid work.

    export OPENROUTER_API_KEY=...
    python scripts/llm_scorecard.py --data <corpus.jsonl> --limit 120 \
        --out-md LLM_SCORECARD.md --out-png docs/assets/llm_scorecard.png

Fresh work may incur provider charges. Cache replay is an earlier observation,
not a new independent experiment; temperature zero does not guarantee determinism.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import importlib
import inspect
import json
import os
import platform
import threading
from typing import Callable, Dict, List, Optional

from lurebench.attacks import get_attack
from lurebench.attacks.llm import LLMParaphraseAttack
from lurebench.detectors import get_detector
from lurebench.generate import get_generator

from lurescope.local_io import read_regular_file
from lurescope.scorecard_cache import (
    CacheFile,
    admit,
    distinct_paths,
    envelope,
    fingerprint,
    paraphrase_key,
    score_key,
    validate_paraphrase,
)
from lurescope.scorecard_corpus import load_cohort, manifest_markdown
from lurescope.scorecard_metrics import (
    MEASUREMENT_VERSION,
    clean_summary,
    evasion_label,
    measurement_note,
    names,
    summarize_attacked,
    validate_score,
    validate_threshold,
)
from lurescope.service import _DEFAULT_TFIDF, _DEFAULT_TFIDF_SHA256, _as_lure, _detector

CHAR_ATTACKS = ["homoglyph", "leet", "zero-width", "whitespace"]
ATTACKS = CHAR_ATTACKS + ["paraphrase"]

# Cheap, current, vendor-diverse OpenRouter judges (IDs verified live 2026-07-24;
# they drift — see https://openrouter.ai/models). Override with --judges.
DEFAULT_JUDGES = [
    "openai/gpt-5-nano",
    "google/gemini-2.5-flash-lite",
    "deepseek/deepseek-v4-flash",
    "qwen/qwen-2.5-7b-instruct",
    "meta-llama/llama-3.1-8b-instruct",
]
DEFAULT_ATTACKER = "deepseek/deepseek-v4-flash"


def experiment_identity(judges, attacker, cache_context="default"):
    """Describe configured code/runtime before any provider or model construction."""
    from pathlib import Path

    from lurebench.attacks import llm as attack_module
    from lurebench.detectors import llm
    from lurebench.generate import PROVIDERS, OpenAICompatibleGenerator

    from lurescope.portable_tfidf import _runtime_digest

    judges = names(judges, "judges")
    names([attacker], "attacker")
    if not isinstance(cache_context, str) or not 1 <= len(cache_context) <= 256:
        raise ValueError("cache context must be a nonempty string of at most 256 characters")
    defaults = inspect.signature(OpenAICompatibleGenerator.__init__).parameters
    settings = {key: defaults[key].default for key in
                ("timeout", "max_retries", "retry_base", "max_delay")}
    settings.update(max_tokens=512, temperature=0.0, extra_params={})
    modules = ["lurebench.schema", "lurebench.receipts", "lurebench.detectors",
               "lurebench.detectors.base", "lurebench.detectors.heuristic",
               "lurebench.detectors.llm", "lurebench.generate",
               "lurebench.generate.openai_compat", "lurebench.attacks",
               "lurebench.attacks.base", "lurebench.attacks.llm", "lurebench.attacks.perturb",
               "lurescope.service", "lurescope.portable_tfidf", "lurescope.scorecard_metrics",
               "lurescope.scorecard_cache"]
    implementations = {}
    for name in modules:
        module = importlib.import_module(name)
        raw = read_regular_file(Path(module.__file__), maximum=4 * 1024 * 1024,
                                label="scorecard implementation")
        implementations[name] = hashlib.sha256(raw).hexdigest()
    implementations["scorecard_driver"] = hashlib.sha256(read_regular_file(
        Path(__file__), maximum=4 * 1024 * 1024, label="scorecard driver")).hexdigest()
    model = hashlib.sha256(read_regular_file(
        Path(_DEFAULT_TFIDF), maximum=8 * 1024 * 1024, label="scorecard model")).hexdigest()
    if model != _DEFAULT_TFIDF_SHA256:
        raise ValueError("scorecard portable model pin mismatch")
    spec = {
        "contract": "scorecard-experiment-v1", "judges": judges, "attacker": attacker,
        "cache_context": cache_context, "provider": "openrouter",
        "endpoint": PROVIDERS["openrouter"]["base_url"].rstrip("/") + "/chat/completions",
        "settings": settings, "model_sha256": model, "implementations": implementations,
        "judge_prompt_sha256": hashlib.sha256(
            llm.LLMJudgeDetector.system_prompt.encode()).hexdigest(),
        "attacker_prompt_sha256": hashlib.sha256(
            attack_module._PARAPHRASE_SYS.encode()).hexdigest(),
        "judge_parser": getattr(llm, "PARSER_VERSION", "legacy-module-bound"),
        "python": platform.python_version(), "runtime": platform.python_implementation(),
        "portable_runtime_sha256": _runtime_digest(),
    }
    return {"sha256": fingerprint(spec), "configuration": spec}


def load_fraud_lures(path: str, limit: int, phishing_cap: int) -> List[dict]:
    """Stratified fraud sample: keep every non-phishing typology (they are rare and
    the interesting failure cases), cap phishing so it does not swamp the mix."""
    if phishing_cap is None:
        raise ValueError("phishing_cap must be a nonnegative integer")
    records, _ = load_cohort(path, limit=limit, phishing_cap=phishing_cap)
    return records


def build_detectors(judges: List[str]) -> "collections.OrderedDict[str, Callable]":
    """Map a display id -> score(text)->Optional[float] for baselines and judges."""
    judges = names(judges, "judges")
    dets: "collections.OrderedDict[str, Callable]" = collections.OrderedDict()

    tfidf = _detector("tfidf-logreg")
    heuristic = _detector("heuristic-v0")

    def _score_with(det):
        def fn(text: str) -> Optional[float]:
            return validate_score(det.score(_as_lure(text)))
        return fn

    dets["tfidf-logreg"] = _score_with(tfidf)
    dets["heuristic-v0"] = _score_with(heuristic)
    for model in judges:
        judge = get_detector("llm-judge", engine="openrouter", model=model, max_tokens=512)
        dets[f"judge:{model}"] = _score_with(judge)
    return dets


def build_attacker(model: str) -> LLMParaphraseAttack:
    # Lower sampling variability, not a guarantee of provider determinism.
    generator = get_generator("openrouter", model=model, max_tokens=512, temperature=0.0)

    def complete(system, text):
        # Do not let the upstream attack's empty-response fallback claim resistance.
        return validate_paraphrase(generator.complete(system, text))

    return LLMParaphraseAttack(complete)


def attacked_variants(lure_text: str, attacker: LLMParaphraseAttack,
                      para_cache: dict, lock: threading.Lock, *, cache_only=False
                      ) -> Dict[str, str]:
    """All attacked texts for one lure. Character attacks are deterministic; the
    paraphrase is cached per lure so reruns don't re-pay for it."""
    variants = {"clean": lure_text}
    for a in CHAR_ATTACKS:
        variants[a] = get_attack(a).apply(lure_text)
    key = paraphrase_key(lure_text)
    with lock:
        cached = para_cache.get(key)
    if cached is None:
        if cache_only:
            raise ValueError("cache-only replay is missing a paraphrase; no callback was invoked")
        cached = validate_paraphrase(attacker.apply(lure_text))
        with lock:
            para_cache[key] = cached
    variants["paraphrase"] = validate_paraphrase(cached)
    return variants


def _parallel(function, items, workers):
    """At most workers outstanding; stop admission on failure and await in-flight work."""
    remaining = iter(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        pending = set()
        try:
            while True:
                while len(pending) < workers:
                    try:
                        item = next(remaining)
                    except StopIteration:
                        break
                    pending.add(executor.submit(function, item))
                if not pending:
                    return
                finished, pending = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in finished:
                    future.result()
        except BaseException:
            for future in pending:
                future.cancel()
            raise


def run(lures, dets, attacker, cache, para_cache, workers, lock, *,
        cache_context=None, cache_only=False) -> dict:
    """Score every (detector, lure, variant). Returns nested scores dict.

    Keyed by position in ``lures``, never by ``rec["id"]``. Record ids are not
    reliably unique across a shard: LureBench shipped ~500 generated records whose
    ids collided across generators, and an earlier version of this script keyed
    these maps by id, so colliding records silently overwrote each other. That
    turned a stated 120-lure sample into 73 distinct records, some counted three
    times. An index cannot collide.
    """
    names(dets, "detectors")
    if isinstance(lures, (str, bytes)):
        raise ValueError("scorecard requires at least one fraud record")
    lures = list(lures)
    if not lures:
        raise ValueError("scorecard requires at least one fraud record")
    if any(not isinstance(record, dict) or not isinstance(record.get("text"), str)
           or not record["text"].strip() for record in lures):
        raise ValueError("scorecard records require nonempty text")
    if type(workers) is not int or not 1 <= workers <= 128:
        raise ValueError("workers must be an integer from 1 through 128")
    if type(cache_only) is not bool:
        raise ValueError("cache_only must be boolean")
    if not isinstance(cache, dict) or not isinstance(para_cache, dict) or cache is para_cache:
        raise ValueError("score and paraphrase caches must be distinct mappings")
    if cache_context is None:
        if cache or para_cache or cache_only:
            raise ValueError("reusing a cache requires an explicit experiment context")
        scores, paraphrases = {}, {}  # one-call ephemeral API, no implicit identity
    else:
        scores = admit(cache or envelope("scores", cache_context), "scores", cache_context)
        paraphrases = admit(para_cache or envelope("paraphrases", cache_context),
                           "paraphrases", cache_context)
    # Precompute all attacked texts (fills the paraphrase cache in parallel).
    variants_by_text: Dict[str, Dict[str, str]] = {}

    def _prep(text):
        variants_by_text[text] = attacked_variants(text, attacker, paraphrases, lock,
                                                  cache_only=cache_only)

    _parallel(_prep, dict.fromkeys(record["text"] for record in lures), workers)

    # Build the scoring worklist, skipping anything already cached.
    tasks = {}
    for det_id in dets:
        for idx in range(len(lures)):
            for text in variants_by_text[lures[idx]["text"]].values():
                ck = score_key(det_id, text)
                if ck not in scores:
                    tasks[ck] = (det_id, text, ck)
    if cache_only and tasks:
        raise ValueError("cache-only replay is missing scores; no scoring callback was invoked")

    done = [0]

    def _do(task):
        det_id, text, ck = task
        score = validate_score(dets[det_id](text))
        with lock:
            scores[ck] = score
            done[0] += 1
            if done[0] % 200 == 0:
                print(f"  scored {done[0]}/{len(tasks)} new (detector calls)")

    _parallel(_do, tasks.values(), workers)

    # Assemble results from cache.
    results = {}
    for det_id in dets:
        results[det_id] = {}
        for idx in range(len(lures)):
            v = variants_by_text[lures[idx]["text"]]
            results[det_id][idx] = {
                variant: validate_score(scores[score_key(det_id, text)])
                for variant, text in v.items()
            }
    if cache_context is not None:
        cache.clear()
        cache.update(envelope("scores", cache_context, scores))
        para_cache.clear()
        para_cache.update(envelope("paraphrases", cache_context, paraphrases))
    return results


def scorecard(results, dets, lures, threshold=0.5) -> dict:
    threshold = validate_threshold(threshold)
    detector_names = names(dets, "detectors")
    if isinstance(lures, (str, bytes)) or not lures:
        raise ValueError("scorecard requires at least one fraud record")
    if not isinstance(results, dict) or set(results) != set(detector_names):
        raise ValueError("scorecard detector results do not match the declared panel")
    validated = {}
    for det_id in detector_names:
        per = results[det_id]
        if (not isinstance(per, dict) or any(type(i) is not int for i in per)
                or set(per) != set(range(len(lures)))):
            raise ValueError("scorecard requires exactly one result per record position")
        validated[det_id] = {}
        for idx, variants in per.items():
            if not isinstance(variants, dict) or set(variants) != {"clean", *ATTACKS}:
                raise ValueError("scorecard requires every variant; missing is not abstention")
            validated[det_id][idx] = {key: validate_score(value) for key, value in variants.items()}
    card = {"measurement_version": MEASUREMENT_VERSION, "threshold": threshold,
            "n_fraud": len(lures), "attacks": list(ATTACKS), "detectors": {}}
    for det_id in detector_names:
        per = validated[det_id]
        caught, row = clean_summary([per[idx]["clean"] for idx in range(len(lures))], threshold)
        row["attacks"] = {}
        for a in ATTACKS:
            row["attacks"][a] = summarize_attacked([per[lid][a] for lid in caught], threshold)
        card["detectors"][det_id] = row
    return card


def _corrections() -> list:
    """Corrections to previously published versions of this table.

    These live in the generator rather than being appended to the file by hand.
    An earlier calibration correction was written straight into LLM_SCORECARD.md
    and then silently deleted the next time the script regenerated it, which is
    exactly the failure mode a correction is supposed to prevent.
    """
    return [
        "",
        "## Corrections to earlier versions of this table",
        "",
        "**2026-11-04 - unknown outcomes are not point estimates.** Earlier cross-model "
        "tables used only scored attacked outcomes as the evasion denominator. That value "
        "is now named `evasion_observed`; when any eligible outcome abstains, the primary "
        "rate is null with logical completion bounds and explicit coverage/counts. Older "
        "character scorecards also converted abstentions to zero and reported zero evasion "
        "for detectors with no clean catches. Preserve historical files: re-evaluation or "
        "re-aggregation of complete, correctly identified observations is required. This "
        "change does not retroactively certify old caches or recompute published results.",
        "",
        "**2026-07-30 - the sample was smaller than stated.** This script keyed its "
        "per-record maps by `rec[\"id\"]`, and LureBench shipped roughly 500 generated "
        "records whose ids collided across generators (`gen-bec-000006` existed once "
        "per model, with different text each time). Colliding records overwrote each "
        "other, so the table headed *120 fraud lures* was computed over **73 distinct "
        "records**, 25 of them counted two or three times. The maps are now keyed by "
        "position and the ids themselves are fixed upstream.",
        "",
        "The effect was not uniform, because the collided records were mostly the "
        "harder BEC lures: judge clean recall was understated by 4 to 10 points, and "
        "`deepseek-v4-flash` paraphrase evasion moved from 27% to 16% while "
        "`qwen-2.5-7b` moved from 21% to 29%. One claim built on the old numbers - "
        "that the best-recall judge was also the most paraphrase-evadable - does not "
        "survive: `qwen-2.5-7b` is now the most paraphrase-evadable and has among the "
        "lowest recall.",
        "",
        "**2026-07-26 - low clean recall was mostly a threshold artifact.** An earlier "
        "version read the judges' low clean recall as a capability trade-off, "
        "\"immunity to character attacks bought with recall\". Measured threshold-free "
        "over the full 2,056-record `core/test` set, the judges post an AUC of 0.89 to "
        "0.94: they rank fraud above benign well and are simply miscalibrated at the "
        "0.50 cutoff this table uses. Dropping `deepseek-v4-flash` to a 0.10 threshold "
        "lifts recall from 0.750 to 0.856 at a 2.5% false-positive rate. Calibrate on "
        "your own data rather than assuming 0.50.",
        "",
    ]


def to_markdown(card, corpus_label, judges, attacker) -> str:
    attacks = card["attacks"]
    head = "| Detector | Observed clean recall | " + " | ".join(attacks) + " |"
    sep = "|" + "---|" * (2 + len(attacks))
    experiment_notes = []
    if "experiment" in card:
        mode = "cache-only replay" if card.get("replay_only") else "evaluation with cache reuse"
        experiment_notes = [
            f"Experiment configuration SHA-256: `{card['experiment']['sha256']}`. Mode: {mode}.",
            "Cached outcomes replay earlier observations, not new independent evidence. "
            "Configuration identity is not source authentication or provider attestation.",
            "",
        ]
    lines = [
        "# Cross-model robustness scorecard",
        "",
        measurement_note(card),
        "",
        *experiment_notes,
        f"Evasion rate = of the fraud lures a detector caught on clean text, the fraction "
        f"that fall below the {card['threshold']:.2f} threshold after the attack. Lower is "
        f"more robust only for comparable populations and coverage. `paraphrase` is an LLM "
        f"rewrite (attacker: `{attacker}`); the other four are character attacks.",
        "Abstentions are unknown, not evasion. Missing attacked outcomes make the point "
        "rate inconclusive; brackets are logical completion bounds, not confidence intervals. "
        "The observed-subset rate is diagnostic, not the full-cohort rate. Observed clean "
        "recall counts confirmed catches over all fraud records, including clean abstentions.",
        "",
        f"**Corpus:** {corpus_label} · {card['n_fraud']} fraud lures. "
        f"**Judges via OpenRouter:** {', '.join(judges)}.",
        "",
        *manifest_markdown(card),
        head,
        sep,
    ]
    for det_id, row in card["detectors"].items():
        cells = [f"`{det_id}`", f"{row['clean_recall']:.0%} ({row['n_caught']}/{card['n_fraud']}; "
                 f"{row.get('clean_abstain', 'unknown')} abstained)"]
        for a in attacks:
            cell = row["attacks"][a]
            cells.append(evasion_label(cell["evasion"], cell if "status" in cell else None))
        lines.append("| " + " | ".join(cells) + " |")
    lines += _corrections()
    lines += [
        "",
        "Interpret the measured cells with their coverage and denominators. Detectors can "
        "catch different clean cohorts; lower observed-subset evasion does not establish "
        "overall superiority. This report does not infer a winning model, a semantic versus "
        "typographic explanation, or performance on operational data from the supplied labels.",
        "",
        f"Check whether the paraphrase attacker (`{attacker}`) shares a judged model family; "
        "the report does not infer independence from names alone. "
        "Evasion is conditioned on a clean catch, so low-recall rows rest on fewer lures.",
        "",
    ]
    return "\n".join(lines)


def to_png(card, path, corpus_label) -> bool:
    note = measurement_note(card)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.colors import LinearSegmentedColormap
    except ImportError:
        return False
    import math
    attacks = card["attacks"]
    dets = list(card["detectors"])
    raw = [[card["detectors"][d]["attacks"][a]["evasion"] for a in attacks] for d in dets]
    data = [[(math.nan if v is None else v) for v in drow] for drow in raw]
    ylabels = [f"{d}\n(observed recall {card['detectors'][d]['clean_recall']:.0%})" for d in dets]
    cmap = LinearSegmentedColormap.from_list(
        "evasion", ["#f6f7f5", "#e5534b", "#7a1712"]
    ).with_extremes(bad="#e3e5e0")  # N/A cells (no clean catches) render neutral gray
    fig, ax = plt.subplots(figsize=(1.3 * len(attacks) + 4.0, 0.66 * len(dets) + 1.8))
    im = ax.imshow(data, cmap=cmap, vmin=0.0, vmax=1.0, aspect="auto")
    ax.set_xticks(range(len(attacks)))
    ax.set_xticklabels(attacks, fontsize=11)
    ax.set_yticks(range(len(dets)))
    ax.set_yticklabels(ylabels, fontsize=9)
    ax.set_xlabel("attack", fontsize=11)
    for i, drow in enumerate(raw):
        for j, v in enumerate(drow):
            cell = card["detectors"][dets[i]]["attacks"][attacks[j]]
            label = evasion_label(v, cell if "status" in cell else None, compact=True)
            hot = v is not None and v >= 0.45
            ax.text(j, i, label, ha="center", va="center",
                    color="white" if hot else "#14171c", fontsize=9, fontweight="bold")
    ax.set_title(
        f"LureScope cross-model robustness — fraud-lure evasion rate\n{corpus_label} · "
        f"{card['n_fraud']} lures · gray = unknown/no eligible",
        fontsize=12.5, pad=12,
    )
    fig.colorbar(im, ax=ax, fraction=0.045, pad=0.03).set_label("evasion rate", fontsize=10)
    footer = ("Brackets = logical bounds, not confidence intervals" if
              card.get("measurement_version") == MEASUREMENT_VERSION else note)
    fig.text(0.5, 0.01, footer, ha="center", fontsize=7)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--data", required=True, help="LureBench JSONL corpus")
    ap.add_argument("--limit", type=int, default=120, help="max fraud lures (0 = all)")
    ap.add_argument("--phishing-cap", type=int, default=50, help="max phishing lures in the mix")
    ap.add_argument("--validate-corpus", action="store_true",
                    help="print a validated corpus manifest; no keys, calls or output writes")
    ap.add_argument("--judges", nargs="+", default=DEFAULT_JUDGES)
    ap.add_argument("--attacker", default=DEFAULT_ATTACKER)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--cache", default=None, help="score cache JSON (resumable across runs)")
    ap.add_argument("--para-cache", default=None, help="paraphrase cache JSON")
    ap.add_argument("--cache-only", action="store_true",
                    help="replay matching caches without keys, model construction or cache writes")
    ap.add_argument("--experiment-context", default="default",
                    help="explicit run/provider epoch; changing it requires fresh cache paths")
    ap.add_argument("--label", default=None)
    ap.add_argument("--out-md", default=None)
    ap.add_argument("--out-json", default=None)
    ap.add_argument("--out-png", default=None)
    args = ap.parse_args(argv)

    args.threshold = validate_threshold(args.threshold)

    lures, manifest = load_cohort(args.data, limit=args.limit, phishing_cap=args.phishing_cap)
    if not lures:
        raise SystemExit(f"no fraud lures in {args.data}")
    if args.validate_corpus:
        print(json.dumps(manifest, indent=2, allow_nan=False))
        return 0
    if type(args.workers) is not int or not 1 <= args.workers <= 128:
        raise ValueError("workers must be an integer from 1 through 128")
    distinct_paths([args.data, args.cache, args.para_cache,
                    args.out_json, args.out_md, args.out_png])
    experiment = experiment_identity(args.judges, args.attacker, args.experiment_context)
    context = experiment["sha256"]
    scores = CacheFile(args.cache, "scores", context)
    paraphrases = CacheFile(args.para_cache, "paraphrases", context)
    if not args.cache_only and not os.environ.get("OPENROUTER_API_KEY"):
        raise SystemExit("OPENROUTER_API_KEY is not set; export it before running.")
    label = args.label or os.path.basename(args.data)
    print(f"{len(lures)} fraud lures · {len(args.judges)} judges · attacker {args.attacker}")

    if args.cache_only:
        dets = dict.fromkeys(["tfidf-logreg", "heuristic-v0"] +
                             [f"judge:{model}" for model in args.judges])
        attacker = None
    else:
        dets = build_detectors(args.judges)
        attacker = build_attacker(args.attacker)
    expected_panel = ["tfidf-logreg", "heuristic-v0"] + [f"judge:{m}" for m in args.judges]
    if list(dets) != expected_panel:
        raise ValueError("constructed scorecard panel does not match the experiment configuration")
    lock = threading.Lock()

    results = run(lures, dets, attacker, scores.value, paraphrases.value, args.workers, lock,
                  cache_context=context, cache_only=args.cache_only)
    if experiment_identity(args.judges, args.attacker, args.experiment_context) != experiment:
        raise ValueError("scorecard experiment configuration changed during evaluation")

    card = scorecard(results, dets, lures, args.threshold)
    card["corpus"] = manifest
    card["experiment"] = experiment
    card["replay_only"] = args.cache_only
    if not args.cache_only:
        scores.flush()
        paraphrases.flush()
    md = to_markdown(card, label, args.judges, args.attacker)
    print("\n" + md)
    if args.out_md:
        with open(args.out_md, "w", encoding="utf-8") as fh:
            fh.write(md)
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as fh:
            json.dump(card, fh, indent=2, allow_nan=False)
    if args.out_png:
        ok = to_png(card, args.out_png, label)
        print("wrote heatmap" if ok else
              "visualization dependencies missing; no PNG (uv sync --locked --extra viz)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
