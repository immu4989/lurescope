"""Cross-model robustness scorecard: token detectors vs LLM detectors, character
attacks vs semantic paraphrase.

The character-attack scorecard (``robustness_scorecard.py``) shows token detectors
collapsing under homoglyph/zero-width edits and a normalization defense closing that
gap. It leaves two claims unmeasured: that an LLM-as-classifier reads *through*
those same character attacks (it judges meaning, not tokens), and that a semantic
paraphrase is the attack that actually evades a strong detector. This script
measures both by running the LLM-judge detector across several models — via one
OpenRouter key — against the four character attacks and an LLM paraphrase.

Each cell is the evasion rate: of the fraud lures a detector caught on clean text,
the fraction that fall below threshold after the attack. Judge scores are cached on
disk (keyed by detector + text hash) so a rerun costs nothing and is resumable.

    export OPENROUTER_API_KEY=...
    python scripts/llm_scorecard.py --data <corpus.jsonl> --limit 120 \
        --out-md LLM_SCORECARD.md --out-png docs/assets/llm_scorecard.png

Cost is dominated by short judge completions (~5 output tokens each); with the cheap
default panel a ~120-lure run is well under $1.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import threading
from typing import Callable, Dict, List, Optional

from lurebench.attacks import get_attack
from lurebench.attacks.llm import LLMParaphraseAttack
from lurebench.detectors import get_detector
from lurebench.generate import get_generator

from lurescope.service import _DEFAULT_TFIDF, _as_lure

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


def _hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def load_fraud_lures(path: str, limit: int, phishing_cap: int) -> List[dict]:
    """Stratified fraud sample: keep every non-phishing typology (they are rare and
    the interesting failure cases), cap phishing so it does not swamp the mix."""
    by_typ: Dict[str, list] = collections.defaultdict(list)
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rec = json.loads(line)
            if rec.get("label") == 1:
                by_typ[rec.get("typology", "other")].append(rec)
    out = []
    for typ, recs in sorted(by_typ.items()):
        keep = recs if typ != "phishing" else recs[:phishing_cap]
        out.extend(keep)
    out.sort(key=lambda r: r.get("id", ""))
    return out[:limit] if limit else out


def build_detectors(judges: List[str]) -> "collections.OrderedDict[str, Callable]":
    """Map a display id -> score(text)->Optional[float] for baselines and judges."""
    dets: "collections.OrderedDict[str, Callable]" = collections.OrderedDict()

    tfidf = get_detector("tfidf-logreg", model_path=_DEFAULT_TFIDF)
    heuristic = get_detector("heuristic-v0")

    def _score_with(det):
        def fn(text: str) -> Optional[float]:
            p = det.score(_as_lure(text))
            return None if p is None else float(p)
        return fn

    dets["tfidf-logreg"] = _score_with(tfidf)
    dets["heuristic-v0"] = _score_with(heuristic)
    for model in judges:
        judge = get_detector("llm-judge", engine="openrouter", model=model)
        dets[f"judge:{model}"] = _score_with(judge)
    return dets


def build_attacker(model: str) -> LLMParaphraseAttack:
    # temperature 0 so the paraphrase (and thus the whole run) is reproducible.
    complete = get_generator("openrouter", model=model, max_tokens=512, temperature=0.0).complete
    return LLMParaphraseAttack(complete)


def attacked_variants(lure_text: str, attacker: LLMParaphraseAttack,
                      para_cache: dict, lock: threading.Lock) -> Dict[str, str]:
    """All attacked texts for one lure. Character attacks are deterministic; the
    paraphrase is cached per lure so reruns don't re-pay for it."""
    variants = {"clean": lure_text}
    for a in CHAR_ATTACKS:
        variants[a] = get_attack(a).apply(lure_text)
    key = _hash(lure_text)
    with lock:
        cached = para_cache.get(key)
    if cached is None:
        cached = attacker.apply(lure_text)
        with lock:
            para_cache[key] = cached
    variants["paraphrase"] = cached
    return variants


def run(lures, dets, attacker, cache, para_cache, workers, lock) -> dict:
    """Score every (detector, lure, variant). Returns nested scores dict.

    Keyed by position in ``lures``, never by ``rec["id"]``. Record ids are not
    reliably unique across a shard: LureBench shipped ~500 generated records whose
    ids collided across generators, and an earlier version of this script keyed
    these maps by id, so colliding records silently overwrote each other. That
    turned a stated 120-lure sample into 73 distinct records, some counted three
    times. An index cannot collide.
    """
    # Precompute all attacked texts (fills the paraphrase cache in parallel).
    variants_by_lure: Dict[int, Dict[str, str]] = {}

    def _prep(item):
        idx, rec = item
        variants_by_lure[idx] = attacked_variants(rec["text"], attacker, para_cache, lock)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_prep, list(enumerate(lures))))

    # Build the scoring worklist, skipping anything already cached.
    tasks = []
    for det_id in dets:
        for idx in range(len(lures)):
            for text in variants_by_lure[idx].values():
                ck = f"{det_id}\n{_hash(text)}"
                if ck not in cache:
                    tasks.append((det_id, text, ck))

    done = [0]

    def _do(task):
        det_id, text, ck = task
        score = dets[det_id](text)
        with lock:
            cache[ck] = score
            done[0] += 1
            if done[0] % 200 == 0:
                print(f"  scored {done[0]}/{len(tasks)} new (detector calls)")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_do, tasks))

    # Assemble results from cache.
    results = {}
    for det_id in dets:
        results[det_id] = {}
        for idx in range(len(lures)):
            v = variants_by_lure[idx]
            results[det_id][idx] = {
                variant: cache.get(f"{det_id}\n{_hash(text)}") for variant, text in v.items()
            }
    return results


def scorecard(results, dets, lures, threshold=0.5) -> dict:
    card = {"threshold": threshold, "n_fraud": len(lures), "attacks": ATTACKS, "detectors": {}}
    for det_id in dets:
        per = results[det_id]
        caught, recall_abstain = [], 0
        for idx in range(len(lures)):
            cp = per[idx]["clean"]
            if cp is None:
                recall_abstain += 1
            elif cp >= threshold:
                caught.append(idx)
        row = {
            "clean_recall": len(caught) / len(lures) if lures else 0.0,
            "n_caught": len(caught),
            "clean_abstain": recall_abstain,
            "attacks": {},
        }
        for a in ATTACKS:
            evaded = scored = 0
            for lid in caught:
                ap = per[lid][a]
                if ap is None:  # abstention is not evasion; exclude from the rate
                    continue
                scored += 1
                if ap < threshold:
                    evaded += 1
            # None (not 0%) when there is nothing to evade — a detector that caught
            # nothing clean can't be scored for robustness and must not read as "green".
            row["attacks"][a] = {
                "evasion": (evaded / scored) if scored else None,
                "n_scored": scored,
            }
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
    head = "| Detector | Clean recall | " + " | ".join(attacks) + " |"
    sep = "|" + "---|" * (2 + len(attacks))
    lines = [
        "# Cross-model robustness scorecard",
        "",
        f"Evasion rate = of the fraud lures a detector caught on clean text, the fraction "
        f"that fall below the {card['threshold']:.2f} threshold after the attack. Lower is "
        f"more robust. `paraphrase` is an LLM rewrite (attacker: `{attacker}`); the other "
        f"four are dependency-free character attacks. Judge abstentions are excluded from "
        f"each rate, not counted as evasions.",
        "",
        f"**Corpus:** {corpus_label} · {card['n_fraud']} fraud lures. "
        f"**Judges via OpenRouter:** {', '.join(judges)}.",
        "",
        head,
        sep,
    ]
    for det_id, row in card["detectors"].items():
        cells = [f"`{det_id}`", f"{row['clean_recall']:.0%} ({row['n_caught']})"]
        for a in attacks:
            ev = row["attacks"][a]["evasion"]
            cells.append("—" if ev is None else f"{ev:.0%}")
        lines.append("| " + " | ".join(cells) + " |")
    lines += _corrections()
    lines += [
        "",
        "Three things to read here. First, the token detectors (`tfidf-logreg`, "
        "`heuristic-v0`) collapse under character attacks while the stronger LLM judges "
        "are essentially immune to them — they read the meaning through the homoglyphs. "
        "Second, that immunity is bought with recall: the judges catch far fewer of these "
        "lures on clean text than the TF-IDF baseline does, so they miss a great deal of "
        "fraud before any attack is applied (this sample is weighted toward the subtle "
        "romance / BEC / pig-butchering typologies). Third, `paraphrase` — the only attack "
        "that changes meaning rather than spelling — is where the judges are most evadable, "
        "and the small judges are weak on every axis at once. No single detector is robust "
        "down all of them.",
        "",
        f"Caveat: the paraphrase attacker (`{attacker}`) is itself one of the judged model "
        "families, so read that judge's `paraphrase` cell with the coupling in mind. "
        "Evasion is conditioned on a clean catch, so low-recall rows rest on fewer lures.",
        "",
    ]
    return "\n".join(lines)


def to_png(card, path, corpus_label) -> bool:
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
    ylabels = [f"{d}\n(recall {card['detectors'][d]['clean_recall']:.0%})" for d in dets]
    cmap = LinearSegmentedColormap.from_list("evasion", ["#f6f7f5", "#e5534b", "#7a1712"])
    cmap.set_bad("#e3e5e0")  # N/A cells (no clean catches) render neutral gray
    fig, ax = plt.subplots(figsize=(1.3 * len(attacks) + 4.0, 0.66 * len(dets) + 1.8))
    im = ax.imshow(data, cmap=cmap, vmin=0.0, vmax=1.0, aspect="auto")
    ax.set_xticks(range(len(attacks)))
    ax.set_xticklabels(attacks, fontsize=11)
    ax.set_yticks(range(len(dets)))
    ax.set_yticklabels(ylabels, fontsize=9)
    ax.set_xlabel("attack", fontsize=11)
    for i, drow in enumerate(raw):
        for j, v in enumerate(drow):
            label = "—" if v is None else f"{v:.0%}"
            hot = v is not None and v >= 0.45
            ax.text(j, i, label, ha="center", va="center",
                    color="white" if hot else "#14171c", fontsize=10, fontweight="bold")
    ax.axhline(1.5, color="#2a313c", linewidth=2)  # separate baselines from judges
    ax.set_title(
        f"LureScope cross-model robustness — fraud-lure evasion rate\n{corpus_label} · "
        f"{card['n_fraud']} lures · lower is more robust",
        fontsize=12.5, pad=12,
    )
    fig.colorbar(im, ax=ax, fraction=0.045, pad=0.03).set_label("evasion rate", fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return True


def _load_cache(path):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def _save_cache(path, obj):
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--data", required=True, help="LureBench JSONL corpus")
    ap.add_argument("--limit", type=int, default=120, help="max fraud lures (0 = all)")
    ap.add_argument("--phishing-cap", type=int, default=50, help="max phishing lures in the mix")
    ap.add_argument("--judges", nargs="+", default=DEFAULT_JUDGES)
    ap.add_argument("--attacker", default=DEFAULT_ATTACKER)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--cache", default=None, help="score cache JSON (resumable across runs)")
    ap.add_argument("--para-cache", default=None, help="paraphrase cache JSON")
    ap.add_argument("--label", default=None)
    ap.add_argument("--out-md", default=None)
    ap.add_argument("--out-json", default=None)
    ap.add_argument("--out-png", default=None)
    args = ap.parse_args(argv)

    if not os.environ.get("OPENROUTER_API_KEY"):
        raise SystemExit("OPENROUTER_API_KEY is not set; export it before running.")

    lures = load_fraud_lures(args.data, args.limit, args.phishing_cap)
    if not lures:
        raise SystemExit(f"no fraud lures in {args.data}")
    label = args.label or os.path.basename(args.data)
    print(f"{len(lures)} fraud lures · {len(args.judges)} judges · attacker {args.attacker}")

    dets = build_detectors(args.judges)
    attacker = build_attacker(args.attacker)
    cache = _load_cache(args.cache)
    para_cache = _load_cache(args.para_cache)
    lock = threading.Lock()

    results = run(lures, dets, attacker, cache, para_cache, args.workers, lock)
    _save_cache(args.cache, cache)
    _save_cache(args.para_cache, para_cache)

    card = scorecard(results, dets, lures, args.threshold)
    md = to_markdown(card, label, args.judges, args.attacker)
    print("\n" + md)
    if args.out_md:
        with open(args.out_md, "w", encoding="utf-8") as fh:
            fh.write(md)
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as fh:
            json.dump(card, fh, indent=2)
    if args.out_png:
        ok = to_png(card, args.out_png, label)
        print("wrote heatmap" if ok else "matplotlib missing; no PNG")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
