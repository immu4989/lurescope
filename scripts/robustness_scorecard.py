"""Robustness scorecard: detector x attack x defense evasion rates over a corpus.

A single-message demo is an anecdote; a rate over a corpus is a claim. This script
runs each detector against every character attack on a set of fraud lures and
reports, for each cell, the **evasion rate** — of the lures a detector caught clean,
what fraction slip below threshold after the attack. It reports that rate twice: on
the raw attacked text, and after the ``normalize`` defense folds the text back to
ASCII. Whether it improves outcomes is measured, not inferred from attack names.
Abstentions remain unknown; incomplete cohorts yield logical completion bounds,
not point estimates or confidence intervals. No clean catches means no rate.

Only the always-on detectors and dependency-free character attacks run by default,
so the scorecard is fully reproducible with no keys. Point ``--data`` at a larger
corpus (e.g. LureBench's ``data/full/core/test.jsonl``) for headline numbers.

    python scripts/robustness_scorecard.py                       # bundled sample
    python scripts/robustness_scorecard.py --data <corpus.jsonl> --out-md SCORECARD.md \
        --out-png docs/assets/scorecard.png
"""

from __future__ import annotations

import argparse
import json
import math
import os
from typing import List

from lurebench.attacks import get_attack

from lurescope.defense import normalize
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
from lurescope.service import _as_lure, _detector

DEFAULT_DATA = os.path.join(
    os.path.dirname(__file__), "..", "lurescope", "data", "sample_lures.jsonl"
)
DEFAULT_DETECTORS = ["tfidf-logreg", "heuristic-v0"]
DEFAULT_ATTACKS = ["homoglyph", "leet", "zero-width", "whitespace"]


def load_fraud_lures(path: str, limit: int = 0) -> List[str]:
    """Read a LureBench JSONL corpus and return the text of the fraud lures (label 1).

    Lines that are blank or begin with ``//`` (sample-shard comments) are skipped.
    """
    records, _ = load_cohort(path, limit=limit)
    return [record["text"] for record in records]


def _scorer(detector_name: str):
    det = _detector(detector_name)

    def sc(text: str):
        return validate_score(det.score(_as_lure(text)))

    return sc


def compute(detectors, attacks, lures, threshold=0.5) -> dict:
    """Return the scorecard as a nested dict keyed by detector then attack."""
    threshold = validate_threshold(threshold)
    detectors, attacks = names(detectors, "detectors"), names(attacks, "attacks")
    if isinstance(lures, (str, bytes)):
        raise ValueError("lures must be a nonempty sequence of texts")
    lures = list(lures)
    if not lures or any(not isinstance(text, str) or not text.strip() for text in lures):
        raise ValueError("lures must be a nonempty sequence of texts")
    built = {a: get_attack(a) for a in attacks}
    card = {"measurement_version": MEASUREMENT_VERSION, "threshold": threshold,
            "n_fraud": len(lures), "detectors": {}}
    for dname in detectors:
        sc = _scorer(dname)
        caught, row = clean_summary([sc(t) for t in lures], threshold)
        row["attacks"] = {}
        for a in attacks:
            raw, defended = [], []
            for i in caught:
                attacked = built[a].apply(lures[i])
                raw.append(sc(attacked))
                defended.append(sc(normalize(attacked)))
            raw_metrics = summarize_attacked(raw, threshold)
            normalized_metrics = summarize_attacked(defended, threshold)
            row["attacks"][a] = {
                "evasion_raw": raw_metrics["evasion"],
                "evasion_normalized": normalized_metrics["evasion"],
                "raw": raw_metrics, "normalized": normalized_metrics,
            }
        card["detectors"][dname] = row
    return card


def to_markdown(card: dict, corpus_label: str) -> str:
    attacks = list(next(iter(card["detectors"].values()))["attacks"])
    cols = " | ".join(f"{a} (raw → +norm)" for a in attacks)
    header = "| Detector | Observed clean recall | " + cols + " |"
    sep = "|" + "---|" * (2 + len(attacks))
    lines = [
        "# Robustness scorecard",
        "",
        measurement_note(card),
        "",
        f"Evasion rate = of the fraud lures a detector caught on clean text, the fraction "
        f"that slip below the {card['threshold']:.2f} threshold after the attack. Lower is "
        f"more robust only for comparable populations and coverage. `+norm` re-scores "
        f"the attacked text after the `normalize` defense.",
        "Abstentions are unknown, not evasion. Missing attacked scores make the point rate "
        "inconclusive; brackets are logical completion bounds, not confidence intervals. "
        "Observed clean recall counts confirmed catches over all fraud records; clean "
        "abstentions remain in that denominator. No eligible catches means no evasion rate.",
        "",
        f"**Corpus:** {corpus_label} · {card['n_fraud']} fraud lures · "
        f"generated by `scripts/robustness_scorecard.py`.",
        "",
        *manifest_markdown(card),
        header,
        sep,
    ]
    for dname, row in card["detectors"].items():
        cells = [f"`{dname}`", f"{row['clean_recall']:.0%} ({row['n_caught']}/{card['n_fraud']}; "
                 f"{row.get('clean_abstain', 'unknown')} abstained)"]
        for a in attacks:
            e = row["attacks"][a]
            cells.append(evasion_label(e['evasion_raw'], e.get('raw')) + " → "
                         + evasion_label(e['evasion_normalized'], e.get('normalized')))
        lines.append("| " + " | ".join(cells) + " |")
    lines += [
        "",
        "Compare the measured cells and their denominators. Raw and normalized outcomes "
        "use the same clean-catch cohort, but can have different missing outcomes. A lower "
        "observed-subset rate alone is not evidence that normalization improved robustness. "
        "Each detector can have a different eligible cohort; these rates do not rank "
        "overall detector quality or establish performance on future operational data.",
        "",
    ]
    return "\n".join(lines)


def to_png(card: dict, path: str, corpus_label: str) -> bool:
    note = measurement_note(card)
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.colors import LinearSegmentedColormap
    except ImportError:
        return False

    attacks = list(next(iter(card["detectors"].values()))["attacks"])
    # Rows: each detector split into a raw row and a +normalize row.
    rows, data = [], []
    for dname, row in card["detectors"].items():
        rows.append(f"{dname}\n(raw attack)")
        data.append([row["attacks"][a]["evasion_raw"] for a in attacks])
        rows.append(f"{dname}\n(+ normalize)")
        data.append([row["attacks"][a]["evasion_normalized"] for a in attacks])

    # Sequential single-hue ramp, light -> dark (magnitude encoding; high evasion = worse).
    cmap = LinearSegmentedColormap.from_list(
        "evasion", ["#f6f7f5", "#e5534b", "#7a1712"]
    ).with_extremes(bad="#e3e5e0")
    fig, ax = plt.subplots(figsize=(1.4 * len(attacks) + 3.2, 0.72 * len(rows) + 1.6))
    plotted = [[math.nan if value is None else value for value in row] for row in data]
    im = ax.imshow(plotted, cmap=cmap, vmin=0.0, vmax=1.0, aspect="auto")

    ax.set_xticks(range(len(attacks)))
    ax.set_xticklabels(attacks, fontsize=11)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(rows, fontsize=10)
    ax.set_xlabel("attack", fontsize=11)
    detector_rows = list(card["detectors"].values())
    for i, drow in enumerate(data):
        for j, v in enumerate(drow):
            metrics = detector_rows[i // 2]["attacks"][attacks[j]].get(
                "raw" if i % 2 == 0 else "normalized")
            ax.text(j, i, evasion_label(v, metrics, compact=True), ha="center", va="center",
                    color="white" if v is not None and v >= 0.45 else "#14171c",
                    fontsize=9, fontweight="bold")
    ax.set_title(
        f"LureScope robustness — fraud-lure evasion rate\n{corpus_label} · "
        f"{card['n_fraud']} lures · gray = unknown/no eligible",
        fontsize=12.5, pad=12,
    )
    cbar = fig.colorbar(im, ax=ax, fraction=0.045, pad=0.03)
    cbar.set_label("evasion rate", fontsize=10)
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
    ap.add_argument("--data", default=os.path.abspath(DEFAULT_DATA), help="LureBench JSONL corpus")
    ap.add_argument("--detectors", nargs="+", default=DEFAULT_DETECTORS)
    ap.add_argument("--attacks", nargs="+", default=DEFAULT_ATTACKS)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--limit", type=int, default=0, help="cap number of fraud lures (0 = all)")
    ap.add_argument("--validate-corpus", action="store_true",
                    help="print a validated corpus manifest; no scoring or output writes")
    ap.add_argument("--out-md", default=None, help="write the scorecard markdown here")
    ap.add_argument("--out-json", default=None, help="write the raw scorecard JSON here")
    ap.add_argument("--out-png", default=None, help="write a heatmap PNG here (needs matplotlib)")
    ap.add_argument("--label", default=None, help="corpus label for the report")
    args = ap.parse_args(argv)

    args.threshold = validate_threshold(args.threshold)
    records, manifest = load_cohort(args.data, limit=args.limit)
    lures = [record["text"] for record in records]
    if not lures:
        raise SystemExit(f"no fraud lures (label==1) found in {args.data}")
    if args.validate_corpus:
        print(json.dumps(manifest, indent=2, allow_nan=False))
        return 0
    label = args.label or os.path.basename(args.data)
    card = compute(args.detectors, args.attacks, lures, args.threshold)
    card["corpus"] = manifest

    md = to_markdown(card, label)
    print(md)
    if args.out_md:
        with open(args.out_md, "w", encoding="utf-8") as fh:
            fh.write(md)
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as fh:
            json.dump(card, fh, indent=2, allow_nan=False)
    if args.out_png:
        if to_png(card, args.out_png, label):
            print(f"\nwrote heatmap -> {args.out_png}")
        else:
            print("\nvisualization dependencies missing; skipped PNG "
                  "(uv sync --locked --extra viz)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
