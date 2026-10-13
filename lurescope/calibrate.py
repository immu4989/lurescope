"""Offline calibration of the exact portable detector used by this installation."""

from __future__ import annotations

import argparse
import sys

from lurebench.schema import load_jsonl

from .portable_tfidf import PortableTfidfDetector, detector_binding


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="lurescope calibrate",
        description="Calibrate the bundled portable fraud model and export a bound v3 policy.")
    parser.add_argument("--validation", "-d", required=True)
    parser.add_argument("--out", "-o", required=True)
    parser.add_argument("--objective", choices=("max_mcc", "target_fpr", "risk_controlled_fpr"),
                        default="max_mcc")
    parser.add_argument("--target-fpr", type=float)
    parser.add_argument("--confidence", type=float, default=.95)
    parser.add_argument("--threshold-grid-size", type=int, default=1001)
    parser.add_argument("--bins", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        from lurebench.calibration import (
            DetectorBinding,
            build_policy,
            calibration_metrics,
            validate_calibration_configuration,
            validate_calibration_population,
            validate_risk_control_groups,
        )
        from lurebench.harness import collect_scores
        from lurebench.lineage import lineage_components
    except ImportError:
        print("! bound calibration requires a compatible LureBench build", file=sys.stderr)
        return 2
    try:
        validate_calibration_configuration(args.objective, args.target_fpr, args.confidence,
                                           args.threshold_grid_size, args.bins)
        records = load_jsonl(args.validation)
        ids, labels = [r.id for r in records], [r.label for r in records]
        validate_calibration_population(
            ids, labels, args.objective, args.target_fpr, args.confidence,
        )
        groups = lineage_components(records) if args.objective == "risk_controlled_fpr" else None
        if groups is not None:
            validate_risk_control_groups(ids, labels, groups)
    except (OSError, KeyError, RuntimeError, ValueError) as exc:
        print(f"! calibration inputs rejected ({type(exc).__name__})", file=sys.stderr)
        return 2
    try:
        from .service import _DEFAULT_TFIDF, _DEFAULT_TFIDF_SHA256

        # Fresh actual serving implementation; never reuse configured thresholds
        # or translate the source joblib hash into an inference-equivalence claim.
        detector = PortableTfidfDetector(_DEFAULT_TFIDF, expected_sha256=_DEFAULT_TFIDF_SHA256)
        binding = DetectorBinding(**detector_binding(detector))
        scored_ids, truths, scores = collect_scores(detector, records, task="fraud")
        if (len(scored_ids) != len(records)
                or DetectorBinding(**detector_binding(detector)) != binding):
            raise ValueError("incomplete scores or changed detector configuration")
        policy, _ = build_policy(detector.name, "fraud", scored_ids, truths, scores,
            args.objective, args.target_fpr, args.confidence, args.threshold_grid_size,
            groups=groups, detector_binding=binding)
        calibration_metrics(truths, scores, n_bins=args.bins)
        policy.save(args.out)
    except (OSError, ImportError, KeyError, RuntimeError, ValueError) as exc:
        print(f"! bound calibration failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(f"wrote bound policy {policy.policy_id} to {args.out}")
    return 0
