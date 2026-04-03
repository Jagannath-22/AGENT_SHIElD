"""Tune anomaly threshold on a labeled dataset.

This utility sweeps thresholds and reports the best candidate under an
optional false-positive-rate constraint.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from agentshield.ml_engine.evaluate import confusion_stats, load_labeled_dataset, ratio
from agentshield.ml_engine.model import AgentShieldModel


def metrics_for_threshold(y_true: List[int], scores: List[float], threshold: float) -> Dict[str, float]:
    y_pred = [1 if s >= threshold else 0 for s in scores]
    cm = confusion_stats(y_true, y_pred)
    tp, fp, tn, fn = cm["tp"], cm["fp"], cm["tn"], cm["fn"]

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * precision * recall, precision + recall)
    accuracy = ratio(tp + tn, max(len(y_true), 1))
    fpr = ratio(fp, fp + tn)
    tnr = ratio(tn, tn + fp)
    balanced_accuracy = (recall + tnr) / 2.0

    return {
        "threshold": threshold,
        "accuracy": accuracy,
        "balanced_accuracy": balanced_accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": ratio(fn, fn + tp),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tune anomaly threshold for AgentShield model")
    parser.add_argument("--dataset", type=Path, required=True, help="Labeled JSONL dataset")
    parser.add_argument("--label-key", type=str, default="__is_attack", help="Label key in dataset records")
    parser.add_argument("--start", type=float, default=0.05, help="Threshold sweep start")
    parser.add_argument("--stop", type=float, default=0.95, help="Threshold sweep stop")
    parser.add_argument("--step", type=float, default=0.01, help="Threshold sweep step")
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.2,
        help="Maximum allowed false positive rate for best-threshold selection",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    samples, y_true = load_labeled_dataset(args.dataset, args.label_key)
    if not samples:
        print("No valid labeled samples found. Check dataset and label-key.")
        return 1

    model = AgentShieldModel()
    scores: List[float] = [float(model.infer(row, row)["anomaly_score"]) for row in samples]

    thresholds: List[float] = []
    t = args.start
    while t <= args.stop + 1e-12:
        thresholds.append(round(t, 6))
        t += args.step

    results = [metrics_for_threshold(y_true, scores, threshold) for threshold in thresholds]

    constrained = [row for row in results if row["false_positive_rate"] <= args.max_fpr]
    pool = constrained if constrained else results
    best = max(pool, key=lambda row: (row["f1"], row["balanced_accuracy"], row["recall"]))

    payload = {
        "samples": len(y_true),
        "max_fpr": args.max_fpr,
        "best_threshold": best,
        "top_5_by_f1": sorted(results, key=lambda row: (row["f1"], row["balanced_accuracy"]), reverse=True)[:5],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
