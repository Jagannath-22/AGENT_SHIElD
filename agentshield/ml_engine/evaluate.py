"""Evaluate AgentShield anomaly model with labeled feature JSONL datasets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple

from agentshield.config.settings import ConfigManager
from agentshield.ml_engine.model import AgentShieldModel, FEATURE_ORDER


def _safe_label(value) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return 1 if float(value) > 0 else 0
    txt = str(value).strip().lower()
    if txt in {"0", "benign", "normal", "false", "no"}:
        return 0
    return 1


def load_labeled_dataset(path: Path, label_key: str) -> Tuple[List[dict], List[int]]:
    rows: List[dict] = []
    labels: List[int] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if all(key in record for key in FEATURE_ORDER):
                feature_source = record
            else:
                feature_source = record.get("inference", {}).get("features", {})
                if not all(key in feature_source for key in FEATURE_ORDER):
                    continue

            if label_key in record:
                label_value = record[label_key]
            elif label_key in record.get("inference", {}):
                label_value = record["inference"][label_key]
            elif "__is_attack" in record:
                label_value = record["__is_attack"]
            elif "signature_detected" in record:
                label_value = record["signature_detected"]
            else:
                continue

            rows.append({key: float(feature_source[key]) for key in FEATURE_ORDER})
            labels.append(_safe_label(label_value))
    return rows, labels


def confusion_stats(y_true: List[int], y_pred: List[int]) -> Dict[str, int]:
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 0 and p == 0:
            tn += 1
        elif t == 1 and p == 0:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def ratio(n: float, d: float) -> float:
    return n / d if d else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate AgentShield model metrics on labeled feature JSONL")
    parser.add_argument("--dataset", type=Path, required=True, help="Labeled JSONL dataset (features JSONL or incidents JSONL)")
    parser.add_argument("--label-key", type=str, default="__is_attack", help="Label key in records; falls back to signature_detected for incidents logs")
    parser.add_argument(
        "--threshold", type=float, default=None, help="Anomaly threshold; default comes from config"
    )
    args = parser.parse_args()

    config = ConfigManager().load(force=True)
    threshold = float(args.threshold) if args.threshold is not None else float(config.anomaly_threshold)

    samples, y_true = load_labeled_dataset(args.dataset, args.label_key)
    if not samples:
        print("No valid labeled samples found. Check feature keys and label-key.")
        return 1

    model = AgentShieldModel()
    scores: List[float] = []
    y_pred: List[int] = []

    for row in samples:
        inference = model.infer(row, row)
        score = float(inference["anomaly_score"])
        pred = 1 if score >= threshold else 0
        scores.append(score)
        y_pred.append(pred)

    cm = confusion_stats(y_true, y_pred)
    tp, fp, tn, fn = cm["tp"], cm["fp"], cm["tn"], cm["fn"]
    total = len(y_true)

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * precision * recall, precision + recall)
    accuracy = ratio(tp + tn, total)
    fpr = ratio(fp, fp + tn)
    fnr = ratio(fn, fn + tp)
    tnr = ratio(tn, tn + fp)
    balanced_accuracy = (recall + tnr) / 2.0

    positives = sum(y_true)
    negatives = total - positives
    majority_baseline = max(positives, negatives) / max(total, 1)

    metrics = {
        "samples": total,
        "threshold": threshold,
        "confusion_matrix": cm,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "balanced_accuracy": balanced_accuracy,
        "majority_baseline_accuracy": majority_baseline,
        "mean_anomaly_score": sum(scores) / max(len(scores), 1),
    }

    print(json.dumps(metrics, indent=2, sort_keys=True))

    if accuracy <= majority_baseline + 0.02:
        print("WARNING: Model is near majority baseline accuracy; results may be weak/random-like.")
    else:
        print("Model is above majority baseline; behavior is likely learning signal beyond random.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
