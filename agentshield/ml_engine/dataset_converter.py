"""Convert public flow datasets (for example CIC CSV) into AgentShield feature JSONL."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Dict, Iterable, Optional

from agentshield.ml_engine.model import FEATURE_ORDER

HIGH_RISK_PORTS = {22, 23, 25, 53, 135, 139, 445, 3389, 4444, 8080}


def _pick(row: Dict[str, str], names: Iterable[str], default: str = "") -> str:
    for name in names:
        if name in row and row[name] not in {None, ""}:
            return row[name]
    return default


def _to_float(value: str, default: float = 0.0) -> float:
    if value is None:
        return default
    txt = str(value).strip().replace(",", "")
    if not txt:
        return default
    try:
        return float(txt)
    except ValueError:
        return default


def _to_int(value: str, default: int = 0) -> int:
    return int(round(_to_float(value, float(default))))


def _is_attack(label: str) -> int:
    text = (label or "").strip().lower()
    if text in {"", "benign", "normal"}:
        return 0
    return 1


def _build_features(row: Dict[str, str]) -> Dict[str, float]:
    duration_us = _to_float(_pick(row, ["Flow Duration", "Flow Duration(us)", "Duration"]))
    duration_s = max(duration_us / 1_000_000.0, 1e-6)

    fwd_pkts = _to_float(_pick(row, ["Tot Fwd Pkts", "Total Fwd Packets", "Fwd Packets"]))
    bwd_pkts = _to_float(_pick(row, ["Tot Bwd Pkts", "Total Backward Packets", "Bwd Packets"]))
    total_pkts = max(fwd_pkts + bwd_pkts, 1.0)

    total_fwd_bytes = _to_float(_pick(row, ["TotLen Fwd Pkts", "Total Length of Fwd Packets", "Fwd Packet Length Total"]))
    total_bwd_bytes = _to_float(_pick(row, ["TotLen Bwd Pkts", "Total Length of Bwd Packets", "Bwd Packet Length Total"]))
    total_bytes = max(total_fwd_bytes + total_bwd_bytes, 0.0)

    flow_bytes_per_sec = _to_float(_pick(row, ["Flow Byts/s", "Flow Bytes/s", "Bytes/s"]))
    byte_transfer_rate = flow_bytes_per_sec if flow_bytes_per_sec > 0 else total_bytes / duration_s

    flow_iat_std_us = _to_float(_pick(row, ["Flow IAT Std", "Flow IAT Std(us)", "IAT Std"]))
    if flow_iat_std_us > 0:
        interval_variance = (flow_iat_std_us * 1_000.0) ** 2
    else:
        approx_iat_ns = (duration_s / total_pkts) * 1_000_000_000.0
        interval_variance = approx_iat_ns**2

    dst_port = _to_int(_pick(row, ["Dst Port", "Destination Port", "DstPort"]))
    high_risk_port_ratio = 1.0 if dst_port in HIGH_RISK_PORTS else 0.0

    protocol = _to_int(_pick(row, ["Protocol", "Proto"]))
    dns_resolution_ratio = 1.0 if dst_port == 53 or protocol == 53 else 0.0

    return {
        "connection_frequency": total_pkts / duration_s,
        "unique_ip_count": 1.0,
        "byte_transfer_rate": byte_transfer_rate,
        "interval_variance": interval_variance,
        "high_risk_port_ratio": high_risk_port_ratio,
        "lineage_depth": 2.0,
        "dns_resolution_ratio": dns_resolution_ratio,
    }


def convert_csv(input_csv: Path, output_jsonl: Path, dataset_name: str, label_column: str) -> int:
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    written = 0

    with input_csv.open("r", encoding="utf-8", errors="ignore", newline="") as source, output_jsonl.open(
        "w", encoding="utf-8"
    ) as target:
        reader = csv.DictReader(source)
        for row in reader:
            label = row.get(label_column, row.get("Label", ""))
            features = _build_features(row)
            if not all(key in features for key in FEATURE_ORDER):
                continue

            payload = {key: float(features[key]) for key in FEATURE_ORDER}
            payload["__dataset"] = dataset_name
            payload["__label"] = str(label)
            payload["__is_attack"] = _is_attack(str(label))

            target.write(json.dumps(payload, sort_keys=True) + "\n")
            written += 1

    return written


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert CIC/public flow CSV into AgentShield feature JSONL")
    parser.add_argument("--input-csv", type=Path, required=True, help="Input CSV path")
    parser.add_argument("--output-jsonl", type=Path, required=True, help="Output JSONL path")
    parser.add_argument("--dataset-name", type=str, default="public_dataset", help="Dataset identifier")
    parser.add_argument("--label-column", type=str, default="Label", help="Column name for class label")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    count = convert_csv(args.input_csv, args.output_jsonl, args.dataset_name, args.label_column)
    print(f"Converted rows={count} -> {args.output_jsonl}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
