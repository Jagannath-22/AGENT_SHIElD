"""CLI utility to retrain the AgentShield anomaly model from local logs."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List

from agentshield.config.settings import ConfigManager
from agentshield.feature_engine.features import SlidingWindowFeatureEngine
from agentshield.ml_engine.model import AgentShieldModel, FEATURE_ORDER

LOGGER = logging.getLogger(__name__)


def _valid_feature_row(row: Dict) -> bool:
    return all(key in row for key in FEATURE_ORDER)


def _normalize_feature_row(row: Dict) -> Dict[str, float]:
    return {key: float(row[key]) for key in FEATURE_ORDER}


def load_from_incidents(path: Path) -> List[Dict[str, float]]:
    rows: List[Dict[str, float]] = []
    if not path.exists():
        return rows

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            features = record.get("inference", {}).get("features", {})
            if _valid_feature_row(features):
                rows.append(_normalize_feature_row(features))

    return rows


def load_from_events(path: Path, window_seconds: int, min_events: int) -> List[Dict[str, float]]:
    rows: List[Dict[str, float]] = []
    if not path.exists():
        return rows

    engine = SlidingWindowFeatureEngine(window_seconds=window_seconds, min_events=min_events)

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            vector = engine.ingest(event)
            if vector is not None:
                rows.append(_normalize_feature_row(vector.raw_features))

    return rows


def write_dataset(rows: List[Dict[str, float]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retrain AgentShield model from local telemetry logs")
    parser.add_argument(
        "--incidents",
        type=Path,
        default=Path("agentshield/logs/incidents.jsonl"),
        help="Path to incidents JSONL with inference.features rows",
    )
    parser.add_argument(
        "--events",
        type=Path,
        default=Path("agentshield/logs/agentshield.jsonl"),
        help="Path to raw events JSONL to derive feature windows",
    )
    parser.add_argument(
        "--prefer",
        choices=["incidents", "events", "auto"],
        default="auto",
        help="Data source selection strategy",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=50,
        help="Minimum number of feature rows required before retraining",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Isolation Forest contamination ratio",
    )
    parser.add_argument(
        "--export-dataset",
        type=Path,
        default=Path("agentshield/logs/retrain_dataset.jsonl"),
        help="Where to save the final feature dataset used for retraining",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = parse_args()

    config = ConfigManager().load(force=True)

    incident_rows = load_from_incidents(args.incidents)
    event_rows = load_from_events(args.events, config.window_seconds, config.min_events)

    if args.prefer == "incidents":
        rows = incident_rows
        source = "incidents"
    elif args.prefer == "events":
        rows = event_rows
        source = "events"
    else:
        rows = incident_rows if len(incident_rows) >= len(event_rows) else event_rows
        source = "incidents" if rows is incident_rows else "events"

    if len(rows) < args.min_samples:
        LOGGER.error(
            "Not enough samples to retrain: got %d rows from %s, require at least %d",
            len(rows),
            source,
            args.min_samples,
        )
        LOGGER.info("Incidents rows=%d Events rows=%d", len(incident_rows), len(event_rows))
        return 1

    write_dataset(rows, args.export_dataset)

    model = AgentShieldModel(contamination=max(0.0001, min(args.contamination, 0.5)))
    model.retrain(rows)

    LOGGER.info("Retrained model successfully")
    LOGGER.info("Source=%s Samples=%d", source, len(rows))
    LOGGER.info("Model path=%s", model.model_path)
    LOGGER.info("Dataset export=%s", args.export_dataset)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
