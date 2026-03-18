"""Lightweight in-process metrics and drift detection."""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean
from typing import Deque

LOGGER = logging.getLogger(__name__)


@dataclass
class MetricsSnapshot:
    timestamp: float
    events_seen: int
    decisions_alert: int
    decisions_kill: int
    anomalies: int
    queue_drops: int
    events_per_second: float
    anomaly_rate: float
    score_mean: float
    drift_detected: bool


class MetricsTracker:
    def __init__(self, output_path: Path | None = None, drift_delta: float = 0.2) -> None:
        self.output_path = output_path or Path("agentshield/logs/metrics.jsonl")
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.start_time = time.time()
        self.events_seen = 0
        self.decisions_alert = 0
        self.decisions_kill = 0
        self.anomalies = 0
        self.queue_drops = 0
        self.score_window: Deque[float] = deque(maxlen=200)
        self.reference_mean: float | None = None
        self.drift_delta = drift_delta

    def record_event(self) -> None:
        self.events_seen += 1

    def record_drop(self) -> None:
        self.queue_drops += 1

    def record_inference(self, anomaly_score: float, label: str, action: str) -> None:
        self.score_window.append(anomaly_score)
        if label == "anomaly":
            self.anomalies += 1
        if action == "alert":
            self.decisions_alert += 1
        elif action == "kill":
            self.decisions_kill += 1
        if self.reference_mean is None and len(self.score_window) >= 20:
            self.reference_mean = mean(self.score_window)

    def snapshot(self) -> MetricsSnapshot:
        elapsed = max(time.time() - self.start_time, 1e-6)
        score_mean = mean(self.score_window) if self.score_window else 0.0
        drift_detected = bool(self.reference_mean is not None and abs(score_mean - self.reference_mean) > self.drift_delta)
        return MetricsSnapshot(
            timestamp=time.time(),
            events_seen=self.events_seen,
            decisions_alert=self.decisions_alert,
            decisions_kill=self.decisions_kill,
            anomalies=self.anomalies,
            queue_drops=self.queue_drops,
            events_per_second=self.events_seen / elapsed,
            anomaly_rate=self.anomalies / max(self.events_seen, 1),
            score_mean=score_mean,
            drift_detected=drift_detected,
        )

    def flush(self) -> None:
        snapshot = self.snapshot()
        if snapshot.drift_detected:
            LOGGER.warning("Anomaly score drift detected; current_mean=%s reference_mean=%s", snapshot.score_mean, self.reference_mean)
        with self.output_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(snapshot), sort_keys=True) + "\n")
