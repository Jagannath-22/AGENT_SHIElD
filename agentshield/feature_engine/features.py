"""Feature engineering for AgentShield behavioral telemetry."""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, List, Optional, Set


@dataclass
class FeatureVector:
    pid: int
    process_name: str
    timestamp_ns: int
    raw_features: Dict[str, float]
    normalized_features: Dict[str, float]
    context: Dict[str, object]


class SlidingWindowFeatureEngine:
    def __init__(self, window_seconds: int = 60, min_events: int = 5) -> None:
        self.window_seconds = window_seconds
        self.min_events = min_events
        self.events_by_pid: Dict[int, Deque[dict]] = defaultdict(deque)
        self.stats = {
            "connection_frequency": {"mean": 10.0, "std": 5.0},
            "unique_ip_count": {"mean": 3.0, "std": 2.0},
            "byte_transfer_rate": {"mean": 4096.0, "std": 2048.0},
            "interval_variance": {"mean": 1e12, "std": 5e11},
            "high_risk_port_ratio": {"mean": 0.2, "std": 0.2},
            "lineage_depth": {"mean": 2.0, "std": 1.0},
            "dns_resolution_ratio": {"mean": 0.4, "std": 0.3},
        }
        self.high_risk_ports = {22, 23, 25, 53, 135, 139, 445, 3389, 4444, 8080}

    def ingest(self, event: dict) -> Optional[FeatureVector]:
        pid = int(event["pid"])
        now_ns = int(event["timestamp_ns"])
        bucket = self.events_by_pid[pid]
        bucket.append(event)
        self._evict_old(bucket, now_ns)
        if len(bucket) < self.min_events:
            return None
        return self._build_vector(pid, bucket)

    def _evict_old(self, bucket: Deque[dict], now_ns: int) -> None:
        cutoff_ns = now_ns - self.window_seconds * 1_000_000_000
        while bucket and int(bucket[0]["timestamp_ns"]) < cutoff_ns:
            bucket.popleft()

    def _build_vector(self, pid: int, bucket: Iterable[dict]) -> FeatureVector:
        events = list(bucket)
        first_ts = int(events[0]["timestamp_ns"])
        last_ts = int(events[-1]["timestamp_ns"])
        window_ns = max(last_ts - first_ts, 1)
        unique_ips: Set[str] = {e["destination_ip"] for e in events if e.get("destination_ip") not in {None, "0.0.0.0"}}
        bytes_total = sum(max(int(e.get("size", 0)), 0) for e in events)
        timestamps: List[int] = [int(e["timestamp_ns"]) for e in events]
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
        variance = self._variance(intervals)
        high_risk_events = sum(1 for e in events if int(e.get("destination_port", 0)) in self.high_risk_ports)
        lineage_depth = float(len(events[-1].get("lineage", [])))
        dns_resolved = sum(1 for e in events if e.get("dns_name"))

        raw = {
            "connection_frequency": len(events) / max(window_ns / 1_000_000_000, 1e-6),
            "unique_ip_count": float(len(unique_ips)),
            "byte_transfer_rate": bytes_total / max(window_ns / 1_000_000_000, 1e-6),
            "interval_variance": variance,
            "high_risk_port_ratio": high_risk_events / len(events),
            "lineage_depth": lineage_depth,
            "dns_resolution_ratio": dns_resolved / len(events),
        }
        normalized = {key: self._normalize(key, value) for key, value in raw.items()}
        return FeatureVector(
            pid=pid,
            process_name=events[-1].get("process_name", "unknown"),
            timestamp_ns=int(time.time_ns()),
            raw_features=raw,
            normalized_features=normalized,
            context={
                "ppid": events[-1].get("ppid", 0),
                "lineage": events[-1].get("lineage", []),
                "cmdline": events[-1].get("cmdline", ""),
                "dns_name": events[-1].get("dns_name", ""),
            },
        )

    @staticmethod
    def _variance(values: List[int]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return sum((value - mean) ** 2 for value in values) / (len(values) - 1)

    def _normalize(self, key: str, value: float) -> float:
        mean = self.stats[key]["mean"]
        std = max(self.stats[key]["std"], 1e-6)
        z_score = (value - mean) / std
        return math.tanh(z_score)
