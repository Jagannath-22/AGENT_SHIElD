"""Decision engine for autonomous enforcement."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List


@dataclass
class Decision:
    action: str
    reasons: List[str]
    severity: str


class DecisionEngine:
    def __init__(self, anomaly_threshold: float = 0.65, repeat_window: int = 5) -> None:
        self.anomaly_threshold = anomaly_threshold
        self.repeat_window = repeat_window
        self.history: Dict[int, Deque[float]] = defaultdict(lambda: deque(maxlen=repeat_window))
        self.high_risk_ports = {22, 23, 25, 53, 135, 139, 445, 3389, 4444, 8080}
        self.protected_processes = {"systemd", "sshd", "kthreadd", "containerd", "dockerd", "init"}

    def evaluate(self, feature_vector, inference: dict, latest_event: dict) -> Decision:
        pid = feature_vector.pid
        process_name = feature_vector.process_name
        score = float(inference["anomaly_score"])
        self.history[pid].append(score)
        reasons: List[str] = []

        if score >= self.anomaly_threshold:
            reasons.append(f"anomaly_score={score:.3f} exceeds threshold={self.anomaly_threshold:.2f}")
        if sum(1 for item in self.history[pid] if item >= self.anomaly_threshold) >= 3:
            reasons.append("repeated anomalies observed in sliding decision window")
        if int(latest_event.get("destination_port", 0)) in self.high_risk_ports:
            reasons.append(f"high-risk port={latest_event['destination_port']}")
        if float(feature_vector.raw_features["byte_transfer_rate"]) > 100_000:
            reasons.append("sustained high byte transfer rate")

        if not reasons:
            return Decision(action="allow", reasons=["behavior within expected baseline"], severity="info")
        if process_name in self.protected_processes:
            return Decision(action="alert", reasons=reasons + ["process is protected from termination"], severity="high")
        if "repeated anomalies observed in sliding decision window" in reasons or score >= 0.85:
            return Decision(action="kill", reasons=reasons, severity="critical")
        return Decision(action="alert", reasons=reasons, severity="high")
