"""Decision engine for autonomous enforcement."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional


@dataclass
class Decision:
    action: str
    reasons: List[str]
    severity: str


class DecisionEngine:
    def __init__(self, config=None, anomaly_threshold: float = 0.65, repeat_window: int = 5) -> None:
        if config is not None:
            self.anomaly_threshold = float(config.anomaly_threshold)
            self.kill_process = bool(config.kill_process)
            self.repeat_window = repeat_window
            self.protected_processes = set(config.protected_processes)
            self.protected_pids = set(config.protected_pids)
            self.whitelisted_processes = set(config.whitelisted_processes)
            self.kill_on_signature_tags = set(config.kill_on_signature_tags)
        else:
            self.anomaly_threshold = float(anomaly_threshold)
            self.kill_process = False
            self.repeat_window = repeat_window
            self.protected_processes = {"systemd", "sshd", "kthreadd", "containerd", "dockerd", "init"}
            self.protected_pids = {1}
            self.whitelisted_processes = set()
            self.kill_on_signature_tags = {"reverse_shell", "dos"}

        self.history: Dict[int, Deque[float]] = defaultdict(lambda: deque(maxlen=self.repeat_window))
        self.high_risk_ports = {22, 23, 25, 53, 135, 139, 445, 3389, 4444, 8080}

    def evaluate(self, feature_vector, inference: dict, latest_event: dict, signature_match: Optional[object] = None) -> Decision:
        pid = int(feature_vector.pid)
        process_name = str(feature_vector.process_name)
        score = float(inference["anomaly_score"])
        self.history[pid].append(score)
        reasons: List[str] = []

        if score >= self.anomaly_threshold:
            reasons.append(f"anomaly_score={score:.3f} exceeds threshold={self.anomaly_threshold:.2f}")

        repeated_anomalies = sum(1 for item in self.history[pid] if item >= self.anomaly_threshold) >= 3
        if repeated_anomalies:
            reasons.append("repeated anomalies observed in sliding decision window")

        destination_port = int(latest_event.get("destination_port", 0) or 0)
        if destination_port in self.high_risk_ports:
            reasons.append(f"high-risk port={destination_port}")

        if float(feature_vector.raw_features.get("byte_transfer_rate", 0.0)) > 100_000:
            reasons.append("sustained high byte transfer rate")

        signature_detected = bool(getattr(signature_match, "detected", False))
        signature_reasons = list(getattr(signature_match, "reasons", []))
        signature_tags = set(getattr(signature_match, "tags", []))
        reasons.extend(signature_reasons)
        critical_signature = bool(signature_tags.intersection(self.kill_on_signature_tags))

        if process_name in self.whitelisted_processes and not critical_signature and score < self.anomaly_threshold:
            return Decision(action="allow", reasons=["whitelisted process within expected baseline"], severity="info")

        if not reasons:
            return Decision(action="allow", reasons=["behavior within expected baseline"], severity="info")

        if pid in self.protected_pids or process_name in self.protected_processes:
            return Decision(action="alert", reasons=reasons + ["process is protected from termination"], severity="high")

        if process_name in self.whitelisted_processes and not critical_signature:
            return Decision(action="alert", reasons=reasons + ["whitelisted process is never auto-killed without critical attack signature"], severity="high")

        if self.kill_process and critical_signature:
            return Decision(action="kill", reasons=reasons, severity="critical")

        return Decision(action="alert", reasons=reasons, severity="high")
