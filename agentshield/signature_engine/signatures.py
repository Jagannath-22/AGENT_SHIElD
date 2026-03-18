"""Hybrid signature-based detection rules."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class SignatureMatch:
    detected: bool
    reasons: List[str]
    severity: str


class SignatureEngine:
    def __init__(self, config) -> None:
        self.reverse_shell_ports = set(config.signature_rules.reverse_shell_ports)
        self.suspicious_cidrs = [ipaddress.ip_network(item) for item in config.signature_rules.suspicious_cidrs]
        self.rapid_connection_threshold = config.signature_rules.rapid_connection_threshold
        self.exfil_byte_rate_threshold = config.signature_rules.exfil_byte_rate_threshold

    def evaluate(self, event: Dict, feature_vector) -> SignatureMatch:
        reasons: List[str] = []
        destination_port = int(event.get("destination_port", 0))
        destination_ip = event.get("destination_ip", "0.0.0.0")

        if destination_port in self.reverse_shell_ports:
            reasons.append(f"reverse-shell port match on {destination_port}")
        try:
            ip_obj = ipaddress.ip_address(destination_ip)
            if any(ip_obj in cidr for cidr in self.suspicious_cidrs):
                reasons.append(f"destination {destination_ip} within suspicious range")
        except ValueError:
            reasons.append(f"invalid destination IP observed: {destination_ip}")

        if feature_vector.raw_features["connection_frequency"] >= self.rapid_connection_threshold:
            reasons.append("rapid outbound connection pattern detected")
        if feature_vector.raw_features["byte_transfer_rate"] >= self.exfil_byte_rate_threshold:
            reasons.append("possible data exfiltration rate threshold exceeded")

        severity = "critical" if reasons else "info"
        return SignatureMatch(detected=bool(reasons), reasons=reasons, severity=severity)
