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
    tags: List[str]
    critical: bool


class SignatureEngine:
    def __init__(self, config) -> None:
        self.reverse_shell_ports = {int(port) for port in config.signature_rules.reverse_shell_ports}
        self.suspicious_cidrs = []
        for item in config.signature_rules.suspicious_cidrs:
            try:
                self.suspicious_cidrs.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
        self.rapid_connection_threshold = config.signature_rules.rapid_connection_threshold
        self.exfil_byte_rate_threshold = config.signature_rules.exfil_byte_rate_threshold
        self.dos_connection_threshold = config.signature_rules.dos_connection_threshold
        self.dos_unique_ip_threshold = config.signature_rules.dos_unique_ip_threshold
        self.dos_byte_rate_threshold = config.signature_rules.dos_byte_rate_threshold

    def evaluate(self, event: Dict, feature_vector) -> SignatureMatch:
        reasons: List[str] = []
        tags = set()
        destination_port = int(event.get("destination_port", 0) or 0)
        destination_ip = event.get("destination_ip", "0.0.0.0")

        if destination_port in self.reverse_shell_ports:
            reasons.append(f"reverse-shell port match on {destination_port}")
            tags.add("reverse_shell")
        try:
            ip_obj = ipaddress.ip_address(destination_ip)
            if any(ip_obj in cidr for cidr in self.suspicious_cidrs):
                reasons.append(f"destination {destination_ip} within suspicious range")
                tags.add("suspicious_cidr")
        except ValueError:
            reasons.append(f"invalid destination IP observed: {destination_ip}")

        connection_frequency = float(feature_vector.raw_features.get("connection_frequency", 0.0))
        unique_ip_count = float(feature_vector.raw_features.get("unique_ip_count", 0.0))
        byte_rate = float(feature_vector.raw_features.get("byte_transfer_rate", 0.0))

        if connection_frequency >= self.rapid_connection_threshold:
            reasons.append("rapid outbound connection pattern detected")
        if byte_rate >= self.exfil_byte_rate_threshold:
            reasons.append("possible data exfiltration rate threshold exceeded")

        if (
            connection_frequency >= self.dos_connection_threshold
            and unique_ip_count >= self.dos_unique_ip_threshold
            and byte_rate >= self.dos_byte_rate_threshold
        ):
            reasons.append("distributed high-rate outbound pattern consistent with DoS behavior")
            tags.add("dos")

        severity = "info"
        if reasons:
            severity = "high"
        if "reverse_shell" in tags or "dos" in tags:
            severity = "critical"
        return SignatureMatch(
            detected=bool(reasons),
            reasons=reasons,
            severity=severity,
            tags=sorted(tags),
            critical=("reverse_shell" in tags or "dos" in tags),
        )
