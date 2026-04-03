"""Lightweight incident retrieval memory for AgentShield logs."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List

TOKEN_RE = re.compile(r"[a-zA-Z0-9_]{2,}")
STOP_WORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "this",
    "that",
    "into",
    "true",
    "false",
    "high",
    "low",
    "info",
}


class ThreatMemory:
    def __init__(self, incidents_path: Path | None = None) -> None:
        self.incidents_path = incidents_path or Path("agentshield/logs/incidents.jsonl")
        self._records: List[dict] = []
        self._vectors: List[Counter] = []

    @staticmethod
    def _tokenize(text: str) -> Counter:
        tokens = [tok.lower() for tok in TOKEN_RE.findall(text)]
        return Counter(tok for tok in tokens if tok not in STOP_WORDS)

    @staticmethod
    def _cosine(a: Counter, b: Counter) -> float:
        if not a or not b:
            return 0.0
        dot = sum(a[k] * b.get(k, 0) for k in a)
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)

    @staticmethod
    def _record_text(record: dict) -> str:
        reasons = " ".join(record.get("decision", {}).get("reasons", []))
        tags = " ".join(record.get("signature_tags", []))
        event = record.get("latest_event", {})
        parts = [
            str(record.get("process_name", "")),
            str(record.get("decision", {}).get("action", "")),
            reasons,
            tags,
            str(event.get("destination_ip", "")),
            str(event.get("destination_port", "")),
            str(event.get("event_type", "")),
        ]
        return " ".join(parts)

    def build(self) -> None:
        self._records.clear()
        self._vectors.clear()
        if not self.incidents_path.exists():
            return
        with self.incidents_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._records.append(record)
                self._vectors.append(self._tokenize(self._record_text(record)))

    def retrieve(self, query: str, k: int = 5, min_score: float = 0.05) -> List[Dict]:
        if not self._records:
            self.build()
        qv = self._tokenize(query)
        scored = []
        for idx, rv in enumerate(self._vectors):
            score = self._cosine(qv, rv)
            if score >= min_score:
                scored.append((score, self._records[idx]))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"score": score, "record": rec} for score, rec in scored[:k]]
