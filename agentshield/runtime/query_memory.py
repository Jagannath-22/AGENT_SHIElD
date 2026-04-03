"""CLI for querying AgentShield lightweight threat memory."""

from __future__ import annotations

import argparse
from pathlib import Path

from agentshield.runtime.threat_memory import ThreatMemory


def main() -> int:
    parser = argparse.ArgumentParser(description="Query incident memory for similar past cases")
    parser.add_argument("--query", type=str, required=True, help="Natural language query")
    parser.add_argument(
        "--incidents",
        type=Path,
        default=Path("agentshield/logs/incidents.jsonl"),
        help="Incident JSONL path",
    )
    parser.add_argument("--k", type=int, default=5, help="Top-k results")
    args = parser.parse_args()

    memory = ThreatMemory(args.incidents)
    results = memory.retrieve(args.query, k=max(1, args.k))

    if not results:
        print("No similar incidents found.")
        return 0

    for i, item in enumerate(results, start=1):
        rec = item["record"]
        print(f"[{i}] score={item['score']:.4f}")
        print(f"  ts={rec.get('timestamp')} process={rec.get('process_name')} action={rec.get('decision', {}).get('action')}")
        print(f"  reasons={rec.get('decision', {}).get('reasons', [])}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
