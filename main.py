"""Main entry point for AgentShield."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from agentshield.collector.collector import TelemetryCollector
from agentshield.decision_engine.decision import DecisionEngine
from agentshield.feature_engine.features import SlidingWindowFeatureEngine
from agentshield.ml_engine.model import AgentShieldModel
from agentshield.response_engine.response import ResponseEngine

LOG_PATH = Path("agentshield/logs/agentshield.log")


def configure_logging(verbose: bool = False) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handlers = [
        RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=5),
        logging.StreamHandler(),
    ]
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
    )


async def run_agent(args: argparse.Namespace) -> None:
    collector = TelemetryCollector(poll_interval=args.poll_interval)
    features = SlidingWindowFeatureEngine(window_seconds=args.window_seconds, min_events=args.min_events)
    model = AgentShieldModel()
    decisions = DecisionEngine(anomaly_threshold=args.anomaly_threshold)
    response = ResponseEngine(webhook_url=args.webhook_url)

    collector_task = asyncio.create_task(collector.start())
    try:
        async for serialized in collector.events():
            event = json.loads(serialized)
            feature_vector = features.ingest(event)
            if feature_vector is None:
                continue
            inference = model.infer(feature_vector.normalized_features, feature_vector.raw_features)
            decision = decisions.evaluate(feature_vector, inference, event)
            logging.getLogger("agentshield.pipeline").info(
                "pid=%s process=%s action=%s score=%.3f",
                feature_vector.pid,
                feature_vector.process_name,
                decision.action,
                inference["anomaly_score"],
            )
            if decision.action != "allow":
                response.execute(decision, feature_vector, inference, event)
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Shutting down AgentShield")
    finally:
        await collector.stop()
        collector_task.cancel()
        await asyncio.gather(collector_task, return_exceptions=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AgentShield autonomous defense system")
    parser.add_argument("--poll-interval", type=float, default=0.2)
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--min-events", type=int, default=5)
    parser.add_argument("--anomaly-threshold", type=float, default=0.65)
    parser.add_argument("--webhook-url", type=str, default=None)
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(verbose=args.verbose)
    asyncio.run(run_agent(args))


if __name__ == "__main__":
    main()
