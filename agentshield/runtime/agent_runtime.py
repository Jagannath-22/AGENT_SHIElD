"""Explicit autonomous agent runtime loop for AgentShield.

This module makes the agentic behavior explicit using a Sense -> Think -> Decide -> Act cycle.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from dataclasses import asdict
from typing import Optional

from agentshield.collector.collector import TelemetryCollector
from agentshield.config.settings import ConfigManager
from agentshield.decision_engine.decision import DecisionEngine
from agentshield.feature_engine.features import SlidingWindowFeatureEngine
from agentshield.ml_engine.model import AgentShieldModel
from agentshield.observability.metrics import MetricsTracker
from agentshield.response_engine.response import ResponseEngine
from agentshield.signature_engine.signatures import SignatureEngine

LOGGER = logging.getLogger(__name__)


@dataclass
class AnalysisArtifact:
    event: dict
    feature_vector: object
    inference: dict
    signature_match: object
    decision: object


class AgentRuntime:
    def __init__(self) -> None:
        self.config_manager = ConfigManager()
        self.config = self.config_manager.load(force=True)
        self.active_config = asdict(self.config)

        self.metrics = MetricsTracker()
        self.collector = TelemetryCollector(
            config=self.config,
            metrics=self.metrics,
            poll_interval=self.config.collector_poll_interval,
        )
        self.features = SlidingWindowFeatureEngine(
            window_seconds=self.config.window_seconds,
            min_events=self.config.min_events,
        )
        self.model = AgentShieldModel()
        self.signatures = SignatureEngine(self.config)
        self.decisions = DecisionEngine(self.config)
        self.response = ResponseEngine(webhook_url=self.config.webhook_url)
        self.raw_event_queue: asyncio.Queue[Optional[dict]] = asyncio.Queue(maxsize=5000)
        self.decision_queue: asyncio.Queue[Optional[AnalysisArtifact]] = asyncio.Queue(maxsize=5000)

    async def _metrics_flusher(self) -> None:
        while True:
            await asyncio.sleep(self.config.metrics_interval)
            self.metrics.flush()

    async def _collector_service(self) -> None:
        async for serialized in self.collector.events():
            self._reload_if_needed()
            event = json.loads(serialized)
            await self.raw_event_queue.put(event)

    async def _analysis_service(self) -> None:
        while True:
            event = await self.raw_event_queue.get()
            if event is None:
                await self.decision_queue.put(None)
                break

            feature_vector = self.features.ingest(event)
            if feature_vector is None:
                continue

            inference = self.model.infer(feature_vector.normalized_features, feature_vector.raw_features)
            signature_match = self.signatures.evaluate(event, feature_vector)
            decision = self.decisions.evaluate(feature_vector, inference, event, signature_match)
            self.metrics.record_inference(inference["anomaly_score"], inference["label"], decision.action)

            LOGGER.info(
                json.dumps(
                    {
                        "pid": feature_vector.pid,
                        "process": feature_vector.process_name,
                        "action": decision.action,
                        "anomaly_score": inference["anomaly_score"],
                        "signature_detected": signature_match.detected,
                    },
                    sort_keys=True,
                )
            )

            await self.decision_queue.put(
                AnalysisArtifact(
                    event=event,
                    feature_vector=feature_vector,
                    inference=inference,
                    signature_match=signature_match,
                    decision=decision,
                )
            )

    async def _response_service(self) -> None:
        while True:
            artifact = await self.decision_queue.get()
            if artifact is None:
                break
            if artifact.decision.action != "allow":
                self.response.execute(
                    artifact.decision,
                    artifact.feature_vector,
                    artifact.inference,
                    artifact.event,
                    artifact.signature_match,
                )

    def _reload_if_needed(self) -> None:
        reloaded = self.config_manager.maybe_reload()
        if asdict(reloaded) == self.active_config:
            return

        self.config = reloaded
        self.active_config = asdict(self.config)

        self.signatures = SignatureEngine(self.config)
        self.decisions = DecisionEngine(self.config)
        LOGGER.info("Runtime configuration reloaded")

    async def run(self) -> None:
        collector_task = asyncio.create_task(self.collector.start())
        await self.collector.started.wait()
        metrics_task = asyncio.create_task(self._metrics_flusher())
        collector_service_task = asyncio.create_task(self._collector_service())
        analysis_service_task = asyncio.create_task(self._analysis_service())
        response_service_task = asyncio.create_task(self._response_service())

        try:
            await collector_service_task
        except KeyboardInterrupt:
            LOGGER.info("Shutting down AgentShield")
        finally:
            await self.raw_event_queue.put(None)
            await analysis_service_task
            await response_service_task
            await self.collector.stop()
            collector_task.cancel()
            metrics_task.cancel()
            await asyncio.gather(
                collector_task,
                metrics_task,
                collector_service_task,
                analysis_service_task,
                response_service_task,
                return_exceptions=True,
            )
            self.metrics.flush()
