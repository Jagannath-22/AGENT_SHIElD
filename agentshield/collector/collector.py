"""Collector for AgentShield raw telemetry."""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from typing import AsyncIterator, Dict, Optional

from agentshield.ebpf.loader import EBPFLoader

LOGGER = logging.getLogger(__name__)


class TelemetryCollector:
    def __init__(self, ebpf_loader: Optional[EBPFLoader] = None, poll_interval: float = 0.1) -> None:
        self.ebpf_loader = ebpf_loader or EBPFLoader()
        self.poll_interval = poll_interval
        self.queue: asyncio.Queue[Dict] = asyncio.Queue(maxsize=10000)
        self._fallback_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        self._running = True
        loaded = self.ebpf_loader.load(self._publish_event)
        if not loaded:
            self._fallback_task = asyncio.create_task(self._synthetic_feed())
            LOGGER.warning("Running in synthetic telemetry mode")
            return

        LOGGER.info("eBPF collector started")
        while self._running:
            self.ebpf_loader.poll(timeout=int(self.poll_interval * 1000))
            await asyncio.sleep(0)

    async def stop(self) -> None:
        self._running = False
        if self._fallback_task:
            self._fallback_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._fallback_task
        self.ebpf_loader.cleanup()

    async def events(self) -> AsyncIterator[str]:
        while self._running or not self.queue.empty():
            event = await self.queue.get()
            yield json.dumps(event, sort_keys=True)

    def _publish_event(self, event: Dict) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            LOGGER.error("collector queue full; dropping event for pid=%s", event.get("pid"))

    async def _synthetic_feed(self) -> None:
        processes = [(4200, "curl"), (4201, "python"), (1, "systemd")]
        risky_ports = [22, 53, 80, 443, 4444, 8080]
        while self._running:
            pid, name = random.choice(processes)
            port = random.choice(risky_ports)
            event = {
                "timestamp_ns": time.time_ns(),
                "pid": pid,
                "uid": 0 if pid == 1 else 1000,
                "event_type": random.choice(["connect", "sendto", "recvfrom", "execve"]),
                "process_name": name,
                "destination_ip": f"192.168.1.{random.randint(2, 200)}",
                "destination_port": port,
                "size": random.randint(64, 8192),
                "ip_version": 4,
                "source": "synthetic",
            }
            self._publish_event(event)
            await asyncio.sleep(self.poll_interval)


import contextlib  # noqa: E402  pylint: disable=wrong-import-position
