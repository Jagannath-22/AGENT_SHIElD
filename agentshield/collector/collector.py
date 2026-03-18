"""Collector for AgentShield raw telemetry."""

from __future__ import annotations

import asyncio
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
import json
import logging
import random
import time
from typing import AsyncIterator, Dict, Optional

from agentshield.ebpf.loader import EBPFLoader
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
import contextlib
import json
import logging
import os
import random
import time
from pathlib import Path
from typing import AsyncIterator, Dict, Optional

from agentshield.ebpf.loader import EBPFLoader
from agentshield.ebpf_core.loader import CoreEBPFLoader
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs

LOGGER = logging.getLogger(__name__)


class TelemetryCollector:
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
    def __init__(self, ebpf_loader: Optional[EBPFLoader] = None, poll_interval: float = 0.1) -> None:
        self.ebpf_loader = ebpf_loader or EBPFLoader()
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
    def __init__(self, config, metrics, ebpf_loader: Optional[EBPFLoader] = None, poll_interval: float = 0.1) -> None:
        self.config = config
        self.metrics = metrics
        self.ebpf_loader = ebpf_loader or EBPFLoader()
        self.core_loader = CoreEBPFLoader(
            loader_path=config.core_ebpf.loader_path,
            object_path=config.core_ebpf.object_path,
        )
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
        self.poll_interval = poll_interval
        self.queue: asyncio.Queue[Dict] = asyncio.Queue(maxsize=10000)
        self._fallback_task: Optional[asyncio.Task] = None
        self._running = False
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours

    async def start(self) -> None:
        self._running = True
        loaded = self.ebpf_loader.load(self._publish_event)
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
        self._active_loader = None
        self.event_log = Path("agentshield/logs/agentshield.jsonl")
        self.event_log.parent.mkdir(parents=True, exist_ok=True)

    async def start(self) -> None:
        self._running = True
        loaded = False
        if self.config.use_core_ebpf:
            loaded = self.core_loader.load(self._publish_event)
            if loaded:
                self._active_loader = self.core_loader
                LOGGER.info("Running with libbpf CO-RE loader")
        if not loaded:
            loaded = self.ebpf_loader.load(self._publish_event)
            if loaded:
                self._active_loader = self.ebpf_loader
                LOGGER.info("Running with BCC loader")
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
        if not loaded:
            self._fallback_task = asyncio.create_task(self._synthetic_feed())
            LOGGER.warning("Running in synthetic telemetry mode")
            return

<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
        LOGGER.info("eBPF collector started")
        while self._running:
            self.ebpf_loader.poll(timeout=int(self.poll_interval * 1000))
=======
        while self._running:
            self._active_loader.poll()
>>>>>>> theirs
=======
        while self._running:
            self._active_loader.poll()
>>>>>>> theirs
=======
        while self._running:
            self._active_loader.poll()
>>>>>>> theirs
=======
        while self._running:
            self._active_loader.poll()
>>>>>>> theirs
=======
        while self._running:
            self._active_loader.poll()
>>>>>>> theirs
=======
        while self._running:
            self._active_loader.poll()
>>>>>>> theirs
            await asyncio.sleep(0)

    async def stop(self) -> None:
        self._running = False
        if self._fallback_task:
            self._fallback_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._fallback_task
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
=======
        if self._active_loader:
            self._active_loader.cleanup()
>>>>>>> theirs
=======
        if self._active_loader:
            self._active_loader.cleanup()
>>>>>>> theirs
=======
        if self._active_loader:
            self._active_loader.cleanup()
>>>>>>> theirs
=======
        if self._active_loader:
            self._active_loader.cleanup()
>>>>>>> theirs
=======
        if self._active_loader:
            self._active_loader.cleanup()
>>>>>>> theirs
=======
        if self._active_loader:
            self._active_loader.cleanup()
>>>>>>> theirs
        self.ebpf_loader.cleanup()

    async def events(self) -> AsyncIterator[str]:
        while self._running or not self.queue.empty():
            event = await self.queue.get()
            yield json.dumps(event, sort_keys=True)

    def _publish_event(self, event: Dict) -> None:
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            LOGGER.error("collector queue full; dropping event for pid=%s", event.get("pid"))
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
        enriched = self._enrich_process_context(event)
        self.metrics.record_event()
        with self.event_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(enriched, sort_keys=True) + "\n")
        try:
            self.queue.put_nowait(enriched)
        except asyncio.QueueFull:
            self.metrics.record_drop()
            LOGGER.error("collector queue full; dropping event for pid=%s", enriched.get("pid"))

    def _enrich_process_context(self, event: Dict) -> Dict:
        pid = int(event.get("pid", 0))
        proc_status = Path(f"/proc/{pid}/status")
        proc_cmdline = Path(f"/proc/{pid}/cmdline")
        enriched = dict(event)
        if proc_status.exists():
            content = proc_status.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if line.startswith("PPid:"):
                    enriched["ppid"] = int(line.split()[1])
                    break
        else:
            enriched.setdefault("ppid", os.getppid())
        if proc_cmdline.exists():
            cmdline = proc_cmdline.read_text(encoding="utf-8", errors="ignore").replace("\x00", " ").strip()
            enriched["cmdline"] = cmdline or enriched.get("process_name", "")
        enriched.setdefault("lineage", self._lineage(enriched.get("ppid", 0)))
        return enriched

    def _lineage(self, ppid: int) -> list[str]:
        lineage = []
        current = ppid
        hops = 0
        while current > 0 and hops < 4:
            comm_path = Path(f"/proc/{current}/comm")
            stat_path = Path(f"/proc/{current}/status")
            if not comm_path.exists():
                break
            lineage.append(comm_path.read_text(encoding="utf-8", errors="ignore").strip())
            next_ppid = 0
            if stat_path.exists():
                for line in stat_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("PPid:"):
                        next_ppid = int(line.split()[1])
                        break
            current = next_ppid
            hops += 1
        return lineage
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs

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
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
=======
                "ppid": os.getpid(),
>>>>>>> theirs
=======
                "ppid": os.getpid(),
>>>>>>> theirs
=======
                "ppid": os.getpid(),
>>>>>>> theirs
=======
                "ppid": os.getpid(),
>>>>>>> theirs
=======
                "ppid": os.getpid(),
>>>>>>> theirs
=======
                "ppid": os.getpid(),
>>>>>>> theirs
                "event_type": random.choice(["connect", "sendto", "recvfrom", "execve"]),
                "process_name": name,
                "destination_ip": f"192.168.1.{random.randint(2, 200)}",
                "destination_port": port,
                "size": random.randint(64, 8192),
                "ip_version": 4,
                "source": "synthetic",
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
            }
            self._publish_event(event)
            await asyncio.sleep(self.poll_interval)


import contextlib  # noqa: E402  pylint: disable=wrong-import-position
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
                "lineage": ["bash", "python"],
                "cmdline": f"{name} --synthetic",
            }
            self._publish_event(event)
            await asyncio.sleep(self.poll_interval)
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
