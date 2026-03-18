"""Response engine for logging, alerting, and killing malicious processes."""

from __future__ import annotations

<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
=======
import hashlib
>>>>>>> theirs
=======
import hashlib
>>>>>>> theirs
=======
import hashlib
>>>>>>> theirs
=======
import hashlib
>>>>>>> theirs
=======
import hashlib
>>>>>>> theirs
=======
import hashlib
>>>>>>> theirs
import json
import logging
import os
import signal
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib import request

LOGGER = logging.getLogger(__name__)


class ResponseEngine:
    def __init__(self, audit_log: Path | None = None, webhook_url: Optional[str] = None) -> None:
        self.audit_log = audit_log or Path("agentshield/logs/incidents.jsonl")
        self.webhook_url = webhook_url
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)

<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
    def execute(self, decision, feature_vector, inference: dict, latest_event: dict) -> None:
=======
    def execute(self, decision, feature_vector, inference: dict, latest_event: dict, signature_match) -> None:
>>>>>>> theirs
=======
    def execute(self, decision, feature_vector, inference: dict, latest_event: dict, signature_match) -> None:
>>>>>>> theirs
=======
    def execute(self, decision, feature_vector, inference: dict, latest_event: dict, signature_match) -> None:
>>>>>>> theirs
=======
    def execute(self, decision, feature_vector, inference: dict, latest_event: dict, signature_match) -> None:
>>>>>>> theirs
=======
    def execute(self, decision, feature_vector, inference: dict, latest_event: dict, signature_match) -> None:
>>>>>>> theirs
=======
    def execute(self, decision, feature_vector, inference: dict, latest_event: dict, signature_match) -> None:
>>>>>>> theirs
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision": asdict(decision),
            "pid": feature_vector.pid,
            "process_name": feature_vector.process_name,
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
            "inference": inference,
            "latest_event": latest_event,
        }
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
            "context": feature_vector.context,
            "inference": inference,
            "signature_detected": signature_match.detected,
            "signature_reasons": signature_match.reasons,
            "latest_event": latest_event,
        }
        record["integrity_sha256"] = hashlib.sha256(json.dumps(record, sort_keys=True).encode("utf-8")).hexdigest()
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
        self._append_audit(record)
        self._alert(record)
        if decision.action == "kill":
            self._kill_process(feature_vector.pid, feature_vector.process_name)

    def _append_audit(self, record: dict) -> None:
        serialized = json.dumps(record, sort_keys=True)
        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(serialized + "\n")
        try:
            os.chmod(self.audit_log, 0o600)
        except PermissionError:
            LOGGER.warning("Could not tighten permissions on %s", self.audit_log)
        LOGGER.info("Wrote audit record for pid=%s", record["pid"])

    def _alert(self, record: dict) -> None:
        LOGGER.warning("AgentShield decision=%s pid=%s reasons=%s", record["decision"]["action"], record["pid"], record["decision"]["reasons"])
        if not self.webhook_url:
            return
        body = json.dumps(record).encode("utf-8")
        req = request.Request(self.webhook_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with request.urlopen(req, timeout=5) as response:  # nosec B310
                LOGGER.info("Webhook alert sent with status %s", response.status)
        except Exception as exc:  # pragma: no cover - network side effect
            LOGGER.error("Failed to send webhook alert: %s", exc)

    def _kill_process(self, pid: int, process_name: str) -> None:
        try:
            os.kill(pid, signal.SIGKILL)
            LOGGER.critical("Killed pid=%s process=%s", pid, process_name)
        except ProcessLookupError:
            LOGGER.warning("Process pid=%s already exited", pid)
        except PermissionError:
            LOGGER.error("Insufficient permissions to kill pid=%s", pid)
