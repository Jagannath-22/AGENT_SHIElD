"""Thin wrapper for the external libbpf CO-RE loader."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import selectors
import subprocess
from pathlib import Path
from typing import Callable, Optional

LOGGER = logging.getLogger(__name__)


class CoreEBPFLoader:
    def __init__(self, loader_path: str, object_path: str, expected_sha256: Optional[str] = None) -> None:
        self.loader_path = Path(loader_path)
        self.object_path = Path(object_path)
        self.expected_sha256 = expected_sha256
        self.process: Optional[subprocess.Popen[str]] = None
        self._callback: Optional[Callable[[dict], None]] = None
        self._selector: Optional[selectors.BaseSelector] = None

    def load(self, callback: Callable[[dict], None]) -> bool:
        self._callback = callback
        if not self.loader_path.exists():
            LOGGER.warning("CO-RE loader binary %s missing", self.loader_path)
            return False
        if not self.object_path.exists():
            LOGGER.warning("CO-RE object %s missing", self.object_path)
            return False
        if not self.loader_path.is_file() or not os.access(self.loader_path, os.X_OK):
            LOGGER.warning("CO-RE loader is not executable: %s", self.loader_path)
            return False
        if self.expected_sha256:
            digest = hashlib.sha256(self.object_path.read_bytes()).hexdigest()
            if digest.lower() != self.expected_sha256.lower():
                LOGGER.error("CO-RE object integrity check failed for %s", self.object_path)
                return False
        self.process = subprocess.Popen(
            [str(self.loader_path), str(self.object_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._selector = selectors.DefaultSelector()
        if self.process.stdout is not None:
            self._selector.register(self.process.stdout, selectors.EVENT_READ)
        if self.process.stderr is not None:
            self._selector.register(self.process.stderr, selectors.EVENT_READ)
        return True

    def poll(self) -> None:
        if self.process is None or self._selector is None or self._callback is None:
            raise RuntimeError("CO-RE loader not started")
        for key, _ in self._selector.select(timeout=0):
            line = key.fileobj.readline()
            if not line:
                continue
            if self.process.stdout is not None and key.fileobj == self.process.stdout:
                try:
                    self._callback(json.loads(line.strip()))
                except json.JSONDecodeError:
                    LOGGER.warning("Malformed CO-RE event line: %s", line.strip())
            else:
                LOGGER.warning("CO-RE loader stderr: %s", line.strip())

    def cleanup(self) -> None:
        if self._selector is not None:
            self._selector.close()
            self._selector = None
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
