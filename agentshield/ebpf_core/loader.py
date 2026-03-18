"""Thin wrapper for the external libbpf CO-RE loader."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Optional

LOGGER = logging.getLogger(__name__)


class CoreEBPFLoader:
    def __init__(self, loader_path: str, object_path: str) -> None:
        self.loader_path = Path(loader_path)
        self.object_path = Path(object_path)
        self.process: Optional[subprocess.Popen[str]] = None
        self._callback: Optional[Callable[[dict], None]] = None

    def load(self, callback: Callable[[dict], None]) -> bool:
        self._callback = callback
        if not self.loader_path.exists():
            LOGGER.warning("CO-RE loader binary %s missing", self.loader_path)
            return False
        if not self.object_path.exists():
            LOGGER.warning("CO-RE object %s missing", self.object_path)
            return False
        if shutil.which(str(self.loader_path)) is None and not self.loader_path.is_file():
            LOGGER.warning("CO-RE loader is not executable: %s", self.loader_path)
            return False
        self.process = subprocess.Popen(
            [str(self.loader_path), str(self.object_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return True

    def poll(self) -> None:
        if self.process is None or self.process.stdout is None or self._callback is None:
            raise RuntimeError("CO-RE loader not started")
        line = self.process.stdout.readline().strip()
        if line:
            self._callback(json.loads(line))

    def cleanup(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
