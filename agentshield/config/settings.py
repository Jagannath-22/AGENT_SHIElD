"""YAML-backed configuration loader with validation and hot reload support."""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

DEFAULT_CONFIG_PATH = Path("agentshield/config/config.yaml")


@dataclass
class SignatureRuleConfig:
    reverse_shell_ports: List[int] = field(default_factory=lambda: [4444])
    suspicious_cidrs: List[str] = field(default_factory=list)
    rapid_connection_threshold: int = 20
    exfil_byte_rate_threshold: int = 100000
    dos_connection_threshold: int = 60
    dos_unique_ip_threshold: int = 25
    dos_byte_rate_threshold: int = 250000


@dataclass
class CoreEbpfConfig:
    loader_path: str = "./agentshield/ebpf_core/loader"
    object_path: str = "./agentshield/ebpf_core/monitor.bpf.o"
    expected_sha256: Optional[str] = None


@dataclass
class AgentShieldConfig:
    anomaly_threshold: float = 0.65
    kill_process: bool = True
    use_core_ebpf: bool = False
    log_level: str = "INFO"
    webhook_url: Optional[str] = None
    collector_poll_interval: float = 0.1
    window_seconds: int = 60
    min_events: int = 5
    metrics_interval: int = 10
    dashboard_refresh_seconds: int = 2
    protected_pids: List[int] = field(default_factory=lambda: [1])
    protected_processes: List[str] = field(default_factory=lambda: ["systemd", "sshd", "docker", "dockerd", "containerd", "init"])
    whitelisted_processes: List[str] = field(default_factory=lambda: ["systemd", "sshd", "docker", "dockerd", "containerd", "init"])
    kill_on_signature_tags: List[str] = field(default_factory=lambda: ["reverse_shell", "dos"])
    signature_rules: SignatureRuleConfig = field(default_factory=SignatureRuleConfig)
    core_ebpf: CoreEbpfConfig = field(default_factory=CoreEbpfConfig)


class ConfigManager:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DEFAULT_CONFIG_PATH
        self._config = AgentShieldConfig()
        self._mtime: float | None = None

    def load(self, force: bool = False) -> AgentShieldConfig:
        if not self.path.exists():
            LOGGER.warning("Config %s missing; using defaults", self.path)
            return copy.deepcopy(self._config)
        current_mtime = self.path.stat().st_mtime
        if not force and self._mtime == current_mtime:
            return copy.deepcopy(self._config)
        data = self._load_yaml(self.path)
        self._config = self._coerce(data)
        self._validate(self._config)
        self._mtime = current_mtime
        LOGGER.info("Loaded configuration from %s", self.path)
        return copy.deepcopy(self._config)

    def maybe_reload(self) -> AgentShieldConfig:
        return self.load(force=False)

    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        raw = path.read_text(encoding="utf-8")
        if yaml is not None:
            data = yaml.safe_load(raw) or {}
            if not isinstance(data, dict):
                raise ValueError("config root must be a mapping")
            return data
        return self._minimal_yaml_parse(raw)

    def _coerce(self, data: Dict[str, Any]) -> AgentShieldConfig:
        signature_rules = SignatureRuleConfig(**(data.get("signature_rules") or {}))
        core_ebpf = CoreEbpfConfig(**(data.get("core_ebpf") or {}))
        payload = {key: value for key, value in data.items() if key not in {"signature_rules", "core_ebpf"}}
        config = AgentShieldConfig(signature_rules=signature_rules, core_ebpf=core_ebpf, **payload)
        config.anomaly_threshold = max(0.0, min(float(config.anomaly_threshold), 1.0))
        config.collector_poll_interval = max(float(config.collector_poll_interval), 0.01)
        config.window_seconds = max(int(config.window_seconds), 5)
        config.min_events = max(int(config.min_events), 2)
        config.metrics_interval = max(int(config.metrics_interval), 1)
        config.dashboard_refresh_seconds = max(int(config.dashboard_refresh_seconds), 1)
        config.signature_rules.reverse_shell_ports = [int(p) for p in config.signature_rules.reverse_shell_ports]
        config.signature_rules.dos_connection_threshold = max(int(config.signature_rules.dos_connection_threshold), 10)
        config.signature_rules.dos_unique_ip_threshold = max(int(config.signature_rules.dos_unique_ip_threshold), 5)
        config.signature_rules.dos_byte_rate_threshold = max(int(config.signature_rules.dos_byte_rate_threshold), 10_000)
        config.protected_pids = [int(p) for p in config.protected_pids]
        config.kill_on_signature_tags = [str(tag).strip() for tag in config.kill_on_signature_tags if str(tag).strip()]
        return config

    def _validate(self, config: AgentShieldConfig) -> None:
        allowed_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if config.log_level.upper() not in allowed_levels:
            raise ValueError(f"log_level must be one of {sorted(allowed_levels)}")
        if not config.protected_pids:
            LOGGER.warning("protected_pids list is empty; this can be unsafe in production")

    @classmethod
    def _minimal_yaml_parse(cls, raw: str) -> Dict[str, Any]:
        lines = [line.rstrip("\n") for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]
        root: Dict[str, Any] = {}
        stack: List[Tuple[int, Any]] = [(-1, root)]
        idx = 0
        while idx < len(lines):
            line = lines[idx]
            indent = len(line) - len(line.lstrip(" "))
            stripped = line.strip()
            while len(stack) > 1 and indent <= stack[-1][0]:
                stack.pop()
            container = stack[-1][1]
            if stripped.startswith("- "):
                if not isinstance(container, list):
                    raise ValueError("list item without list container")
                container.append(cls._parse_scalar(stripped[2:].strip()))
                idx += 1
                continue
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            if value:
                container[key] = cls._parse_scalar(value)
                idx += 1
                continue
            next_indent, next_stripped = cls._peek_next(lines, idx)
            new_container: Any = [] if next_stripped.startswith("- ") and next_indent > indent else {}
            container[key] = new_container
            stack.append((indent, new_container))
            idx += 1
        return root

    @staticmethod
    def _peek_next(lines: List[str], idx: int) -> Tuple[int, str]:
        if idx + 1 >= len(lines):
            return -1, ""
        nxt = lines[idx + 1]
        return len(nxt) - len(nxt.lstrip(" ")), nxt.strip()

    @staticmethod
    def _parse_scalar(value: str) -> Any:
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if lowered in {"null", "none"}:
            return None
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            return value.strip('"')
