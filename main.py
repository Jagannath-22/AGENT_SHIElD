"""Main entry point for AgentShield."""

from __future__ import annotations

import asyncio
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from agentshield.config.settings import ConfigManager
from agentshield.runtime.agent_runtime import AgentRuntime

LOG_PATH = Path("agentshield/logs/agentshield.log")


def configure_logging(log_level: str = "INFO") -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handlers = [
        RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=5),
        logging.StreamHandler(),
    ]
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(message)s",
        handlers=handlers,
    )
async def run_agent() -> None:
    config_manager = ConfigManager()
    config = config_manager.load(force=True)
    configure_logging(config.log_level)
    runtime = AgentRuntime()
    await runtime.run()


def main() -> None:
    asyncio.run(run_agent())


if __name__ == "__main__":
    main()
