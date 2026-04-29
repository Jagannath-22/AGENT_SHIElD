"""Run AgentShield dashboard with quick health-check and optional browser open."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import webbrowser
from urllib.request import Request, urlopen


def health_check(url: str, timeout_secs: int = 25) -> bool:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        try:
            req = Request(url, headers={"User-Agent": "AgentShield/1.0"})
            with urlopen(req, timeout=2) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.7)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch the Streamlit dashboard.")
    parser.add_argument("--host", default="0.0.0.0", help="Host bind for Streamlit server")
    parser.add_argument("--port", type=int, default=8501, help="Port for Streamlit server")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    parser.add_argument("--health-timeout", type=int, default=25, help="Health check timeout seconds")
    parser.add_argument(
        "--dev-mode",
        action="store_true",
        help="Enable VS Code/Codespaces-friendly flags (disable CORS/XSRF checks).",
    )
    args = parser.parse_args()

    cmd = [
        "streamlit",
        "run",
        "agentshield/dashboard/app.py",
        "--server.headless",
        "true",
        "--server.address",
        args.host,
        "--server.port",
        str(args.port),
    ]
    if args.dev_mode:
        cmd.extend(["--server.enableCORS", "false", "--server.enableXsrfProtection", "false"])

    print(f"[AgentShield] Starting dashboard on http://{args.host}:{args.port}")
    proc = subprocess.Popen(cmd)

    check_host = "127.0.0.1" if args.host == "0.0.0.0" else args.host
    health_url = f"http://{check_host}:{args.port}/_stcore/health"
    app_url = f"http://{check_host}:{args.port}"
    if health_check(health_url, timeout_secs=args.health_timeout):
        print(f"[AgentShield] Dashboard is healthy: {health_url}")
        if not args.no_browser:
            webbrowser.open(app_url)
            print(f"[AgentShield] Opened browser at {app_url}")
    else:
        print(
            f"[AgentShield] Warning: health endpoint not ready within {args.health_timeout}s. "
            f"Check terminal logs. URL: {app_url}",
            file=sys.stderr,
        )

    try:
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
