"""Streamlit dashboard for AgentShield."""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

LOG_PATH = Path("agentshield/logs/agentshield.jsonl")
INCIDENT_PATH = Path("agentshield/logs/incidents.jsonl")
METRICS_PATH = Path("agentshield/logs/metrics.jsonl")


def read_jsonl(path: Path, limit: int = 200):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        lines = handle.readlines()[-limit:]
    return [json.loads(line) for line in lines if line.strip()]


st.set_page_config(page_title="AgentShield Dashboard", layout="wide")
st.title("AgentShield Live Security Dashboard")

metrics = read_jsonl(METRICS_PATH, limit=1)
incidents = read_jsonl(INCIDENT_PATH)
events = read_jsonl(LOG_PATH)

col1, col2, col3, col4 = st.columns(4)
latest_metrics = metrics[-1] if metrics else {}
col1.metric("Events Seen", latest_metrics.get("events_seen", 0))
col2.metric("Anomaly Rate", f"{latest_metrics.get('anomaly_rate', 0):.2%}")
col3.metric("Alerts", latest_metrics.get("decisions_alert", 0))
col4.metric("Kills", latest_metrics.get("decisions_kill", 0))

st.subheader("Recent Events")
st.dataframe(events[-100:] if events else [])

st.subheader("Incidents")
st.dataframe(incidents[-100:] if incidents else [])

st.subheader("Metrics")
st.dataframe(metrics if metrics else [])
