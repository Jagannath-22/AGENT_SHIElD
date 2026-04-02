"""Streamlit dashboard for AgentShield."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
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


def to_df(rows):
    return pd.DataFrame(rows) if rows else pd.DataFrame()


st.set_page_config(page_title="AgentShield Dashboard", layout="wide")
st.title("AgentShield Live Security Dashboard")

auto_refresh = st.sidebar.checkbox("Auto refresh", value=True)
refresh_secs = st.sidebar.slider("Refresh interval (seconds)", min_value=1, max_value=30, value=2)
event_limit = st.sidebar.slider("Event rows", min_value=100, max_value=5000, value=500, step=100)

if auto_refresh:
    st.caption(f"Auto refresh enabled every {refresh_secs} seconds")
    st.experimental_set_query_params(refresh=str(refresh_secs))

metrics = read_jsonl(METRICS_PATH, limit=1)
incidents = read_jsonl(INCIDENT_PATH)
events = read_jsonl(LOG_PATH, limit=event_limit)

col1, col2, col3, col4 = st.columns(4)
latest_metrics = metrics[-1] if metrics else {}
col1.metric("Events Seen", latest_metrics.get("events_seen", 0))
col2.metric("Anomaly Rate", f"{latest_metrics.get('anomaly_rate', 0):.2%}")
col3.metric("Alerts", latest_metrics.get("decisions_alert", 0))
col4.metric("Kills", latest_metrics.get("decisions_kill", 0))

metrics_df = to_df(read_jsonl(METRICS_PATH, limit=300))
if not metrics_df.empty and "timestamp" in metrics_df:
    st.subheader("Anomaly Trend")
    metrics_df["timestamp"] = pd.to_datetime(metrics_df["timestamp"], unit="s", errors="coerce")
    chart_df = metrics_df[["timestamp", "anomaly_rate", "events_per_second", "queue_drops"]].set_index("timestamp")
    st.line_chart(chart_df)

st.subheader("Recent Events")
events_df = to_df(events[-100:] if events else [])
if not events_df.empty:
    st.dataframe(events_df, use_container_width=True)
else:
    st.info("No events yet")

st.subheader("Incidents")
incidents_df = to_df(incidents[-100:] if incidents else [])
if not incidents_df.empty:
    st.dataframe(incidents_df, use_container_width=True)
else:
    st.info("No incidents yet")

st.subheader("Metrics")
st.dataframe(metrics_df if not metrics_df.empty else [], use_container_width=True)
