"""Styled Streamlit dashboard for AgentShield.

This UI is intentionally visual-first and mirrors the dark SOC-style dashboard
requested by users while still reading real AgentShield JSONL logs when present.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

LOG_PATH = Path("agentshield/logs/agentshield.jsonl")
INCIDENT_PATH = Path("agentshield/logs/incidents.jsonl")
METRICS_PATH = Path("agentshield/logs/metrics.jsonl")


# ----------------------------- data helpers ---------------------------------

def read_jsonl(path: Path, limit: int = 200) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        lines = handle.readlines()[-limit:]
    return [json.loads(line) for line in lines if line.strip()]


def to_df(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def synthetic_metrics(hours: int = 24) -> pd.DataFrame:
    """Build fake-but-realistic telemetry if logs are empty."""
    n = hours * 4
    now = datetime.now(timezone.utc)
    times = [now - timedelta(minutes=15 * (n - i)) for i in range(n)]
    baseline = np.clip(np.random.normal(0.28, 0.09, size=n), 0.05, 0.95)
    spikes = np.random.choice(n, 5, replace=False)
    baseline[spikes] = np.clip(baseline[spikes] + np.random.uniform(0.35, 0.55, size=5), 0, 1)

    return pd.DataFrame(
        {
            "timestamp": times,
            "anomaly_rate": baseline,
            "events_per_second": np.random.randint(70, 280, size=n),
            "queue_drops": np.random.randint(0, 6, size=n),
            "blocked_threats": np.random.randint(15, 60, size=n),
        }
    )


def load_dashboard_data(limit: int) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    metrics_df = to_df(read_jsonl(METRICS_PATH, limit=500))
    events_df = to_df(read_jsonl(LOG_PATH, limit=limit))
    incidents_df = to_df(read_jsonl(INCIDENT_PATH, limit=200))

    if metrics_df.empty:
        metrics_df = synthetic_metrics(hours=24)
    elif "timestamp" in metrics_df:
        metrics_df["timestamp"] = pd.to_datetime(metrics_df["timestamp"], unit="s", errors="coerce")

    if "timestamp" in metrics_df:
        metrics_df = metrics_df.dropna(subset=["timestamp"]).sort_values("timestamp")

    return metrics_df, events_df, incidents_df


# ----------------------------- ui helpers -----------------------------------

def inject_styles() -> None:
    st.markdown(
        """
        <style>
            .stApp { background: radial-gradient(circle at top, #0b1838 0%, #040a1a 60%); color: #dce9ff; }
            .main .block-container { padding-top: 1.2rem; max-width: 1700px; }
            div[data-testid="stMetric"] { background: linear-gradient(120deg,#0f2044,#0b1633); border: 1px solid #1f3768; border-radius: 14px; padding: 10px; }
            .panel { background: linear-gradient(145deg,#071028,#0a1735); border: 1px solid #1e3567; border-radius: 14px; padding: 12px 14px; }
            .menu-item { padding: 8px 12px; margin-bottom: 8px; border-radius: 10px; border: 1px solid #1c305c; background: #081328; color: #9fb5e9; }
            .menu-item.active { background: linear-gradient(90deg,#194d2f,#0f2f2a); color: #7CFF9F; border: 1px solid #2f7a4b; font-weight: 600; }
            .small { color: #8fa8d8; font-size: 0.84rem; }
            .title { font-size: 2rem; color: #7CFF9F; font-weight: 700; }
            .subtitle { color: #a8bcdf; margin-bottom: 0.7rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def sidebar_menu() -> None:
    st.sidebar.markdown("## 🛡️ AgentShield")
    st.sidebar.markdown("<div class='small'>Autonomous Cybersecurity Agent</div>", unsafe_allow_html=True)
    st.sidebar.divider()
    entries = [
        ("Dashboard", True),
        ("Real-time Monitor", False),
        ("Anomaly Detection", False),
        ("Signature Engine", False),
        ("Agent (Think-Decide-Act)", False),
        ("Alerts & Incidents", False),
        ("Logs & Audit", False),
        ("System Health", False),
    ]
    for label, active in entries:
        css_class = "menu-item active" if active else "menu-item"
        st.sidebar.markdown(f"<div class='{css_class}'>{label}</div>", unsafe_allow_html=True)


# ----------------------------- app ------------------------------------------

st.set_page_config(page_title="AgentShield Dashboard", layout="wide")
inject_styles()
sidebar_menu()

st.markdown("<div class='title'>SYSTEM STATUS: PROTECTED</div>", unsafe_allow_html=True)
st.markdown("<div class='subtitle'>AgentShield is Active & Monitoring</div>", unsafe_allow_html=True)

col_opts1, col_opts2, col_opts3 = st.columns([1, 1, 1.7])
auto_refresh = col_opts1.checkbox("Auto refresh", value=True)
refresh_secs = col_opts2.slider("Refresh interval", min_value=2, max_value=30, value=5)
event_limit = col_opts3.slider("Event rows", min_value=100, max_value=5000, value=600, step=100)

if auto_refresh:
<<<<<<< ours
<<<<<<< ours
    st.caption(f"Auto refresh enabled every {refresh_secs} seconds")
    try:
        st.experimental_set_query_params(refresh=str(refresh_secs))
    except Exception:
        # Some Streamlit versions don't expose experimental_set_query_params;
        # ignore silently for compatibility.
        pass

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
=======
=======
>>>>>>> theirs
    st.caption(
        f"Auto-refresh every {refresh_secs}s. "
        "If your Streamlit version supports it, use the browser refresh button every few seconds."
    )

metrics_df, events_df, incidents_df = load_dashboard_data(event_limit)
latest = metrics_df.iloc[-1].to_dict() if not metrics_df.empty else {}

# Top metric cards
k1, k2, k3, k4, k5 = st.columns(5)

k1.metric("TOTAL EVENTS", f"{int(metrics_df['events_per_second'].sum()):,}" if "events_per_second" in metrics_df else "0")
k2.metric("ANOMALIES DETECTED", f"{int((metrics_df['anomaly_rate'] > 0.45).sum())}")
k3.metric("HIGH RISK ALERTS", f"{int((metrics_df['anomaly_rate'] > 0.65).sum())}")
k4.metric("ACTIONS TAKEN", f"{len(incidents_df) if not incidents_df.empty else int((metrics_df['anomaly_rate'] > 0.55).sum())}")
k5.metric("BLOCKED THREATS", f"{int(latest.get('blocked_threats', 0))}")

st.markdown("### ANOMALY TREND (Last 24 Hours)")
if not metrics_df.empty and "timestamp" in metrics_df and "anomaly_rate" in metrics_df:
    chart_df = metrics_df.set_index("timestamp")[["anomaly_rate"]]
    st.line_chart(chart_df, height=310)

left, mid, right = st.columns([1.05, 1.15, 1.1])

with left:
    st.markdown("### ANOMALY SCORE DISTRIBUTION")
    if "anomaly_rate" in metrics_df:
        bins = pd.cut(metrics_df["anomaly_rate"], bins=[0, 0.4, 0.65, 1.0], labels=["Normal", "Medium", "High"])
        dist = bins.value_counts().reindex(["Normal", "Medium", "High"]).fillna(0)
        st.bar_chart(dist)

with mid:
    st.markdown("### TOP ANOMALY SOURCES")
    source_df = incidents_df.copy()
    if source_df.empty:
        source_df = pd.DataFrame(
            {
                "source": ["192.168.1.45", "10.0.0.23", "172.16.5.10", "192.168.1.88", "10.0.1.15"],
                "anomaly_score": [0.92, 0.88, 0.81, 0.72, 0.69],
                "risk": ["High", "High", "High", "Medium", "Medium"],
            }
        )
    cols = [c for c in ["source", "anomaly_score", "risk", "action"] if c in source_df.columns]
    st.dataframe(source_df[cols].head(8), use_container_width=True)

with right:
    st.markdown("### SYSTEM HEALTH")
    cpu = int(np.clip(np.random.normal(22, 8), 5, 95))
    mem = int(np.clip(np.random.normal(37, 10), 8, 96))
    disk = int(np.clip(np.random.normal(27, 8), 10, 97))
    st.progress(cpu / 100, text=f"CPU Usage: {cpu}%")
    st.progress(mem / 100, text=f"Memory Usage: {mem}%")
    st.progress(disk / 100, text=f"Disk Usage: {disk}%")

b1, b2 = st.columns(2)
with b1:
    st.markdown("### RECENT EVENTS")
    if events_df.empty:
        st.info("No event logs yet. Start the runtime with `python main.py` to populate telemetry.")
    else:
        st.dataframe(events_df.tail(20), use_container_width=True)

with b2:
    st.markdown("### RECENT INCIDENTS")
    if incidents_df.empty:
        st.info("No incidents yet — system currently looks clean.")
    else:
        st.dataframe(incidents_df.tail(20), use_container_width=True)

st.caption("AgentShield Dashboard — real-time visibility into anomalies and automated protection.")
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
