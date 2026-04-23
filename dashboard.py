import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import os
import time
from datetime import datetime

# ─────────────────────────────────────────
# PAGE CONFIGURATION
# ─────────────────────────────────────────
st.set_page_config(
    page_title="IoT Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

os.chdir(r"C:\Users\madha\OneDrive\LLM IN SECURITY PROJECT")

# ─────────────────────────────────────────
# CUSTOM CSS
# ─────────────────────────────────────────
st.markdown("""
<style>
.main-title {
    font-size: 32px; font-weight: 700;
    color: #1f77b4; margin-bottom: 0px;
}
.sub-title { font-size: 14px; color: #666; margin-bottom: 10px; }
.live-badge {
    background: #00cc44; color: white;
    padding: 4px 12px; border-radius: 12px;
    font-size: 13px; font-weight: bold;
    display: inline-block; margin-bottom: 10px;
}
.paused-badge {
    background: #ff8800; color: white;
    padding: 4px 12px; border-radius: 12px;
    font-size: 13px; font-weight: bold;
    display: inline-block; margin-bottom: 10px;
}
.alert-new {
    background: #fff3cd; border-left: 4px solid #ff8800;
    padding: 10px; border-radius: 6px; margin-bottom: 8px;
}
.alert-critical {
    background: #ffe0e0; border-left: 4px solid #ff4444;
    padding: 10px; border-radius: 6px; margin-bottom: 8px;
}
.alert-normal {
    background: #f0f0f0; border-left: 4px solid #aaa;
    padding: 8px; border-radius: 6px; margin-bottom: 6px;
}
.severity-CRITICAL {
    background:#ff4444; color:white; padding:2px 8px;
    border-radius:10px; font-size:11px; font-weight:bold;
}
.severity-HIGH {
    background:#ff8800; color:white; padding:2px 8px;
    border-radius:10px; font-size:11px; font-weight:bold;
}
.severity-MEDIUM {
    background:#ffcc00; color:black; padding:2px 8px;
    border-radius:10px; font-size:11px; font-weight:bold;
}
.severity-LOW {
    background:#00cc44; color:white; padding:2px 8px;
    border-radius:10px; font-size:11px; font-weight:bold;
}
.threat-report {
    background:#1e1e1e; color:#00ff88;
    padding:15px; border-radius:8px;
    font-family:monospace; font-size:12px;
    white-space:pre-wrap; line-height:1.6;
}
.section-header {
    font-size:18px; font-weight:600; color:#333;
    border-bottom:2px solid #1f77b4;
    padding-bottom:5px; margin-bottom:15px;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────
@st.cache_data
def load_data():
    flagged = pd.read_csv("flagged_anomalies.csv")
    reports = pd.read_csv("llm_threat_reports.csv")
    return flagged, reports

flagged_df, reports_df = load_data()

# ─────────────────────────────────────────
# SEVERITY SCORING (same logic as Module 3)
# ─────────────────────────────────────────
CRITICAL_ATTACKS = ["ddos", "ransomware", "mitm"]
HIGH_ATTACKS     = ["backdoor", "scanning", "dos"]
MEDIUM_ATTACKS   = ["injection", "password", "xss"]
CRITICAL_PORTS   = [22, 23, 53, 443, 3389, 8080]

def calculate_severity(row):
    score       = float(row["anomaly_score"])
    attack_type = str(row["type"]).lower().strip()
    try:
        dst_port = int(row["dst_port"])
    except:
        dst_port = 0
    if score > 0.35 or attack_type in CRITICAL_ATTACKS:
        return "CRITICAL"
    elif score > 0.25 or attack_type in HIGH_ATTACKS:
        return "HIGH"
    elif score > 0.15 or attack_type in MEDIUM_ATTACKS:
        return "MEDIUM"
    elif dst_port in CRITICAL_PORTS:
        return "HIGH"
    else:
        return "LOW"

if "severity" not in flagged_df.columns:
    flagged_df["severity"] = flagged_df.apply(calculate_severity, axis=1)


# ─────────────────────────────────────────
# SESSION STATE — stores live alerts
# ─────────────────────────────────────────
if "alert_log"      not in st.session_state:
    st.session_state.alert_log = []
if "current_index"  not in st.session_state:
    st.session_state.current_index = 0
if "monitoring"     not in st.session_state:
    st.session_state.monitoring = False
if "total_critical" not in st.session_state:
    st.session_state.total_critical = 0
if "total_high"     not in st.session_state:
    st.session_state.total_high = 0


# ─────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────
st.sidebar.markdown("## 🛡️ IoT Security Monitor")
st.sidebar.markdown("---")

# Start / Stop monitoring button
if st.sidebar.button(
    "⏹ Stop Monitoring" if st.session_state.monitoring else "▶ Start Monitoring",
    use_container_width=True
):
    st.session_state.monitoring = not st.session_state.monitoring

# Reset button
if st.sidebar.button("🔄 Reset Dashboard", use_container_width=True):
    st.session_state.alert_log     = []
    st.session_state.current_index = 0
    st.session_state.monitoring    = False
    st.session_state.total_critical= 0
    st.session_state.total_high    = 0
    st.rerun()

# Refresh speed
refresh_speed = st.sidebar.slider(
    "Refresh speed (seconds)", 1, 10, 3
)

st.sidebar.markdown("---")
st.sidebar.markdown("### Filters")
severity_filter = st.sidebar.multiselect(
    "Show severities:",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### Model Performance")
st.sidebar.metric("Accuracy",        "82.54%")
st.sidebar.metric("Precision",       "88.30%")
st.sidebar.metric("Recall",          "75.02%")
st.sidebar.metric("F1 Score",        "0.81")
st.sidebar.metric("False Alarm Rate","9.94%")

st.sidebar.markdown("---")
st.sidebar.info(
    f"Dataset: TON_IoT\n"
    f"Total flagged: {len(flagged_df):,}\n"
    f"LLM analysed: {len(reports_df)}\n"
    f"Model: Isolation Forest\n"
    f"LLM: Mistral 7B via Ollama"
)


# ─────────────────────────────────────────
# MAIN HEADER
# ─────────────────────────────────────────
st.markdown(
    '<p class="main-title">🛡️ LLM-Enhanced IoT Security Dashboard</p>',
    unsafe_allow_html=True
)
st.markdown(
    '<p class="sub-title">Real-Time Anomaly Detection and Malicious Device '
    'Identification — TON_IoT Dataset | Mistral 7B via Ollama</p>',
    unsafe_allow_html=True
)

# Live / Paused status badge
if st.session_state.monitoring:
    st.markdown('<span class="live-badge">🟢 LIVE MONITORING ACTIVE</span>',
                unsafe_allow_html=True)
    st.markdown(f"*Last updated: {datetime.now().strftime('%H:%M:%S')}*")
else:
    st.markdown('<span class="paused-badge">⏸ MONITORING PAUSED</span>',
                unsafe_allow_html=True)


# ─────────────────────────────────────────
# STREAM NEXT ROW if monitoring is active
# ─────────────────────────────────────────
if st.session_state.monitoring:
    idx = st.session_state.current_index
    if idx < len(flagged_df):
        row = flagged_df.iloc[idx]
        sev = row["severity"]

        # Build alert entry
        alert = {
            "time"         : datetime.now().strftime("%H:%M:%S"),
            "src_ip"       : row["src_ip"],
            "dst_ip"       : row["dst_ip"],
            "dst_port"     : row["dst_port"],
            "proto"        : row["proto"],
            "attack_type"  : row["type"],
            "anomaly_score": round(float(row["anomaly_score"]), 4),
            "severity"     : sev
        }

        # Try to match LLM report
        match = reports_df[reports_df["src_ip"] == row["src_ip"]]
        alert["llm_report"] = match.iloc[0]["llm_report"] \
                              if len(match) > 0 else "LLM report not available"

        st.session_state.alert_log.insert(0, alert)

        if sev == "CRITICAL":
            st.session_state.total_critical += 1
        elif sev == "HIGH":
            st.session_state.total_high += 1

        # Keep only last 100 alerts in memory
        st.session_state.alert_log = st.session_state.alert_log[:100]
        st.session_state.current_index += 1
    else:
        # Loop back to start
        st.session_state.current_index = 0


# ─────────────────────────────────────────
# TOP METRIC CARDS
# ─────────────────────────────────────────
m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    st.metric("Alerts Processed",
              st.session_state.current_index)
with m2:
    st.metric("Critical Alerts",
              st.session_state.total_critical,
              delta="immediate action" if st.session_state.total_critical > 0 else None)
with m3:
    st.metric("High Alerts",
              st.session_state.total_high)
with m4:
    avg = round(flagged_df["anomaly_score"].mean(), 4) \
          if len(flagged_df) > 0 else 0
    st.metric("Avg Anomaly Score", avg)
with m5:
    st.metric("Model F1 Score", "0.81")

st.markdown("---")


# ─────────────────────────────────────────
# SECTION 1: LIVE ALERT FEED + LLM VIEWER
# ─────────────────────────────────────────
col_feed, col_llm = st.columns([1.5, 1])

with col_feed:
    st.markdown('<p class="section-header">🚨 Live Alert Feed</p>',
                unsafe_allow_html=True)

    if len(st.session_state.alert_log) == 0:
        st.info("Press ▶ Start Monitoring in the sidebar to begin.")
    else:
        # Filter by selected severities
        visible = [a for a in st.session_state.alert_log
                   if a["severity"] in severity_filter]

        for alert in visible[:15]:
            css = "alert-critical" if alert["severity"] == "CRITICAL" \
                  else "alert-new" if alert["severity"] == "HIGH" \
                  else "alert-normal"
            st.markdown(f"""
<div class="{css}">
  <span class="severity-{alert['severity']}">{alert['severity']}</span>
  &nbsp;
  <strong>{alert['time']}</strong> &nbsp;|&nbsp;
  {alert['src_ip']} → {alert['dst_ip']}:{alert['dst_port']}
  &nbsp;|&nbsp; <strong>{alert['attack_type'].upper()}</strong>
  &nbsp;|&nbsp; Score: {alert['anomaly_score']}
</div>
""", unsafe_allow_html=True)

with col_llm:
    st.markdown('<p class="section-header">🤖 LLM Threat Explanation</p>',
                unsafe_allow_html=True)

    if len(st.session_state.alert_log) > 0:
        visible = [a for a in st.session_state.alert_log
                   if a["severity"] in severity_filter]
        if len(visible) > 0:
            options = [
                f"{a['src_ip']} | {a['attack_type'].upper()} | {a['severity']} | {a['time']}"
                for a in visible[:15]
            ]
            selected = st.selectbox("Select alert:", options)
            sel_idx  = options.index(selected)
            sel_alert= visible[sel_idx]

            sev = sel_alert["severity"]
            st.markdown(
                f'<span class="severity-{sev}">{sev}</span>',
                unsafe_allow_html=True
            )
            st.markdown(f"**Device:** {sel_alert['src_ip']} → {sel_alert['dst_ip']}")
            st.markdown(f"**Type:** {sel_alert['attack_type'].upper()}")
            st.markdown(f"**Score:** {sel_alert['anomaly_score']}")
            st.markdown("**LLM Analysis:**")
            st.markdown(
                f'<div class="threat-report">{sel_alert["llm_report"]}</div>',
                unsafe_allow_html=True
            )
    else:
        st.info("Start monitoring to see LLM threat explanations.")

st.markdown("---")


# ─────────────────────────────────────────
# SECTION 2: LIVE CHARTS
# ─────────────────────────────────────────
if len(st.session_state.alert_log) > 0:
    log_df = pd.DataFrame(st.session_state.alert_log)

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown('<p class="section-header">📊 Attack Distribution</p>',
                    unsafe_allow_html=True)
        atk_counts = log_df["attack_type"].value_counts().reset_index()
        atk_counts.columns = ["Attack Type", "Count"]
        fig1 = px.pie(
            atk_counts, values="Count", names="Attack Type",
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig1.update_layout(margin=dict(t=10,b=10,l=10,r=10), height=260)
        st.plotly_chart(fig1, use_container_width=True)

    with c2:
        st.markdown('<p class="section-header">📈 Severity Breakdown</p>',
                    unsafe_allow_html=True)
        sev_counts = log_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        sev_colors = {
            "CRITICAL":"#ff4444","HIGH":"#ff8800",
            "MEDIUM":"#ffcc00","LOW":"#00cc44"
        }
        fig2 = px.bar(
            sev_counts, x="Severity", y="Count",
            color="Severity", color_discrete_map=sev_colors
        )
        fig2.update_layout(
            showlegend=False,
            margin=dict(t=10,b=10,l=10,r=10),
            height=260
        )
        st.plotly_chart(fig2, use_container_width=True)

    with c3:
        st.markdown('<p class="section-header">📉 Score Over Time</p>',
                    unsafe_allow_html=True)
        recent = log_df.head(20).copy()
        recent = recent.iloc[::-1].reset_index(drop=True)
        fig3 = px.line(
            recent, x=recent.index, y="anomaly_score",
            color_discrete_sequence=["#1f77b4"],
            markers=True
        )
        fig3.update_layout(
            margin=dict(t=10,b=10,l=10,r=10),
            height=260,
            xaxis_title="Alert #",
            yaxis_title="Anomaly Score"
        )
        st.plotly_chart(fig3, use_container_width=True)

    st.markdown("---")

    # ─────────────────────────────────────
    # SECTION 3: DEVICE RISK PROFILING
    # ─────────────────────────────────────
    st.markdown('<p class="section-header">🖥️ Device Risk Profiling</p>',
                unsafe_allow_html=True)

    device_profile = log_df.groupby("src_ip").agg(
        times_flagged    = ("src_ip", "count"),
        avg_score        = ("anomaly_score", "mean"),
        max_score        = ("anomaly_score", "max"),
        highest_severity = ("severity", lambda x:
                            "CRITICAL" if "CRITICAL" in x.values else
                            "HIGH"     if "HIGH"     in x.values else
                            "MEDIUM"   if "MEDIUM"   in x.values else "LOW"),
        attack_types     = ("attack_type",
                            lambda x: ", ".join(x.unique()))
    ).reset_index()

    device_profile["avg_score"] = device_profile["avg_score"].round(4)
    device_profile["max_score"] = device_profile["max_score"].round(4)
    device_profile = device_profile.sort_values(
        "times_flagged", ascending=False
    )

    st.dataframe(
        device_profile,
        use_container_width=True,
        column_config={
            "src_ip"          : st.column_config.TextColumn("Device IP"),
            "times_flagged"   : st.column_config.NumberColumn("Times Flagged"),
            "avg_score"       : st.column_config.NumberColumn("Avg Score",
                                format="%.4f"),
            "max_score"       : st.column_config.NumberColumn("Max Score",
                                format="%.4f"),
            "highest_severity": st.column_config.TextColumn("Highest Severity"),
            "attack_types"    : st.column_config.TextColumn("Attack Types"),
        }
    )

    st.markdown("---")

# ─────────────────────────────────────────
# SECTION 4: MODEL PERFORMANCE
# ─────────────────────────────────────────
st.markdown('<p class="section-header">📋 Model Performance Summary</p>',
            unsafe_allow_html=True)

p1, p2 = st.columns(2)

with p1:
    metrics = pd.DataFrame({
        "Metric" : ["Accuracy","Precision","Recall",
                    "F1 Score","False Alarm Rate"],
        "Value"  : ["82.54%","88.30%","75.02%","0.81","9.94%"],
        "Status" : ["✅ Good","✅ Excellent","✅ Good",
                    "✅ Strong","✅ Low"]
    })
    st.dataframe(metrics, use_container_width=True, hide_index=True)

with p2:
    st.markdown("**Confusion Matrix**")
    cm = pd.DataFrame({
        ""                : ["Actual Benign","Actual Attack"],
        "Predicted Benign": ["9,006 ✅ TN","2,498 ❌ FN"],
        "Predicted Attack": ["994 ❌ FP","7,502 ✅ TP"]
    })
    st.dataframe(cm, use_container_width=True, hide_index=True)

st.markdown("---")
st.markdown(
    "*LLM-Enhanced Security Framework for IoT Networks — "
    "Anomaly Detection and Malicious Device Identification | "
    "TON_IoT Dataset | Mistral 7B via Ollama | Isolation Forest*"
)

# ─────────────────────────────────────────
# AUTO REFRESH when monitoring is active
# ─────────────────────────────────────────
if st.session_state.monitoring:
    time.sleep(refresh_speed)
    st.rerun()