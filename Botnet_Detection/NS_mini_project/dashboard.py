import streamlit as st
import pandas as pd
import os
import time


FILE = "live_logs.csv"

st.set_page_config(layout="wide")

# -----------------------------
# 🔥 FULL DARK THEME OVERRIDE
# -----------------------------
st.markdown("""
<style>

/* FORCE DARK MODE EVERYWHERE */
.stApp {
    background-color: black !important;
}

/* Main container */
[data-testid="stAppViewContainer"] {
    background-color: black !important;
}

/* Remove white blocks */
[data-testid="stHeader"],
[data-testid="stToolbar"],
[data-testid="stSidebar"] {
    background-color: black !important;
}

/* ALL text */
* {
    color: #00BFFF !important;
}

/* Titles */
h1, h2, h3 {
    color: #00BFFF !important;
}

/* Metrics cards */
[data-testid="stMetric"] {
    background-color: black !important;
    border: 1px solid #00BFFF !important;
    border-radius: 10px;
    padding: 15px;
}

/* REMOVE WHITE TABLE BLOCK */
.element-container {
    background-color: black !important;
}

/* CUSTOM TABLE */
table {
    width: 100%;
    border-collapse: collapse;
    background-color: black !important;
}

th {
    color: #00BFFF !important;
    border-bottom: 1px solid #00BFFF;
    padding: 10px;
}

td {
    padding: 10px;
    border-bottom: 1px solid #222;
    color: white !important;
}

</style>
""", unsafe_allow_html=True)

# -----------------------------
# TITLE
# -----------------------------
st.title("🚨 REAL-TIME BOTNET DETECTION")

st.caption(f"Last updated: {time.strftime('%H:%M:%S')}")

# -----------------------------
# LOAD DATA
# -----------------------------
if not os.path.exists(FILE):
    st.warning("No data yet...")
    st.stop()

df = pd.read_csv(FILE)

if df.empty:
    st.warning("No data yet...")
    st.stop()

# -----------------------------
# METRICS
# -----------------------------
col1, col2, col3 = st.columns(3)

col1.metric("TOTAL FLOWS", len(df))
col2.metric("🔴 BOTNET", len(df[df["label"] == "BOTNET"]))
col3.metric("🟡 SUSPICIOUS", len(df[df["label"] == "SUSPICIOUS"]))

st.markdown("---")



# -----------------------------
# 🔥 CUSTOM TABLE (FIXED)
# -----------------------------
st.subheader("📡 LIVE TRAFFIC")

latest = df.tail(15)

table_html = "<table>"

table_html += "<tr>"
table_html += "<th>SRC</th>"
table_html += "<th>DST</th>"
table_html += "<th>CONFIDENCE</th>"
table_html += "<th>STATUS</th>"
table_html += "</tr>"

for _, row in latest.iterrows():
    label = row["label"]

    if label == "BOTNET":
        color = "#ff4b4b"   # red
    elif label == "SUSPICIOUS":
        color = "#ffd700"   # yellow
    else:
        color = "#00ff7f"   # green

    table_html += "<tr>"
    table_html += f"<td>{row['src']}</td>"
    table_html += f"<td>{row['dst']}</td>"
    table_html += f"<td>{row['confidence']:.3f}</td>"
    table_html += f"<td style='color:{color}; font-weight:bold;'>{label}</td>"
    table_html += "</tr>"

table_html += "</table>"

st.markdown(table_html, unsafe_allow_html=True)

# -----------------------------
# SUMMARY (NO WHITE CHARTS)
# -----------------------------
st.subheader("📈 TRAFFIC TREND")

# Convert timestamp
df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")

# Group into time bins (5 sec)
df["time_bin"] = df["timestamp"].dt.floor("5s")

trend = df.groupby(["time_bin", "label"]).size().unstack(fill_value=0)
trend = trend.reset_index()

import altair as alt

chart = alt.Chart(trend).transform_fold(
    ["NORMAL", "SUSPICIOUS", "BOTNET"],
    as_=["Label", "Count"]
).mark_line(point=True, strokeWidth=3).encode(
    
    x=alt.X(
        "time_bin:T",
        title="Time",
        axis=alt.Axis(labelColor="#00BFFF", titleColor="#00BFFF")
    ),
    
    y=alt.Y(
        "Count:Q",
        title="Flow Count",
        axis=alt.Axis(labelColor="#00BFFF", titleColor="#00BFFF")
    ),
    
    color=alt.Color(
        "Label:N",
        scale=alt.Scale(
            domain=["NORMAL", "SUSPICIOUS", "BOTNET"],
            range=["#00FF00", "#FFD700", "#FF0000"]
        ),
        legend=alt.Legend(
            labelColor="#00BFFF",
            titleColor="#00BFFF"
        )
    )
).properties(
    height=400
).configure_view(
    stroke=None
).configure_axis(
    gridColor="#222"
).configure(
    background="black"   # ✅ FIXED HERE
)

st.altair_chart(chart, use_container_width=True)

# -----------------------------
# 🔄 AUTO REFRESH (WORKS ALWAYS)
# -----------------------------
time.sleep(2)
st.rerun()
