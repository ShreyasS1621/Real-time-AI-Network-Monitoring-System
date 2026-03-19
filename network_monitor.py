# NOTE: Requires root/admin privileges for packet sniffing
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd
import numpy as np
import plotly.express as px
import time
from collections import deque, Counter
import threading

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from scapy.all import sniff, IP, TCP, UDP, ICMP

# GLOBAL STORAGE
packet_data = deque(maxlen=1000)

# PACKET PROCESSING
def process_packet(packet):
    try:
        if IP in packet:
            proto = "OTHER"
            if TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"
            elif ICMP in packet:
                proto = "ICMP"

            packet_data.append({
                "time": time.time(),
                "datetime": time.strftime("%d:%m:%Y-%H:%M:%S", time.localtime()),
                "src": packet[IP].src,
                "len": len(packet),
                "proto": proto
            })
    except Exception as e:
     print("Error processing packet:", e)

# START SNIFFING THREAD
def start_sniffing():
    sniff(prn=process_packet, store=False)

threading.Thread(target=start_sniffing, daemon=True).start()

# DATAFRAME
def get_dataframe():
    df = pd.DataFrame(list(packet_data))
    if len(df) == 0:
        return df

    df["packet_rate"] = df["time"].diff().fillna(0)
    df["time_only"] = pd.to_datetime(df["datetime"], format="%d:%m:%Y-%H:%M:%S").dt.strftime("%H:%M:%S")

    return df

# DASH APP
app = dash.Dash(
    __name__,
    title="Network Monitoring System Dashboard"
)

app.layout = html.Div([
    html.H1("🛡 Real-time AI Network Monitoring System"),

    html.Div(id="metrics"),
    dcc.Graph(id="traffic-graph"),

    html.H3("Anomalous Packets"),
    html.Div(id="anomaly-table"),

    html.H3("DDoS Detection"),
    html.Div(id="ddos-alert"),

    html.H3("Live Packet Stream"),
    html.Div(id="packet-table"),

    dcc.Interval(id="interval", interval=2000, n_intervals=0)
])

@app.callback(
    [Output("metrics", "children"),
     Output("traffic-graph", "figure"),
     Output("anomaly-table", "children"),
     Output("ddos-alert", "children"),
     Output("packet-table", "children")],
    [Input("interval", "n_intervals")]
)
def update_dashboard(n):

    df = get_dataframe()

    if len(df) < 10:
        return "Waiting for packets...", {}, "", "", ""

    # FEATURES
    features = df[["len", "packet_rate"]]
    scaler = StandardScaler()
    X = scaler.fit_transform(features)

    # ANOMALY DETECTION
    iso = IsolationForest(contamination=0.05)
    df["anomaly"] = iso.fit_predict(X)
    df["anomaly"] = df["anomaly"] == -1

    # DDOS DETECTION
    ip_counts = Counter(df["src"])
    ddos_ips = [ip for ip, count in ip_counts.items() if count > 5000]
    df["ddos"] = df["src"].isin(ddos_ips)

    # METRICS
    metrics = html.Div([
        html.P(f"Total Packets: {len(df)}"),
        html.P(f"Anomalies: {df['anomaly'].sum()}"),
        html.P(f"DDoS IPs: {len(ddos_ips)}")
    ])

    # GRAPH
    fig = px.line(df, x="time_only", y="len", title="Packet Size Over Time")

    # TABLES
    anomaly_table = html.Pre(df[df["anomaly"]][["datetime","src","proto","len"]].tail(10).to_string())
    packet_table = html.Pre(df[["datetime","src","proto","len"]].tail(20).to_string())

    # DDOS ALERT
    if len(ddos_ips) > 0:
        ddos_alert = f"⚠ DDoS detected from IPs: {ddos_ips}"
    else:
        ddos_alert = "No DDoS detected"

    return metrics, fig, anomaly_table, ddos_alert, packet_table

if __name__ == "__main__":
    app.run(debug=True)