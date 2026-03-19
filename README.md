# Real-time-AI-Network-Monitoring-System
🛡 Real-time AI network monitoring dashboard built with Dash &amp; Plotly. Captures live packets with Scapy, detects anomalies via IsolationForest, flags potential DDoS attacks, and visualizes traffic in an interactive dashboard for network analysis and security monitoring.
# 🛡 AI-Powered Live Network Monitoring Dashboard

A real-time network traffic monitoring system built using Dash, Scapy, and Machine Learning.

## 🚀 Features

* 📡 Live packet sniffing using Scapy
* 📊 Real-time dashboard with Dash & Plotly
* 🤖 Anomaly detection using Isolation Forest
* ⚠ DDoS detection based on traffic spikes
* 📈 Interactive traffic visualization

## 🧠 Tech Stack

* Python
* Dash (Plotly)
* Scapy
* Scikit-learn
* Pandas / NumPy

## 📂 Project Structure

```
app.py
requirements.txt
README.md
.gitignore
```

## ⚙️ Installation

1. Clone the repo:

```bash
git clone https://github.com/your-username/network-monitor.git
cd network-monitor
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
python app.py
```

## 🌐 Access Dashboard

Open your browser and go to:

```
http://127.0.0.1:8050/
```

## ⚠️ Important Notes

* Run as administrator/root (required for packet sniffing)
* Works best on Linux/macOS
* Windows may require Npcap installed

## 📸 Screenshots

(Add screenshots here)

## 🛡 Future Improvements

* Geo-IP tracking
* Advanced DDoS ML models
* Alert notifications (Email/SMS)
* Docker deployment

## 📜 License

MIT License
