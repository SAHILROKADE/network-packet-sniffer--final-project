# 🛡️ Network Packet Sniffer with Anomaly Detection & Alert System

> 💼 Developed by **Sahil Rokade** as part of Elevate Labs Cybersecurity Internship  
> 📅 June 2025 · 🔐 Kali Linux · 🐍 Python

---

## 📌 Overview

A real-time network monitoring tool that captures live packets, detects suspicious behavior (e.g., port scanning, flooding), and generates alerts. Designed as a lightweight, CLI-based Intrusion Detection System (IDS) alternative.

---

## 🎯 Objectives

- Capture and log live IP traffic.
- Detect network anomalies such as:
  - 🔍 Port scans (`nmap`, `hping`)
  - 🚨 Flood attacks
- Alert user in real-time and log incidents.
- Store traffic logs in a SQLite database.

---

## 🧰 Tech Stack

| Component        | Tool/Library        |
|------------------|---------------------|
| Language         | Python 3.x          |
| Packet Capture   | Scapy               |
| Database         | SQLite3             |
| Plotting (optional) | Matplotlib        |
| Platform         | Kali Linux          |

---

## ⚙️ Features

| Feature             | Description |
|---------------------|-------------|
| 🔍 Live Sniffing    | Captures IP, ports, flags, and length of every packet |
| ⚠ Port Scan Detection | Detects sequential SYN requests from a single IP |
| 🚨 Flood Detection  | Detects burst of packets from same source within 5s |
| 📂 SQLite Logging   | Stores packet metadata in `packets.db` |
| 📝 Alert Logging    | Logs alerts in `alerts.log` with timestamps |
| 🧪 Test-Ready       | Validated with `nmap`, `ping`, etc. |

---

## 🗂️ Project Structure


---

## 🚀 How to Run

```bash
# 1. Clone the repo
git clone https://github.com/SAHILROKADE/network-packet-sniffer--final-project.git
cd network-packet-sniffer--final-project

# 2. (Optional) Create virtual environment
python3 -m venv myenv
source myenv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the sniffer
sudo python3 sniffer.py

🔐 Example Alerts
[ALERT] ⚠ Port scan detected from 192.168.1.101 on ports: {21, 22, 23, ...}
[ALERT] 🚨 Flood attack detected from 192.168.1.105 - 500 packets in 5 seconds

🧪 Testing Tools Used
nmap -sS -p 1-100 127.0.0.1

ping, hping3 to simulate flood or scan traffic

Custom UDP/TCP packets using Scapy

👨‍💻 Author
Sahil Rokade
Cybersecurity Intern, Ethical Hacking & VAPT
📧 sahilrokade6400@gmail.com
📞 +91 9321741190
🌐 GitHub
