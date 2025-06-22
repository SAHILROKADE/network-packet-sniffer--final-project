from collections import defaultdict
import time

# Track port scans and flood attacks
scan_log = defaultdict(list)
flood_log = defaultdict(list)

# File to store alerts
ALERT_LOG_FILE = "alerts.log"

def log_alert(message):
    print("[ALERT]", message)
    with open(ALERT_LOG_FILE, "a") as f:
        f.write(f"[{time.ctime()}] {message}\n")

def detect_anomalies(ip, dport):
    current_time = time.time()

    # --- Port Scan Detection ---
    scan_log[ip].append((dport, current_time))
    recent_ports = [p for p, t in scan_log[ip] if current_time - t < 5]
    if len(set(recent_ports)) > 10:
        log_alert(f"⚠️ Port scan detected from {ip} on ports: {set(recent_ports)}")

    # --- Flood Detection ---
    flood_log[ip].append(current_time)
    recent_packets = [t for t in flood_log[ip] if current_time - t < 5]
    if len(recent_packets) > 100:
        log_alert(f"🚨 Flood attack detected from {ip} - {len(recent_packets)} packets in 5 seconds")

