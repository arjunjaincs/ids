# ------------------------------------------------------------
# 📡 realtime_ids.py
# Real-Time Intrusion Detection using ML + Heuristics
# Intel Unnati IDS | Authors : Arjun, Nimish and Shaurya | Version: 1.0
# ------------------------------------------------------------

import joblib
import time
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from utils.ids_utils import extract_features, detect_port_scan, detect_icmp_flood

# ------------------------------------------------------------
# 🔧 Configurations
# ------------------------------------------------------------

MODEL_PATH = "data/ids_model_final.pkl"
INTERFACE = "wlan0"
start_time = time.time()

# ------------------------------------------------------------
# 🧠 ML Prediction + Heuristic Detection
# ------------------------------------------------------------

def predict(pkt):
    global model, start_time

    features = extract_features(pkt, start_time)

    # 🔎 Heuristic Alerts
    scan_alert = detect_port_scan(features)
    flood_alert = detect_icmp_flood(pkt)

    # 🧠 ML Feature Order (same as during training)
    feature_order = [
        "frame.time_relative", "frame.len", "ip.src", "ip.dst", "ip.proto",
        "tcp.srcport", "tcp.dstport", "tcp.flags",
        "udp.srcport", "udp.dstport", "udp.length",
        "icmp.type", "icmp.code",
        "is_well_known_port", "port_diff", "tcp_flag_score",
        "proto_complexity", "payload_size_est"
    ]

    # ➤ Predict Label
    X_df = pd.DataFrame([[features[f] for f in feature_order]], columns=feature_order)
    prediction = model.predict(X_df)[0]

    # 🏷️ Label Assignment
    label = "NORMAL ✅"
    if prediction == 1:
        if features["tcp.flags"] == 2 and features["ip.proto"] == 6:
            label = "SYN FLOOD 🚨"
        elif features["ip.proto"] == 1:
            label = "ICMP ATTACK 🚨"
        elif features["ip.proto"] == 17:
            label = "UDP ATTACK 🚨"
        elif features["tcp_flag_score"] > 0.8:
            label = "MALFORMED PACKET 🚨"
        else:
            label = "GENERIC ATTACK 🚨"

    # 🖨️ Output
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Packet classified as: {label}")

    if scan_alert:
        print(scan_alert)
    if flood_alert:
        print(flood_alert)

# ------------------------------------------------------------
# 🚀 Main Execution
# ------------------------------------------------------------

print("✅ Model loaded.")
model = joblib.load(MODEL_PATH)

print(f"🟢 Starting real-time packet analysis on {INTERFACE} (Press Ctrl+C to stop)...")
sniff(iface=INTERFACE, prn=predict, store=False)
