# ------------------------------------------------------------
# 📦 ids_utils.py
# Utility Functions for Feature Extraction & Attack Detection
# Intel Unnati IDS | Developer : Arjun, Nimish and Shaurya | Version: 1.0
# ------------------------------------------------------------

import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP

# ------------------------------------------------------------
# 🌐 Global State Trackers (Port Scans, ICMP Floods)
# ------------------------------------------------------------

port_tracker = defaultdict(list)
icmp_timestamps = []

# ------------------------------------------------------------
# 🔧 Convert IP Address (str) to Integer
# ------------------------------------------------------------

def ip_to_int(ip):
    try:
        return int.from_bytes(bytes(map(int, ip.split("."))), "big")
    except:
        return 0

# ------------------------------------------------------------
# 🧠 Extract Features from Packet
# ------------------------------------------------------------

def extract_features(pkt, start_time):
    base = {
        "frame.time_relative": time.time() - start_time,
        "frame.len": len(pkt),
        "ip.src": 0,
        "ip.dst": 0,
        "ip.proto": 0,
        "tcp.srcport": 0,
        "tcp.dstport": 0,
        "tcp.flags": 0,
        "udp.srcport": 0,
        "udp.dstport": 0,
        "udp.length": 0,
        "icmp.type": 0,
        "icmp.code": 0,
    }

    # Parse IP layer and sublayers
    if IP in pkt:
        ip = pkt[IP]
        base["ip.src"] = ip_to_int(ip.src)
        base["ip.dst"] = ip_to_int(ip.dst)
        base["ip.proto"] = ip.proto

        if TCP in pkt:
            tcp = pkt[TCP]
            base["tcp.srcport"] = tcp.sport
            base["tcp.dstport"] = tcp.dport
            base["tcp.flags"] = int(tcp.flags)

        elif UDP in pkt:
            udp = pkt[UDP]
            base["udp.srcport"] = udp.sport
            base["udp.dstport"] = udp.dport
            base["udp.length"] = udp.len

        elif ICMP in pkt:
            icmp = pkt[ICMP]
            base["icmp.type"] = icmp.type
            base["icmp.code"] = icmp.code

    # --------------------------------------------------------
    # ➕ Engineered ML Features
    # --------------------------------------------------------
    base["is_well_known_port"] = int(base["tcp.dstport"] < 1024)
    base["port_diff"] = abs(base["tcp.srcport"] - base["tcp.dstport"])
    base["tcp_flag_score"] = base["tcp.flags"] / (base["frame.len"] + 1)
    base["proto_complexity"] = int(base["ip.proto"] > 100)
    base["payload_size_est"] = base["udp.length"] + base["frame.len"]

    return base

# ------------------------------------------------------------
# 🚨 Detect Port Scan (based on unique ports over time)
# ------------------------------------------------------------

def detect_port_scan(features, window=3, threshold=15):
    src_ip = features["ip.src"]
    dst_port = features["tcp.dstport"]
    now = time.time()

    if src_ip and dst_port:
        # Update tracker
        port_tracker[src_ip].append((now, dst_port))
        port_tracker[src_ip] = [(t, p) for (t, p) in port_tracker[src_ip] if now - t <= window]
        unique_ports = set(p for (t, p) in port_tracker[src_ip])

        if len(unique_ports) >= threshold:
            return f"🚨 Port Scan Detected from {src_ip} → {len(unique_ports)} ports"

    return None

# ------------------------------------------------------------
# 🚨 Detect ICMP Flood (burst over short window)
# ------------------------------------------------------------

def detect_icmp_flood(pkt, limit=50):
    global icmp_timestamps

    if ICMP in pkt:
        now = time.time()
        icmp_timestamps.append(now)
        icmp_timestamps = [t for t in icmp_timestamps if now - t <= 2]

        if len(icmp_timestamps) > limit:
            return "🚨 ICMP FLOOD DETECTED!"

    return None
