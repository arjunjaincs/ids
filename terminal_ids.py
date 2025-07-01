# ------------------------------------------------------------
# 🖥️ terminal_ids.py
# Real-Time Terminal Dashboard for AI-Powered IDS
# Intel Unnati Project | Authors : Arjun, Nimish and Shaurya | Version: 1.0
# ------------------------------------------------------------

import os
import time
import joblib
import curses
import pandas as pd
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from collections import deque, Counter
from datetime import datetime
from utils.ids_utils import extract_features, detect_port_scan, detect_icmp_flood

# ------------------------------------------------------------
# ⚙️ Configurations
# ------------------------------------------------------------

MODEL_PATH = "data/ids_model_final.pkl"
INTERFACE = "wlan0"
LOG_LIMIT = 20
IDLE_TIMEOUT = 5
LOG_FLUSH_INTERVAL = 0.5

# ------------------------------------------------------------
# 🧰 Initialization
# ------------------------------------------------------------

os.makedirs("logs", exist_ok=True)
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
CSV_LOG_FILE = f"logs/ids_log_{timestamp}.csv"
TXT_LOG_FILE = f"logs/ids_log_{timestamp}.log"

model = joblib.load(MODEL_PATH)
packet_log = deque(maxlen=LOG_LIMIT)
proto_count = Counter()
sniff_queue = deque()
log_buffer = []

stats = {"total": 0, "normal": 0, "attack": 0}
start_time = time.time()
last_packet_time = time.time()
last_flush_time = time.time()

# Initialize CSV headers
with open(CSV_LOG_FILE, "w") as f:
    f.write("time,src_ip,dst_ip,protocol,label\n")
with open(TXT_LOG_FILE, "w") as f:
    f.write("")

# ------------------------------------------------------------
# 📦 Packet Classification + Logging
# ------------------------------------------------------------

def classify_packet(pkt):
    global last_packet_time

    stats["total"] += 1
    proto = "Other"

    if IP in pkt:
        if TCP in pkt: proto = "TCP"
        elif UDP in pkt: proto = "UDP"
        elif ICMP in pkt: proto = "ICMP"
        else: proto = f"Proto-{pkt[IP].proto}"
    proto_count[proto] += 1

    features = extract_features(pkt, start_time)
    label = "NORMAL ✅"

    detect_port_scan(features)
    detect_icmp_flood(pkt)

    # Matching model feature order
    feature_order = [
        "frame.time_relative", "frame.len", "ip.src", "ip.dst", "ip.proto",
        "tcp.srcport", "tcp.dstport", "tcp.flags", "udp.srcport", "udp.dstport",
        "udp.length", "icmp.type", "icmp.code",
        "is_well_known_port", "port_diff", "tcp_flag_score",
        "proto_complexity", "payload_size_est"
    ]
    df = pd.DataFrame([[features[f] for f in feature_order]], columns=feature_order)
    prediction = model.predict(df)[0]

    if prediction == 1:
        stats["attack"] += 1
        if features["tcp.flags"] == 2:
            label = "SYN FLOOD 🚨"
        elif features["ip.proto"] == 1:
            label = "ICMP ATTACK 🚨"
        elif features["ip.proto"] == 17:
            label = "UDP ATTACK 🚨"
        else:
            label = "GENERIC ATTACK 🚨"
    else:
        stats["normal"] += 1

    # Logging output
    try:
        now = datetime.now().strftime("%H:%M:%S")
        line = f"[{now}] {pkt[IP].src} → {pkt[IP].dst} | {proto} | {label}"
        packet_log.appendleft(line)
        log_buffer.append((f"{now},{pkt[IP].src},{pkt[IP].dst},{proto},{label}\n", f"{line}\n"))
        last_packet_time = time.time()
    except:
        pass

# ------------------------------------------------------------
# 🖥️ Terminal Dashboard Renderer
# ------------------------------------------------------------

def draw_ui(stdscr):
    global last_flush_time
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)

    while True:
        for _ in range(min(200, len(sniff_queue))):
            classify_packet(sniff_queue.popleft())

        stdscr.erase()
        height, width = stdscr.getmaxyx()
        uptime = int(time.time() - start_time)
        idle = time.time() - last_packet_time
        status = "🟢 Receiving packets..." if idle < IDLE_TIMEOUT else "🔴 Idle: No packets"

        # Header
        stdscr.addstr(0, 0, "INTRUSION DETECTION DASHBOARD".center(width - 1), curses.A_BOLD | curses.A_UNDERLINE)
        stdscr.addstr(2, 0, f"⏱  Uptime:   {uptime // 60}m {uptime % 60}s")
        stdscr.addstr(3, 0, f"📦  Packets: {stats['total']}")
        stdscr.addstr(4, 0, f"✅  Normal:  {stats['normal']}")
        stdscr.addstr(5, 0, f"🚨  Attacks: {stats['attack']}")
        stdscr.addstr(6, 0, f"🚦  Queue Size: {len(sniff_queue)}")
        stdscr.addstr(7, 0, f"📶  Status: {status}")
        stdscr.addstr(9, 0, "Latest Packets:")

        for i, line in enumerate(list(packet_log)[:20]):
            if 10 + i >= height - 1: break
            color = curses.color_pair(1) if "🚨" in line else curses.color_pair(2)
            try:
                stdscr.addstr(10 + i, 0, line[:width - 1], color)
            except curses.error:
                pass

        stdscr.refresh()

        # Auto flush logs
        if time.time() - last_flush_time >= LOG_FLUSH_INTERVAL and log_buffer:
            with open(CSV_LOG_FILE, "a") as f_csv, open(TXT_LOG_FILE, "a") as f_txt:
                for csv_line, txt_line in log_buffer:
                    f_csv.write(csv_line)
                    f_txt.write(txt_line)
            log_buffer.clear()
            last_flush_time = time.time()

        time.sleep(0.01)

# ------------------------------------------------------------
# 🌐 Packet Handler for AsyncSniffer
# ------------------------------------------------------------

def packet_handler(pkt):
    sniff_queue.append(pkt)

# ------------------------------------------------------------
# 📝 Write Summary to Log Files
# ------------------------------------------------------------

def write_summary():
    uptime = int(time.time() - start_time)
    summary = [
        f"# IDS Log started at {timestamp}",
        f"# Uptime: {uptime // 60}m {uptime % 60}s",
        f"# Total Packets: {stats['total']}",
        f"# Normal: {stats['normal']}",
        f"# Attacks: {stats['attack']}",
    ]

    # CSV: keep header, insert summary on top
    with open(CSV_LOG_FILE, "r") as f:
        lines = f.readlines()
    with open(CSV_LOG_FILE, "w") as f:
        f.write("\n".join(summary) + "\n")
        for line in lines[1:]:
            f.write(line)

    # TXT: write summary at top
    with open(TXT_LOG_FILE, "r") as f:
        log_lines = f.readlines()
    with open(TXT_LOG_FILE, "w") as f:
        f.write("\n".join(summary) + "\n\n")
        for line in log_lines:
            f.write(line)

# ------------------------------------------------------------
# 🚀 Main
# ------------------------------------------------------------

def main():
    sniffer = AsyncSniffer(iface=INTERFACE, prn=packet_handler, store=False)
    sniffer.start()
    try:
        curses.wrapper(draw_ui)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        write_summary()

        uptime = int(time.time() - start_time)
        print("\n📊 IDS Session Summary")
        print(f"⏱  Uptime:   {uptime // 60}m {uptime % 60}s")
        print(f"📦  Packets: {stats['total']}")
        print(f"✅  Normal:  {stats['normal']}")
        print(f"🚨  Attacks: {stats['attack']}")
        print(f"📁 Logs saved to: {CSV_LOG_FILE}")

if __name__ == "__main__":
    main()
