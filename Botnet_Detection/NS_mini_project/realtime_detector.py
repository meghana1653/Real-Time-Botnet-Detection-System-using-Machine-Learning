import pandas as pd
from scapy.all import sniff, IP, IPv6
import pickle
import time
import numpy as np
import csv
import os

# -----------------------------
# CONFIG
# -----------------------------
FLOW_SIZE = 50
TIME_WINDOW = 5   # seconds
MIN_PACKETS = 5   # avoid weak flows

blocked_ips = set()

# -----------------------------
# BLOCKING (OPTIONAL)
# -----------------------------
def block_ip(ip):
    if ip in blocked_ips:
        return
    
    print(f"🚫 Blocking IP: {ip}")
    
    command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
    os.system(command)

    blocked_ips.add(ip)

# -----------------------------
# LOG FILE SETUP
# -----------------------------
log_file = "live_logs.csv"
file_exists = os.path.isfile(log_file)

log = open(log_file, "a", newline="")
writer = csv.writer(log)

if not file_exists:
    writer.writerow(["timestamp", "src", "dst", "confidence", "label"])

# -----------------------------
# LOAD MODEL
# -----------------------------
model = pickle.load(open("model.pkl", "rb"))

history = {}
flows = {}

# -----------------------------
# PACKET PROCESSING
# -----------------------------
def process_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        src = ip.src
        dst = ip.dst
        proto = ip.nh
    else:
        return

    key = (src, dst, proto)

    size = len(packet)
    timestamp = time.time()

    if key not in flows:
        flows[key] = []

    flows[key].append((size, timestamp))

    # -----------------------------
    # HYBRID TRIGGER
    # -----------------------------
    if len(flows[key]) >= 1 and (
        len(flows[key]) >= FLOW_SIZE or
        (timestamp - flows[key][0][1]) >= TIME_WINDOW
    ):
        data = flows[key]

        # 🔥 SAFETY: avoid tiny flows
        if len(data) < MIN_PACKETS:
            flows[key] = []
            return

        sizes = [x[0] for x in data]
        times = [x[1] for x in data]

        time_diffs = np.diff(times)

        # -----------------------------
        # FEATURES
        # -----------------------------
        packet_count = len(sizes)

        avg_packet_size = np.mean(sizes)
        std_packet_size = np.std(sizes)

        min_packet_size = np.min(sizes)
        max_packet_size = np.max(sizes)

        flow_duration = max(times[-1] - times[0], 1e-6)

        avg_time_diff = np.mean(time_diffs)

        packet_rate = packet_count / flow_duration

        burst_rate = sum(1 for t in time_diffs if t < 0.005) / len(time_diffs)

        size_variation = std_packet_size / (avg_packet_size + 1e-6)

        max_time_diff = np.max(time_diffs)
        min_time_diff = np.min(time_diffs)

        time_variation = np.std(time_diffs)

        idle_time = max_time_diff

        # -----------------------------
        # MODEL INPUT
        # -----------------------------
        input_df = pd.DataFrame([[
            packet_count,
            avg_packet_size,
            std_packet_size,
            min_packet_size,
            max_packet_size,
            flow_duration,
            avg_time_diff,
            packet_rate,
            burst_rate,
            size_variation,
            max_time_diff,
            min_time_diff,
            time_variation,
            idle_time
        ]], columns=[
            "packet_count",
            "avg_packet_size",
            "std_packet_size",
            "min_packet_size",
            "max_packet_size",
            "flow_duration",
            "avg_time_diff",
            "packet_rate",
            "burst_rate",
            "size_variation",
            "max_time_diff",
            "min_time_diff",
            "time_variation",
            "idle_time"
        ])

        # -----------------------------
        # PREDICTION
        # -----------------------------
        proba = model.predict_proba(input_df)[0]

        flow_id = f"{src}->{dst}"

        if flow_id not in history:
            history[flow_id] = []

        history[flow_id].append(proba[1])
        history[flow_id] = history[flow_id][-3:]

        avg_score = sum(history[flow_id]) / len(history[flow_id])

        print(f"\nFlow: {src} → {dst}")
        print(f"Avg Confidence: {avg_score:.2f}")

        # -----------------------------
        # LABEL (CLEAN VERSION)
        # -----------------------------
        if avg_score > 0.90:
            label = "BOTNET"
            print("🔴 CONFIRMED BOTNET")
            # block_ip(src)  # enable if running as admin

        elif avg_score > 0.70:
            label = "SUSPICIOUS"
            print("🟡 SUSPICIOUS")

        else:
            label = "NORMAL"
            print("🟢 NORMAL")

        # -----------------------------
        # LOGGING
        # -----------------------------
        writer.writerow([timestamp, src, dst, round(avg_score, 3), label])
        log.flush()

        # reset flow
        flows[key] = []

    # -----------------------------
    # CLEANUP OLD FLOWS
    # -----------------------------
    for k in list(flows.keys()):
        if len(flows[k]) == 0:
            del flows[k]
        elif time.time() - flows[k][0][1] > 30:
            del flows[k]


# -----------------------------
# START SNIFFING
# -----------------------------
print("📡 Real-time detection started...")
sniff(prn=process_packet, store=False)