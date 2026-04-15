import pandas as pd
from scapy.all import sniff, IP, IPv6
import time
import numpy as np
import csv
import os


flows = {}
FLOW_SIZE = 50

# -----------------------------
# Label input
# -----------------------------
print("Enter label for this session:")
print("0 → Normal Traffic")
print("1 → Attack Traffic (ping/flood)")
LABEL = int(input("Label: "))

# -----------------------------
# File handling (AUTO HEADER)
# -----------------------------
file_exists = os.path.isfile("flow_dataset.csv")

file = open("flow_dataset.csv", "a", newline="")
writer = csv.writer(file)

# if not file_exists:
#     writer.writerow([
#         "packet_count",
#         "avg_packet_size",
#         "std_packet_size",
#         "min_packet_size",
#         "max_packet_size",
#         "flow_duration",
#         "avg_time_diff",
#         "packet_rate",
#         "burst_rate",
#         "size_variation",
#         "max_time_diff",
#         "min_time_diff",
#         "time_variation",
#         "idle_time",
#         "label"
#     ])

# -----------------------------
# Packet Processing
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
    # When flow is complete
    # -----------------------------
    if len(flows[key]) >= FLOW_SIZE:
        data = flows[key]

        sizes = [x[0] for x in data]
        times = [x[1] for x in data]

        # Time differences
        time_diffs = np.diff(times) if len(times) > 1 else [0]

        # -----------------------------
        # Feature Engineering (FINAL)
        # -----------------------------
        packet_count = len(sizes)
        
        avg_packet_size = np.mean(sizes)
        std_packet_size = np.std(sizes)
        
        min_packet_size = np.min(sizes)
        max_packet_size = np.max(sizes)
        
        flow_duration = times[-1] - times[0]
        
        avg_time_diff = np.mean(time_diffs)
        
        packet_rate = packet_count / (flow_duration + 1e-6)
        
        # Timing-based features
        burst_rate = sum(1 for t in time_diffs if t < 0.005) / len(time_diffs)
        
        size_variation = std_packet_size / (avg_packet_size + 1e-6)
        
        max_time_diff = np.max(time_diffs)
        min_time_diff = np.min(time_diffs)
        
        time_variation = np.std(time_diffs)
        
        # ✅ NEW FEATURE (FIXED)
        idle_time = max_time_diff
        
        
        # -----------------------------
        # Save to CSV
        # -----------------------------
        writer.writerow([
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
            idle_time,   # ✅ fixed
            LABEL        # ✅ fixed comma
        ])

        print(f"Saved flow: {src} → {dst}")

        # Reset flow
        flows[key] = []


# -----------------------------
# Start Sniffing
# -----------------------------
try:
    print("📡 Capturing flows... Press Ctrl+C to stop")
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\nStopping capture...")
    file.close()
    print("✅ Dataset saved successfully!")