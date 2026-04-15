# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 15:40:39 2026

@author: ranil
"""

from scapy.all import sniff, IP, IPv6
import time
import csv

last_time = None

# Create CSV file + header
with open("attack_data.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["src_ip", "dst_ip", "protocol", "packet_size", "time_diff"])

    def process_packet(packet):
        global last_time

        current_time = time.time()
        time_diff = 0 if last_time is None else current_time - last_time
        last_time = current_time

        # IPv4
        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.proto

        # IPv6
        elif packet.haslayer(IPv6):
            ip = packet[IPv6]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.nh

        else:
            return

        size = len(packet)

        # Save row
        writer.writerow([src_ip, dst_ip, proto, size, time_diff])

        print(f"Saved: {src_ip} → {dst_ip}")

    sniff(prn=process_packet, count=200)