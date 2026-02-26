#!/usr/bin/env python3
"""
generate_sample.py – creates a small synthetic PCAP for Sentinel demos.
Run once with: python3 generate_sample.py

Requires: scapy
  pip install scapy
"""

import random
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap

random.seed(42)
packets = []

SRC_IPS   = [f"192.168.1.{i}" for i in range(10, 20)]
DST_IPS   = ["10.0.0.1", "10.0.0.2", "8.8.8.8", "1.1.1.1", "93.184.216.34"]
DST_PORTS = [80, 443, 22, 53, 8080, 3306, 9200]

base_ts = 1700000000.0

def add_tcp_flow(src, dst, sport, dport, payload_size=512):
    global base_ts
    data = b"X" * payload_size
    # SYN
    packets.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S"))
    # SYN-ACK
    packets.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA"))
    # ACK
    packets.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A"))
    # Data
    packets.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=data))
    # FIN
    packets.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA"))
    packets.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA"))
    base_ts += random.uniform(0.05, 0.5)

def add_udp_flow(src, dst, sport, dport, size=64):
    global base_ts
    packets.append(IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=b"U" * size))
    packets.append(IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / Raw(load=b"R" * 32))
    base_ts += random.uniform(0.01, 0.1)

def add_dns_query(src, dst="8.8.8.8", domain="example.com"):
    global base_ts
    qpkt = IP(src=src, dst=dst) / UDP(sport=random.randint(1024,65535), dport=53) / \
           DNS(rd=1, qd=DNSQR(qname=domain))
    packets.append(qpkt)
    base_ts += 0.002

def add_icmp(src, dst):
    global base_ts
    packets.append(IP(src=src, dst=dst) / ICMP())
    packets.append(IP(src=dst, dst=src) / ICMP(type=0))
    base_ts += 0.01

# ── Normal traffic ────────────────────────────────────────────────────────────
print("Generating normal traffic…")
for _ in range(30):
    src = random.choice(SRC_IPS)
    dst = random.choice(DST_IPS)
    sport = random.randint(1024, 65535)
    dport = random.choice([80, 443, 22])
    add_tcp_flow(src, dst, sport, dport, random.randint(100, 2000))

for _ in range(20):
    src = random.choice(SRC_IPS)
    add_dns_query(src, domain=random.choice(["example.com", "google.com", "github.com"]))

for _ in range(10):
    src = random.choice(SRC_IPS)
    dst = random.choice(DST_IPS)
    add_udp_flow(src, dst, random.randint(1024,65535), 53)

for _ in range(5):
    src = random.choice(SRC_IPS)
    dst = random.choice(DST_IPS)
    add_icmp(src, dst)

# ── Anomalous traffic (port scan + large data exfil) ─────────────────────────
print("Generating anomalous traffic…")
attacker = "172.16.0.55"
for port in range(20, 45):  # port scan
    packets.append(IP(src=attacker, dst="10.0.0.1") / TCP(sport=random.randint(1024,65535), dport=port, flags="S"))
    base_ts += 0.001

# Large data exfiltration
add_tcp_flow(attacker, "93.184.216.34", 54321, 443, payload_size=65000)
add_tcp_flow(attacker, "93.184.216.34", 54322, 443, payload_size=65000)

out = "sample.pcap"
wrpcap(out, packets)
print(f"Written {len(packets)} packets to {out}")
