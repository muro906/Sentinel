#!/usr/bin/env python3
"""
Normal Traffic Test Generator
==============================
Generates PCAPs with feature distributions that closely match each model's
training data so flows score BELOW the anomaly threshold.

CIC-Darknet2020 normal class = 'non-tor' / 'nonvpn':
  - Web browsing (HTTP/HTTPS): asymmetric bytes, SF state, TCP
  - DNS:  small UDP datagrams, short duration
  - Email/SMTP: medium payload, SF state
  - Streaming: large resp_bytes, long duration, TCP

Feature targets (after RobustScaler these land near 0):
  duration      0.05 – 30 s
  orig_bytes    100  – 5 000
  resp_bytes    500  – 200 000
  orig_pkts     2    – 30
  resp_pkts     2    – 50
  conn_state    SF   (completed flows)
  proto         tcp  / udp

Usage:
    pip install scapy
    python scripts/test_normal_traffic.py              # 1 run to capture/pcap/
    python scripts/test_normal_traffic.py --loop 30    # repeat every 30 s
    python scripts/test_normal_traffic.py --n 500      # 500 flows
    python scripts/test_normal_traffic.py --out /tmp/normal.pcap
"""

import argparse
import random
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import IP, TCP, UDP, Raw, Ether, wrpcap
except ImportError:
    sys.exit("pip install scapy")

REPO_ROOT = Path(__file__).parent.parent
PCAP_DIR  = REPO_ROOT / "capture" / "pcap"

# ── IPs from seeded asset inventory ──────────────────────────────────────────
WORKSTATIONS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.50"]
SERVERS      = ["10.0.0.1", "10.0.0.2", "10.0.0.10"]
DNS_SERVER   = "10.0.0.53"
INTERNET     = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "151.101.1.140"]


# ── Packet helpers ────────────────────────────────────────────────────────────

def _tcp_flow(src, dst, sport, dport, t,
              orig_bytes, resp_bytes, duration):
    """Realistic TCP flow: SYN → SYN-ACK → ACK → data (possibly multiple) → FIN."""
    seq, rseq = random.randint(100000, 999999), random.randint(100000, 999999)
    pkts = []

    # Handshake
    pkts += [
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S",  seq=seq),
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=rseq, ack=seq+1),
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A",  seq=seq+1, ack=rseq+1),
    ]
    times = [t, t + 0.001, t + 0.002]

    # Originator data (split into MSS-ish chunks)
    sent = 0
    mss  = random.randint(512, 1448)
    while sent < orig_bytes:
        chunk = min(mss, orig_bytes - sent)
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(b"R" * chunk)
        pkts.append(p)
        times.append(t + 0.003 + sent / max(orig_bytes, 1) * duration * 0.3)
        sent += chunk

    # Responder data (split into chunks)
    sent = 0
    chunk_t = t + duration * 0.35
    while sent < resp_bytes:
        chunk = min(mss, resp_bytes - sent)
        p = Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA") / Raw(b"S" * chunk)
        pkts.append(p)
        times.append(chunk_t + sent / max(resp_bytes, 1) * duration * 0.5)
        sent += chunk

    # Teardown
    pkts += [
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA"),
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA"),
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A"),
    ]
    for _ in range(3):
        times.append(t + duration + random.uniform(0.001, 0.005))

    for p, ts in zip(pkts, times):
        p.time = ts
    return pkts


def _udp_flow(src, dst, sport, dport, t, req_size, resp_size):
    q = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(b"Q" * req_size)
    r = Ether() / IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / Raw(b"R" * resp_size)
    q.time, r.time = t, t + random.uniform(0.005, 0.050)
    return [q, r]


# ── Traffic profiles ──────────────────────────────────────────────────────────

def http_browsing(n, base_t):
    """HTTP web requests — asymmetric bytes, SF, TCP 80.
    Matches darknet 'BROWSING' normal class."""
    pkts = []
    t = base_t
    for _ in range(n):
        src   = random.choice(WORKSTATIONS)
        dst   = random.choice(SERVERS + INTERNET)
        sport = random.randint(32768, 60999)
        ob    = int(random.lognormvariate(5.5, 1.0))   # ~250 median
        rb    = int(random.lognormvariate(9.0, 1.5))   # ~8 000 median
        ob, rb = max(50, min(ob, 8000)), max(200, min(rb, 500000))
        dur   = random.expovariate(1 / 1.5)            # ~1.5 s median
        dur   = max(0.05, min(dur, 60.0))
        pkts.extend(_tcp_flow(src, dst, sport, 80, t, ob, rb, dur))
        t += random.expovariate(1 / 0.3)               # ~0.3 s between requests
    return pkts


def https_browsing(n, base_t):
    """HTTPS — similar to HTTP but on port 443, slightly larger payloads."""
    pkts = []
    t = base_t
    for _ in range(n):
        src   = random.choice(WORKSTATIONS)
        dst   = random.choice(SERVERS + INTERNET)
        sport = random.randint(32768, 60999)
        # HTTPS has TLS overhead so slightly larger request
        ob  = int(random.lognormvariate(6.0, 0.8))
        rb  = int(random.lognormvariate(9.5, 1.2))
        ob, rb = max(100, min(ob, 10000)), max(500, min(rb, 800000))
        dur = random.expovariate(1 / 2.0)
        dur = max(0.1, min(dur, 120.0))
        pkts.extend(_tcp_flow(src, dst, sport, 443, t, ob, rb, dur))
        t += random.expovariate(1 / 0.4)
    return pkts


def dns_queries(n, base_t):
    """DNS UDP queries + responses — short, small, normal baseline."""
    pkts = []
    t = base_t
    for _ in range(n):
        src   = random.choice(WORKSTATIONS)
        sport = random.randint(32768, 60999)
        qsize = random.randint(28, 64)     # typical DNS query
        rsize = random.randint(60, 512)    # typical DNS response
        pkts.extend(_udp_flow(src, DNS_SERVER, sport, 53, t, qsize, rsize))
        t += random.expovariate(1 / 0.1)
    return pkts


def email_traffic(n, base_t):
    """SMTP/IMAP — medium payloads, longer-lived connections.
    Matches darknet 'EMAIL' normal class."""
    pkts = []
    t = base_t
    ports = [25, 143, 465, 587, 993]
    for _ in range(n):
        src   = random.choice(WORKSTATIONS)
        dst   = random.choice(INTERNET)
        sport = random.randint(32768, 60999)
        port  = random.choice(ports)
        ob    = int(random.lognormvariate(7.5, 1.0))   # ~1800 median
        rb    = int(random.lognormvariate(7.0, 1.5))   # ~1100 median
        ob, rb = max(100, min(ob, 50000)), max(100, min(rb, 50000))
        dur   = random.uniform(0.5, 10.0)
        pkts.extend(_tcp_flow(src, dst, sport, port, t, ob, rb, dur))
        t += random.uniform(5.0, 30.0)
    return pkts


def streaming_video(n, base_t):
    """HTTP/HTTPS streaming — large resp, longer duration.
    Matches darknet 'AUDIO'/'VIDEO' normal class."""
    pkts = []
    t = base_t
    for _ in range(n):
        src   = random.choice(WORKSTATIONS)
        dst   = random.choice(INTERNET)
        sport = random.randint(32768, 60999)
        port  = random.choice([80, 443, 8080])
        ob    = int(random.lognormvariate(5.0, 0.5))     # small request
        rb    = int(random.lognormvariate(12.5, 1.0))    # ~270 KB median
        ob, rb = max(50, min(ob, 2000)), max(10000, min(rb, 5000000))
        dur   = random.uniform(5.0, 120.0)               # 5 s – 2 min segment
        pkts.extend(_tcp_flow(src, dst, sport, port, t, ob, rb, dur))
        t += random.uniform(1.0, 10.0)
    return pkts


def voip_calls(n, base_t):
    """VoIP RTP — small fixed-size UDP, consistent rate.
    Matches darknet 'VOIP' normal class."""
    pkts = []
    t = base_t
    for _ in range(n):
        src   = random.choice(WORKSTATIONS)
        dst   = random.choice(INTERNET)
        sport = random.randint(16384, 32767)
        dport = random.randint(16384, 32767)
        # RTP: 160-byte payloads at 50 pps for ~10 s = 500 packets
        n_pkts = random.randint(100, 600)
        pkt_interval = random.uniform(0.018, 0.022)  # ~20 ms
        for i in range(n_pkts):
            p_fwd = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(b"\x80" + b"\x00" * 159)
            p_fwd.time = t + i * pkt_interval
            pkts.append(p_fwd)
            if random.random() < 0.9:   # bidirectional
                p_rev = Ether() / IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / Raw(b"\x80" + b"\x00" * 159)
                p_rev.time = t + i * pkt_interval + 0.001
                pkts.append(p_rev)
        t += n_pkts * pkt_interval + random.uniform(2, 10)
    return pkts


def ftp_transfer(n, base_t):
    """FTP data transfer — medium to large files. Matches darknet 'FTP' class."""
    pkts = []
    t = base_t
    for _ in range(n):
        src   = random.choice(WORKSTATIONS)
        dst   = random.choice(INTERNET)
        sport = random.randint(32768, 60999)
        # FTP control
        pkts.extend(_tcp_flow(src, dst, sport, 21, t,
                               orig_bytes=random.randint(100, 500),
                               resp_bytes=random.randint(200, 1000),
                               duration=random.uniform(0.2, 2.0)))
        # FTP data
        file_size = int(random.lognormvariate(12, 1.5))   # ~160 KB median
        file_size = max(1000, min(file_size, 10_000_000))
        dur = file_size / random.uniform(50000, 500000)   # network speed
        pkts.extend(_tcp_flow(src, dst, sport + 1, 20, t + 0.5,
                               orig_bytes=random.randint(50, 200),
                               resp_bytes=file_size,
                               duration=dur))
        t += dur + random.uniform(5, 30)
    return pkts


# ── Main ──────────────────────────────────────────────────────────────────────

PROFILES = {
    "http":      (http_browsing,   "HTTP browsing"),
    "https":     (https_browsing,  "HTTPS browsing"),
    "dns":       (dns_queries,     "DNS queries"),
    "email":     (email_traffic,   "Email (SMTP/IMAP)"),
    "streaming": (streaming_video, "Video streaming"),
    "voip":      (voip_calls,      "VoIP RTP"),
    "ftp":       (ftp_transfer,    "FTP transfer"),
}


def generate(n_per_profile: int, out: Path) -> None:
    base = time.time()
    all_pkts = []
    offset = 0.0

    for key, (fn, label) in PROFILES.items():
        print(f"  Generating {label} ({n_per_profile} flows)...")
        pkts = fn(n_per_profile, base + offset)
        all_pkts.extend(pkts)
        offset += max(len(pkts) * 0.02, 5.0)

    all_pkts.sort(key=lambda p: float(p.time))
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), all_pkts)
    print(f"\n  {len(all_pkts):,} packets → {out}")
    print(f"  Drop into capture/pcap/ — Zeek will process automatically.")
    print(f"\n  Expected scores (darknet model, threshold=3.3174):")
    print(f"    In-distribution flows  → scores near 2–8  (near threshold)")
    print(f"    Out-of-distribution    → scores > 100     (flagged)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Normal traffic generator for Sentinel pipeline testing")
    ap.add_argument("--n",    type=int, default=30,  help="Flows per profile (default 30)")
    ap.add_argument("--out",  default=None,           help="Output PCAP path")
    ap.add_argument("--loop", type=int, default=0,    help="Repeat every N seconds")
    args = ap.parse_args()

    def _out():
        if args.out:
            return Path(args.out)
        ts = datetime.now().strftime("%H%M%S")
        return PCAP_DIR / f"normal-traffic-{ts}.pcap"

    if args.loop:
        print(f"Loop mode: every {args.loop}s  (Ctrl-C to stop)")
        while True:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Generating normal traffic...")
            generate(args.n, _out())
            time.sleep(args.loop)
    else:
        generate(args.n, _out())


if __name__ == "__main__":
    main()
