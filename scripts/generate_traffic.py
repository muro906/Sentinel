#!/usr/bin/env python3
"""
Sentinel Traffic Generator
==========================
Generates PCAPs with realistic benign and attack flows targeting seeded asset
IPs, then drops them into capture/pcap/ for Zeek to pick up automatically.

No root required — Scapy writes PCAPs directly without injecting real packets.

Covers all three training distributions:
  UNSW-NB15  → recon, DoS, fuzzing, exploits, backdoors
  CIC-IDS2018 → web attacks, brute force, botnet C2, SQL injection, XSS
  CIC-Darknet → Tor-like tunnels, VPN-like flows, obfuscated traffic

Usage:
    pip install scapy
    python scripts/generate_traffic.py                  # all scenarios once
    python scripts/generate_traffic.py --loop 60        # repeat every 60s
    python scripts/generate_traffic.py --type unsw      # UNSW-only
    python scripts/generate_traffic.py --type ids2018   # IDS2018-only
    python scripts/generate_traffic.py --type darknet   # Darknet-only
    python scripts/generate_traffic.py --type benign    # benign baseline only
    python scripts/generate_traffic.py --out /tmp/t.pcap
"""

import argparse
import random
import sys
import time
from pathlib import Path
from datetime import datetime

try:
    from scapy.all import IP, TCP, UDP, Raw, wrpcap, Ether
except ImportError:
    sys.exit("scapy not installed — run: pip install scapy")

REPO_ROOT = Path(__file__).parent.parent
PCAP_DIR  = REPO_ROOT / "capture" / "pcap"

# ── Asset IPs (matches database/seed/seed_assets.py) ──────────────────────────
DMZ_WEB  = "10.0.0.1"       # web-prod-01       criticality 2
DMZ_WEB2 = "10.0.0.2"       # web-prod-02       criticality 2
DMZ_API  = "10.0.0.10"      # api-gateway       criticality 1
DMZ_DNS  = "10.0.0.53"      # dns-resolver      criticality 2
INT_WS1  = "192.168.1.10"   # dev-workstation-01
INT_WS2  = "192.168.1.11"   # dev-workstation-02
INT_WS3  = "192.168.1.12"   # dev-workstation-03
INT_DB   = "192.168.1.100"  # db-internal       criticality 2
EXT_ATK1 = "172.16.0.1"     # external attacker
EXT_ATK2 = "172.16.0.50"    # second attacker
EXT_C2   = "172.16.99.1"    # C2 / exfil server
EXT_VPN  = "172.16.200.1"   # simulated VPN/Tor exit


# ── Packet helpers ────────────────────────────────────────────────────────────

def _syn(src, dst, sport, dport, ts):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
    p.time = ts
    return p

def _rst(src, dst, sport, dport, ts):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="R")
    p.time = ts
    return p

def _flow(src, dst, sport, dport, ts,
          payload=512, resp=1024, dur=0.5):
    """Complete TCP flow (SF conn_state in Zeek)."""
    seq, rseq = random.randint(1000, 99999), random.randint(1000, 99999)
    pkts = [
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S",  seq=seq),
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=rseq, ack=seq+1),
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A",  seq=seq+1, ack=rseq+1),
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq+1) / Raw(b"A"*payload),
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=rseq+1) / Raw(b"B"*resp),
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA"),
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA"),
    ]
    for p, t in zip(pkts, [ts, ts+.001, ts+.002, ts+.01, ts+.05, ts+dur, ts+dur+.001]):
        p.time = t
    return pkts

def _udp(src, dst, sport, dport, ts, size=64):
    q = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(b"Q"*size)
    r = Ether() / IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / Raw(b"R"*size)
    q.time, r.time = ts, ts + .005
    return [q, r]


# ── UNSW-NB15 style attacks ───────────────────────────────────────────────────
# Patterns: Reconnaissance, DoS, Exploits, Backdoors, Fuzzers, Analysis

def unsw_recon(base):
    """Fast port sweep — many S0/REJ states, short duration, low bytes."""
    print("  [UNSW] Reconnaissance: port sweep on api-gateway")
    pkts, t = [], base
    for port in range(1, 1025, 8):
        sp = random.randint(40000, 60000)
        pkts.append(_syn(EXT_ATK1, DMZ_API, sp, port, t))
        if random.random() < 0.35:
            pkts.append(_rst(DMZ_API, EXT_ATK1, port, sp, t + .001))
        t += .015
    return pkts

def unsw_dos(base):
    """SYN flood — massive packet rate, all S0."""
    print("  [UNSW] DoS: SYN flood on web-prod-01:80")
    pkts, t = [], base
    for _ in range(600):
        pkts.append(_syn(EXT_ATK2, DMZ_WEB, random.randint(1024, 65535), 80, t))
        t += .0015
    return pkts

def unsw_exploit(base):
    """Exploit attempt — established connection to unusual high port."""
    print("  [UNSW] Exploit: shell/backdoor connection attempt")
    pkts, t = [], base
    for port in [4444, 5555, 31337, 8888, 1337]:
        sp = random.randint(40000, 60000)
        pkts.extend(_flow(EXT_ATK1, DMZ_WEB, sp, port, t,
                          payload=256, resp=512, dur=random.uniform(1, 5)))
        t += random.uniform(2, 6)
    return pkts

def unsw_fuzzer(base):
    """Fuzzing — rapid connections to random ports with random-sized payloads."""
    print("  [UNSW] Fuzzer: random port/payload probing")
    pkts, t = [], base
    for _ in range(80):
        port = random.randint(1, 65535)
        sp   = random.randint(40000, 60000)
        size = random.randint(1, 2000)
        pkts.extend(_flow(EXT_ATK1, DMZ_API, sp, port, t,
                          payload=size, resp=random.randint(0, 100), dur=0.05))
        t += .1
    return pkts

def unsw_backdoor(base):
    """Backdoor/C2 beaconing — periodic short connections on non-standard ports."""
    print("  [UNSW] Backdoor: C2 beaconing from compromised internal host")
    pkts, t = [], base
    for _ in range(20):
        sp = random.randint(40000, 60000)
        pkts.extend(_flow(INT_WS2, EXT_C2, sp, 8443, t,
                          payload=64, resp=128, dur=0.2))
        t += random.uniform(5, 15)   # periodic beacon interval
    return pkts


# ── CIC-IDS2018 style attacks ─────────────────────────────────────────────────
# Patterns: DDoS, Brute Force, Web Attacks (SQL/XSS/Injection), Infiltration, Botnet

def ids_ddos(base):
    """HTTP flood DDoS — high-rate GET requests (application layer)."""
    print("  [IDS2018] DDoS: HTTP GET flood on web-prod-01")
    pkts, t = [], base
    for _ in range(400):
        src  = f"172.16.{random.randint(1,254)}.{random.randint(1,254)}"
        sp   = random.randint(1024, 65535)
        http = b"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"
        pkts.extend(_flow(src, DMZ_WEB, sp, 80, t,
                          payload=len(http), resp=200, dur=0.05))
        t += .005
    return pkts

def ids_brute_ssh(base):
    """SSH brute force — rapid failed auth attempts (S0/REJ on port 22)."""
    print("  [IDS2018] Brute Force: SSH password spray on web-prod-01")
    pkts, t = [], base
    for _ in range(150):
        sp = random.randint(40000, 60000)
        # Attempt: partial handshake then reset (failed auth)
        pkts.append(_syn(EXT_ATK1, DMZ_WEB, sp, 22, t))
        pkts.extend(_flow(EXT_ATK1, DMZ_WEB, sp, 22, t + .001,
                          payload=48, resp=32, dur=0.3))
        t += .4
    return pkts

def ids_web_attack(base):
    """Web attack — SQL injection / XSS payloads in HTTP (long URI, abnormal sizes)."""
    print("  [IDS2018] Web Attack: SQL injection probes on api-gateway")
    pkts, t = [], base
    # Abnormally large requests (injection payloads) with small responses
    for _ in range(60):
        sp = random.randint(40000, 60000)
        pkts.extend(_flow(EXT_ATK1, DMZ_API, sp, 80, t,
                          payload=random.randint(1500, 4000),
                          resp=random.randint(50, 200),
                          dur=0.1))
        t += .3
    return pkts

def ids_botnet(base):
    """Botnet C2 — multiple infected internal hosts calling home periodically."""
    print("  [IDS2018] Botnet: multiple hosts contacting C2 (HTTP/IRC-like)")
    pkts, t = [], base
    bots = [INT_WS1, INT_WS2, INT_WS3]
    for _ in range(30):
        src = random.choice(bots)
        sp  = random.randint(40000, 60000)
        # C2 channels often use port 80/443 to blend with traffic but have
        # characteristic small/fixed payload sizes
        pkts.extend(_flow(src, EXT_C2, sp, 80, t,
                          payload=random.choice([64, 128, 256]),
                          resp=random.choice([64, 128]),
                          dur=random.uniform(0.1, 0.5)))
        t += random.uniform(10, 30)
    return pkts

def ids_infiltration(base):
    """Infiltration — internal data staging and slow exfiltration."""
    print("  [IDS2018] Infiltration: slow data exfil from internal workstation")
    pkts, t = [], base
    for _ in range(15):
        sp = random.randint(40000, 60000)
        # Large outbound, tiny inbound — classic exfil pattern
        pkts.extend(_flow(INT_WS3, EXT_C2, sp, 443, t,
                          payload=random.randint(5000, 15000),
                          resp=random.randint(20, 100),
                          dur=random.uniform(10, 40)))
        t += random.uniform(30, 90)
    return pkts


# ── CIC-Darknet2020 style traffic ─────────────────────────────────────────────
# Patterns: Tor, VPN, I2P — encrypted, tunnelled, specific port/size distributions

def darknet_tor(base):
    """Tor-like traffic — connections to port 9001/9030 (Tor relay ports),
    medium-sized symmetric flows, long duration."""
    print("  [Darknet] Tor: encrypted relay traffic from workstation")
    pkts, t = [], base
    tor_ports = [9001, 9030, 9050, 9150, 443]
    for _ in range(25):
        sp   = random.randint(40000, 60000)
        port = random.choice(tor_ports)
        # Tor has characteristic nearly-equal orig/resp byte ratios for relay traffic
        size = random.randint(500, 1500)
        pkts.extend(_flow(INT_WS1, EXT_VPN, sp, port, t,
                          payload=size,
                          resp=int(size * random.uniform(0.8, 1.2)),
                          dur=random.uniform(30, 300)))
        t += random.uniform(5, 20)
    return pkts

def darknet_vpn(base):
    """VPN-like traffic — UDP on non-standard ports, fixed MTU-sized datagrams,
    high sustained rate (characteristic of OpenVPN/WireGuard)."""
    print("  [Darknet] VPN: sustained UDP tunnel from workstation to external")
    pkts, t = [], base
    vpn_ports = [1194, 51820, 500, 4500, 1723]
    for _ in range(200):
        sp   = random.randint(40000, 60000)
        port = random.choice(vpn_ports)
        # WireGuard/OpenVPN datagrams are close to MTU (1400 bytes)
        pkts.extend(_udp(INT_WS2, EXT_VPN, sp, port, t,
                         size=random.randint(1300, 1450)))
        t += .05   # ~20 pps sustained
    return pkts

def darknet_i2p(base):
    """I2P-like traffic — UDP flood to many different IPs/ports (garlic routing),
    very short high-rate bursts."""
    print("  [Darknet] I2P: garlic-routed UDP to multiple endpoints")
    pkts, t = [], base
    for _ in range(150):
        dst  = f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
        sp   = random.randint(40000, 60000)
        port = random.randint(10000, 60000)
        pkts.extend(_udp(INT_WS3, dst, sp, port, t, size=random.randint(200, 900)))
        t += .02
    return pkts


# ── Benign baseline ────────────────────────────────────────────────────────────

def benign(base):
    """Normal workstation traffic — HTTP, HTTPS, DNS, API calls."""
    print("  [Benign] Normal web/DNS/API traffic from internal workstations")
    pkts, t = [], base
    # HTTP/HTTPS browsing
    for _ in range(80):
        src  = random.choice([INT_WS1, INT_WS2, INT_WS3])
        dst  = random.choice([DMZ_WEB, DMZ_WEB2, DMZ_API])
        port = random.choice([80, 443])
        sp   = random.randint(40000, 60000)
        pkts.extend(_flow(src, dst, sp, port, t,
                          payload=random.randint(200, 800),
                          resp=random.randint(500, 8000),
                          dur=random.uniform(0.1, 2.0)))
        t += random.uniform(0.1, 0.8)
    # DNS
    for _ in range(40):
        src = random.choice([INT_WS1, INT_WS2, INT_WS3])
        pkts.extend(_udp(src, DMZ_DNS, random.randint(40000, 60000), 53, t, size=48))
        t += random.uniform(0.05, 0.3)
    return pkts


# ── Scenario groups ────────────────────────────────────────────────────────────

GROUPS = {
    "unsw": [
        ("recon",    unsw_recon),
        ("dos",      unsw_dos),
        ("exploit",  unsw_exploit),
        ("fuzzer",   unsw_fuzzer),
        ("backdoor", unsw_backdoor),
    ],
    "ids2018": [
        ("ddos",          ids_ddos),
        ("brute_ssh",     ids_brute_ssh),
        ("web_attack",    ids_web_attack),
        ("botnet",        ids_botnet),
        ("infiltration",  ids_infiltration),
    ],
    "darknet": [
        ("tor",  darknet_tor),
        ("vpn",  darknet_vpn),
        ("i2p",  darknet_i2p),
    ],
    "benign": [
        ("benign", benign),
    ],
}


def run(out_path: Path, traffic_type: str = "all") -> None:
    now  = time.time()
    all_pkts = []
    offset   = 0.0

    groups = GROUPS if traffic_type == "all" else {traffic_type: GROUPS[traffic_type]}

    for group_name, scenarios in groups.items():
        print(f"\n── {group_name.upper()} ──")
        for name, fn in scenarios:
            pkts = fn(now + offset)
            all_pkts.extend(pkts)
            offset += max(len(pkts) * 0.05, 10)

    all_pkts.sort(key=lambda p: float(p.time))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_path), all_pkts)
    print(f"\n  {len(all_pkts)} packets → {out_path}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out",  default=None)
    ap.add_argument("--type", choices=list(GROUPS) + ["all"], default="all",
                    help="Traffic type: all | unsw | ids2018 | darknet | benign")
    ap.add_argument("--loop", type=int, default=0,
                    help="Repeat every N seconds (0 = run once)")
    args = ap.parse_args()

    def _out():
        if args.out:
            return Path(args.out)
        ts = datetime.now().strftime("%H%M%S")
        tag = args.type
        return PCAP_DIR / f"sentinel-{tag}-{ts}.pcap"

    if args.loop:
        print(f"Loop mode: every {args.loop}s  (Ctrl-C to stop)")
        while True:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Generating {args.type}...")
            run(_out(), args.type)
            time.sleep(args.loop)
    else:
        run(_out(), args.type)


if __name__ == "__main__":
    main()
