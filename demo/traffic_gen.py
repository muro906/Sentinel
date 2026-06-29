"""
Sentinel Demo Traffic Generator
================================
Injects synthetic network flow records directly into the Kafka `network-features`
topic, bypassing Zeek.  zeek_parser.py accepts both Zeek-native and already-
normalised field names, so these records flow straight through the detection
service exactly like real traffic.

Usage:
    # From project root (Kafka must be running):
    pip install confluent-kafka
    python demo/traffic_gen.py --scenario all          # run every scenario in sequence
    python demo/traffic_gen.py --scenario normal       # background normal traffic only
    python demo/traffic_gen.py --scenario log4shell    # single Log4Shell burst
    python demo/traffic_gen.py --scenario eternalblue  # EternalBlue SMB burst
    python demo/traffic_gen.py --scenario rdp          # RDP brute-force burst
    python demo/traffic_gen.py --scenario ssh          # SSH brute-force burst
    python demo/traffic_gen.py --scenario portscan     # Port reconnaissance
    python demo/traffic_gen.py --scenario exfiltration # Data exfiltration burst
    python demo/traffic_gen.py --scenario mixed        # interleaved normal + all attacks

    # Connect to Kafka inside Docker:
    KAFKA_BOOTSTRAP=localhost:9092 python demo/traffic_gen.py --scenario all
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Iterator

# ── Target asset IPs (must match seed_demo.py) ───────────────────────────────
WEB_SERVER   = "10.10.1.10"
APP_SERVER   = "10.10.2.10"
FILE_SERVER  = "10.10.2.20"
WORKSTATION  = "10.10.3.100"
ATTACKER_EXT = "185.220.101.50"   # external threat actor
ATTACKER_2   = "203.0.113.99"     # secondary external actor
INTERNAL_PIVOT = FILE_SERVER       # lateral movement source


# ── Record builder ────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def _uid() -> str:
    return f"C{uuid.uuid4().hex[:12]}"

def _record(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    proto: str, service: str, duration: float,
    orig_bytes: int, resp_bytes: int, orig_pkts: int, resp_pkts: int,
    conn_state: str, classification: str = "network_anomaly",
    normal: bool = False,
) -> dict:
    return {
        "uid":          _uid(),
        "ts":           _ts(),
        "src_ip":       src_ip,
        "src_port":     src_port,
        "dst_ip":       dst_ip,
        "dst_port":     dst_port,
        "proto":        proto,
        "service":      service,
        "duration":     duration,
        "orig_bytes":   orig_bytes,
        "resp_bytes":   resp_bytes,
        "orig_pkts":    orig_pkts,
        "resp_pkts":    resp_pkts,
        "conn_state":   conn_state,
        "classification": "normal" if normal else classification,
    }


def _rport() -> int:
    return random.randint(49152, 65535)


# ── Normal traffic patterns ───────────────────────────────────────────────────

def gen_normal(n: int = 20) -> list[dict]:
    """Generates benign-looking background traffic."""
    records = []
    for _ in range(n):
        kind = random.choice(["web", "ssh_admin", "dns", "db_query"])

        if kind == "web":
            records.append(_record(
                WORKSTATION, _rport(), WEB_SERVER, 80, "tcp", "http",
                duration=round(random.uniform(0.05, 0.4), 3),
                orig_bytes=random.randint(200, 800),
                resp_bytes=random.randint(1000, 12000),
                orig_pkts=random.randint(4, 10), resp_pkts=random.randint(6, 20),
                conn_state="SF", normal=True,
            ))
        elif kind == "ssh_admin":
            records.append(_record(
                WORKSTATION, _rport(), WEB_SERVER, 22, "tcp", "ssh",
                duration=round(random.uniform(30, 180), 1),
                orig_bytes=random.randint(2000, 8000),
                resp_bytes=random.randint(3000, 10000),
                orig_pkts=random.randint(50, 200), resp_pkts=random.randint(60, 220),
                conn_state="SF", normal=True,
            ))
        elif kind == "dns":
            records.append(_record(
                WORKSTATION, _rport(), "8.8.8.8", 53, "udp", "dns",
                duration=round(random.uniform(0.001, 0.05), 4),
                orig_bytes=random.randint(50, 100),
                resp_bytes=random.randint(80, 300),
                orig_pkts=1, resp_pkts=1,
                conn_state="SF", normal=True,
            ))
        else:  # db_query
            records.append(_record(
                APP_SERVER, _rport(), APP_SERVER, 3306, "tcp", "mysql",
                duration=round(random.uniform(0.001, 0.02), 4),
                orig_bytes=random.randint(100, 500),
                resp_bytes=random.randint(200, 2000),
                orig_pkts=random.randint(2, 6), resp_pkts=random.randint(3, 8),
                conn_state="SF", normal=True,
            ))
    return records


# ── Attack scenarios ──────────────────────────────────────────────────────────

def gen_log4shell(count: int = 8) -> list[dict]:
    """
    Log4Shell (CVE-2021-44228) — crafted HTTP POST/GET with JNDI injection
    in User-Agent or X-Api-Version headers targeting the web server.
    Characteristic: large orig_bytes (payload), SF or RSTO state.
    """
    records = []
    for _ in range(count):
        records.append(_record(
            ATTACKER_EXT, _rport(), WEB_SERVER, 80, "tcp", "http",
            duration=round(random.uniform(0.1, 0.8), 3),
            orig_bytes=random.randint(1200, 4000),   # large — JNDI payload in headers
            resp_bytes=random.randint(500, 3000),
            orig_pkts=random.randint(5, 12), resp_pkts=random.randint(4, 10),
            conn_state=random.choice(["SF", "RSTO"]),
            classification="log4shell_http_exploit",
        ))
    return records


def gen_eternalblue(count: int = 5) -> list[dict]:
    """
    EternalBlue (CVE-2017-0144) — malformed SMBv1 requests to port 445.
    Characteristic: large orig_bytes, RSTO or S1 state (server reset after exploit).
    """
    records = []
    for _ in range(count):
        records.append(_record(
            ATTACKER_EXT, _rport(), FILE_SERVER, 445, "tcp", "smb",
            duration=round(random.uniform(0.5, 3.0), 3),
            orig_bytes=random.randint(8000, 65000),   # large SMB negotiate + exploit payload
            resp_bytes=random.randint(1000, 8000),
            orig_pkts=random.randint(15, 50), resp_pkts=random.randint(8, 25),
            conn_state=random.choice(["RSTO", "S1", "RSTOS0"]),
            classification="smb_exploit_eternalblue",
        ))
    return records


def gen_rdp_bruteforce(count: int = 30) -> list[dict]:
    """
    RDP brute-force / BlueKeep probe (CVE-2019-0708).
    Characteristic: many short-lived connections, almost all RSTO.
    """
    records = []
    for _ in range(count):
        records.append(_record(
            ATTACKER_EXT, _rport(), FILE_SERVER, 3389, "tcp", "rdp",
            duration=round(random.uniform(0.05, 0.3), 3),
            orig_bytes=random.randint(200, 600),
            resp_bytes=random.randint(100, 400),
            orig_pkts=random.randint(3, 8), resp_pkts=random.randint(2, 6),
            conn_state="RSTO",
            classification="rdp_brute_force_bluekeep",
        ))
    return records


def gen_ssh_bruteforce(count: int = 40) -> list[dict]:
    """
    SSH brute-force — rapid authentication attempts against port 22.
    Characteristic: very many fast connections, all RSTO (auth failure).
    """
    records = []
    for _ in range(count):
        records.append(_record(
            ATTACKER_2, _rport(), WEB_SERVER, 22, "tcp", "ssh",
            duration=round(random.uniform(0.02, 0.15), 3),
            orig_bytes=random.randint(150, 400),
            resp_bytes=random.randint(100, 300),
            orig_pkts=random.randint(3, 6), resp_pkts=random.randint(2, 5),
            conn_state="RSTO",
            classification="ssh_brute_force",
        ))
    return records


def gen_portscan(count: int = 50) -> list[dict]:
    """
    Port scan — rapid REJ responses across a range of ports.
    Characteristic: many connections to random ports, all REJ or RSTOS0.
    """
    records = []
    ports = random.sample(range(1, 10000), count)
    for port in ports:
        records.append(_record(
            ATTACKER_EXT, _rport(), WEB_SERVER, port, "tcp", "-",
            duration=0.0,
            orig_bytes=random.randint(40, 80),
            resp_bytes=0,
            orig_pkts=1, resp_pkts=0,
            conn_state=random.choice(["REJ", "RSTOS0"]),
            classification="reconnaissance_port_scan",
        ))
    return records


def gen_exfiltration(count: int = 6) -> list[dict]:
    """
    Data exfiltration from MySQL DB server — lateral movement from
    the file server to the app server's database, extracting large datasets.
    Characteristic: very high resp_bytes (database dump), internal src.
    """
    records = []
    for _ in range(count):
        records.append(_record(
            INTERNAL_PIVOT, _rport(), APP_SERVER, 3306, "tcp", "mysql",
            duration=round(random.uniform(5.0, 30.0), 1),
            orig_bytes=random.randint(500, 2000),
            resp_bytes=random.randint(5_000_000, 50_000_000),  # 5–50 MB data dump
            orig_pkts=random.randint(20, 80), resp_pkts=random.randint(4000, 40000),
            conn_state="SF",
            classification="data_exfiltration_lateral_movement",
        ))
    return records


# ── Scenario dispatcher ───────────────────────────────────────────────────────

SCENARIOS: dict[str, callable] = {
    "normal":       lambda: gen_normal(30),
    "log4shell":    gen_log4shell,
    "eternalblue":  gen_eternalblue,
    "rdp":          gen_rdp_bruteforce,
    "ssh":          gen_ssh_bruteforce,
    "portscan":     gen_portscan,
    "exfiltration": gen_exfiltration,
}

DEMO_SEQUENCE = [
    # (scenario, pause_seconds_after, description)
    ("normal",       5,  "Baseline: normal web/SSH/DNS/DB traffic"),
    ("log4shell",    8,  "ATTACK: Log4Shell HTTP exploit on web-server-01"),
    ("normal",       3,  "Normal traffic continues between attacks…"),
    ("portscan",     6,  "ATTACK: Reconnaissance port scan of web-server-01"),
    ("eternalblue",  8,  "ATTACK: EternalBlue SMB exploit on file-server-01"),
    ("ssh",          6,  "ATTACK: SSH brute-force against web-server-01"),
    ("rdp",          6,  "ATTACK: RDP brute-force / BlueKeep probe on file-server-01"),
    ("normal",       3,  "Normal traffic after RDP attack…"),
    ("exfiltration", 8,  "ATTACK: Data exfiltration via lateral movement (SMB→MySQL)"),
    ("normal",       5,  "Final normal baseline"),
]


def run_scenario(producer, topic: str, name: str, delay: float = 0.05) -> int:
    fn = SCENARIOS[name]
    records = fn()
    for r in records:
        producer.produce(topic, value=json.dumps(r).encode("utf-8"))
        producer.poll(0)
        time.sleep(delay)
    producer.flush(timeout=10)
    return len(records)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel demo traffic generator")
    parser.add_argument("--scenario", default="all",
                        choices=list(SCENARIOS) + ["all", "mixed"],
                        help="Which scenario to run (default: all = scripted demo sequence)")
    parser.add_argument("--bootstrap", default="localhost:9092",
                        help="Kafka bootstrap servers (default: localhost:9092)")
    parser.add_argument("--topic", default="network-features",
                        help="Target Kafka topic (default: network-features)")
    parser.add_argument("--delay", type=float, default=0.05,
                        help="Seconds between records (default: 0.05)")
    args = parser.parse_args()

    try:
        from confluent_kafka import Producer
    except ImportError:
        print("ERROR: confluent-kafka not installed.  pip install confluent-kafka", file=sys.stderr)
        sys.exit(1)

    producer = Producer({
        "bootstrap.servers": args.bootstrap,
        "socket.timeout.ms": 5000,
    })

    # Quick connectivity check
    try:
        from confluent_kafka.admin import AdminClient
        AdminClient({"bootstrap.servers": args.bootstrap,
                     "socket.timeout.ms": 4000}).list_topics(timeout=5)
    except Exception as exc:
        print(f"ERROR: Cannot reach Kafka at {args.bootstrap}: {exc}", file=sys.stderr)
        print("Is the stack running?  docker-compose up -d", file=sys.stderr)
        sys.exit(1)

    if args.scenario == "all":
        print("=== Sentinel Demo — scripted attack sequence ===\n")
        for name, pause, description in DEMO_SEQUENCE:
            print(f"[{name.upper():15s}] {description}")
            n = run_scenario(producer, args.topic, name, args.delay)
            print(f"             → {n} records published.  Pausing {pause}s…\n")
            time.sleep(pause)
        print("Demo sequence complete.")

    elif args.scenario == "mixed":
        print("Running continuous mixed traffic (Ctrl-C to stop)…")
        i = 0
        try:
            while True:
                scen = random.choice(list(SCENARIOS.keys()))
                n = run_scenario(producer, args.topic, scen, args.delay)
                print(f"  [{scen}] {n} records")
                time.sleep(random.uniform(1, 4))
                i += 1
        except KeyboardInterrupt:
            print(f"\nStopped after {i} bursts.")

    else:
        print(f"Running scenario: {args.scenario}")
        n = run_scenario(producer, args.topic, args.scenario, args.delay)
        print(f"Published {n} records to {args.topic}.")


if __name__ == "__main__":
    main()
