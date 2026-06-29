"""
Sentinel Alert Injector
=======================
Publishes synthetic alerts directly to the `anomaly-alerts` Kafka topic,
bypassing Zeek and the detection service.

The orchestrator consumes from that topic, creates an incident in Postgres
with status 'received', and it appears in the dashboard immediately.
From there you can click "Start Investigation" and watch the agents run live.

Usage:
    python demo/inject_alerts.py                      # injects all 6 demo alerts
    python demo/inject_alerts.py --scenario log4shell
    python demo/inject_alerts.py --scenario eternalblue
    python demo/inject_alerts.py --scenario ssh
    python demo/inject_alerts.py --scenario rdp
    python demo/inject_alerts.py --scenario exfiltration
    python demo/inject_alerts.py --scenario portscan
    python demo/inject_alerts.py --scenario all       # all 6 with 3 s gaps

Environment variables (override defaults):
    KAFKA_BOOTSTRAP=localhost:9092   (or kafka:9092 from inside Docker)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone

# ── Asset IPs (must match seed_demo.py) ──────────────────────────────────────
WEB_SERVER   = "10.10.1.10"
APP_SERVER   = "10.10.2.10"
FILE_SERVER  = "10.10.2.20"
ATTACKER_EXT = "185.220.101.50"
ATTACKER_2   = "203.0.113.99"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _alert(
    src_ip: str, dst_ip: str, dst_port: int, proto: str, service: str,
    anomaly_score: float, classification: str,
    orig_bytes: int, resp_bytes: int, duration: float,
) -> dict:
    alert_id = f"alert-{uuid.uuid4().hex[:12]}"
    return {
        "alert_id":      alert_id,
        "timestamp":     _ts(),
        "anomaly_score": anomaly_score,
        "classification": classification,
        "feature_vector": {
            "uid":        f"C{uuid.uuid4().hex[:12]}",
            "ts":         _ts(),
            "src_ip":     src_ip,
            "src_port":   40000 + (hash(src_ip) % 20000),
            "dst_ip":     dst_ip,
            "dst_port":   dst_port,
            "proto":      proto,
            "service":    service,
            "duration":   duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts":  orig_bytes // 600 + 1,
            "resp_pkts":  resp_bytes // 600 + 1,
            "conn_state": "RSTO",
        },
        "model_votes": [{"model_name": "injected", "score": anomaly_score,
                         "label": "anomaly", "confidence": anomaly_score}],
    }


# ── Scenario definitions ──────────────────────────────────────────────────────

SCENARIOS = {
    "log4shell": _alert(
        src_ip=ATTACKER_EXT, dst_ip=WEB_SERVER, dst_port=80,
        proto="tcp", service="http",
        anomaly_score=0.96, classification="log4shell_http_exploit",
        orig_bytes=3200, resp_bytes=1800, duration=0.3,
    ),
    "eternalblue": _alert(
        src_ip=ATTACKER_EXT, dst_ip=FILE_SERVER, dst_port=445,
        proto="tcp", service="smb",
        anomaly_score=0.94, classification="smb_exploit_eternalblue",
        orig_bytes=42000, resp_bytes=6500, duration=1.8,
    ),
    "ssh": _alert(
        src_ip=ATTACKER_2, dst_ip=WEB_SERVER, dst_port=22,
        proto="tcp", service="ssh",
        anomaly_score=0.88, classification="ssh_brute_force",
        orig_bytes=320, resp_bytes=280, duration=0.08,
    ),
    "rdp": _alert(
        src_ip=ATTACKER_EXT, dst_ip=FILE_SERVER, dst_port=3389,
        proto="tcp", service="rdp",
        anomaly_score=0.91, classification="rdp_brute_force_bluekeep",
        orig_bytes=480, resp_bytes=220, duration=0.12,
    ),
    "exfiltration": _alert(
        src_ip=FILE_SERVER, dst_ip=APP_SERVER, dst_port=3306,
        proto="tcp", service="mysql",
        anomaly_score=0.97, classification="data_exfiltration_lateral_movement",
        orig_bytes=1100, resp_bytes=28_000_000, duration=18.4,
    ),
    "portscan": _alert(
        src_ip=ATTACKER_EXT, dst_ip=WEB_SERVER, dst_port=443,
        proto="tcp", service="-",
        anomaly_score=0.82, classification="reconnaissance_port_scan",
        orig_bytes=60, resp_bytes=0, duration=0.0,
    ),
}

SCENARIO_LABELS = {
    "log4shell":    "Log4Shell RCE on web-server-01:80  (CVE-2021-44228)",
    "eternalblue":  "EternalBlue SMB on file-server-01:445  (CVE-2017-0144)",
    "ssh":          "SSH brute-force on web-server-01:22  (CVE-2023-38408)",
    "rdp":          "RDP BlueKeep on file-server-01:3389  (CVE-2019-0708)",
    "exfiltration": "Data exfiltration file-server→app-server:3306 (lateral movement)",
    "portscan":     "Port reconnaissance against web-server-01",
}


def publish(producer, topic: str, alert: dict) -> None:
    producer.produce(
        topic,
        key=alert["alert_id"].encode(),
        value=json.dumps(alert).encode("utf-8"),
    )
    producer.flush(timeout=10)


def main() -> None:
    import os
    bootstrap = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")

    parser = argparse.ArgumentParser(description="Inject demo alerts into Sentinel")
    parser.add_argument(
        "--scenario", default="all",
        choices=list(SCENARIOS) + ["all"],
        help="Which attack scenario to inject (default: all)",
    )
    parser.add_argument("--bootstrap", default=bootstrap,
                        help=f"Kafka bootstrap address (default: {bootstrap})")
    parser.add_argument("--topic", default="anomaly-alerts")
    args = parser.parse_args()

    try:
        from confluent_kafka import Producer
    except ImportError:
        print("ERROR: pip install confluent-kafka", file=sys.stderr)
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
        print(f"\nERROR: Cannot reach Kafka at {args.bootstrap}\n  {exc}", file=sys.stderr)
        print("\nMake sure the stack is running:\n  docker-compose up -d kafka postgres redis orchestrator dashboard-backend gateway",
              file=sys.stderr)
        sys.exit(1)

    if args.scenario == "all":
        print(f"Injecting {len(SCENARIOS)} alerts → {args.topic}\n")
        for name, alert in SCENARIOS.items():
            print(f"  [{alert['alert_id']}]  {SCENARIO_LABELS[name]}")
            publish(producer, args.topic, alert)
            time.sleep(3)   # stagger so the orchestrator processes them one at a time
        print(f"\nAll {len(SCENARIOS)} alerts injected.")
    else:
        alert = SCENARIOS[args.scenario]
        print(f"Injecting: {SCENARIO_LABELS[args.scenario]}")
        print(f"  alert_id = {alert['alert_id']}")
        publish(producer, args.topic, alert)
        print("Done — check the dashboard (Alert Feed → Active tab).")

    print("\nNext steps:")
    print("  1. Open the dashboard and go to Alert Feed → Active tab")
    print("  2. Click an alert to open AlertDetail")
    print("  3. Click 'Start Investigation' to trigger the agents")
    print("  4. Watch the Reasoning Traces panel update in real time")
    print("  5. When plans appear, review them in Plan Review")


if __name__ == "__main__":
    main()
