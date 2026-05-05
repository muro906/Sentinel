"""
Alert Simulator
================
Publishes synthetic anomaly alerts to the 'anomaly-alerts' Kafka topic,
simulating what the Hybrid Detection Layer (Layer 2) would produce.

This allows testing the full agentic pipeline without Layer 2 being built.
Generates realistic alerts matching the sample.pcap traffic patterns:
- Port scans from 172.16.0.55 targeting 10.0.0.1
- Data exfiltration flows
- DNS tunneling attempts

Usage:
    python scripts/simulate_alerts.py                  # send 1 port_scan alert
    python scripts/simulate_alerts.py --type exfil     # send 1 exfiltration alert
    python scripts/simulate_alerts.py --burst 10       # send 10 random alerts
"""

import argparse
import json
import os
import time
import uuid
from datetime import datetime, timezone

from confluent_kafka import Producer

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC = "anomaly-alerts"


def make_port_scan_alert() -> dict:
    return {
        "alert_id": f"alert-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "anomaly_score": 0.91,
        "classification": "port_scan",
        "feature_vector": {
            "uid": f"C{uuid.uuid4().hex[:16]}",
            "ts": str(time.time()),
            "src_ip": "172.16.0.55",
            "src_port": 54321,
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "proto": "tcp",
            "service": None,
            "duration": 0.001,
            "orig_bytes": 64,
            "resp_bytes": 0,
            "orig_pkts": 1,
            "resp_pkts": 0,
            "bytes_ratio": 0.0,
            "pkts_ratio": 0.0,
            "avg_pkt_size_orig": 64.0,
            "avg_pkt_size_resp": 0.0,
            "missed_bytes": 0,
            "conn_state": "S0",
            "ssl_version": None,
            "ssl_cipher": None,
            "is_encrypted": 0,
            "is_dns": 0,
            "dns_query": None,
        },
        "model_votes": [
            {"model_name": "autoencoder", "score": 0.89, "label": "port_scan", "confidence": 0.85},
            {"model_name": "random_forest", "score": 0.93, "label": "port_scan", "confidence": 0.92},
        ],
    }


def make_exfiltration_alert() -> dict:
    return {
        "alert_id": f"alert-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "anomaly_score": 0.85,
        "classification": "data_exfiltration",
        "feature_vector": {
            "uid": f"C{uuid.uuid4().hex[:16]}",
            "ts": str(time.time()),
            "src_ip": "192.168.1.12",
            "src_port": 49152,
            "dst_ip": "203.0.113.50",
            "dst_port": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 125.5,
            "orig_bytes": 65536,
            "resp_bytes": 2048,
            "orig_pkts": 450,
            "resp_pkts": 30,
            "bytes_ratio": 32.0,
            "pkts_ratio": 15.0,
            "avg_pkt_size_orig": 145.6,
            "avg_pkt_size_resp": 68.3,
            "missed_bytes": 0,
            "conn_state": "SF",
            "ssl_version": "TLSv12",
            "ssl_cipher": "TLS_AES_256_GCM_SHA384",
            "is_encrypted": 1,
            "is_dns": 0,
            "dns_query": None,
        },
        "model_votes": [
            {"model_name": "autoencoder", "score": 0.82, "label": "data_exfiltration", "confidence": 0.78},
            {"model_name": "random_forest", "score": 0.88, "label": "data_exfiltration", "confidence": 0.85},
        ],
    }


def make_dns_tunneling_alert() -> dict:
    return {
        "alert_id": f"alert-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "anomaly_score": 0.78,
        "classification": "dns_tunneling",
        "feature_vector": {
            "uid": f"C{uuid.uuid4().hex[:16]}",
            "ts": str(time.time()),
            "src_ip": "192.168.1.50",
            "src_port": 52000,
            "dst_ip": "10.0.0.53",
            "dst_port": 53,
            "proto": "udp",
            "service": "dns",
            "duration": 0.05,
            "orig_bytes": 512,
            "resp_bytes": 256,
            "orig_pkts": 4,
            "resp_pkts": 4,
            "bytes_ratio": 2.0,
            "pkts_ratio": 1.0,
            "avg_pkt_size_orig": 128.0,
            "avg_pkt_size_resp": 64.0,
            "missed_bytes": 0,
            "conn_state": "SF",
            "ssl_version": None,
            "ssl_cipher": None,
            "is_encrypted": 0,
            "is_dns": 1,
            "dns_query": "aGVsbG8gd29ybGQ.data.evil-c2.example.com",
            "dns_qtype": 16,
            "dns_rcode": 0,
            "dns_answers": 1,
        },
        "model_votes": [
            {"model_name": "autoencoder", "score": 0.75, "label": "dns_tunneling", "confidence": 0.72},
            {"model_name": "random_forest", "score": 0.81, "label": "dns_tunneling", "confidence": 0.80},
        ],
    }


ALERT_FACTORIES = {
    "port_scan": make_port_scan_alert,
    "exfil": make_exfiltration_alert,
    "dns": make_dns_tunneling_alert,
}


def main():
    parser = argparse.ArgumentParser(description="Simulate anomaly alerts")
    parser.add_argument("--type", choices=["port_scan", "exfil", "dns"], default="port_scan")
    parser.add_argument("--burst", type=int, default=1, help="Number of alerts to send")
    args = parser.parse_args()

    producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP})

    for i in range(args.burst):
        alert_type = args.type
        if args.burst > 1:
            # Rotate through types for burst mode
            alert_type = list(ALERT_FACTORIES.keys())[i % len(ALERT_FACTORIES)]

        alert = ALERT_FACTORIES[alert_type]()
        key = alert["alert_id"].encode("utf-8")
        value = json.dumps(alert).encode("utf-8")

        producer.produce(TOPIC, key=key, value=value)
        print(f"[{i+1}/{args.burst}] Sent {alert['classification']} alert: {alert['alert_id']}")

        if args.burst > 1:
            time.sleep(0.5)

    producer.flush()
    print(f"\nDone. {args.burst} alert(s) published to '{TOPIC}'")


if __name__ == "__main__":
    main()
