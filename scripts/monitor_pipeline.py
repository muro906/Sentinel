#!/usr/bin/env python3
"""
Pipeline Monitor
================
Watches Kafka topics in real time to verify the full pipeline is working.

Shows:
  - network-features  : flows extracted from Zeek logs
  - anomaly-alerts    : alerts from detection service with per-model scores

Usage:
    python scripts/monitor_pipeline.py                # watch both topics
    python scripts/monitor_pipeline.py --topic alerts  # alerts only
    python scripts/monitor_pipeline.py --topic features

Press Ctrl-C to stop.
"""

import argparse
import json
import os
import sys
import threading
from datetime import datetime

try:
    from confluent_kafka import Consumer, KafkaError
except ImportError:
    sys.exit("pip install confluent-kafka")

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
THRESHOLD  = 3.3174   # darknet model threshold


def _consumer(topic: str, group: str) -> Consumer:
    c = Consumer({
        "bootstrap.servers":  BOOTSTRAP,
        "group.id":           group,
        "auto.offset.reset":  "latest",
        "enable.auto.commit": True,
    })
    c.subscribe([topic])
    return c


def watch_features():
    c = _consumer("network-features", "monitor-features")
    print(f"[features] Watching network-features on {BOOTSTRAP} ...")
    while True:
        msg = c.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            if msg.error().code() != KafkaError._PARTITION_EOF:
                print(f"[features] Kafka error: {msg.error()}")
            continue
        try:
            d = json.loads(msg.value())
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] FLOW  {d.get('src_ip','?'):>16} → {d.get('dst_ip','?'):<16}"
                  f"  {d.get('proto','?'):4}  dur={d.get('duration',0):.3f}s"
                  f"  ob={d.get('orig_bytes',0):>7}  rb={d.get('resp_bytes',0):>8}"
                  f"  state={d.get('conn_state','?')}")
        except Exception:
            pass


def watch_alerts():
    c = _consumer("anomaly-alerts", "monitor-alerts")
    print(f"[alerts]   Watching anomaly-alerts on {BOOTSTRAP} ...")
    while True:
        msg = c.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            if msg.error().code() != KafkaError._PARTITION_EOF:
                print(f"[alerts]  Kafka error: {msg.error()}")
            continue
        try:
            d = json.loads(msg.value())
            ts    = datetime.now().strftime("%H:%M:%S")
            score = d.get("anomaly_score", 0)
            conf  = d.get("confidence", 0)
            fv    = d.get("feature_vector", {})
            votes = d.get("model_votes", [])
            src   = fv.get("src_ip", "?")
            dst   = fv.get("dst_ip", "?")
            dport = fv.get("dst_port", 0)

            # Colour-code by score relative to threshold
            flag = "🔴 ANOMALY" if conf > 0.9 else "🟡 BORDER "

            vote_str = "  ".join(
                f"{v['model_name']}:{v['score']:.1f}(thr={v['threshold']:.1f})"
                for v in votes
            )

            print(f"[{ts}] {flag}  {src:>16} → {dst}:{dport:<6}"
                  f"  score={score:.2e}  conf={conf:.3f}")
            if vote_str:
                print(f"         votes: {vote_str}")
            print()
        except Exception as e:
            print(f"[alerts]  parse error: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--topic", choices=["features", "alerts", "both"], default="both")
    args = ap.parse_args()

    threads = []
    if args.topic in ("features", "both"):
        t = threading.Thread(target=watch_features, daemon=True)
        t.start()
        threads.append(t)

    if args.topic in ("alerts", "both"):
        t = threading.Thread(target=watch_alerts, daemon=True)
        t.start()
        threads.append(t)

    print("Press Ctrl-C to stop.\n")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
