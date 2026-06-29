"""
Detection Service — Kafka consumer/producer bridge.

Consumes: network-features  (raw Zeek conn.log JSON from ingestion layer)
Produces: anomaly-alerts     (AnomalyAlert schema for agentic layer)

Flow:
    Ingestion → Kafka[network-features]
              → parse_kafka_message()   # zeek_parser: normalize Zeek field names
              → build_feature_vector()  # feature_builder: build 20-dim numpy vector
              → ETSSLDetector.detect()
              → Kafka[anomaly-alerts]
              → Agentic Orchestrator
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
import uuid
from datetime import datetime, timezone

from confluent_kafka import Consumer, Producer, KafkaError
from confluent_kafka.admin import AdminClient, NewTopic

from detector import ETSSLDetector

# hybrid-detection modules (mounted into the container at /app/hybrid-detection)
_HYBRID = os.getenv("HYBRID_DETECTION_DIR", "/app/hybrid-detection")
if _HYBRID not in sys.path:
    sys.path.insert(0, _HYBRID)

from feature_extractor.zeek_parser import parse_kafka_message

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
log = logging.getLogger("sentinel.detection_service")

# ── Environment config ────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP  = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INPUT_TOPIC      = os.getenv("INPUT_TOPIC",  "network-features")
OUTPUT_TOPIC     = os.getenv("OUTPUT_TOPIC", "anomaly-alerts")
EMA_UPDATE_EVERY = int(os.getenv("EMA_UPDATE_EVERY", "1000"))  # update centroid every N normal flows
POLL_TIMEOUT     = float(os.getenv("POLL_TIMEOUT", "1.0"))


def _ensure_topics(bootstrap: str) -> None:
    admin = AdminClient({"bootstrap.servers": bootstrap})
    topics = [
        NewTopic(INPUT_TOPIC,  num_partitions=3, replication_factor=1),
        NewTopic(OUTPUT_TOPIC, num_partitions=3, replication_factor=1),
    ]
    futures = admin.create_topics(topics, request_timeout=10.0)
    for topic, fut in futures.items():
        try:
            fut.result()
            log.info("Created topic: %s", topic)
        except Exception:
            pass  # already exists


def _wait_for_kafka(bootstrap: str, retries: int = 30, delay: float = 5.0) -> None:
    for attempt in range(1, retries + 1):
        try:
            admin = AdminClient({"bootstrap.servers": bootstrap, "socket.timeout.ms": 4000})
            admin.list_topics(timeout=5)
            log.info("Kafka ready (%s)", bootstrap)
            return
        except Exception as exc:
            log.info("Waiting for Kafka [%d/%d] … %s", attempt, retries, exc)
        time.sleep(delay)
    log.error("Cannot reach Kafka after %d attempts", retries)
    sys.exit(1)


def _build_alert(feature_dict: dict, detection: dict) -> dict:
    """Construct an AnomalyAlert-compatible dict for the agentic layer."""
    return {
        "alert_id":      f"alert-{uuid.uuid4().hex[:12]}",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "anomaly_score": min(1.0, detection["confidence"]),   # normalised [0,1]
        # Use the label injected by the traffic generator when available;
        # in production the LLM classifies from context during investigation.
        "classification": feature_dict.get("classification", "network_anomaly"),
        "feature_vector": {
            "uid":       feature_dict.get("uid", ""),
            "ts":        feature_dict.get("timestamp", ""),
            "src_ip":    feature_dict.get("src_ip", ""),
            "src_port":  feature_dict.get("src_port", 0),
            "dst_ip":    feature_dict.get("dst_ip", ""),
            "dst_port":  feature_dict.get("dst_port", 0),
            "proto":     feature_dict.get("proto", ""),
            "service":   feature_dict.get("service", ""),
            "duration":  feature_dict.get("duration", 0),
            "orig_bytes": feature_dict.get("orig_bytes", 0),
            "resp_bytes": feature_dict.get("resp_bytes", 0),
            "orig_pkts":  feature_dict.get("orig_pkts", 0),
            "resp_pkts":  feature_dict.get("resp_pkts", 0),
            "conn_state": feature_dict.get("conn_state", ""),
        },
        "model_votes": detection.get("model_votes", [{
            "model_name": detection.get("model_name", "et_ssl"),
            "score":      detection["anomaly_score"],
            "label":      detection["classification"],
            "confidence": detection["confidence"],
        }]),
        "raw_features": {
            "triggering_model": detection.get("model_name", "et_ssl"),
            "raw_score":        detection["anomaly_score"],
        },
    }


class DetectionService:
    def __init__(self) -> None:
        self._running  = False
        self._detector: ETSSLDetector | None = None
        self._consumer: Consumer | None = None
        self._producer: Producer | None = None
        self._normal_buffer: list[dict] = []   # for EMA centroid updates
        self._processed = 0
        self._alerts_sent = 0

    def start(self) -> None:
        log.info("Detection service starting …")
        _wait_for_kafka(KAFKA_BOOTSTRAP)
        _ensure_topics(KAFKA_BOOTSTRAP)

        # Load ensemble — per-model thresholds come from model_meta.json
        # or THRESHOLD_<MODEL> env vars. ANOMALY_THRESHOLD is no longer used.
        self._detector = ETSSLDetector.load()

        # Kafka consumer
        self._consumer = Consumer({
            "bootstrap.servers":  KAFKA_BOOTSTRAP,
            "group.id":           "sentinel-detection-service",
            "auto.offset.reset":  "latest",
            "enable.auto.commit": False,
            "max.poll.interval.ms": 60_000,
        })
        self._consumer.subscribe([INPUT_TOPIC])

        # Kafka producer
        self._producer = Producer({
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "acks": "all",
            "retries": 3,
        })

        self._running = True
        log.info("Detection service ready — consuming from '%s'", INPUT_TOPIC)

    def run(self) -> None:
        while self._running:
            msg = self._consumer.poll(POLL_TIMEOUT)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    log.error("Kafka error: %s", msg.error())
                continue

            try:
                # Parse + normalize Zeek field names (id.orig_h → src_ip etc.)
                feature_dict = parse_kafka_message(msg.value())
                if feature_dict is None:
                    log.warning("Skipping malformed Kafka message")
                    self._consumer.commit(msg)
                    continue
            except Exception as exc:
                log.warning("Feature extraction failed: %s", exc)
                self._consumer.commit(msg)
                continue

            try:
                # detect() calls _build_feature_vector() internally
                detection = self._detector.detect(feature_dict)
                self._processed += 1

                if detection["is_anomaly"]:
                    alert = _build_alert(feature_dict, detection)
                    self._producer.produce(
                        OUTPUT_TOPIC,
                        key=feature_dict.get("uid", "").encode("utf-8"),
                        value=json.dumps(alert).encode("utf-8"),
                    )
                    self._producer.poll(0)
                    self._alerts_sent += 1
                    log.info(
                        "ANOMALY | uid=%-20s score=%.4f confidence=%.3f",
                        feature_dict.get("uid", "?"),
                        detection["anomaly_score"],
                        detection["confidence"],
                    )
                else:
                    # Buffer normal dicts for EMA centroid update
                    # update_centroid() expects dicts and calls _build_feature_vector() internally
                    self._normal_buffer.append(feature_dict)
                    if len(self._normal_buffer) >= EMA_UPDATE_EVERY:
                        self._detector.update_centroid(self._normal_buffer)
                        self._normal_buffer.clear()
                        log.debug("Centroid EMA updated from %d normal flows", EMA_UPDATE_EVERY)

            except Exception as exc:
                log.error("Detection error: %s", exc, exc_info=True)
            finally:
                self._consumer.commit(msg)

            if self._processed % 1000 == 0:
                log.info("Processed %d flows | %d alerts sent", self._processed, self._alerts_sent)

    def stop(self) -> None:
        log.info("Stopping detection service …")
        self._running = False
        if self._producer:
            self._producer.flush(timeout=10)
        if self._consumer:
            self._consumer.close()
        log.info("Detection service stopped. Processed=%d Alerts=%d",
                 self._processed, self._alerts_sent)


def main() -> None:
    svc = DetectionService()

    def _handle_signal(signum, _frame):
        log.info("Signal %d received", signum)
        svc.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    svc.start()
    svc.run()


if __name__ == "__main__":
    main()
