"""
Kafka producer – publishes feature vectors to the `network-features` topic.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient, NewTopic

log = logging.getLogger(__name__)

BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
TOPIC             = os.getenv("KAFKA_TOPIC", "network-features")


def _ensure_topic(bootstrap: str, topic: str) -> None:
    """Create the topic if it doesn't exist (idempotent)."""
    admin = AdminClient({"bootstrap.servers": bootstrap})
    existing = admin.list_topics(timeout=10).topics
    if topic not in existing:
        fs = admin.create_topics([NewTopic(topic, num_partitions=3, replication_factor=1)])
        for t, f in fs.items():
            try:
                f.result()
                log.info("Created topic: %s", t)
            except Exception as exc:
                log.debug("Topic may already exist: %s – %s", t, exc)


def delivery_report(err: Any, msg: Any) -> None:
    if err:
        log.warning("Delivery failed for %s: %s", msg.key(), err)
    else:
        log.debug("Delivered to %s [%d] @ %d", msg.topic(), msg.partition(), msg.offset())


class FeatureProducer:
    def __init__(self) -> None:
        _ensure_topic(BOOTSTRAP_SERVERS, TOPIC)
        self._producer = Producer({
            "bootstrap.servers": BOOTSTRAP_SERVERS,
            "acks": "all",
            "retries": 5,
            "retry.backoff.ms": 500,
        })
        log.info("Kafka producer ready → %s / %s", BOOTSTRAP_SERVERS, TOPIC)

    def publish(self, vectors: list[dict]) -> int:
        """
        Publish a list of feature vector dicts to Kafka.
        Returns the number of messages successfully enqueued.
        """
        sent = 0
        for vec in vectors:
            key = f"{vec.get('src_ip', 'unknown')}-{vec.get('uid', 'x')}"
            payload = json.dumps(vec, default=str).encode("utf-8")
            self._producer.produce(
                TOPIC,
                key=key.encode("utf-8"),
                value=payload,
                callback=delivery_report,
            )
            sent += 1
        self._producer.flush(timeout=30)
        log.info("Published %d feature vectors to Kafka topic '%s'", sent, TOPIC)
        return sent

    def close(self) -> None:
        self._producer.flush(timeout=10)
