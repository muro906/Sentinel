"""
Sentinel – Feature Extractor service entrypoint.
Waits for Kafka, then starts the Zeek log watcher pipeline.
"""

from __future__ import annotations

import logging
import os
import sys
import time

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
log = logging.getLogger("sentinel.ingestion")


def _wait_for_kafka(bootstrap: str, retries: int = 30, delay: float = 5.0) -> None:
    """Block until Kafka is reachable."""
    from confluent_kafka.admin import AdminClient

    for attempt in range(1, retries + 1):
        try:
            client = AdminClient({"bootstrap.servers": bootstrap, "socket.timeout.ms": 4000})
            meta = client.list_topics(timeout=5)
            if meta:
                log.info("Kafka is ready (%s)", bootstrap)
                return
        except Exception as exc:
            log.info("Waiting for Kafka [%d/%d]… (%s)", attempt, retries, exc)
        time.sleep(delay)

    log.error("Could not connect to Kafka after %d attempts – exiting.", retries)
    sys.exit(1)


def main() -> None:
    bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

    log.info("Sentinel Feature Extractor starting…")
    _wait_for_kafka(bootstrap)

    from kafka.producer import FeatureProducer
    from pipeline.watcher import run_watcher

    producer = FeatureProducer()
    run_watcher(producer)


if __name__ == "__main__":
    main()
