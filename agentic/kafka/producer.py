"""
Kafka Producer for the Agentic Layer
======================================
Publishes to:
1. 'execution-plans' — ranked plans for the SOC dashboard to display
2. 'reasoning-events' — (optional) real-time reasoning events for live trace

Design:
- Serializes Pydantic models to JSON
- Keys messages by alert_id for deterministic partition routing
  (all messages for one alert go to the same partition → ordering guaranteed)
- Delivery callbacks log success/failure
- Flush after each publish to ensure plans reach the dashboard immediately
"""

import json
import logging
import os
from typing import Optional

from confluent_kafka import Producer

from agentic.models.plan import PlanSet

logger = logging.getLogger(__name__)


def _delivery_callback(err, msg):
    """Called once per message to confirm delivery or log error."""
    if err:
        logger.error(f"Message delivery failed: {err}")
    else:
        logger.debug(f"Delivered to {msg.topic()} [{msg.partition()}] @ offset {msg.offset()}")


class PlanProducer:
    """
    Publishes execution plans to the 'execution-plans' Kafka topic.
    The SOC dashboard consumes this topic to present plans to the analyst.
    """

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        plans_topic: str = "execution-plans",
    ):
        self.bootstrap_servers = bootstrap_servers or os.environ.get(
            "KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"
        )
        self.plans_topic = plans_topic
        self._producer: Optional[Producer] = None

    def connect(self):
        """Initialize the Kafka producer."""
        config = {
            "bootstrap.servers": self.bootstrap_servers,
            "acks": "all",  # wait for all replicas (durability over speed)
            "retries": 3,
            "retry.backoff.ms": 500,
            "linger.ms": 0,  # send immediately (plans are latency-sensitive)
        }
        self._producer = Producer(config)
        logger.info(f"Kafka producer connected to {self.bootstrap_servers}")

    def publish_plans(self, plan_set: PlanSet):
        """
        Publish a complete PlanSet to the execution-plans topic.
        Keyed by alert_id so all plans for one alert land in the same partition.
        """
        if not self._producer:
            raise RuntimeError("Producer not connected. Call connect() first.")

        key = plan_set.alert_id.encode("utf-8")
        value = plan_set.model_dump_json().encode("utf-8")

        self._producer.produce(
            topic=self.plans_topic,
            key=key,
            value=value,
            callback=_delivery_callback,
        )
        # Flush immediately — plans must reach dashboard ASAP
        self._producer.flush(timeout=5.0)
        logger.info(
            f"Published PlanSet for alert {plan_set.alert_id} "
            f"({len(plan_set.plans)} plans, best confidence: {plan_set.best_plan.confidence:.2f})"
        )

    def publish_raw(self, topic: str, key: str, data: dict):
        """Publish arbitrary JSON data to a topic (used for reasoning events)."""
        if not self._producer:
            raise RuntimeError("Producer not connected. Call connect() first.")

        self._producer.produce(
            topic=topic,
            key=key.encode("utf-8"),
            value=json.dumps(data, default=str).encode("utf-8"),
            callback=_delivery_callback,
        )
        self._producer.flush(timeout=5.0)

    def close(self):
        """Flush remaining messages and close."""
        if self._producer:
            self._producer.flush(timeout=10.0)
            logger.info("Kafka producer flushed and closed")
