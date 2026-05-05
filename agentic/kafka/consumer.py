"""
Kafka Consumer for the Agentic Layer
======================================
Consumes from two topics:
1. 'anomaly-alerts' — incoming alerts from the Hybrid Detection Layer
2. 'action-results' — feedback from the Execution Layer

Design decisions:
- Uses confluent-kafka (same as Layer 1) for consistency
- Consumer group 'sentinel-orchestrator' ensures only one orchestrator instance
  processes each alert (supports future horizontal scaling)
- Messages are deserialized into Pydantic models with validation
- Invalid messages are logged and skipped (dead-letter pattern)
- Commits offsets only AFTER the orchestrator acknowledges processing
"""

import json
import logging
import os
from typing import Callable, Awaitable, Optional

from confluent_kafka import Consumer, KafkaError, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic

from agentic.models.alert import AnomalyAlert
from agentic.models.plan import ActionResult

logger = logging.getLogger(__name__)


class AlertConsumer:
    """
    Consumes anomaly alerts from Kafka and dispatches them to the orchestrator.

    The consumer runs in a background thread and calls the provided async
    handler for each valid alert. Invalid messages are logged and skipped.
    """

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        group_id: str = "sentinel-orchestrator",
        alert_topic: str = "anomaly-alerts",
        results_topic: str = "action-results",
    ):
        self.bootstrap_servers = bootstrap_servers or os.environ.get(
            "KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"
        )
        self.group_id = group_id
        self.alert_topic = alert_topic
        self.results_topic = results_topic
        self._consumer: Optional[Consumer] = None
        self._running = False

    def _ensure_topics(self):
        """Create topics if they don't exist (idempotent)."""
        admin = AdminClient({"bootstrap.servers": self.bootstrap_servers})
        topics = [
            NewTopic(self.alert_topic, num_partitions=3, replication_factor=1),
            NewTopic(self.results_topic, num_partitions=1, replication_factor=1),
            NewTopic("execution-plans", num_partitions=1, replication_factor=1),
            NewTopic("approved-actions", num_partitions=1, replication_factor=1),
        ]
        futures = admin.create_topics(topics, request_timeout=10.0)
        for topic, future in futures.items():
            try:
                future.result()
                logger.info(f"Created topic: {topic}")
            except KafkaException as e:
                if e.args[0].code() == KafkaError.TOPIC_ALREADY_EXISTS:
                    logger.debug(f"Topic already exists: {topic}")
                else:
                    logger.warning(f"Failed to create topic {topic}: {e}")

    def connect(self):
        """Initialize the Kafka consumer and subscribe to topics."""
        self._ensure_topics()

        config = {
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": self.group_id,
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,  # manual commit after processing
            "max.poll.interval.ms": 300000,  # 5 min max processing time per message
            "session.timeout.ms": 30000,
        }

        self._consumer = Consumer(config)
        self._consumer.subscribe([self.alert_topic, self.results_topic])
        self._running = True
        logger.info(
            f"Kafka consumer connected. Subscribed to: {self.alert_topic}, {self.results_topic}"
        )

    def poll(self, timeout: float = 1.0) -> Optional[tuple[str, dict]]:
        """
        Poll for a single message. Returns (topic, parsed_data) or None.
        Caller is responsible for committing offset after processing.
        """
        if not self._consumer:
            raise RuntimeError("Consumer not connected. Call connect() first.")

        msg = self._consumer.poll(timeout)
        if msg is None:
            return None

        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                return None
            logger.error(f"Kafka consumer error: {msg.error()}")
            return None

        try:
            value = json.loads(msg.value().decode("utf-8"))
            topic = msg.topic()
            return (topic, value)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to decode message: {e}")
            # Skip invalid message by committing its offset
            self._consumer.commit(msg)
            return None

    def commit(self):
        """Commit current offsets (call after successful processing)."""
        if self._consumer:
            self._consumer.commit()

    def close(self):
        """Clean shutdown."""
        self._running = False
        if self._consumer:
            self._consumer.close()
            logger.info("Kafka consumer closed")

    @property
    def is_running(self) -> bool:
        return self._running
