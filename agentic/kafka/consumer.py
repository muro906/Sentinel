"""
Kafka Consumer for anomaly alerts.
"""
import json
import logging
import os
from typing import Optional, Tuple

from confluent_kafka import Consumer, KafkaError, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic

logger = logging.getLogger(__name__)


class AlertConsumer:
    """Consumes anomaly alerts from Kafka."""
    
    def __init__(self):
        self.bootstrap_servers = os.getenv(
            "KAFKA_BOOTSTRAP_SERVERS",
            "localhost:9092"
        )
        self.group_id = "sentinel-orchestrator"
        self.topic = "anomaly-alerts"
        self._consumer: Optional[Consumer] = None
        self._running = False
    
    def _ensure_topics(self):
        """Create topics if they don't exist."""
        admin = AdminClient({"bootstrap.servers": self.bootstrap_servers})
        topics = [
            NewTopic(self.topic, num_partitions=3, replication_factor=1),
            NewTopic("execution-plans", num_partitions=1, replication_factor=1),
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
        """Initialize the Kafka consumer."""
        self._ensure_topics()
        
        config = {
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": self.group_id,
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
        }
        
        self._consumer = Consumer(config)
        self._consumer.subscribe([self.topic])
        self._running = True
        logger.info(f"Kafka consumer connected to {self.bootstrap_servers}")
    
    def poll(self, timeout: float = 1.0) -> Optional[Tuple[str, dict]]:
        """Poll for a message. Returns (topic, data) or None."""
        if not self._consumer:
            raise RuntimeError("Consumer not connected")
        
        msg = self._consumer.poll(timeout)
        if msg is None:
            return None
        
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                return None
            logger.error(f"Kafka error: {msg.error()}")
            return None
        
        try:
            data = json.loads(msg.value().decode("utf-8"))
            return (msg.topic(), data)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to decode message: {e}")
            self._consumer.commit(msg)
            return None
    
    def commit(self):
        """Commit current offsets."""
        if self._consumer:
            self._consumer.commit()
    
    def close(self):
        """Close the consumer."""
        self._running = False
        if self._consumer:
            self._consumer.close()
            logger.info("Kafka consumer closed")
