"""
Kafka Producer for execution plans.
"""
import json
import logging
import os
from typing import Optional

from confluent_kafka import Producer

logger = logging.getLogger(__name__)


class PlanProducer:
    """Publishes execution plans to Kafka."""
    
    def __init__(self):
        self.bootstrap_servers = os.getenv(
            "KAFKA_BOOTSTRAP_SERVERS",
            "localhost:9092"
        )
        self.topic = "execution-plans"
        self._producer: Optional[Producer] = None
    
    def connect(self):
        """Initialize the Kafka producer."""
        config = {
            "bootstrap.servers": self.bootstrap_servers,
            "acks": "all",
            "retries": 3,
        }
        self._producer = Producer(config)
        logger.info(f"Kafka producer connected to {self.bootstrap_servers}")
    
    def publish_plans(self, alert_id: str, plans: list, context: dict):
        """Publish plans to Kafka."""
        if not self._producer:
            raise RuntimeError("Producer not connected")
        
        message = {
            "alert_id": alert_id,
            "plans": plans,
            "asset_context": context.get("asset_context"),
            "cve_matches": context.get("cve_matches"),
            "generated_at": context.get("generated_at")
        }
        
        key = alert_id.encode("utf-8")
        value = json.dumps(message, default=str).encode("utf-8")
        
        self._producer.produce(
            topic=self.topic,
            key=key,
            value=value
        )
        self._producer.flush(timeout=5.0)
        logger.info(f"Published plans for alert {alert_id}")
    
    def close(self):
        """Close the producer."""
        if self._producer:
            self._producer.flush(timeout=10.0)
            logger.info("Kafka producer closed")
