"""Kafka producer for publishing approved remediation plans."""

import json
import logging
from typing import Optional

from confluent_kafka import Producer

from core.config import settings

logger = logging.getLogger(__name__)

# Module-level producer instance (lazy initialization)
_producer: Optional[Producer] = None


def _get() -> Producer:
    """Get or create the Kafka producer instance.
    
    Returns:
        Configured Kafka Producer with 'acks=all' for durability.
    """
    global _producer
    if _producer is None:
        _producer = Producer({
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "acks": "all"  # Wait for all replicas to acknowledge
        })
    return _producer


async def publish_approval(
    alert_id: str,
    plan_id: str,
    actions: list,
    approved_by: str,
    notes: str = ""
) -> None:
    """Publish an approved plan to the 'approved-actions' Kafka topic.
    
    The orchestrator consumes from this topic to execute remediation actions.
    
    Args:
        alert_id: The associated alert identifier.
        plan_id: The approved plan identifier.
        actions: List of approved action dictionaries.
        approved_by: Username of the approving analyst.
        notes: Optional approval notes.
    """
    p = _get()
    payload = {
        "alert_id": alert_id,
        "plan_id": plan_id,
        "actions": actions,
        "approved_by": approved_by,
        "notes": notes
    }
    p.produce(
        topic="approved-actions",
        key=alert_id.encode(),
        value=json.dumps(payload).encode(),
        callback=lambda err, _: logger.error(f"Delivery failed: {err}") if err else None
    )
    # Block up to 5 seconds for delivery confirmation
    p.flush(5.0)