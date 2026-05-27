"""Kafka consumer for receiving execution plans from the orchestrator."""

import asyncio
import json
import logging
from threading import Thread

from confluent_kafka import Consumer, KafkaError

from core.config import settings
from db.incidents import upsert_plan_set

logger = logging.getLogger(__name__)

# Event loop reference for cross-thread async operations
_loop: asyncio.AbstractEventLoop | None = None


async def start_plan_consumer() -> None:
    """Start the plan consumer in a background daemon thread.
    
    Consumes from 'execution-plans' topic and stores plans in database.
    """
    global _loop
    _loop = asyncio.get_event_loop()
    Thread(target=_run, daemon=True).start()


def _run() -> None:
    """Main consumer loop running in background thread.
    
    Polls Kafka for new plan messages, processes them, and commits offsets.
    If Kafka is unavailable, logs a warning and exits gracefully.
    """
    try:
        c = Consumer({
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "group.id": "sentinel-dashboard",
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
            "socket.timeout.ms": 5000,  # 5 second timeout
            "session.timeout.ms": 10000,  # 10 second session timeout
        })
        c.subscribe(["execution-plans"])
        logger.info("Kafka consumer connected successfully")
    except Exception as e:
        logger.warning(f"Kafka not available - plan consumer disabled: {e}")
        return  # Exit gracefully if Kafka can't connect
    
    error_count = 0
    max_errors = 5  # Stop after 5 consecutive errors
    while error_count < max_errors:
        try:
            msg = c.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    error_count += 1
                    if error_count >= max_errors:
                        logger.warning("Kafka consumer: Too many errors, shutting down")
                        break
                    logger.error(f"Kafka: {msg.error()}")
                continue
            # Reset error count on successful message
            error_count = 0
            
            # Process the message
            plan_set = json.loads(msg.value().decode())
            # Process plan in async context and wait for completion
            asyncio.run_coroutine_threadsafe(_handle(plan_set), _loop).result(timeout=10)
            c.commit(asynchronous=False)
        except Exception as e:
            logger.error(f"Plan consumer error: {e}")


async def _handle(plan_set: dict) -> None:
    """Process a received plan set.
    
    Stores plan in database and broadcasts to connected WebSocket clients.
    
    Args:
        plan_set: The plan set dictionary from Kafka.
    """
    from ws.manager import manager
    aid = plan_set.get("alert_id", "unknown")
    await upsert_plan_set(aid, plan_set)
    await manager.broadcast("feed", {
        "type": "new_plans",
        "alert_id": aid,
        "classification": plan_set.get("threat_summary", ""),
        "priority": plan_set.get("priority", "medium")
    })