"""Kafka consumers for the dashboard backend.

Consumers:
  execution-plans  → store plans in DB, broadcast new_plans via WebSocket
  action-results   → update alert status, broadcast execution_complete via WebSocket
"""

import asyncio
import json
import logging
from threading import Thread

from confluent_kafka import Consumer, KafkaError

from core.config import settings
from db.incidents import upsert_plan_set

logger = logging.getLogger(__name__)

_loop: asyncio.AbstractEventLoop | None = None


# ── Public startup functions ───────────────────────────────────────────────────

async def start_plan_consumer() -> None:
    """Start the execution-plans consumer in a background thread."""
    global _loop
    _loop = asyncio.get_event_loop()
    Thread(target=_run_plans, daemon=True, name="kafka-plans").start()
    Thread(target=_run_results, daemon=True, name="kafka-results").start()


# ── execution-plans consumer ──────────────────────────────────────────────────

def _run_plans() -> None:
    try:
        c = Consumer({
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "group.id": "sentinel-dashboard-plans",
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
            "socket.timeout.ms": 5000,
            "session.timeout.ms": 10000,
        })
        c.subscribe(["execution-plans"])
        logger.info("Plans consumer connected")
    except Exception as e:
        logger.warning("Plans consumer unavailable: %s", e)
        return

    errors = 0
    while errors < 5:
        try:
            msg = c.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    errors += 1
                    logger.error("Plans Kafka error: %s", msg.error())
                continue
            errors = 0
            plan_set = json.loads(msg.value().decode())
            asyncio.run_coroutine_threadsafe(_handle_plan(plan_set), _loop).result(timeout=10)
            c.commit(asynchronous=False)
        except Exception as e:
            logger.error("Plans consumer error: %s", e)
            errors += 1


async def _handle_plan(plan_set: dict) -> None:
    from ws.manager import manager
    aid = plan_set.get("alert_id", "unknown")
    await upsert_plan_set(aid, plan_set)
    await manager.broadcast("feed", {
        "type": "new_plans",
        "alert_id": aid,
    })
    logger.info("Plans stored and broadcast for alert %s", aid)


# ── action-results consumer ───────────────────────────────────────────────────

def _run_results() -> None:
    try:
        c = Consumer({
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "group.id": "sentinel-dashboard-results",
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
            "socket.timeout.ms": 5000,
            "session.timeout.ms": 10000,
        })
        c.subscribe(["action-results"])
        logger.info("Results consumer connected")
    except Exception as e:
        logger.warning("Results consumer unavailable: %s", e)
        return

    errors = 0
    while errors < 5:
        try:
            msg = c.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    errors += 1
                    logger.error("Results Kafka error: %s", msg.error())
                continue
            errors = 0
            result = json.loads(msg.value().decode())
            asyncio.run_coroutine_threadsafe(_handle_result(result), _loop).result(timeout=10)
            c.commit(asynchronous=False)
        except Exception as e:
            logger.error("Results consumer error: %s", e)
            errors += 1


async def _handle_result(result: dict) -> None:
    from ws.manager import manager
    from db.connection import get_pool

    aid      = result.get("alert_id", "unknown")
    verified = result.get("verified", False)
    status   = result.get("status", "closed")

    # Ensure DB reflects final status (execution.py already updated, this is a safety net)
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE incidents SET approval_status=$2, execution_status='completed' "
                "WHERE alert_id=$1 AND approval_status NOT IN ('closed')",
                aid, status
            )
    except Exception as e:
        logger.warning("Result DB update failed: %s", e)

    # Broadcast to all connected frontend clients so the UI updates without polling
    await manager.broadcast("feed", {
        "type":     "execution_complete",
        "alert_id": aid,
        "status":   status,
        "verified": verified,
    })
    logger.info("Execution result broadcast for alert %s: %s", aid, status)
