"""
Session State (Redis Hash + TTL)
=================================
Manages per-incident session state for the orchestrator. Tracks where each
alert is in its lifecycle (triage → agents → planning → approval → execution).

This enables:
- Resumability: if the orchestrator restarts, it can pick up where it left off
- Deduplication: detect if we've already seen this alert pattern recently
- Timeout tracking: know when to escalate if approval is overdue

Key structure:
    session:{alert_id} → Hash {
        "state": current orchestrator state name,
        "priority": computed priority,
        "created_at": timestamp,
        "triaged_at": timestamp,
        "plans_ready_at": timestamp,
        "approved_at": timestamp,
        ...
    }

    dedup:{classification}:{src_ip} → String with TTL (deduplication window)
"""

import json
import logging
import time
from typing import Optional

from .redis_client import get_redis

logger = logging.getLogger(__name__)

SESSION_PREFIX = "session"
DEDUP_PREFIX = "dedup"
SESSION_TTL = 7200  # 2 hours
DEDUP_WINDOW = 300  # 5 minutes


async def create_session(alert_id: str, initial_data: dict) -> bool:
    """
    Create a new session for an alert. Returns False if session already exists
    (indicates duplicate processing).
    """
    redis = await get_redis()
    key = f"{SESSION_PREFIX}:{alert_id}"

    # Use HSETNX on a sentinel field to atomically check existence
    created = await redis.hsetnx(key, "_created", "1")
    if not created:
        logger.warning(f"Session already exists for {alert_id}")
        return False

    # Set initial state
    session_data = {
        "state": "received",
        "created_at": str(time.time()),
        **{k: json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v)
           for k, v in initial_data.items()}
    }
    await redis.hset(key, mapping=session_data)
    await redis.expire(key, SESSION_TTL)

    logger.debug(f"Created session for alert {alert_id}")
    return True


async def update_session(alert_id: str, updates: dict):
    """Update session fields (e.g., state transition, timestamps)."""
    redis = await get_redis()
    key = f"{SESSION_PREFIX}:{alert_id}"

    serialized = {
        k: json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v)
        for k, v in updates.items()
    }
    await redis.hset(key, mapping=serialized)
    # Refresh TTL on activity
    await redis.expire(key, SESSION_TTL)


async def get_session(alert_id: str) -> Optional[dict]:
    """Retrieve full session state for an alert."""
    redis = await get_redis()
    key = f"{SESSION_PREFIX}:{alert_id}"
    data = await redis.hgetall(key)
    return data if data else None


async def get_session_state(alert_id: str) -> Optional[str]:
    """Get just the current state name."""
    redis = await get_redis()
    key = f"{SESSION_PREFIX}:{alert_id}"
    return await redis.hget(key, "state")


async def check_duplicate(classification: str, src_ip: str) -> bool:
    """
    Check if we've already processed an alert with the same classification
    and source IP within the deduplication window (5 minutes).

    Returns True if this is a DUPLICATE (should be skipped).
    """
    redis = await get_redis()
    key = f"{DEDUP_PREFIX}:{classification}:{src_ip}"

    # If key exists, it's a duplicate
    existing = await redis.get(key)
    if existing:
        logger.info(f"Duplicate detected: {classification} from {src_ip} (original: {existing})")
        return True

    return False


async def mark_seen(classification: str, src_ip: str, alert_id: str):
    """Mark an alert pattern as seen for deduplication purposes."""
    redis = await get_redis()
    key = f"{DEDUP_PREFIX}:{classification}:{src_ip}"
    await redis.setex(key, DEDUP_WINDOW, alert_id)


async def delete_session(alert_id: str):
    """Remove session state (called after incident fully closed)."""
    redis = await get_redis()
    key = f"{SESSION_PREFIX}:{alert_id}"
    await redis.delete(key)
