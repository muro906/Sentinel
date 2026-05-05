"""
Agent Task Queue (Redis Streams)
=================================
Implements a distributed task queue using Redis Streams for dispatching
work to sub-agents. Redis Streams provide:
- Ordered, persistent message log
- Consumer groups (multiple workers can share load)
- Acknowledgment (tasks only removed after confirmed completion)
- Automatic ID generation (timestamp-based ordering)

Flow:
    Orchestrator → XADD to "agent-tasks:{agent_name}" stream
    Sub-agent   → XREADGROUP from its stream → process → XACK
"""

import json
import logging
import time
from typing import Optional

from .redis_client import get_redis

logger = logging.getLogger(__name__)

# Stream names
TASK_STREAM_PREFIX = "agent-tasks"
CONSUMER_GROUP = "sentinel-agents"


async def dispatch_task(agent_name: str, alert_id: str, task_data: dict) -> str:
    """
    Dispatch a task to a sub-agent via Redis Stream.

    Args:
        agent_name: Target agent (e.g., 'cve_lookup', 'asset_discovery')
        alert_id: Alert this task belongs to
        task_data: Serializable task payload

    Returns:
        Stream entry ID (used for tracking)
    """
    redis = await get_redis()
    stream_key = f"{TASK_STREAM_PREFIX}:{agent_name}"

    # Ensure consumer group exists (idempotent)
    try:
        await redis.xgroup_create(stream_key, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception:
        pass  # group already exists

    # Add task to stream
    entry = {
        "alert_id": alert_id,
        "payload": json.dumps(task_data, default=str),
        "dispatched_at": str(time.time()),
    }

    entry_id = await redis.xadd(stream_key, entry)
    logger.debug(f"Dispatched task to {agent_name}: {entry_id} (alert: {alert_id})")
    return entry_id


async def consume_task(
    agent_name: str,
    consumer_id: str,
    block_ms: int = 5000,
) -> Optional[tuple[str, dict]]:
    """
    Consume a single task from the agent's stream.

    Args:
        agent_name: Which agent stream to read from
        consumer_id: Unique consumer identifier (for group tracking)
        block_ms: How long to block waiting for a message

    Returns:
        (entry_id, task_data) or None if no message within timeout
    """
    redis = await get_redis()
    stream_key = f"{TASK_STREAM_PREFIX}:{agent_name}"

    # Ensure consumer group exists
    try:
        await redis.xgroup_create(stream_key, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception:
        pass

    # Read one message from the group
    result = await redis.xreadgroup(
        groupname=CONSUMER_GROUP,
        consumername=consumer_id,
        streams={stream_key: ">"},  # ">" = only new messages
        count=1,
        block=block_ms,
    )

    if not result:
        return None

    # Parse result: [[stream_key, [(entry_id, fields)]]]
    stream_data = result[0]
    entries = stream_data[1]
    if not entries:
        return None

    entry_id, fields = entries[0]
    task_data = json.loads(fields["payload"])
    task_data["_entry_id"] = entry_id
    task_data["_alert_id"] = fields["alert_id"]

    return (entry_id, task_data)


async def acknowledge_task(agent_name: str, entry_id: str):
    """Mark a task as completed (removes from pending list)."""
    redis = await get_redis()
    stream_key = f"{TASK_STREAM_PREFIX}:{agent_name}"
    await redis.xack(stream_key, CONSUMER_GROUP, entry_id)
    logger.debug(f"Acknowledged task {entry_id} on {agent_name}")
