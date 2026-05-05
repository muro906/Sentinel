"""
Result Store (Redis Hash)
==========================
Temporary storage for sub-agent results during incident processing.
Each alert gets a Redis Hash that aggregates results from all sub-agents.
TTL ensures stale data is cleaned up automatically.

Key structure:
    results:{alert_id} → Hash {
        "cve_lookup": JSON string of CVEMatch list,
        "asset_discovery": JSON string of AssetInfo list,
        "status": "pending|partial|complete",
        "_completed_agents": comma-separated list of done agents,
    }

The orchestrator's await_results node polls this store until all expected
agents have written their results (or timeout is reached).
"""

import json
import logging
from typing import Optional

from .redis_client import get_redis

logger = logging.getLogger(__name__)

RESULT_KEY_PREFIX = "results"
DEFAULT_TTL_SECONDS = 3600  # 1 hour


async def store_result(alert_id: str, agent_name: str, result: dict | list):
    """
    Store an agent's result for a given alert.
    Updates the completed agents list and checks if all agents are done.
    """
    redis = await get_redis()
    key = f"{RESULT_KEY_PREFIX}:{alert_id}"

    # Store the result as JSON
    await redis.hset(key, agent_name, json.dumps(result, default=str))

    # Track which agents have completed
    completed = await redis.hget(key, "_completed_agents") or ""
    completed_set = set(completed.split(",")) if completed else set()
    completed_set.discard("")
    completed_set.add(agent_name)
    await redis.hset(key, "_completed_agents", ",".join(completed_set))

    # Set/refresh TTL
    await redis.expire(key, DEFAULT_TTL_SECONDS)

    logger.debug(f"Stored result for alert {alert_id} from {agent_name}. Completed: {completed_set}")


async def get_result(alert_id: str, agent_name: str) -> Optional[dict | list]:
    """Retrieve a specific agent's result for an alert."""
    redis = await get_redis()
    key = f"{RESULT_KEY_PREFIX}:{alert_id}"
    raw = await redis.hget(key, agent_name)
    if raw:
        return json.loads(raw)
    return None


async def get_all_results(alert_id: str) -> dict:
    """
    Retrieve all agent results for an alert.
    Returns dict: {agent_name: parsed_result, ...}
    Excludes internal tracking fields (prefixed with _).
    """
    redis = await get_redis()
    key = f"{RESULT_KEY_PREFIX}:{alert_id}"
    all_fields = await redis.hgetall(key)

    results = {}
    for field, value in all_fields.items():
        if field.startswith("_"):
            continue
        try:
            results[field] = json.loads(value)
        except json.JSONDecodeError:
            results[field] = value

    return results


async def get_completed_agents(alert_id: str) -> set[str]:
    """Get the set of agents that have completed for this alert."""
    redis = await get_redis()
    key = f"{RESULT_KEY_PREFIX}:{alert_id}"
    completed = await redis.hget(key, "_completed_agents") or ""
    agents = set(completed.split(","))
    agents.discard("")
    return agents


async def all_agents_complete(alert_id: str, expected_agents: set[str]) -> bool:
    """Check if all expected agents have stored their results."""
    completed = await get_completed_agents(alert_id)
    return expected_agents.issubset(completed)


async def clear_results(alert_id: str):
    """Delete all results for an alert (called after incident closes)."""
    redis = await get_redis()
    key = f"{RESULT_KEY_PREFIX}:{alert_id}"
    await redis.delete(key)
