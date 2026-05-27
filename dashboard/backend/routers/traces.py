"""Reasoning trace retrieval router for agent activity logs."""

import json

from fastapi import APIRouter, Depends, Query

from core.dependencies import analyst_or_above
from db.traces import get_trace_from_db
from state.redis_client import get_redis

router = APIRouter()


async def _from_redis(alert_id: str) -> list:
    """Fetch reasoning traces from Redis stream.
    
    Args:
        alert_id: The alert identifier for the Redis key.
        
    Returns:
        List of trace events, empty if Redis unavailable.
    """
    redis = await get_redis()
    events = []
    try:
        for _id, fields in await redis.xrange(f"reasoning:{alert_id}"):
            events.append({
                k: (json.loads(v) if v.startswith(("{", "[", '"')) else v)
                for k, v in fields.items()
            })
    except Exception:
        pass  # Gracefully handle Redis errors
    return events


@router.get("/{alert_id}/trace")
async def get_trace(
    alert_id: str,
    source: str = Query("auto", enum=["redis", "postgres", "auto"]),
    _: None = Depends(analyst_or_above)
) -> list:
    """Retrieve reasoning traces for an alert.
    
    Traces show agent decision-making steps during incident analysis.
    
    Args:
        alert_id: The alert identifier.
        source: Data source - 'redis' for live, 'postgres' for archived,
                'auto' tries Redis first then falls back to Postgres.
        _: Authentication dependency (unused).
        
    Returns:
        List of trace events ordered chronologically.
    """
    if source == "redis":
        return await _from_redis(alert_id)
    if source == "postgres":
        return await get_trace_from_db(alert_id)
    # Auto: prefer Redis for live data, fallback to Postgres
    events = await _from_redis(alert_id)
    return events if events else await get_trace_from_db(alert_id)