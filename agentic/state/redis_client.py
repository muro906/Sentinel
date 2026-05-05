"""
Redis Client
=============
Centralized async Redis connection pool shared across all agent components.

Redis serves three roles in the agentic layer:
1. Task Queue (Streams) — dispatching work to sub-agents
2. Result Store (Hash) — temporary cache of agent results per incident
3. Session State (Hash + TTL) — tracking orchestrator state per alert
4. Reasoning Events (Stream) — real-time agent trace for WebSocket push

All operations are async (redis.asyncio) to integrate with the asyncio-based
LangGraph orchestrator without blocking.
"""

import os
import logging
from typing import Optional

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

# Module-level connection pool (singleton pattern)
_pool: Optional[aioredis.ConnectionPool] = None
_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """
    Get or create the shared async Redis client.
    Uses a connection pool for efficient connection reuse across
    concurrent agent tasks.
    """
    global _pool, _client

    if _client is None:
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        _pool = aioredis.ConnectionPool.from_url(
            redis_url,
            max_connections=20,
            decode_responses=True,  # return strings instead of bytes
        )
        _client = aioredis.Redis(connection_pool=_pool)
        # Verify connection
        await _client.ping()
        logger.info(f"Redis connected: {redis_url}")

    return _client


async def close_redis():
    """Close the Redis connection pool on shutdown."""
    global _pool, _client
    if _client:
        await _client.aclose()
        _client = None
    if _pool:
        await _pool.aclose()
        _pool = None
        logger.info("Redis connection closed")
