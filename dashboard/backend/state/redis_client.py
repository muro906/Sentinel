"""Redis client management for async Redis connections."""

import logging
from typing import Optional

import redis.asyncio as aioredis
from core.config import settings

logger = logging.getLogger(__name__)
_redis: Optional[aioredis.Redis] = None


async def init_redis() -> None:
    """Initialize the Redis connection pool."""
    global _redis
    _redis = aioredis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
        max_connections=20
    )
    logger.info("Redis connection initialized")


async def get_redis() -> aioredis.Redis:
    """Get the Redis client instance.
    
    Returns:
        aioredis.Redis: The Redis client instance.
        
    Raises:
        RuntimeError: If Redis has not been initialized.
    """
    if _redis is None:
        raise RuntimeError("Redis not initialized. Call init_redis() first.")
    return _redis


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global _redis
    if _redis:
        await _redis.close()
        _redis = None
        logger.info("Redis connection closed")
