"""PostgreSQL database connection management.

Provides connection pooling and lifecycle management for async PostgreSQL
connections using asyncpg.
"""

import logging
from typing import Optional

import asyncpg

from core.config import settings

logger = logging.getLogger(__name__)

# Module-level connection pool (initialized once)
_pool: Optional[asyncpg.Pool] = None


async def init_pool() -> None:
    """Initialize the PostgreSQL connection pool.
    
    Creates a pool with 2-10 connections and 30-second command timeout.
    Must be called once before any database operations.
    """
    global _pool
    _pool = await asyncpg.create_pool(
        settings.DATABASE_URL,
        min_size=2,
        max_size=10,
        command_timeout=30
    )
    logger.info("PostgreSQL pool initialized")


async def get_pool() -> asyncpg.Pool:
    """Get the initialized connection pool.
    
    Returns:
        The asyncpg connection pool instance.
        
    Raises:
        RuntimeError: If the pool has not been initialized.
    """
    if _pool is None:
        raise RuntimeError("Pool not initialized")
    return _pool


async def close_pool() -> None:
    """Close the connection pool and cleanup resources.
    
    Should be called during application shutdown.
    """
    global _pool
    if _pool:
        await _pool.close()
        _pool = None