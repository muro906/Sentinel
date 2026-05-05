"""
PostgreSQL Connection Pool (asyncpg)
=====================================
Provides an async connection pool shared across all database repositories
(CVE, Asset, Incident). Uses asyncpg for high-performance async PostgreSQL
access that integrates naturally with the asyncio-based orchestrator.
"""

import os
import logging
from typing import Optional

import asyncpg

logger = logging.getLogger(__name__)

_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    """Get or create the shared asyncpg connection pool."""
    global _pool

    if _pool is None:
        database_url = os.environ.get(
            "DATABASE_URL",
            "postgresql://sentinel:sentinel_dev@localhost:5432/sentinel"
        )
        _pool = await asyncpg.create_pool(
            database_url,
            min_size=2,
            max_size=10,
            command_timeout=30,
        )
        logger.info("PostgreSQL connection pool created")

    return _pool


async def close_pool():
    """Close the connection pool on shutdown."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("PostgreSQL connection pool closed")
