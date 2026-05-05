"""
Reasoning Trace Persistence
=============================
Persists reasoning events from Redis Stream into PostgreSQL for long-term
audit storage and historical retrieval. Runs as a background task alongside
the orchestrator.

The dual-write strategy:
- Redis Stream: real-time (WebSocket push to dashboard, ~0ms latency)
- PostgreSQL:   durable  (audit log, historical queries, survives restarts)

This module reads from Redis Streams and batch-inserts into the
reasoning_traces table on a configurable interval.
"""

import asyncio
import json
import logging
from typing import Optional

from agentic.db.connection import get_pool
from agentic.state.redis_client import get_redis

logger = logging.getLogger(__name__)

REASONING_STREAM_PREFIX = "reasoning"
BATCH_SIZE = 50
FLUSH_INTERVAL_SECONDS = 5


async def persist_traces_loop():
    """
    Background loop that reads reasoning events from Redis Streams
    and persists them to PostgreSQL in batches.

    Runs continuously until cancelled. Designed to be started as an
    asyncio task alongside the main orchestrator loop.
    """
    logger.info("Reasoning trace persister started")
    redis = await get_redis()

    # Track last-read IDs per stream
    stream_cursors: dict[str, str] = {}

    while True:
        try:
            # Discover active reasoning streams
            keys = []
            async for key in redis.scan_iter(match=f"{REASONING_STREAM_PREFIX}:*"):
                keys.append(key)

            if not keys:
                await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
                continue

            # Build read request (from last cursor or beginning)
            streams = {}
            for key in keys:
                cursor = stream_cursors.get(key, "0")
                streams[key] = cursor

            # Read new events from all streams
            results = await redis.xread(streams, count=BATCH_SIZE, block=2000)
            if not results:
                await asyncio.sleep(1)
                continue

            # Collect events for batch insert
            events_to_persist = []
            for stream_key, messages in results:
                for entry_id, fields in messages:
                    stream_cursors[stream_key] = entry_id
                    event = _parse_stream_event(fields)
                    if event:
                        events_to_persist.append(event)

            # Batch insert into PostgreSQL
            if events_to_persist:
                await _batch_insert(events_to_persist)
                logger.debug(f"Persisted {len(events_to_persist)} reasoning events")

        except asyncio.CancelledError:
            logger.info("Reasoning trace persister shutting down")
            break
        except Exception as e:
            logger.error(f"Trace persister error: {e}")
            await asyncio.sleep(FLUSH_INTERVAL_SECONDS)


def _parse_stream_event(fields: dict) -> Optional[dict]:
    """Parse a Redis Stream entry into a reasoning trace record."""
    try:
        # Deserialize JSON fields
        parsed = {}
        for key, value in fields.items():
            try:
                parsed[key] = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                parsed[key] = value

        return {
            "event_id": parsed.get("event_id", ""),
            "alert_id": parsed.get("alert_id", ""),
            "timestamp": parsed.get("timestamp", ""),
            "agent": parsed.get("agent", ""),
            "event_type": parsed.get("event_type", ""),
            "action": parsed.get("action", ""),
            "input_summary": parsed.get("input_summary", ""),
            "output_summary": parsed.get("output_summary", ""),
            "full_input": json.dumps(parsed.get("full_input")) if parsed.get("full_input") else None,
            "full_output": json.dumps(parsed.get("full_output")) if parsed.get("full_output") else None,
            "rationale": parsed.get("rationale", ""),
            "duration_ms": int(parsed.get("duration_ms", 0)),
            "confidence": float(parsed["confidence"]) if parsed.get("confidence") else None,
            "error": parsed.get("error"),
        }
    except Exception as e:
        logger.warning(f"Failed to parse stream event: {e}")
        return None


async def _batch_insert(events: list[dict]):
    """Insert a batch of reasoning events into PostgreSQL."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        await conn.executemany("""
            INSERT INTO reasoning_traces
                (event_id, alert_id, timestamp, agent, event_type, action,
                 input_summary, output_summary, full_input, full_output,
                 rationale, duration_ms, confidence, error)
            VALUES ($1, $2, $3::timestamptz, $4, $5, $6, $7, $8,
                    $9::jsonb, $10::jsonb, $11, $12, $13, $14)
            ON CONFLICT (event_id) DO NOTHING
        """, [
            (
                e["event_id"], e["alert_id"], e["timestamp"],
                e["agent"], e["event_type"], e["action"],
                e["input_summary"], e["output_summary"],
                e["full_input"], e["full_output"],
                e["rationale"], e["duration_ms"],
                e["confidence"], e["error"],
            )
            for e in events
        ])
