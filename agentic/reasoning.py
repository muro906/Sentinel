"""Reasoning trace emitter for the simplified orchestrator.

Writes trace events to PostgreSQL so the dashboard can display them.
Also attempts Redis for live WebSocket streaming if redis is available.
"""
import json
import logging
import os
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://sentinel:sentinel@localhost:5432/sentinel"
)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


async def emit_trace(
    alert_id: str,
    event_type: str,
    agent: str,
    action: str,
    rationale: str,
    input_summary: str = "",
    output_summary: str = "",
    full_input: dict | None = None,
    full_output: dict | None = None,
    duration_ms: int = 0,
    confidence: float | None = None,
    error: str | None = None,
):
    """Emit a reasoning trace event to PostgreSQL (and Redis if available)."""
    event_id = f"evt-{uuid.uuid4().hex[:12]}"
    ts = datetime.now(timezone.utc)

    # ── PostgreSQL ──────────────────────────────────────────────────────────
    try:
        import asyncpg
        conn = await asyncpg.connect(DB_URL)
        try:
            await conn.execute(
                """
                INSERT INTO reasoning_traces
                    (event_id, alert_id, timestamp, agent, event_type, action,
                     input_summary, output_summary, full_input, full_output,
                     rationale, duration_ms, confidence, error)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb,
                        $11, $12, $13, $14)
                ON CONFLICT (event_id) DO NOTHING
                """,
                event_id, alert_id, ts, agent, event_type, action,
                input_summary, output_summary,
                json.dumps(full_input, default=str) if full_input else None,
                json.dumps(full_output, default=str) if full_output else None,
                rationale, duration_ms, confidence, error,
            )
        finally:
            await conn.close()
    except Exception as e:
        logger.warning(f"Failed to persist trace to DB: {e}")

    # ── Redis Stream (best-effort) ───────────────────────────────────────────
    try:
        from redis.asyncio import Redis
        redis = Redis.from_url(REDIS_URL, decode_responses=True)
        payload = {
            "event_id": event_id,
            "alert_id": alert_id,
            "timestamp": ts.isoformat(),
            "agent": agent,
            "event_type": event_type,
            "action": action,
            "input_summary": input_summary,
            "output_summary": output_summary,
            "rationale": rationale,
            "duration_ms": str(duration_ms),
        }
        if confidence is not None:
            payload["confidence"] = str(confidence)
        if error:
            payload["error"] = error
        if full_input:
            payload["full_input"] = json.dumps(full_input, default=str)
        if full_output:
            payload["full_output"] = json.dumps(full_output, default=str)

        await redis.xadd(f"reasoning:{alert_id}", payload, maxlen=500)
        await redis.expire(f"reasoning:{alert_id}", 7200)
        await redis.aclose()
    except Exception as e:
        logger.debug(f"Redis trace emission skipped: {e}")
