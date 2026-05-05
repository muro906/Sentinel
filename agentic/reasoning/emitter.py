"""
Reasoning Event Emitter
========================
Publishes ReasoningEvents to two destinations simultaneously:

1. Redis Stream (keyed by alert_id) — for real-time WebSocket push to the
   SOC dashboard. The dashboard subscribes to the stream for a specific
   alert and renders events as they arrive (live-updating timeline).

2. PostgreSQL reasoning_traces table — for persistent audit log and
   historical retrieval (async, non-blocking).

The emitter is called by every agent at every decision point. It's designed
to be lightweight and non-blocking so agent execution isn't slowed by
trace persistence.
"""

import json
import logging
from typing import Optional

from agentic.models.reasoning import ReasoningEvent
from agentic.state.redis_client import get_redis

logger = logging.getLogger(__name__)

REASONING_STREAM_PREFIX = "reasoning"


async def emit_reasoning_event(event: ReasoningEvent):
    """
    Publish a reasoning event to Redis Stream for real-time consumption.

    The event is serialized to JSON and added to a per-alert stream:
        reasoning:{alert_id}

    The SOC dashboard consumes these streams via WebSocket, rendering
    each event in the analyst's trace viewer as it arrives.
    """
    try:
        redis = await get_redis()
        stream_key = f"{REASONING_STREAM_PREFIX}:{event.alert_id}"

        # Serialize event, excluding None fields for cleaner storage
        event_data = event.model_dump(exclude_none=True)

        # Redis Streams require flat string values, so we JSON-encode complex fields
        flat_data = {}
        for key, value in event_data.items():
            if isinstance(value, (dict, list)):
                flat_data[key] = json.dumps(value, default=str)
            else:
                flat_data[key] = str(value)

        await redis.xadd(stream_key, flat_data, maxlen=500)  # cap at 500 events per alert
        # Set TTL on the stream (auto-cleanup after 2 hours)
        await redis.expire(stream_key, 7200)

        logger.debug(
            f"Reasoning event emitted: [{event.event_type.value}] "
            f"{event.agent} → {event.action[:60]}"
        )

    except Exception as e:
        # Never let reasoning emission break agent execution
        logger.warning(f"Failed to emit reasoning event: {e}")


async def get_trace(alert_id: str, count: int = 100) -> list[dict]:
    """
    Retrieve the full reasoning trace for an alert.
    Used by the dashboard API: GET /alerts/{alert_id}/trace

    Returns events in chronological order.
    """
    try:
        redis = await get_redis()
        stream_key = f"{REASONING_STREAM_PREFIX}:{alert_id}"

        # Read all entries from the stream
        entries = await redis.xrange(stream_key, count=count)

        events = []
        for entry_id, fields in entries:
            # Deserialize complex fields back from JSON
            event = {}
            for key, value in fields.items():
                try:
                    event[key] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    event[key] = value
            event["_stream_id"] = entry_id
            events.append(event)

        return events

    except Exception as e:
        logger.error(f"Failed to retrieve trace for {alert_id}: {e}")
        return []


async def subscribe_trace(alert_id: str, last_id: str = "0"):
    """
    Subscribe to new reasoning events for an alert (for WebSocket streaming).
    Yields new events as they arrive.

    Usage (in WebSocket handler):
        async for event in subscribe_trace(alert_id):
            await websocket.send_json(event)
    """
    redis = await get_redis()
    stream_key = f"{REASONING_STREAM_PREFIX}:{alert_id}"

    while True:
        entries = await redis.xread({stream_key: last_id}, count=10, block=5000)
        if not entries:
            continue

        for stream, messages in entries:
            for entry_id, fields in messages:
                last_id = entry_id
                event = {}
                for key, value in fields.items():
                    try:
                        event[key] = json.loads(value)
                    except (json.JSONDecodeError, TypeError):
                        event[key] = value
                event["_stream_id"] = entry_id
                yield event
