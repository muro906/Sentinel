"""WebSocket endpoint for streaming agent reasoning traces.

Streams real-time agent activity from Redis streams to connected clients.
"""

import json

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from core.security import decode_token
from state.redis_client import get_redis
from ws.manager import manager

router = APIRouter()


@router.websocket("/ws/alerts/{alert_id}/trace")
async def trace_ws(alert_id: str, ws: WebSocket, token: str = Query(...)) -> None:
    """WebSocket endpoint for streaming reasoning traces for an alert.
    
    Connects to Redis stream and pushes new trace events to the client.
    Uses blocking read with timeout to enable periodic ping messages.
    
    Args:
        alert_id: The alert identifier for the trace stream.
        ws: The WebSocket connection object.
        token: JWT access token passed as query parameter.
        
    Note:
        Connection is closed with code 4001 if authentication fails.
    """
    # Validate JWT token
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            await ws.close(code=4001)
            return
    except Exception:
        await ws.close(code=4001)
        return
    
    # Register connection to alert-specific channel
    await manager.connect(f"trace:{alert_id}", ws)
    redis = await get_redis()
    last_id = "0-0"  # Start from beginning of stream
    try:
        while True:
            # Block for up to 5 seconds waiting for new messages
            entries = await redis.xread(
                {f"reasoning:{alert_id}": last_id},
                count=20,
                block=5000
            )
            if not entries:
                # Send ping to keep connection alive
                await ws.send_json({"type": "ping"})
                continue
            # Process and forward trace events
            for _key, messages in entries:
                for eid, fields in messages:
                    last_id = eid
                    event = {}
                    for k, v in fields.items():
                        try:
                            event[k] = json.loads(v)
                        except Exception:
                            event[k] = v
                    await ws.send_json(event)
    except WebSocketDisconnect:
        manager.disconnect(f"trace:{alert_id}", ws)