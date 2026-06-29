"""WebSocket endpoint for streaming agent reasoning traces.

Streams real-time agent activity from Redis streams to connected clients.
"""

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.security import decode_token
from state.redis_client import get_redis
from ws.manager import manager

router = APIRouter()


@router.websocket("/ws/alerts/{alert_id}/trace")
async def trace_ws(alert_id: str, ws: WebSocket) -> None:
    """WebSocket endpoint for streaming reasoning traces for an alert.

    Accepts the connection, then expects the client to send a JSON auth
    message as the very first frame: {"type": "auth", "token": "<jwt>"}.
    The token is validated before the connection is registered, keeping
    the JWT out of URLs and server access logs.

    Connection is closed with code 4001 if authentication fails or times out.
    """
    await ws.accept()

    try:
        auth_msg = await asyncio.wait_for(ws.receive_json(), timeout=10)
    except (asyncio.TimeoutError, Exception):
        await ws.close(code=4001)
        return

    token = auth_msg.get("token") if isinstance(auth_msg, dict) else None
    if not token:
        await ws.close(code=4001)
        return

    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            await ws.close(code=4001)
            return
    except Exception:
        await ws.close(code=4001)
        return

    manager.register(f"trace:{alert_id}", ws)
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