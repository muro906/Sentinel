"""WebSocket endpoint for real-time alert feed updates.

Pushes new plan notifications to connected dashboard clients.
"""

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.security import decode_token
from ws.manager import manager

router = APIRouter()


@router.websocket("/ws/alerts")
async def alert_feed_ws(ws: WebSocket) -> None:
    """WebSocket endpoint for real-time alert notifications.

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

    manager.register("feed", ws)
    try:
        while True:
            await asyncio.sleep(30)
            await ws.send_json({"type": "ping"})
    except WebSocketDisconnect:
        manager.disconnect("feed", ws)