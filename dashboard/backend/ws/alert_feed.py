"""WebSocket endpoint for real-time alert feed updates.

Pushes new plan notifications to connected dashboard clients.
"""

import asyncio

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from core.security import decode_token
from ws.manager import manager

router = APIRouter()


@router.websocket("/ws/alerts")
async def alert_feed_ws(ws: WebSocket, token: str = Query(...)) -> None:
    """WebSocket endpoint for real-time alert notifications.
    
    Validates JWT from query parameter, then maintains connection
    with periodic ping messages to keep connection alive.
    
    Args:
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
    
    # Register connection and start heartbeat loop
    await manager.connect("feed", ws)
    try:
        while True:
            await asyncio.sleep(30)
            await ws.send_json({"type": "ping"})
    except WebSocketDisconnect:
        manager.disconnect("feed", ws)