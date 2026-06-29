"""WebSocket connection manager for handling multiple concurrent connections."""

import logging
from typing import Dict, List

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections grouped by channel.
    
    Supports multiple channels (e.g., 'feed', 'trace:{alert_id}') with
    multiple concurrent connections per channel.
    """
    
    def __init__(self) -> None:
        """Initialize the connection manager with empty channel registry."""
        # Mapping of channel name to list of active WebSocket connections
        self._channels: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, channel: str, ws: WebSocket) -> None:
        """Accept a WebSocket connection and register it to a channel.

        Args:
            channel: The channel identifier (e.g., 'feed', 'trace:123').
            ws: The WebSocket connection object.
        """
        await ws.accept()
        if channel not in self._channels:
            self._channels[channel] = []
        self._channels[channel].append(ws)
        logger.debug(f"WebSocket connected to channel '{channel}'")

    def register(self, channel: str, ws: WebSocket) -> None:
        """Register an already-accepted WebSocket connection to a channel.

        Use this when the endpoint has already called ws.accept() itself
        (e.g., for pre-connection authentication).

        Args:
            channel: The channel identifier.
            ws: The already-accepted WebSocket connection.
        """
        if channel not in self._channels:
            self._channels[channel] = []
        self._channels[channel].append(ws)
        logger.debug(f"WebSocket registered to channel '{channel}'")
    
    def disconnect(self, channel: str, ws: WebSocket) -> None:
        """Remove a WebSocket connection from a channel.
        
        Args:
            channel: The channel identifier.
            ws: The WebSocket connection to remove.
        """
        if channel in self._channels and ws in self._channels[channel]:
            self._channels[channel].remove(ws)
            logger.debug(f"WebSocket disconnected from channel '{channel}'")
    
    async def broadcast(self, channel: str, message: dict) -> None:
        """Send a message to all connections in a channel.
        
        Args:
            channel: The channel identifier.
            message: The message payload to send as JSON.
        """
        if channel not in self._channels:
            return
        
        # Track disconnected clients for cleanup
        disconnected = []
        for ws in self._channels[channel]:
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket: {e}")
                disconnected.append(ws)
        
        # Clean up dead connections
        for ws in disconnected:
            self.disconnect(channel, ws)


# Global connection manager instance
manager = ConnectionManager()
