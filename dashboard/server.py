"""
Sentinel Dashboard – FastAPI WebSocket server.

Consumes from the Kafka `network-features` topic and broadcasts each
feature vector to all connected browser clients via WebSocket.
Also serves the static dashboard HTML.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from confluent_kafka import Consumer, KafkaError

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
log = logging.getLogger("sentinel.dashboard")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC     = os.getenv("KAFKA_TOPIC", "network-features")
HTML_PATH       = Path(__file__).parent / "index.html"

app = FastAPI(title="Sentinel Dashboard")

# ── Connection manager ────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self) -> None:
        self._clients: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.append(ws)
        log.info("Client connected. Total: %d", len(self._clients))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients = [c for c in self._clients if c is not ws]
        log.info("Client disconnected. Total: %d", len(self._clients))

    async def broadcast(self, message: str) -> None:
        async with self._lock:
            dead: list[WebSocket] = []
            for client in self._clients:
                try:
                    await client.send_text(message)
                except Exception:
                    dead.append(client)
            for d in dead:
                self._clients.remove(d)


manager = ConnectionManager()
_event_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=500)


# ── Kafka consumer (runs in background thread) ─────────────────────────────────

def _kafka_consumer_thread(loop: asyncio.AbstractEventLoop) -> None:
    """Blocking Kafka consumer that pushes messages into the asyncio queue."""
    conf = {
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id":          "sentinel-dashboard",
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,
    }

    # Wait for Kafka to be ready
    for attempt in range(30):
        try:
            consumer = Consumer(conf)
            consumer.subscribe([KAFKA_TOPIC])
            log.info("[kafka] Subscribed to '%s'", KAFKA_TOPIC)
            break
        except Exception as exc:
            log.warning("[kafka] Attempt %d – %s", attempt + 1, exc)
            time.sleep(5)
    else:
        log.error("[kafka] Could not connect. Dashboard will show empty data.")
        return

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    log.warning("[kafka] Error: %s", msg.error())
                continue
            try:
                payload = msg.value().decode("utf-8")
                # Wrap with type for the frontend
                envelope = json.dumps({"type": "feature", "data": json.loads(payload)})
                asyncio.run_coroutine_threadsafe(
                    _event_queue.put(envelope), loop
                )
            except Exception as exc:
                log.warning("[kafka] Parse error: %s", exc)
    finally:
        consumer.close()


# ── Background broadcaster ─────────────────────────────────────────────────────

async def _broadcaster() -> None:
    """Pull events from the queue and broadcast to all WebSocket clients."""
    while True:
        message = await _event_queue.get()
        await manager.broadcast(message)


# ── Startup / shutdown ─────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    loop = asyncio.get_event_loop()
    t = threading.Thread(target=_kafka_consumer_thread, args=(loop,), daemon=True)
    t.start()
    asyncio.create_task(_broadcaster())
    log.info("Sentinel Dashboard ready.")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(HTML_PATH.read_text())


@app.get("/health")
async def health():
    return {"status": "ok", "connected_clients": len(manager._clients)}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # Keep connection alive; client sends pings
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(ws)
