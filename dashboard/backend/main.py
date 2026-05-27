"""Sentinel Dashboard API main application module.

This module initializes the FastAPI application with all routers,
middleware, and lifecycle management for database and Kafka connections.
"""

from contextlib import asynccontextmanager
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from db.connection import init_pool, close_pool
from kafka.consumer import start_plan_consumer
from middleware.rate_limit import RateLimitMiddleware
from routers import auth, alerts, plans, traces, assets, cves, admin, health, role_requests, transfers
from state.redis_client import init_redis, close_redis
from ws.alert_feed import router as ws_alerts_router
from ws.trace_stream import router as ws_trace_router

# Configure logging with timestamp, level, and logger name
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown events.
    
    Initializes database connection pool, Redis, and starts Kafka consumer on startup.
    Closes all connections on shutdown.
    
    Args:
        app: The FastAPI application instance.
    """
    # Startup: Initialize database, Redis, and Kafka consumer
    await init_pool()
    await init_redis()
    await start_plan_consumer()
    yield
    # Shutdown: Cleanup all connections
    await close_redis()
    await close_pool()

# Initialize FastAPI application with lifespan and conditional docs
app = FastAPI(
    title="Sentinel Dashboard API",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,  # Disable docs in production
    redoc_url=None,
    lifespan=lifespan
)

# CORS middleware - restrict origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"]
)

# Rate limiting middleware to prevent abuse
app.add_middleware(RateLimitMiddleware)

# Register API routers with appropriate prefixes
app.include_router(auth.router,        prefix="/api/auth")
app.include_router(alerts.router,      prefix="/api/alerts")
app.include_router(plans.router,       prefix="/api/plans")
app.include_router(traces.router,      prefix="/api/traces")
app.include_router(assets.router,      prefix="/api/assets")
app.include_router(cves.router,        prefix="/api/cves")
app.include_router(admin.router,       prefix="/api/admin")
app.include_router(role_requests.router, prefix="/api")
app.include_router(transfers.router,   prefix="/api/transfers")
app.include_router(health.router)

# Register WebSocket routers (no prefix - paths defined in routers)
app.include_router(ws_alerts_router)
app.include_router(ws_trace_router)