"""Health check router for monitoring and load balancers."""

from fastapi import APIRouter, Depends, HTTPException, status

from core.dependencies import get_current_user
from db.connection import get_pool
from state.redis_client import get_redis
import asyncio

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Basic health check endpoint.
    
    Returns:
        Simple health status. Does not check dependencies.
    """
    return {"status": "healthy"}


@router.get("/ready")
async def readiness_check() -> dict:
    """Readiness probe - checks database and Redis connectivity.
    
    Used by Kubernetes/orchestrators to determine if service is ready.
    
    Raises:
        HTTPException: 503 if any dependency is unavailable.
        
    Returns:
        Readiness status with component health.
    """
    health = {"database": False, "redis": False}
    
    # Check PostgreSQL
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        health["database"] = True
    except Exception as e:
        health["database_error"] = str(e)
    
    # Check Redis
    try:
        redis = await get_redis()
        await redis.ping()
        health["redis"] = True
    except Exception as e:
        health["redis_error"] = str(e)
    
    if not all([health["database"], health["redis"]]):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=health
        )
    
    return {"status": "ready", "checks": health}


@router.get("/me")
async def current_user_info(user: dict = Depends(get_current_user)) -> dict:
    """Get current authenticated user information.
    
    Args:
        user: Current user from JWT token.
        
    Returns:
        User profile information.
    """
    return {
        "username": user.username,
        "role": user.role,
    }
