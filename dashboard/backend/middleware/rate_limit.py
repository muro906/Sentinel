"""Rate limiting middleware to prevent API abuse.

Uses a simple in-memory token bucket per IP address.
"""

import time
from collections import defaultdict

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token bucket rate limiter with separate limits for auth endpoints.
    
    Tracks requests per IP address in a sliding 60-second window.
    Login endpoints have stricter limits than general API endpoints.
    """
    
    def __init__(self, app, default_rpm: int = 120, auth_rpm: int = 5):
        """Initialize rate limiter with configurable limits.
        
        Args:
            app: The ASGI application.
            default_rpm: Default requests per minute limit.
            auth_rpm: Stricter limit for authentication endpoints.
        """
        super().__init__(app)
        self.default_rpm = default_rpm
        self.auth_rpm = auth_rpm
        # Map of IP -> (last_request_time, request_count)
        self._buckets: dict[str, tuple[float, int]] = defaultdict(lambda: (time.time(), 0))
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting.
        
        Args:
            request: The incoming HTTP request.
            call_next: Function to call the next middleware/handler.
            
        Raises:
            HTTPException: 429 if rate limit exceeded.
            
        Returns:
            The response from downstream handlers.
        """
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        last, count = self._buckets[ip]
        
        # Reset counter if 60 seconds have passed
        if now - last >= 60:
            count = 0
            last = now
        
        # Apply stricter limits to auth endpoints
        path = str(request.url.path)
        if "/auth/login" in path or "/auth/refresh" in path:
            limit = 20  # Increased from 5 to 20 login attempts per minute
        elif path.startswith("/api/auth"):
            # Other auth endpoints (register, profile, etc) - more lenient
            limit = 60
        else:
            limit = self.default_rpm
        
        # Check rate limit before incrementing
        if count >= limit:
            raise HTTPException(429, "Rate limit exceeded. Please try again later.")
        
        # Update counter and proceed
        self._buckets[ip] = (last, count + 1)
        return await call_next(request)