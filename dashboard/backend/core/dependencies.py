"""Dependency injection utilities for authentication and authorization.

Provides FastAPI dependencies for extracting current user from JWT tokens
and enforcing role-based access control.
"""

from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError

from core.security import decode_token

# HTTP Bearer token security scheme
bearer = HTTPBearer()


@dataclass
class CurrentUser:
    """Authenticated user data extracted from JWT token.
    
    Attributes:
        username: The unique username identifier.
        role: The assigned role (analyst, senior_analyst, admin).
    """
    username: str
    role: str


async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
) -> CurrentUser:
    """Extract and validate the current user from the Authorization header.
    
    Args:
        creds: The HTTP Authorization credentials containing the Bearer token.
        
    Returns:
        CurrentUser object with username and role.
        
    Raises:
        HTTPException: 401 if token is invalid, expired, or wrong type.
    """
    try:
        payload = decode_token(creds.credentials)
        if payload.get("type") != "access":
            raise HTTPException(401, "Invalid token type")
        return CurrentUser(username=payload["sub"], role=payload["role"])
    except JWTError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )


def require_role(*roles: str):
    """Create a dependency that requires specific roles.
    
    Args:
        *roles: Variable number of allowed role names.
        
    Returns:
        A dependency function that validates user role membership.
    """
    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in roles:
            raise HTTPException(403, "Insufficient permissions")
        return user
    return _check


# Predefined role-based access control dependencies
analyst_or_above = require_role("analyst", "senior_analyst", "admin")
senior_or_above = require_role("senior_analyst", "admin")
admin_only = require_role("admin")