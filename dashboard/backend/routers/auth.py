"""Authentication router for login, logout, token refresh, and user registration."""

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr

from core.dependencies import admin_only, get_current_user, CurrentUser
from core.email import email_service
from core.security import create_access_token, create_refresh_token, decode_token, hash_password, verify_password
from db.connection import get_pool
from models.auth import TokenResponse

logger = logging.getLogger(__name__)
router = APIRouter()

# Password reset token validity window
RESET_TOKEN_EXPIRE_HOURS = 1


class RegisterRequest(BaseModel):
    """User registration request."""
    username: str
    email: EmailStr
    password: str


class ApproveUserRequest(BaseModel):
    """User approval request by admin."""
    role: str  # analyst, senior_analyst, admin


async def _get_user(username: str) -> Optional[dict]:
    """Fetch user record from database by username.
    
    Args:
        username: The username to look up.
        
    Returns:
        User dictionary with hashed_password, role, and status, or None if not found/inactive.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username,hashed_password,role,status FROM users WHERE username=$1 AND is_active=TRUE",
            username
        )
    return dict(row) if row else None


@router.post("/login", response_model=TokenResponse)
async def login(response: Response, form: OAuth2PasswordRequestForm = Depends()) -> TokenResponse:
    """Authenticate user and issue access/refresh tokens.
    
    Validates credentials against database, sets HTTP-only refresh cookie,
    and returns short-lived access token in response body.
    
    Args:
        response: FastAPI response object for setting cookies.
        form: OAuth2 password credentials (username/password).
        
    Raises:
        HTTPException: 401 if credentials are invalid.
    """
    user = await _get_user(form.username)
    if not user or not verify_password(form.password, user["hashed_password"]):
        raise HTTPException(401, "Invalid credentials")
    
    # Check if user is pending approval
    if user.get("status") == "pending":
        raise HTTPException(403, "Account pending admin approval. Please wait for confirmation.")
    
    # Set long-lived refresh token in HTTP-only cookie
    response.set_cookie(
        "refresh_token",
        create_refresh_token(form.username, user["role"]),
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=8 * 3600,
        path="/api/auth"
    )
    return TokenResponse(
        access_token=create_access_token(form.username, user["role"]),
        token_type="bearer"
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(refresh_token: str = Cookie(default=None)) -> TokenResponse:
    """Refresh an expired access token using the refresh token cookie.
    
    Args:
        refresh_token: The refresh token from HTTP-only cookie.
        
    Raises:
        HTTPException: 401 if refresh token is missing or invalid.
    """
    if not refresh_token:
        raise HTTPException(401, "No refresh token")
    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid token type")
        return TokenResponse(
            access_token=create_access_token(payload["sub"], payload["role"]),
            token_type="bearer"
        )
    except Exception:
        raise HTTPException(401, "Invalid refresh token")


@router.post("/logout")
async def logout(response: Response) -> dict:
    """Logout user by clearing the refresh token cookie.
    
    Args:
        response: FastAPI response object for clearing cookies.
        
    Returns:
        Confirmation message.
    """
    response.delete_cookie("refresh_token", path="/api/auth")
    return {"detail": "Logged out"}


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest) -> dict:
    """Register a new user account.
    
    Creates a pending account that requires admin approval.
    
    Args:
        body: Registration details (username, email, password).
        
    Raises:
        HTTPException: 400 if username or email already exists.
        
    Returns:
        Confirmation message that account is pending approval.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Check if active user with same username exists
        existing_active = await conn.fetchval(
            "SELECT 1 FROM users WHERE username = $1 AND is_active = TRUE", body.username
        )
        if existing_active:
            raise HTTPException(400, "Username already taken")
        
        # Check if active user with same email exists
        existing_email_active = await conn.fetchval(
            "SELECT 1 FROM users WHERE email = $1 AND is_active = TRUE", body.email
        )
        if existing_email_active:
            raise HTTPException(400, "Email already registered")
        
        # Check for inactive/deleted user with same username
        existing_inactive = await conn.fetchrow(
            "SELECT id FROM users WHERE username = $1 AND is_active = FALSE", body.username
        )
        
        hashed_pw = hash_password(body.password)
        
        if existing_inactive:
            # Reactivate the inactive user
            await conn.execute(
                """UPDATE users 
                   SET email = $1, hashed_password = $2, role = 'analyst', 
                       is_active = FALSE, status = 'pending', created_at = NOW()
                   WHERE id = $3""",
                body.email, hashed_pw, existing_inactive["id"]
            )
            logger.info(f"Reactivating inactive user: {body.username} ({body.email})")
            return {
                "detail": "Account reactivated. Please wait for admin approval.",
                "username": body.username,
                "status": "pending",
                "reactivated": True
            }
        else:
            # Create new pending user
            await conn.execute(
                """INSERT INTO users (username, email, hashed_password, role, is_active, status)
                   VALUES ($1, $2, $3, 'analyst', FALSE, 'pending')""",
                body.username, body.email, hashed_pw
            )
            logger.info(f"New user registered: {body.username} ({body.email}) - pending approval")
            return {
                "detail": "Account created successfully. Please wait for admin approval.",
                "username": body.username,
                "status": "pending",
                "reactivated": False
            }


@router.get("/pending-users")
async def list_pending_users(admin: dict = Depends(admin_only)) -> dict:
    """List users awaiting admin approval.
    
    Args:
        admin: Admin authentication dependency.
        
    Returns:
        List of pending user accounts.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, username, email, created_at FROM users WHERE status = 'pending' ORDER BY created_at"
        )
    
    return {
        "users": [
            {
                "id": r["id"],
                "username": r["username"],
                "email": r["email"],
                "requested_at": r["created_at"].isoformat() if r["created_at"] else None
            }
            for r in rows
        ]
    }


@router.post("/approve-user/{user_id}")
async def approve_user(
    user_id: int,
    body: ApproveUserRequest,
    admin: dict = Depends(admin_only)
) -> dict:
    """Approve a pending user account and assign role.
    
    Args:
        user_id: The pending user ID.
        body: Approval details including role.
        admin: Admin authentication dependency.
        
    Raises:
        HTTPException: 404 if user not found or not pending.
        
    Returns:
        Confirmation with user details.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Get user details
        user = await conn.fetchrow(
            "SELECT username, email, status FROM users WHERE id = $1", user_id
        )
        if not user:
            raise HTTPException(404, "User not found")
        if user["status"] != "pending":
            raise HTTPException(400, "User is not pending approval")
        
        # Approve user
        await conn.execute(
            """UPDATE users 
               SET status = 'approved', is_active = TRUE, role = $1 
               WHERE id = $2""",
            body.role, user_id
        )
    
    # Send confirmation email
    await email_service.send_account_confirmation(
        user["email"],
        user["username"],
        body.role
    )
    
    logger.info(f"User approved: {user['username']} with role {body.role} by admin")
    return {
        "detail": "User approved successfully",
        "username": user["username"],
        "role": body.role,
        "email_sent": True
    }


class UpdateProfileRequest(BaseModel):
    email: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.get("/me")
async def get_profile(current_user: CurrentUser = Depends(get_current_user)) -> dict:
    """Get current user's profile information.
    
    Args:
        current_user: Current authenticated user.
        
    Returns:
        User profile details.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT username, email, role, created_at FROM users WHERE username = $1",
            current_user.username
        )
    
    return {
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "created_at": user["created_at"].isoformat() if user["created_at"] else None
    }


@router.patch("/me")
async def update_profile(
    body: UpdateProfileRequest,
    current_user: CurrentUser = Depends(get_current_user)
) -> dict:
    """Update current user's profile (email).
    
    Args:
        body: Profile updates.
        current_user: Current authenticated user.
        
    Raises:
        HTTPException: 400 if email already in use.
        
    Returns:
        Updated profile details.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        if body.email:
            # Check if email is already in use by another user
            existing = await conn.fetchval(
                "SELECT 1 FROM users WHERE email = $1 AND username != $2",
                body.email, current_user.username
            )
            if existing:
                raise HTTPException(400, "Email already in use")
            
            # Update email
            await conn.execute(
                "UPDATE users SET email = $1 WHERE username = $2",
                body.email, current_user.username
            )
    
    return {"detail": "Profile updated", "username": current_user.username, "email": body.email}


@router.post("/me/change-password")
async def change_password(
    body: ChangePasswordRequest,
    current_user: CurrentUser = Depends(get_current_user)
) -> dict:
    """Change current user's password.
    
    Args:
        body: Current and new password.
        current_user: Current authenticated user.
        
    Raises:
        HTTPException: 400 if current password is incorrect.
        
    Returns:
        Confirmation of password change.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Get current password hash
        user = await conn.fetchrow(
            "SELECT hashed_password FROM users WHERE username = $1",
            current_user.username
        )
        
        # Verify current password
        if not verify_password(body.current_password, user["hashed_password"]):
            raise HTTPException(400, "Current password is incorrect")
        
        # Validate new password length
        if len(body.new_password) < 8:
            raise HTTPException(400, "New password must be at least 8 characters")
        
        # Update password
        new_hash = hash_password(body.new_password)
        await conn.execute(
            "UPDATE users SET hashed_password = $1 WHERE username = $2",
            new_hash, current_user.username
        )
    
    return {"detail": "Password changed successfully"}


# ── Password Reset (unauthenticated) ─────────────────────────────────────────

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@router.post("/forgot-password")
async def forgot_password(body: ForgotPasswordRequest, request: Request) -> dict:
    """Request a password reset link sent to the user's email.

    Deliberately returns the same response whether or not the email is found,
    to prevent user enumeration attacks.

    Args:
        body: The email address to send the reset link to.
        request: FastAPI request object (used to build the reset URL).

    Returns:
        Generic confirmation message.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT username, email FROM users WHERE email = $1 AND is_active = TRUE",
            body.email
        )

        if user:
            # Generate a cryptographically secure random token
            raw_token = secrets.token_urlsafe(48)
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            expires_at = datetime.now(timezone.utc) + timedelta(hours=RESET_TOKEN_EXPIRE_HOURS)

            # Invalidate any previous unused tokens for this user
            await conn.execute(
                "UPDATE password_reset_tokens SET used = TRUE WHERE username = $1 AND used = FALSE",
                user["username"]
            )

            # Store the new token hash
            await conn.execute(
                """INSERT INTO password_reset_tokens (username, token_hash, expires_at)
                   VALUES ($1, $2, $3)""",
                user["username"], token_hash, expires_at
            )

            # Build the reset URL (frontend handles it)
            base_url = str(request.base_url).rstrip("/")
            # In production the gateway serves frontend at root; use relative path
            reset_link = f"{base_url}/reset-password?token={raw_token}"

            await email_service.send_password_reset_email(
                to_email=user["email"],
                username=user["username"],
                reset_link=reset_link
            )

            logger.info(f"Password reset requested for {user['username']}")

    # Always return the same response (prevents email enumeration)
    return {
        "detail": "If that email address is registered, you will receive a reset link shortly."
    }


@router.post("/reset-password")
async def reset_password(body: ResetPasswordRequest) -> dict:
    """Reset a user's password using a valid reset token.

    Args:
        body: The reset token and new desired password.

    Raises:
        HTTPException: 400 if the token is invalid, expired, or already used.
        HTTPException: 400 if the new password is too short.

    Returns:
        Confirmation of successful password reset.
    """
    if len(body.new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    token_hash = hashlib.sha256(body.token.encode()).hexdigest()

    pool = await get_pool()
    async with pool.acquire() as conn:
        record = await conn.fetchrow(
            """SELECT id, username, expires_at, used
               FROM password_reset_tokens
               WHERE token_hash = $1""",
            token_hash
        )

        if not record:
            raise HTTPException(400, "Invalid or expired reset token")

        if record["used"]:
            raise HTTPException(400, "This reset link has already been used")

        if record["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(400, "Reset link has expired. Please request a new one.")

        new_hash = hash_password(body.new_password)

        # Update password and mark token as used atomically
        async with conn.transaction():
            await conn.execute(
                "UPDATE users SET hashed_password = $1 WHERE username = $2",
                new_hash, record["username"]
            )
            await conn.execute(
                "UPDATE password_reset_tokens SET used = TRUE WHERE id = $1",
                record["id"]
            )

        logger.info(f"Password reset completed for {record['username']}")

    return {"detail": "Password reset successfully. You can now log in with your new password."}