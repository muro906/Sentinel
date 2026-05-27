"""Admin router for analyst management and administrative functions."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from core.dependencies import admin_only
from core.email import email_service
from db.connection import get_pool

router = APIRouter()


class UpdateRoleRequest(BaseModel):
    role: str  # analyst, senior_analyst, admin


class DeleteUserRequest(BaseModel):
    username: str


@router.get("/analysts")
async def list_analysts(_: None = Depends(admin_only)) -> dict:
    """List all active analysts with their status.
    
    Args:
        _: Admin-only authentication dependency.
        
    Returns:
        Dictionary containing list of analysts.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT username, role, is_active FROM users WHERE is_active=TRUE ORDER BY username"
        )
    
    analysts = []
    for row in rows:
        analysts.append({
            "id": row["username"],
            "name": row["username"].replace("_", " ").title(),
            "role": row["role"],
            "status": "online",  # Placeholder - would be dynamic in production
            "avatar": "".join([p[0].upper() for p in row["username"].split("_") if p])[:2]
        })
    
    return {"analysts": analysts}


@router.get("/users")
async def list_all_users(_: None = Depends(admin_only)) -> dict:
    """List all users with their details.
    
    Args:
        _: Admin-only authentication dependency.
        
    Returns:
        Dictionary containing list of all users.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, username, email, role, is_active, status, created_at FROM users ORDER BY username"
        )
    
    return {
        "users": [
            {
                "id": r["id"],
                "username": r["username"],
                "email": r["email"],
                "role": r["role"],
                "is_active": r["is_active"],
                "status": r["status"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None
            }
            for r in rows
        ]
    }


@router.post("/users/{username}/role")
async def update_user_role(
    username: str,
    body: UpdateRoleRequest,
    _: None = Depends(admin_only)
) -> dict:
    """Update a user's role.
    
    Args:
        username: The username to update.
        body: New role assignment.
        _: Admin-only authentication dependency.
        
    Raises:
        HTTPException: 404 if user not found.
        
    Returns:
        Confirmation with updated role.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Check if user exists
        user = await conn.fetchrow(
            "SELECT username, email FROM users WHERE username = $1", username
        )
        if not user:
            raise HTTPException(404, "User not found")
        
        # Update role
        await conn.execute(
            "UPDATE users SET role = $1 WHERE username = $2",
            body.role, username
        )
        
        # Send email notification
        if user["email"]:
            await email_service.send_email(
                to_email=user["email"],
                subject="Your Role Has Been Updated",
                html_content=f"""
                <p>Hello {username},</p>
                <p>Your role has been updated to: <strong>{body.role.replace('_', ' ').title()}</strong></p>
                <p>Please log out and log back in for changes to take effect.</p>
                """,
                text_content=f"Your role has been updated to: {body.role}. Please log out and log back in."
            )
    
    return {"detail": "Role updated successfully", "username": username, "role": body.role}


@router.delete("/users/{username}")
async def delete_user(
    username: str,
    _: None = Depends(admin_only)
) -> dict:
    """Delete (deactivate) a user account.
    
    Args:
        username: The username to delete.
        _: Admin-only authentication dependency.
        
    Raises:
        HTTPException: 404 if user not found.
        
    Returns:
        Confirmation of deletion.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Check if user exists
        user = await conn.fetchrow(
            "SELECT username, email, role FROM users WHERE username = $1", username
        )
        if not user:
            raise HTTPException(404, "User not found")
        
        # Prevent deleting admin users (safety measure)
        if user["role"] == "admin":
            # Check if this is the last admin
            admin_count = await conn.fetchval(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = TRUE"
            )
            if admin_count <= 1:
                raise HTTPException(400, "Cannot delete the last admin account")
        
        # Soft delete - deactivate account
        await conn.execute(
            "UPDATE users SET is_active = FALSE, status = 'inactive' WHERE username = $1",
            username
        )
        
        # Send email notification
        if user["email"]:
            await email_service.send_email(
                to_email=user["email"],
                subject="Account Deactivated",
                html_content=f"""
                <p>Hello {username},</p>
                <p>Your Sentinel SOC account has been deactivated by an administrator.</p>
                <p>If you believe this is an error, please contact your system administrator.</p>
                """,
                text_content="Your account has been deactivated. Contact admin if this is an error."
            )
    
    return {"detail": "User account deactivated", "username": username}


@router.get("/stats")
async def get_dashboard_stats(_: None = Depends(admin_only)) -> dict:
    """Get dashboard statistics for admin overview.
    
    Args:
        _: Admin-only authentication dependency.
        
    Returns:
        Summary statistics about incidents and system state.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Count incidents by status
        total = await conn.fetchval("SELECT COUNT(*) FROM incidents")
        pending = await conn.fetchval("SELECT COUNT(*) FROM incidents WHERE approval_status='pending'")
        approved = await conn.fetchval("SELECT COUNT(*) FROM incidents WHERE approval_status='approved'")
        critical = await conn.fetchval("SELECT COUNT(*) FROM incidents WHERE priority='critical'")
        
        # Count active users
        active_users = await conn.fetchval("SELECT COUNT(*) FROM users WHERE is_active=TRUE")
    
    return {
        "incidents": {
            "total": total,
            "pending": pending,
            "approved": approved,
            "critical": critical,
        },
        "users": {
            "active": active_users
        }
    }
