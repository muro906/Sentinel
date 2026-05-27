"""Role change request router for users requesting role upgrades."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from core.dependencies import admin_only, get_current_user, CurrentUser
from core.email import email_service
from db.connection import get_pool

router = APIRouter()


class RoleChangeRequest(BaseModel):
    """User request for role change."""
    requested_role: str
    reason: str


class ApproveRoleRequest(BaseModel):
    """Admin approval/denial of role change."""
    approve: bool  # True to approve, False to deny
    notes: Optional[str] = None


@router.post("/me/request-role")
async def request_role_change(
    body: RoleChangeRequest,
    current_user: CurrentUser = Depends(get_current_user)
) -> dict:
    """Submit a role change request for admin review.
    
    Args:
        body: Request details with desired role and reason.
        current_user: Current authenticated user.
        
    Raises:
        HTTPException: 400 if invalid role or already has requested role.
        HTTPException: 409 if pending request already exists.
        
    Returns:
        Confirmation of request submission.
    """
    valid_roles = ["analyst", "senior_analyst", "admin"]
    if body.requested_role not in valid_roles:
        raise HTTPException(400, f"Invalid role. Must be one of: {', '.join(valid_roles)}")
    
    if current_user.role == body.requested_role:
        raise HTTPException(400, "You already have this role")
    
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Check for existing pending request
        existing = await conn.fetchval(
            """SELECT 1 FROM role_change_requests 
               WHERE username = $1 AND status = 'pending'""",
            current_user.username
        )
        if existing:
            raise HTTPException(409, "You already have a pending role change request")
        
        # Get user email
        user_email = await conn.fetchval(
            "SELECT email FROM users WHERE username = $1",
            current_user.username
        )
        
        # Create request
        await conn.execute(
            """INSERT INTO role_change_requests 
               (username, "current_role", requested_role, reason, status, created_at)
               VALUES ($1, $2, $3, $4, 'pending', NOW())""",
            current_user.username,
            current_user.role,
            body.requested_role,
            body.reason
        )
        
        # Notify admins via email
        admin_rows = await conn.fetch(
            "SELECT email, username FROM users WHERE role = 'admin' AND is_active = TRUE"
        )
        
        for admin in admin_rows:
            if admin["email"]:
                await email_service.send_email(
                    to_email=admin["email"],
                    subject=f"Role Change Request: {current_user.username}",
                    html_content=f"""
                    <p>Hello {admin['username']},</p>
                    <p>User <strong>{current_user.username}</strong> has requested a role change.</p>
                    <div style="background: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <p><strong>Current Role:</strong> {current_user.role.replace('_', ' ').title()}</p>
                        <p><strong>Requested Role:</strong> {body.requested_role.replace('_', ' ').title()}</p>
                        <p><strong>Reason:</strong> {body.reason}</p>
                    </div>
                    <p>Please review this request in the admin dashboard.</p>
                    """
                )
    
    return {
        "detail": "Role change request submitted for admin review",
        "username": current_user.username,
        "requested_role": body.requested_role,
        "status": "pending"
    }


@router.get("/admin/role-requests")
async def list_role_requests(
    status: Optional[str] = None,
    _: None = Depends(admin_only)
) -> dict:
    """List all role change requests (admin only).
    
    Args:
        status: Optional filter by status (pending, approved, denied).
        _: Admin authentication.
        
    Returns:
        List of role change requests.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        if status:
            rows = await conn.fetch(
                """SELECT id, username, current_role, requested_role, reason, 
                          status, admin_notes, created_at, processed_at
                   FROM role_change_requests 
                   WHERE status = $1 
                   ORDER BY created_at DESC""",
                status
            )
        else:
            rows = await conn.fetch(
                """SELECT id, username, current_role, requested_role, reason,
                          status, admin_notes, created_at, processed_at
                   FROM role_change_requests 
                   ORDER BY created_at DESC"""
            )
    
    return {
        "requests": [
            {
                "id": r["id"],
                "username": r["username"],
                "current_role": r["current_role"],
                "requested_role": r["requested_role"],
                "reason": r["reason"],
                "status": r["status"],
                "admin_notes": r["admin_notes"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "processed_at": r["processed_at"].isoformat() if r["processed_at"] else None,
            }
            for r in rows
        ]
    }


@router.post("/admin/role-requests/{request_id}/process")
async def process_role_request(
    request_id: int,
    body: ApproveRoleRequest,
    admin: CurrentUser = Depends(get_current_user),
    _: None = Depends(admin_only)
) -> dict:
    """Approve or deny a role change request (admin only).
    
    Args:
        request_id: The request ID to process.
        body: Approval decision and optional notes.
        admin: Current admin user.
        _: Admin verification.
        
    Raises:
        HTTPException: 404 if request not found.
        HTTPException: 400 if request already processed.
        
    Returns:
        Confirmation of decision.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Get request details
        request = await conn.fetchrow(
            "SELECT * FROM role_change_requests WHERE id = $1",
            request_id
        )
        if not request:
            raise HTTPException(404, "Role change request not found")
        
        if request["status"] != "pending":
            raise HTTPException(400, f"Request already {request['status']}")
        
        new_status = "approved" if body.approve else "denied"
        
        # Update request status
        await conn.execute(
            """UPDATE role_change_requests 
               SET status = $1, admin_notes = $2, processed_by = $3, processed_at = NOW()
               WHERE id = $4""",
            new_status,
            body.notes,
            admin.username,
            request_id
        )
        
        # If approved, update user's role
        if body.approve:
            await conn.execute(
                "UPDATE users SET role = $1 WHERE username = $2",
                request["requested_role"],
                request["username"]
            )
        
        # Get user email for notification
        user_email = await conn.fetchval(
            "SELECT email FROM users WHERE username = $1",
            request["username"]
        )
        
        # Send email notification to user
        if user_email:
            if body.approve:
                subject = "Role Change Approved"
                html_content = f"""
                <p>Hello {request['username']},</p>
                <p>Your role change request has been <strong>approved</strong>!</p>
                <div style="background: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>New Role:</strong> {request['requested_role'].replace('_', ' ').title()}</p>
                    <p><strong>Previous Role:</strong> {request['current_role'].replace('_', ' ').title()}</p>
                    {f"<p><strong>Admin Notes:</strong> {body.notes}</p>" if body.notes else ""}
                </div>
                <p>Please log out and log back in for your new privileges to take effect.</p>
                """
            else:
                subject = "Role Change Request Denied"
                html_content = f"""
                <p>Hello {request['username']},</p>
                <p>Your role change request has been <strong>denied</strong>.</p>
                <div style="background: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>Requested Role:</strong> {request['requested_role'].replace('_', ' ').title()}</p>
                    <p><strong>Current Role:</strong> {request['current_role'].replace('_', ' ').title()}</p>
                    {f"<p><strong>Reason:</strong> {body.notes}</p>" if body.notes else ""}
                </div>
                <p>If you have questions, please contact your administrator.</p>
                """
            
            await email_service.send_email(
                to_email=user_email,
                subject=subject,
                html_content=html_content
            )
    
    return {
        "detail": f"Role change request {new_status}",
        "request_id": request_id,
        "username": request["username"],
        "new_role": request["requested_role"] if body.approve else request["current_role"],
        "status": new_status
    }


@router.get("/me/role-request-status")
async def my_role_request_status(
    current_user: CurrentUser = Depends(get_current_user)
) -> dict:
    """Get current user's pending role change request status.
    
    Args:
        current_user: Current authenticated user.
        
    Returns:
        Pending request details or empty if none.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        request = await conn.fetchrow(
            """SELECT id, requested_role, reason, status, created_at
               FROM role_change_requests
               WHERE username = $1 AND status = 'pending'
               ORDER BY created_at DESC
               LIMIT 1""",
            current_user.username
        )
    
    if request:
        return {
            "has_pending_request": True,
            "request": {
                "id": request["id"],
                "requested_role": request["requested_role"],
                "reason": request["reason"],
                "status": request["status"],
                "created_at": request["created_at"].isoformat()
            }
        }
    
    return {"has_pending_request": False}
