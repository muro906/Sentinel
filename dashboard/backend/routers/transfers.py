"""Alert transfer request router — peer-to-peer alert handoff workflow."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core.dependencies import analyst_or_above, get_current_user, CurrentUser
from core.email import email_service
from db.connection import get_pool
from ws.manager import manager

logger = logging.getLogger(__name__)
router = APIRouter()


class TransferRequest(BaseModel):
    alert_id: str
    to_user: str
    reason: str


class RespondRequest(BaseModel):
    accept: bool


@router.post("")
async def request_transfer(
    body: TransferRequest,
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(analyst_or_above),
) -> dict:
    """Request to transfer an alert to another analyst.

    Only the currently assigned analyst (or admin) may initiate a transfer.
    Only one pending transfer per alert is allowed at a time.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Verify alert exists and current user is the assignee
        alert = await conn.fetchrow(
            "SELECT alert_id, classification, priority, assigned_to FROM incidents WHERE alert_id = $1",
            body.alert_id,
        )
        if not alert:
            raise HTTPException(404, "Alert not found")

        if alert["assigned_to"] != user.username and user.role not in ("admin", "senior_analyst"):
            raise HTTPException(403, "Only the currently assigned analyst can initiate a transfer")

        # Check recipient exists
        recipient = await conn.fetchrow(
            "SELECT username, email FROM users WHERE username = $1 AND is_active = TRUE",
            body.to_user,
        )
        if not recipient:
            raise HTTPException(404, f"User '{body.to_user}' not found")

        if body.to_user == user.username:
            raise HTTPException(400, "Cannot transfer alert to yourself")

        # Only one pending transfer per alert
        existing = await conn.fetchval(
            "SELECT id FROM alert_transfer_requests WHERE alert_id = $1 AND status = 'pending'",
            body.alert_id,
        )
        if existing:
            raise HTTPException(409, "There is already a pending transfer request for this alert")

        # Create transfer request
        req_id = await conn.fetchval(
            """INSERT INTO alert_transfer_requests (alert_id, from_user, to_user, reason, status, created_at)
               VALUES ($1, $2, $3, $4, 'pending', NOW()) RETURNING id""",
            body.alert_id, user.username, body.to_user, body.reason,
        )

    # Notify recipient via WebSocket
    await manager.broadcast("feed", {
        "type": "transfer_request",
        "transfer_id": req_id,
        "alert_id": body.alert_id,
        "alert_classification": alert["classification"],
        "alert_priority": alert["priority"],
        "from_user": user.username,
        "to_user": body.to_user,
        "reason": body.reason,
    })

    # Email recipient
    if recipient["email"]:
        await email_service.send_email(
            to_email=recipient["email"],
            subject=f"Alert Transfer Request: {alert['classification']}",
            html_content=f"""
            <p>Hello {recipient['username']},</p>
            <p><strong>{user.username}</strong> wants to transfer alert
               <strong>{alert['classification']}</strong> ({alert['priority']} priority) to you.</p>
            <blockquote style="border-left: 3px solid #4b5563; padding-left: 12px; color: #6b7280;">
              {body.reason}
            </blockquote>
            <p>Log in to the Sentinel dashboard to accept or decline this transfer.</p>
            """,
        )

    logger.info(f"Transfer request {req_id}: {user.username} → {body.to_user} for alert {body.alert_id}")
    return {"transfer_id": req_id, "status": "pending", "to_user": body.to_user}


@router.post("/{transfer_id}/respond")
async def respond_to_transfer(
    transfer_id: int,
    body: RespondRequest,
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(analyst_or_above),
) -> dict:
    """Accept or decline an incoming transfer request.

    Only the intended recipient may respond.
    Accepting reassigns the alert and cancels any other pending requests for it.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        req = await conn.fetchrow(
            """SELECT r.*, i.classification, i.priority
               FROM alert_transfer_requests r
               JOIN incidents i ON i.alert_id = r.alert_id
               WHERE r.id = $1""",
            transfer_id,
        )
        if not req:
            raise HTTPException(404, "Transfer request not found")

        if req["to_user"] != user.username:
            raise HTTPException(403, "You are not the intended recipient of this transfer")

        if req["status"] != "pending":
            raise HTTPException(409, f"Transfer request is already '{req['status']}'")

        new_status = "accepted" if body.accept else "declined"

        # Update request status
        await conn.execute(
            "UPDATE alert_transfer_requests SET status = $1, responded_at = NOW() WHERE id = $2",
            new_status, transfer_id,
        )

        if body.accept:
            # Reassign alert from original owner to recipient
            await conn.execute(
                "UPDATE incidents SET assigned_to = $1 WHERE alert_id = $2",
                user.username, req["alert_id"],
            )
            # Cancel any other pending transfers for this alert
            await conn.execute(
                "UPDATE alert_transfer_requests SET status = 'cancelled' WHERE alert_id = $1 AND id != $2 AND status = 'pending'",
                req["alert_id"], transfer_id,
            )

    # Notify feed channel
    await manager.broadcast("feed", {
        "type": "transfer_responded",
        "transfer_id": transfer_id,
        "alert_id": req["alert_id"],
        "from_user": req["from_user"],
        "to_user": req["to_user"],
        "accepted": body.accept,
    })

    logger.info(f"Transfer {transfer_id} {new_status} by {user.username}")
    return {
        "transfer_id": transfer_id,
        "status": new_status,
        "alert_id": req["alert_id"],
        "accepted": body.accept,
    }


@router.get("")
async def list_transfers(
    direction: Optional[str] = Query(None, description="'incoming' | 'outgoing' | None for all"),
    status: Optional[str] = Query(None),
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(analyst_or_above),
) -> dict:
    """List transfer requests relevant to the current user (incoming + outgoing).
    
    Admins and senior analysts see all transfers system-wide.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        is_elevated = user.role in ("admin", "senior_analyst")

        conds, params, i = [], [], 1

        if not is_elevated:
            # Regular analysts only see their own transfers
            conds.append(f"(r.from_user = ${i} OR r.to_user = ${i})")
            params.append(user.username)
            i += 1
        elif direction == "incoming":
            conds.append(f"r.to_user = ${i}")
            params.append(user.username)
            i += 1
        elif direction == "outgoing":
            conds.append(f"r.from_user = ${i}")
            params.append(user.username)
            i += 1

        if status:
            conds.append(f"r.status = ${i}")
            params.append(status)
            i += 1

        where = ("WHERE " + " AND ".join(conds)) if conds else ""

        rows = await conn.fetch(
            f"""SELECT r.id, r.alert_id, r.from_user, r.to_user, r.reason,
                       r.status, r.responded_at, r.created_at,
                       i.classification, i.priority
                FROM alert_transfer_requests r
                JOIN incidents i ON i.alert_id = r.alert_id
                {where}
                ORDER BY r.created_at DESC
                LIMIT 100""",
            *params,
        )

    items = []
    for row in rows:
        d = dict(row)
        for ts in ("created_at", "responded_at"):
            if d.get(ts):
                d[ts] = d[ts].isoformat()
        items.append(d)

    return {"items": items, "total": len(items)}


@router.delete("/{transfer_id}")
async def cancel_transfer(
    transfer_id: int,
    user: CurrentUser = Depends(get_current_user),
    _: None = Depends(analyst_or_above),
) -> dict:
    """Cancel a pending transfer request (initiator only)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        req = await conn.fetchrow(
            "SELECT from_user, status FROM alert_transfer_requests WHERE id = $1",
            transfer_id,
        )
        if not req:
            raise HTTPException(404, "Transfer request not found")
        if req["from_user"] != user.username and user.role != "admin":
            raise HTTPException(403, "Only the initiator or an admin can cancel a transfer")
        if req["status"] != "pending":
            raise HTTPException(409, f"Cannot cancel a '{req['status']}' transfer")

        await conn.execute(
            "UPDATE alert_transfer_requests SET status = 'cancelled', responded_at = NOW() WHERE id = $1",
            transfer_id,
        )

    return {"transfer_id": transfer_id, "status": "cancelled"}
