"""Database operations for asset inventory management."""

from typing import Optional

from db.connection import get_pool


async def list_assets(search: Optional[str] = None, page: int = 1, limit: int = 100) -> dict:
    """List assets with optional search filtering and pagination.
    
    Args:
        search: Optional search string for hostname or IP address (ILIKE match).
        page: Page number (1-indexed).
        limit: Maximum items per page.
        
    Returns:
        Dictionary with 'items' (list of assets) and 'total' count.
    """
    pool = await get_pool()
    offset = (page - 1) * limit
    where, params = "", []
    if search:
        where = "WHERE a.hostname ILIKE $1 OR a.ip_address::text ILIKE $1"
        params.append(f"%{search}%")
    n = len(params)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT a.id,a.hostname,a.ip_address::text,a.os,a.asset_type,"
            f"a.criticality_tier,a.is_active,nz.zone_name "
            f"FROM assets a LEFT JOIN network_zones nz ON a.zone_id=nz.id "
            f"{where} ORDER BY a.criticality_tier,a.hostname LIMIT ${n+1} OFFSET ${n+2}",
            *params, limit, offset
        )
        total = await conn.fetchval(f"SELECT COUNT(*) FROM assets a {where}", *params)
    return {"items": [dict(r) for r in rows], "total": total}


async def get_asset(asset_id: int) -> Optional[dict]:
    """Get detailed information about a single asset.
    
    Args:
        asset_id: The unique asset identifier.
        
    Returns:
        Asset dictionary including network zone and services, or None if not found.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT a.*,nz.zone_name,nz.trust_level FROM assets a "
            "LEFT JOIN network_zones nz ON a.zone_id=nz.id WHERE a.id=$1",
            asset_id
        )
        if not row:
            return None
        svcs = await conn.fetch(
            "SELECT port,protocol,service_name,version,is_exposed FROM services WHERE asset_id=$1 ORDER BY port",
            asset_id
        )
    r = dict(row)
    r["ip_address"] = str(r["ip_address"])
    r["services"] = [dict(s) for s in svcs]
    return r