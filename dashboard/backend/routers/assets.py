"""Asset inventory router for network asset management."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from core.dependencies import analyst_or_above
from db.assets import get_asset, list_assets

router = APIRouter()


@router.get("")
async def list_assets_ep(
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(100, le=500),
    _: None = Depends(analyst_or_above)
) -> dict:
    """List network assets with optional search and pagination.
    
    Args:
        search: Optional search string for hostname or IP address.
        page: Page number for pagination.
        limit: Items per page (max 500).
        _: Authentication dependency (unused).
        
    Returns:
        Paginated list of assets with total count.
    """
    return await list_assets(search=search, page=page, limit=limit)


@router.get("/{asset_id}")
async def get_asset_ep(asset_id: int, _: None = Depends(analyst_or_above)) -> dict:
    """Get detailed information about a specific asset.
    
    Includes asset details, network zone, and discovered services.
    
    Args:
        asset_id: The unique asset identifier.
        _: Authentication dependency (unused).
        
    Raises:
        HTTPException: 404 if asset not found.
        
    Returns:
        Complete asset details with services.
    """
    a = await get_asset(asset_id)
    if not a:
        raise HTTPException(404, "Asset not found")
    return a