"""CVE (Common Vulnerabilities and Exposures) router."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from core.dependencies import analyst_or_above
from db.cves import get_cve, list_cves

router = APIRouter()


@router.get("")
async def list_cves_ep(
    search: Optional[str] = Query(None),
    min_cvss: float = Query(0.0, ge=0.0, le=10.0),
    attack_vector: Optional[str] = Query(None),
    exploit_only: bool = Query(False),
    page: int = Query(1, ge=1),
    limit: int = Query(100, le=500),
    _: None = Depends(analyst_or_above)
) -> dict:
    """List CVE entries with filtering and pagination.
    
    Args:
        search: Optional text search across CVE ID, description, or product.
        min_cvss: Minimum CVSS v3 score filter (0-10).
        attack_vector: Optional attack vector filter (e.g., 'NETWORK', 'LOCAL').
        exploit_only: If True, only show CVEs with known exploits.
        page: Page number for pagination.
        limit: Items per page (max 500).
        _: Authentication dependency (unused).
        
    Returns:
        Paginated list of CVEs with total count.
    """
    return await list_cves(
        search=search,
        min_cvss=min_cvss,
        attack_vector=attack_vector,
        exploit_only=exploit_only,
        page=page,
        limit=limit
    )


@router.get("/{cve_id}")
async def get_cve_ep(cve_id: str, _: None = Depends(analyst_or_above)) -> dict:
    """Get detailed information about a specific CVE.
    
    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2023-1234').
        _: Authentication dependency (unused).
        
    Raises:
        HTTPException: 404 if CVE not found.
        
    Returns:
        Complete CVE details.
    """
    cve = await get_cve(cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    return cve
