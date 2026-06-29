"""Database operations for CVE (Common Vulnerabilities and Exposures) data."""

from typing import Optional

from db.connection import get_pool


async def list_cves(
    search: Optional[str] = None,
    min_cvss: float = 0.0,
    attack_vector: Optional[str] = None,
    exploit_only: bool = False,
    page: int = 1,
    limit: int = 100
) -> dict:
    """List CVE entries with filtering and pagination.
    
    Args:
        search: Optional text search across CVE ID, description, or product.
        min_cvss: Minimum CVSS v3 score filter.
        attack_vector: Optional attack vector filter (e.g., 'NETWORK', 'LOCAL').
        exploit_only: If True, only show CVEs with known exploits.
        page: Page number (1-indexed).
        limit: Maximum items per page.
        
    Returns:
        Dictionary with 'items' (CVE list) and 'total' count.
    """
    pool = await get_pool()
    offset = (page - 1) * limit
    conds = ["(cvss_v3_score>=$1 OR cvss_v3_score IS NULL)"]
    params: list = [min_cvss]
    i = 2
    if search:
        conds.append(f"(cve_id ILIKE ${i} OR description ILIKE ${i} OR affected_product ILIKE ${i})")
        params.append(f"%{search}%")
        i += 1
    if attack_vector:
        conds.append(f"attack_vector=${i}")
        params.append(attack_vector)
        i += 1
    if exploit_only:
        conds.append("exploit_available=TRUE")
    where = "WHERE " + " AND ".join(conds)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT cve_id,description,cvss_v3_score,severity,affected_vendor,"
            f"affected_product,attack_vector,exploit_available FROM cve_entries "
            f"{where} ORDER BY cvss_v3_score DESC NULLS LAST LIMIT ${i} OFFSET ${i+1}",
            *params, limit, offset
        )
        total = await conn.fetchval(f"SELECT COUNT(*) FROM cve_entries {where}", *params)
    return {"items": [dict(r) for r in rows], "total": total}


async def upsert_cves(cves: list) -> None:
    """Upsert a list of CVE dicts (from NVD) into cve_entries."""
    if not cves:
        return
    pool = await get_pool()
    async with pool.acquire() as conn:
        for c in cves:
            await conn.execute(
                """
                INSERT INTO cve_entries (
                    cve_id, description, cvss_v3_score, cvss_v3_vector, severity,
                    published_date, modified_date, affected_vendor, affected_product,
                    affected_versions, attack_vector, attack_complexity,
                    privileges_required, user_interaction, exploit_available
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                ON CONFLICT (cve_id) DO UPDATE SET
                    description       = EXCLUDED.description,
                    cvss_v3_score     = EXCLUDED.cvss_v3_score,
                    severity          = EXCLUDED.severity,
                    modified_date     = EXCLUDED.modified_date,
                    exploit_available = EXCLUDED.exploit_available
                """,
                c["cve_id"], c["description"], c["cvss_v3_score"], c["cvss_v3_vector"],
                c["severity"], c["published_date"], c["modified_date"],
                c["affected_vendor"], c["affected_product"], c["affected_versions"],
                c["attack_vector"], c["attack_complexity"],
                c["privileges_required"], c["user_interaction"], c["exploit_available"],
            )


async def get_cve(cve_id: str) -> Optional[dict]:
    """Get detailed information about a specific CVE.
    
    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2023-1234').
        
    Returns:
        Complete CVE record, or None if not found.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM cve_entries WHERE cve_id=$1", cve_id)
    return dict(row) if row else None