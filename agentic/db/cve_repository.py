"""
CVE Repository
===============
Database access layer for CVE queries. Supports two search strategies:

1. Full-text search (tsvector) — keyword matching on CVE descriptions,
   vendor names, and product names. Fast and deterministic.

2. Service + port matching — direct lookup by affected product and
   attack vector characteristics.

The CVE Lookup Agent uses these functions to find CVEs relevant to
the observed traffic pattern.
"""

import logging
from typing import Optional

from .connection import get_pool

logger = logging.getLogger(__name__)


async def search_by_keywords(
    keywords: list[str],
    min_cvss: float = 0.0,
    attack_vector: Optional[str] = None,
    limit: int = 10,
) -> list[dict]:
    """
    Full-text search on CVE descriptions and metadata.

    Args:
        keywords: Search terms (e.g., ['openssh', 'pre-auth', 'remote code execution'])
        min_cvss: Minimum CVSS score filter
        attack_vector: Optional filter (NETWORK, ADJACENT, LOCAL, PHYSICAL)
        limit: Maximum results

    Returns:
        List of CVE dicts ordered by relevance (ts_rank) then CVSS score
    """
    pool = await get_pool()

    # Build tsquery from keywords (OR logic between terms)
    query_string = " | ".join(keywords)

    sql = """
        SELECT cve_id, description, cvss_v3_score, cvss_v3_vector, severity,
               affected_vendor, affected_product, affected_versions,
               attack_vector, attack_complexity, privileges_required,
               exploit_available, exploit_description,
               ts_rank(search_vector, to_tsquery('english', $1)) as relevance
        FROM cve_entries
        WHERE search_vector @@ to_tsquery('english', $1)
          AND (cvss_v3_score >= $2 OR cvss_v3_score IS NULL)
    """
    params = [query_string, min_cvss]

    if attack_vector:
        sql += " AND attack_vector = $3"
        params.append(attack_vector)

    sql += " ORDER BY relevance DESC, cvss_v3_score DESC NULLS LAST LIMIT $" + str(len(params) + 1)
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)

    return [dict(row) for row in rows]


async def search_by_product(
    product: str,
    vendor: Optional[str] = None,
    min_cvss: float = 0.0,
    limit: int = 10,
) -> list[dict]:
    """
    Search CVEs by affected product name (exact match with ILIKE).

    Args:
        product: Software name (e.g., 'openssh', 'nginx', 'bind9')
        vendor: Optional vendor filter
        min_cvss: Minimum CVSS score
        limit: Maximum results
    """
    pool = await get_pool()

    sql = """
        SELECT cve_id, description, cvss_v3_score, cvss_v3_vector, severity,
               affected_vendor, affected_product, affected_versions,
               attack_vector, attack_complexity, privileges_required,
               exploit_available, exploit_description
        FROM cve_entries
        WHERE affected_product ILIKE $1
          AND (cvss_v3_score >= $2 OR cvss_v3_score IS NULL)
    """
    params = [f"%{product}%", min_cvss]

    if vendor:
        sql += " AND affected_vendor ILIKE $3"
        params.append(f"%{vendor}%")

    sql += " ORDER BY cvss_v3_score DESC NULLS LAST, exploit_available DESC LIMIT $" + str(len(params) + 1)
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)

    return [dict(row) for row in rows]


async def search_by_attack_pattern(
    attack_vector: str = "NETWORK",
    privileges_required: str = "NONE",
    min_cvss: float = 7.0,
    exploit_only: bool = False,
    limit: int = 10,
) -> list[dict]:
    """
    Search CVEs by attack characteristics (useful for pattern-based matching).

    Used when the traffic signature maps to a general attack type rather
    than a specific product (e.g., network-based with no auth required).
    """
    pool = await get_pool()

    sql = """
        SELECT cve_id, description, cvss_v3_score, cvss_v3_vector, severity,
               affected_vendor, affected_product, affected_versions,
               attack_vector, attack_complexity, privileges_required,
               exploit_available, exploit_description
        FROM cve_entries
        WHERE attack_vector = $1
          AND privileges_required = $2
          AND (cvss_v3_score >= $3 OR cvss_v3_score IS NULL)
    """
    params = [attack_vector, privileges_required, min_cvss]

    if exploit_only:
        sql += " AND exploit_available = TRUE"

    sql += " ORDER BY cvss_v3_score DESC NULLS LAST LIMIT $" + str(len(params) + 1)
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)

    return [dict(row) for row in rows]


async def get_cve_by_id(cve_id: str) -> Optional[dict]:
    """Fetch a single CVE by its ID."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM cve_entries WHERE cve_id = $1", cve_id
        )

    return dict(row) if row else None
