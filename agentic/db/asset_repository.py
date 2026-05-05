"""
Asset Repository
=================
Database access layer for asset, service, and network zone queries.
The Asset Discovery Agent uses these functions to resolve IPs to
concrete assets and calculate blast radius.
"""

import logging
from typing import Optional

from .connection import get_pool

logger = logging.getLogger(__name__)


async def find_asset_by_ip(ip_address: str) -> Optional[dict]:
    """
    Resolve an IP address to an asset record.
    Uses PostgreSQL INET type for proper IP matching.
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT a.*, nz.zone_name, nz.subnet, nz.vlan_id, nz.trust_level,
                   nz.description as zone_description
            FROM assets a
            LEFT JOIN network_zones nz ON a.zone_id = nz.id
            WHERE a.ip_address = $1::inet AND a.is_active = TRUE
        """, ip_address)

    return dict(row) if row else None


async def get_services_for_asset(asset_id: int) -> list[dict]:
    """Get all services running on a given asset."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT port, protocol, service_name, version, is_exposed
            FROM services
            WHERE asset_id = $1
            ORDER BY port
        """, asset_id)

    return [dict(row) for row in rows]


async def get_downstream_dependents(asset_id: int) -> list[dict]:
    """
    Get assets that DEPEND ON this asset (downstream).
    Used for blast radius calculation: if this asset is compromised,
    which other assets are affected?
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT a.hostname, a.ip_address, a.criticality_tier,
                   ad.dependency_type, ad.is_critical
            FROM asset_dependencies ad
            JOIN assets a ON a.id = ad.downstream_id
            WHERE ad.upstream_id = $1 AND a.is_active = TRUE
        """, asset_id)

    return [dict(row) for row in rows]


async def get_upstream_dependencies(asset_id: int) -> list[dict]:
    """
    Get assets that this asset DEPENDS ON (upstream).
    Used to understand what services this asset needs.
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT a.hostname, a.ip_address, a.criticality_tier,
                   ad.dependency_type, ad.is_critical
            FROM asset_dependencies ad
            JOIN assets a ON a.id = ad.upstream_id
            WHERE ad.downstream_id = $1 AND a.is_active = TRUE
        """, asset_id)

    return [dict(row) for row in rows]


async def find_assets_in_zone(zone_name: str) -> list[dict]:
    """Find all assets in a given network zone."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT a.id, a.hostname, a.ip_address, a.criticality_tier, a.asset_type
            FROM assets a
            JOIN network_zones nz ON a.zone_id = nz.id
            WHERE nz.zone_name = $1 AND a.is_active = TRUE
            ORDER BY a.criticality_tier
        """, zone_name)

    return [dict(row) for row in rows]


async def find_zone_for_ip(ip_address: str) -> Optional[dict]:
    """
    Determine which network zone an IP belongs to using CIDR matching.
    Useful for resolving IPs that aren't in the asset inventory (e.g., attackers).
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT zone_name, subnet, vlan_id, trust_level, description
            FROM network_zones
            WHERE subnet >> $1::inet
            ORDER BY masklen(subnet) DESC
            LIMIT 1
        """, ip_address)

    return dict(row) if row else None
