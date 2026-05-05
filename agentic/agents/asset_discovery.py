"""
Asset Discovery Agent
======================
Resolves IPs from an anomaly alert to concrete assets in the inventory,
enriches with service and network zone information, and calculates the
blast radius (potential impact if the asset is compromised).

Process:
1. RESOLVE — Look up src_ip and dst_ip in the asset database
2. ENRICH — For each resolved asset, fetch running services, network zone,
   and downstream dependencies
3. ASSESS IMPACT — Calculate blast radius using:
   blast_radius = criticality × (1 + critical_dependents) × zone_exposure_factor

The blast radius tells the Planning Agent how severe the potential impact is,
which directly influences plan aggression and confidence scoring.
"""

import logging
from typing import Optional

from agentic.agents.base import BaseAgent
from agentic.db import asset_repository
from agentic.models.asset import AssetInfo, ServiceInfo, NetworkZone, AssetDependency

logger = logging.getLogger(__name__)

# Zone trust level → exposure factor (lower trust = higher exposure)
ZONE_EXPOSURE_FACTORS = {
    1: 2.0,   # untrusted (public-facing) — maximum exposure
    2: 1.5,   # semi-trusted (DMZ)
    3: 1.0,   # trusted (internal)
    4: 0.7,   # highly trusted (management)
    5: 0.5,   # restricted (secrets)
}


class AssetDiscoveryAgent(BaseAgent):
    """
    Sub-agent that resolves IPs to assets, enriches with context,
    and calculates blast radius for impact assessment.
    """

    @property
    def name(self) -> str:
        return "asset_discovery"

    async def _process(self, task_data: dict) -> dict:
        """
        Core asset discovery logic.

        Input (task_data keys):
            - src_ip: source IP from the alert
            - dst_ip: destination IP from the alert
            - dst_port: target port (for service matching)
            - classification: attack type

        Output:
            - affected_assets: list of AssetInfo dicts
            - source_context: context about the source (attacker)
            - target_context: context about the target (victim)
            - _confidence: confidence in the resolution
        """
        src_ip = task_data.get("src_ip")
        dst_ip = task_data.get("dst_ip")
        dst_port = task_data.get("dst_port")

        affected_assets = []
        source_context = None
        target_context = None

        # Resolve destination IP (the target/victim)
        if dst_ip:
            target_asset = await self._resolve_and_enrich(dst_ip)
            if target_asset:
                target_context = target_asset.model_dump()
                affected_assets.append(target_asset.model_dump())

        # Resolve source IP (may be internal compromised host)
        if src_ip:
            source_asset = await self._resolve_and_enrich(src_ip)
            if source_asset:
                source_context = source_asset.model_dump()
                # Only add to affected if it's an internal asset (possibly compromised)
                if source_asset.network_zone and source_asset.network_zone.trust_level >= 2:
                    affected_assets.append(source_asset.model_dump())
            else:
                # Source not in inventory — determine its zone for context
                source_zone = await asset_repository.find_zone_for_ip(src_ip)
                source_context = {
                    "ip_address": src_ip,
                    "hostname": None,
                    "known_asset": False,
                    "zone": source_zone,
                    "assessment": "External/unknown source — likely attacker"
                                  if not source_zone or source_zone.get("trust_level", 0) <= 1
                                  else "Internal asset not in inventory — possible shadow IT"
                }

        # Calculate overall confidence
        confidence = 0.0
        if target_context and isinstance(target_context, dict) and target_context.get("hostname"):
            confidence = 0.9  # high confidence — known asset
        elif target_context:
            confidence = 0.5  # partial — zone identified but asset unknown
        else:
            confidence = 0.3  # low — nothing resolved

        return {
            "affected_assets": affected_assets,
            "source_context": source_context,
            "target_context": target_context,
            "total_blast_radius": sum(
                a.get("blast_radius", 0) for a in affected_assets
            ),
            "_confidence": confidence,
        }

    async def _resolve_and_enrich(self, ip_address: str) -> Optional[AssetInfo]:
        """
        Resolve an IP to a full AssetInfo with services, zone, and blast radius.
        Returns None if the IP is not in the asset inventory.
        """
        # Step 1: Find the asset
        asset_record = await asset_repository.find_asset_by_ip(ip_address)
        if not asset_record:
            return None

        asset_id = asset_record["id"]

        # Step 2: Fetch running services
        service_records = await asset_repository.get_services_for_asset(asset_id)
        services = [
            ServiceInfo(
                port=s["port"],
                protocol=s["protocol"],
                service_name=s["service_name"],
                version=s.get("version"),
                is_exposed=s.get("is_exposed", False),
            )
            for s in service_records
        ]

        # Step 3: Build network zone
        network_zone = None
        if asset_record.get("zone_name"):
            network_zone = NetworkZone(
                zone_name=asset_record["zone_name"],
                subnet=str(asset_record.get("subnet", "")),
                vlan_id=asset_record.get("vlan_id"),
                trust_level=asset_record.get("trust_level", 3),
            )

        # Step 4: Fetch downstream dependents (for blast radius)
        dependents_raw = await asset_repository.get_downstream_dependents(asset_id)
        dependents = [
            AssetDependency(
                hostname=d["hostname"],
                dependency_type=d["dependency_type"],
                is_critical=d.get("is_critical", False),
            )
            for d in dependents_raw
        ]

        # Step 5: Calculate blast radius
        criticality = asset_record.get("criticality_tier", 5)
        critical_deps = sum(1 for d in dependents if d.is_critical)
        zone_trust = network_zone.trust_level if network_zone else 3
        zone_exposure = ZONE_EXPOSURE_FACTORS.get(zone_trust, 1.0)

        blast_radius = round(
            (6 - criticality) * (1 + critical_deps) * zone_exposure, 2
        )
        # (6 - criticality) inverts the scale: tier 1 → factor 5, tier 5 → factor 1

        # Build complete AssetInfo
        return AssetInfo(
            hostname=asset_record["hostname"],
            ip_address=ip_address,
            os=asset_record.get("os"),
            os_version=asset_record.get("os_version"),
            owner=asset_record.get("owner"),
            department=asset_record.get("department"),
            criticality_tier=criticality,
            asset_type=asset_record.get("asset_type"),
            network_zone=network_zone,
            services=services,
            downstream_dependents=dependents,
            blast_radius=blast_radius,
        )

    def _summarize_output(self, result: dict) -> str:
        """Human-readable summary for reasoning trace."""
        assets = result.get("affected_assets", [])
        if not assets:
            return "No known assets resolved from IPs"
        names = [a.get("hostname", a.get("ip_address", "?")) for a in assets]
        blast = result.get("total_blast_radius", 0)
        return f"Resolved {len(assets)} assets: {', '.join(names)}. Total blast radius: {blast:.1f}"

    def _explain_result(self, result: dict) -> str:
        """Detailed rationale for reasoning trace."""
        parts = []
        assets = result.get("affected_assets", [])
        source = result.get("source_context")
        target = result.get("target_context")

        if target and isinstance(target, dict):
            if target.get("hostname"):
                parts.append(
                    f"Target {target['ip_address']} resolved to '{target['hostname']}' "
                    f"(criticality={target.get('criticality_tier')}, "
                    f"zone={target.get('network_zone', {}).get('zone_name', 'unknown')})."
                )
                services = target.get("services", [])
                if services:
                    svc_list = [f"{s['service_name']}:{s['port']}" for s in services[:3]]
                    parts.append(f"  Running services: {', '.join(svc_list)}")
                deps = target.get("downstream_dependents", [])
                if deps:
                    parts.append(f"  {len(deps)} downstream dependents (blast radius: {target.get('blast_radius', 0):.1f})")
            else:
                parts.append(f"Target {target.get('ip_address')} not in asset inventory.")
        else:
            parts.append("Target IP could not be resolved to any known asset.")

        if source and isinstance(source, dict):
            if source.get("hostname"):
                parts.append(
                    f"Source {source['ip_address']} is internal asset '{source['hostname']}' "
                    f"— possible compromised host."
                )
            elif source.get("assessment"):
                parts.append(f"Source: {source['assessment']}")

        return "\n".join(parts)
