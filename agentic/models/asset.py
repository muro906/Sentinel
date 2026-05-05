"""
Asset Models
=============
Represents assets, services, and network zones resolved by the Asset Discovery
Agent. When an anomaly is detected, the agent resolves the involved IPs to
concrete assets and calculates the blast radius (how much damage could spread).
"""

from typing import Optional
from pydantic import BaseModel, Field


class ServiceInfo(BaseModel):
    """A service running on an asset (port + software + version)."""
    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp")
    service_name: str = Field(..., description="e.g., openssh, nginx, postgresql")
    version: Optional[str] = Field(None, description="Software version string")
    is_exposed: bool = Field(False, description="Externally reachable from untrusted zones")


class NetworkZone(BaseModel):
    """Logical network segment with trust boundaries."""
    zone_name: str = Field(..., description="e.g., dmz, internal, management")
    subnet: str = Field(..., description="CIDR notation, e.g. 10.0.0.0/24")
    vlan_id: Optional[int] = None
    trust_level: int = Field(..., ge=1, le=5, description="1=untrusted, 5=restricted")


class AssetDependency(BaseModel):
    """A dependency between two assets (for blast radius calculation)."""
    hostname: str
    dependency_type: str = Field(..., description="database, api, auth, dns")
    is_critical: bool = Field(False, description="Failure causes downstream breakage")


class AssetInfo(BaseModel):
    """
    Complete asset profile as resolved by the Asset Discovery Agent.
    Combines host info, running services, network position, and
    downstream dependencies for blast radius calculation.
    """
    hostname: str = Field(..., description="Resolved hostname")
    ip_address: str = Field(..., description="IP address that was resolved")
    os: Optional[str] = Field(None, description="Operating system")
    os_version: Optional[str] = None
    owner: Optional[str] = Field(None, description="Responsible person/team")
    department: Optional[str] = None
    criticality_tier: int = Field(
        ..., ge=1, le=5,
        description="1=mission-critical, 2=high, 3=medium, 4=low, 5=negligible"
    )
    asset_type: Optional[str] = Field(None, description="server, workstation, IoT, network_device")

    # Network context
    network_zone: Optional[NetworkZone] = Field(None, description="Zone this asset lives in")
    services: list[ServiceInfo] = Field(default_factory=list, description="Running services")

    # Blast radius
    downstream_dependents: list[AssetDependency] = Field(
        default_factory=list,
        description="Assets that depend on this one"
    )
    blast_radius: float = Field(
        0.0,
        description="Calculated impact score: criticality × (1 + dependents) × zone_exposure"
    )

    # Vulnerability posture
    last_vuln_scan: Optional[str] = None
    known_vulnerabilities: int = Field(0, description="Count of unpatched vulns from last scan")

    class Config:
        json_schema_extra = {
            "example": {
                "hostname": "web-prod-01",
                "ip_address": "10.0.0.1",
                "os": "Ubuntu 22.04",
                "os_version": "22.04.3 LTS",
                "owner": "infra-team",
                "department": "Engineering",
                "criticality_tier": 2,
                "asset_type": "server",
                "network_zone": {
                    "zone_name": "dmz",
                    "subnet": "10.0.0.0/24",
                    "vlan_id": 100,
                    "trust_level": 2
                },
                "services": [
                    {"port": 22, "protocol": "tcp", "service_name": "openssh", "version": "9.5p1", "is_exposed": True},
                    {"port": 443, "protocol": "tcp", "service_name": "nginx", "version": "1.24.0", "is_exposed": True}
                ],
                "downstream_dependents": [
                    {"hostname": "api-gateway", "dependency_type": "api", "is_critical": True}
                ],
                "blast_radius": 4.8
            }
        }
