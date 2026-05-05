"""
ThreatBundle Model
===================
The aggregated context object assembled by the Orchestrator after sub-agents
return their results. This is the COMPLETE picture of the threat that gets
passed to the Planning Agent (LLM) for plan generation.

It contains:
- The original alert with features
- All matched CVEs from the CVE Lookup Agent
- All affected assets from the Asset Discovery Agent
- Historical incidents with similar patterns (for few-shot context)
- Computed risk metadata
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

from .alert import AnomalyAlert
from .cve import CVEMatch
from .asset import AssetInfo


class HistoricalIncident(BaseModel):
    """A past incident with similar characteristics, used for LLM context."""
    alert_id: str
    timestamp: datetime
    classification: str
    anomaly_score: float
    actions_taken: list[str] = Field(default_factory=list)
    outcome: str = Field(..., description="resolved, escalated, false_positive")
    similarity_score: float = Field(..., ge=0.0, le=1.0)


class ThreatBundle(BaseModel):
    """
    Complete enriched threat context — the input to the Planning Agent.
    Assembled by the Orchestrator's aggregation node after sub-agents complete.
    """
    # Original alert
    alert: AnomalyAlert

    # Sub-agent results
    cve_matches: list[CVEMatch] = Field(
        default_factory=list,
        description="CVEs matched by the CVE Lookup Agent"
    )
    affected_assets: list[AssetInfo] = Field(
        default_factory=list,
        description="Assets resolved by the Asset Discovery Agent"
    )

    # Historical context
    similar_incidents: list[HistoricalIncident] = Field(
        default_factory=list,
        description="Past incidents with similar patterns (max 5)"
    )

    # Computed risk metadata
    priority: str = Field(default="medium", description="Computed priority: low, medium, high, critical")
    max_cvss: float = Field(default=0.0, description="Highest CVSS score among matched CVEs")
    max_asset_criticality: int = Field(default=5, description="Most critical asset tier affected (1=highest)")
    total_blast_radius: float = Field(default=0.0, description="Sum of blast radius across affected assets")
    has_active_exploit: bool = Field(default=False, description="Any matched CVE has known exploit")

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    sub_agents_completed_at: Optional[datetime] = None

    def compute_risk_metadata(self):
        """Recompute derived risk fields from sub-agent results."""
        if self.cve_matches:
            self.max_cvss = max(c.cvss_score for c in self.cve_matches)
            self.has_active_exploit = any(c.exploit_available for c in self.cve_matches)

        if self.affected_assets:
            self.max_asset_criticality = min(a.criticality_tier for a in self.affected_assets)
            self.total_blast_radius = sum(a.blast_radius for a in self.affected_assets)

        # Priority calculation
        score = self.alert.anomaly_score
        if self.max_cvss >= 9.0 or self.max_asset_criticality == 1:
            self.priority = "critical"
        elif self.max_cvss >= 7.0 or self.max_asset_criticality <= 2 or score >= 0.9:
            self.priority = "high"
        elif self.max_cvss >= 4.0 or score >= 0.7:
            self.priority = "medium"
        else:
            self.priority = "low"
