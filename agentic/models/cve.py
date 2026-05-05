"""
CVE Models
===========
Represents CVE database entries and match results returned by the CVE Lookup
Agent. CVEEntry models the raw database record; CVEMatch models a scored
result linking a CVE to the traffic that triggered the alert.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class CVEEntry(BaseModel):
    """Raw CVE record as stored in PostgreSQL (mirrors NVD schema)."""
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")
    description: str
    cvss_v3_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_v3_vector: Optional[str] = None
    severity: Optional[str] = None
    published_date: Optional[datetime] = None
    affected_vendor: Optional[str] = None
    affected_product: Optional[str] = None
    affected_versions: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    exploit_available: bool = False
    exploit_description: Optional[str] = None


class CVEMatch(BaseModel):
    """
    A CVE matched to the current alert by the CVE Lookup Agent.
    Includes the matching rationale and confidence score.
    """
    cve_id: str = Field(..., description="CVE identifier")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS v3 base score")
    severity: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    description: str = Field(..., description="CVE description")
    affected_product: Optional[str] = Field(None, description="Affected software name")
    affected_versions: Optional[str] = Field(None, description="Affected version range")
    exploit_available: bool = Field(False, description="Known exploit exists in the wild")

    # Match metadata
    matched_signature: str = Field(
        ...,
        description="Which traffic signature matched this CVE (e.g., 'dst_port=22, service=openssh')"
    )
    match_confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confidence that this CVE is relevant to the observed traffic"
    )
    match_rationale: str = Field(
        ...,
        description="Human-readable explanation of why this CVE was matched"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "cve_id": "CVE-2024-6387",
                "cvss_score": 8.1,
                "severity": "HIGH",
                "description": "Race condition in OpenSSH sshd allows remote code execution",
                "affected_product": "openssh",
                "affected_versions": "8.5p1 - 9.7p1",
                "exploit_available": True,
                "matched_signature": "dst_port=22, service=openssh, conn_state=S0",
                "match_confidence": 0.85,
                "match_rationale": "Target port 22 with SYN-only connections matches reconnaissance pattern for CVE-2024-6387 (regreSSHion)"
            }
        }
