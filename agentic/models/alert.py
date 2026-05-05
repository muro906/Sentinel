"""
AnomalyAlert Model
===================
Represents an anomaly detection alert produced by the Hybrid Detection Layer
(Layer 2). This is the INPUT to the agentic layer — consumed from the Kafka
topic 'anomaly-alerts'.

The detection layer classifies traffic as anomalous and attaches:
- The anomaly score (0.0-1.0) from the ensemble classifier
- A classification label (e.g., port_scan, data_exfiltration)
- The raw feature vector for signature extraction by sub-agents
- Model votes showing which models flagged the traffic
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator
import uuid


class ModelVote(BaseModel):
    """Individual model's classification decision."""
    model_name: str = Field(..., description="Name of the model (e.g., 'autoencoder', 'random_forest')")
    score: float = Field(..., ge=0.0, le=1.0, description="Model's anomaly score")
    label: str = Field(..., description="Model's classification label")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model's confidence in its prediction")


class FeatureVector(BaseModel):
    """CESSNET-like feature vector from the ingestion layer."""
    uid: str
    ts: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    service: Optional[str] = None
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    bytes_ratio: float = 0.0
    pkts_ratio: float = 0.0
    avg_pkt_size_orig: float = 0.0
    avg_pkt_size_resp: float = 0.0
    missed_bytes: int = 0
    conn_state: Optional[str] = None
    ssl_version: Optional[str] = None
    ssl_cipher: Optional[str] = None
    is_encrypted: int = 0
    is_dns: int = 0
    dns_query: Optional[str] = None
    dns_qtype: Optional[int] = None
    dns_rcode: Optional[int] = None
    dns_answers: Optional[int] = None


class AnomalyAlert(BaseModel):
    """
    Top-level alert message consumed from Kafka 'anomaly-alerts' topic.
    This is the entry point for the orchestrator agent.
    """
    alert_id: str = Field(
        default_factory=lambda: f"alert-{uuid.uuid4().hex[:12]}",
        description="Unique identifier for this alert"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the anomaly was detected"
    )
    anomaly_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Ensemble anomaly score (0=normal, 1=highly anomalous)"
    )
    classification: str = Field(
        ...,
        description="Attack type classification (port_scan, data_exfiltration, dns_tunneling, etc.)"
    )
    feature_vector: FeatureVector = Field(
        ...,
        description="Raw network features that triggered the alert"
    )
    model_votes: list[ModelVote] = Field(
        default_factory=list,
        description="Individual model decisions that formed the ensemble"
    )
    raw_features: Optional[dict] = Field(
        default=None,
        description="Additional raw features not in the standard schema"
    )

    @field_validator("classification")
    @classmethod
    def validate_classification(cls, v: str) -> str:
        valid = {
            "port_scan", "data_exfiltration", "dns_tunneling",
            "brute_force", "lateral_movement", "c2_communication",
            "exploit_attempt", "privilege_escalation", "unknown"
        }
        if v not in valid:
            return "unknown"
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "alert-a1b2c3d4e5f6",
                "timestamp": "2024-01-15T10:30:00Z",
                "anomaly_score": 0.91,
                "classification": "port_scan",
                "feature_vector": {
                    "uid": "CKyrpe4JCbVRCPbNe8",
                    "ts": "1700000001.234",
                    "src_ip": "172.16.0.55",
                    "src_port": 54321,
                    "dst_ip": "10.0.0.1",
                    "dst_port": 22,
                    "proto": "tcp",
                    "duration": 0.001,
                    "orig_bytes": 64,
                    "resp_bytes": 0,
                    "conn_state": "S0"
                },
                "model_votes": [
                    {"model_name": "autoencoder", "score": 0.89, "label": "port_scan", "confidence": 0.85},
                    {"model_name": "random_forest", "score": 0.93, "label": "port_scan", "confidence": 0.92}
                ]
            }
        }
