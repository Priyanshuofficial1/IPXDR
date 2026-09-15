from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator

class FlowEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str
    packets: int = Field(ge=0)
    bytes: int = Field(ge=0)
    duration_ms: float = Field(ge=0)
    tcp_flags: list[str] = Field(default_factory=list)
    direction: str
    dns: dict[str, Any] | None = None
    tls: dict[str, Any] | None = None
    quic: dict[str, Any] | None = None
    source: str = "unknown"

    @field_validator("protocol", "direction", "source")
    @classmethod
    def nonempty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value

class DetectorResult(BaseModel):
    detector_name: str
    threat_class: str
    score: float = Field(ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    features_used: list[str] = Field(default_factory=list)
    model_version: str = "baseline"
    latency_ms: float = Field(ge=0)

class Alert(BaseModel):
    alert_id: str
    timestamp: datetime
    flow_id: str
    threat_class: str
    confidence: float = Field(ge=0, le=1)
    severity: str
    supporting_evidence: list[str] = Field(default_factory=list)
    model_scores: dict[str, float] = Field(default_factory=dict)
    behavior_deviation: float = Field(default=0, ge=0, le=1)
