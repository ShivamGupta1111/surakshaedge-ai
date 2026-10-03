"""Pydantic request and response contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

RiskLevel = Literal["low", "medium", "high", "critical"]
AdvisorBackend = Literal["local_template", "executorch_llama", "unavailable"]


class DetectorResult(BaseModel):
    detector: str
    label: str
    probability: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str
    model_version: str
    used_fallback: bool = False


class Advice(BaseModel):
    title: str
    explanation: str
    why_concerned: str
    immediate_actions: list[str]
    do_not: list[str]
    uncertainty: str
    disclaimer: str
    backend: AdvisorBackend
    sanitized: bool = True


class AnalyzeMessageRequest(BaseModel):
    message: str = Field(min_length=1)
    locale: str | None = None
    source: str | None = Field(default="sms")


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(min_length=4)
    redirect_count: int | None = Field(default=None, ge=0, le=50)


class NetworkFlowRequest(BaseModel):
    duration: float = Field(ge=0, default=0)
    protocol: str = Field(default="tcp")
    src_port: int = Field(ge=0, le=65535, default=0)
    dst_port: int = Field(ge=0, le=65535, default=0)
    fwd_packets: int = Field(ge=0, default=0)
    bwd_packets: int = Field(ge=0, default=0)
    bytes_transferred: int = Field(ge=0, default=0)
    packet_rate: float = Field(ge=0, default=0)
    failed_count: int = Field(ge=0, default=0)
    repeated_dst: int = Field(ge=0, default=0)
    conn_freq: float = Field(ge=0, default=0)
    syn_count: int | None = Field(default=None, ge=0)
    rst_count: int | None = Field(default=None, ge=0)


class TelemetryRequest(BaseModel):
    unexpected_process_spawn: bool = False
    persistence_attempt: bool = False
    suspicious_executable_location: bool = False
    abnormal_outbound_connections: int = Field(default=0, ge=0, le=100_000)
    failed_authentication_count: int = Field(default=0, ge=0, le=100_000)
    privilege_escalation_indicator: bool = False
    unusual_file_modification_rate: float = Field(default=0, ge=0)
    known_suspicious_hashes: list[str] = Field(default_factory=list)

    @field_validator("known_suspicious_hashes")
    @classmethod
    def _limit_hashes(cls, value: list[str]) -> list[str]:
        if len(value) > 32:
            raise ValueError("At most 32 hash indicators are accepted")
        return [item.lower() for item in value]


class BatchAnalyzeRequest(BaseModel):
    messages: list[AnalyzeMessageRequest] = Field(default_factory=list)
    urls: list[AnalyzeUrlRequest] = Field(default_factory=list)
    flows: list[NetworkFlowRequest] = Field(default_factory=list)
    telemetry: list[TelemetryRequest] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    risk_level: RiskLevel
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    primary_threat: str
    detectors: list[DetectorResult]
    evidence: list[str]
    recommended_actions: list[str]
    score_explanation: str
    created_at: datetime
    advice: Advice | None = None
    alert_id: str | None = None
    advisor_backend: AdvisorBackend | None = None
    content_hash: str | None = None
    request_id: str | None = None


class FeedbackRequest(BaseModel):
    alert_id: str
    useful: bool
    comment: str | None = Field(default=None, max_length=500)


class AlertRecord(BaseModel):
    alert_id: str
    created_at: str
    detector_type: str
    risk_level: str
    risk_score: float
    evidence_redacted: str
    content_hash: str | None
    advisor_backend: str
    model_versions: str
    feedback: str | None = None


class ErrorResponse(BaseModel):
    error: str
    code: str
    request_id: str
    details: dict[str, Any] | None = None


class HealthResponse(BaseModel):
    status: str
    offline_mode: bool
    advisor_backend: str
    time_utc: str


class InfoResponse(BaseModel):
    name: str
    version: str
    offline_mode: bool
    memory_safe_mode: bool
    advisor_backend: str
    advisor_available: dict[str, bool]
    loaded_models: dict[str, str]
    host: str
    env: str
