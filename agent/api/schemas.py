"""Pydantic schemas for the REST API."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AuthorizationCreate(BaseModel):
    target: str = Field(..., description="Target base URL, e.g. http://127.0.0.1:8001")
    target_type: str = Field("WEB_APP", description="WEB_APP | API | HOST")
    label: str = ""
    authorized_by: str = Field(..., description="Person/role granting authorization")
    authorization_reference: str = Field("", description="Ticket, contract or email reference")
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])
    excluded_targets: list[str] = Field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None


class AuthorizationOut(BaseModel):
    target_id: str
    target_url: str
    authorization: dict[str, Any]


class TargetOut(BaseModel):
    id: str
    url: str
    target_type: str
    label: str
    created_at: datetime


class JobCreate(BaseModel):
    target_id: str
    trigger: str = Field("INITIAL", description="INITIAL | REASSESSMENT | VERIFICATION")
    profile: str = Field("STANDARD", description="QUICK | STANDARD | DEEP")
    previous_assessment_id: str | None = None


class JobOut(BaseModel):
    id: str
    target_id: str
    status: str
    trigger: str
    profile: str
    attempts: int
    error: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class AssessmentOut(BaseModel):
    id: str
    job_id: str
    target_id: str
    status: str
    trigger: str
    target_url: str
    started_at: datetime
    finished_at: datetime | None
    security_score: float | None
    risk_summary: dict | None
    ai_summary: dict | None
    verification_summary: dict | None
    attack_surface: dict | None = None


class FindingOut(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    confidence: str
    description: str
    affected_asset: str
    impact: str
    remediation: str
    references: list
    source: str
    verified: bool
    status: str
    false_positive: bool
    risk_score: float | None
    risk_factors: dict | None
    ai_notes: dict | None
    evidence_refs: list
    fingerprint: str


class EvidenceOut(BaseModel):
    id: str
    kind: str
    source: str
    url: str
    sha256: str
    collected_at: datetime


class ReportArtifactOut(BaseModel):
    id: str
    assessment_id: str
    fmt: str
    path: str
    generated_at: datetime


class AuditEventOut(BaseModel):
    id: str
    ts: datetime
    event: str
    actor: str
    job_id: str | None
    target: str | None
    outcome: str
    details: dict


class StatusOut(BaseModel):
    status: str
    env: str
    version: str
