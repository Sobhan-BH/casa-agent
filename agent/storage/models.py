"""SQLAlchemy ORM models for CASA."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agent.storage.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    url: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="WEB_APP")
    label: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    authorizations: Mapped[list["Authorization"]] = relationship(back_populates="target")


class Authorization(Base):
    __tablename__ = "authorizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), index=True)
    authorized_by: Mapped[str] = mapped_column(String(256))
    authorization_reference: Mapped[str] = mapped_column(String(256), default="")
    allowed_domains: Mapped[list] = mapped_column(JSON, default=list)
    allowed_paths: Mapped[list] = mapped_column(JSON, default=list)
    excluded_targets: Mapped[list] = mapped_column(JSON, default=list)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    target: Mapped["Target"] = relationship(back_populates="authorizations")


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), index=True)
    authorization_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="QUEUED", index=True)
    trigger: Mapped[str] = mapped_column(String(16), default="INITIAL")
    profile: Mapped[str] = mapped_column(String(16), default="STANDARD")
    previous_assessment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=1)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assessments: Mapped[list["Assessment"]] = relationship(back_populates="job")


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(String(36), ForeignKey("jobs.id"), index=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="RUNNING")
    trigger: Mapped[str] = mapped_column(String(16), default="INITIAL")
    previous_assessment_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    target_url: Mapped[str] = mapped_column(String(512))
    base_domain: Mapped[str] = mapped_column(String(256))
    scope_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    security_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ai_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    verification_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    attack_surface: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    job: Mapped["Job"] = relationship(back_populates="assessments")
    findings: Mapped[list["FindingRow"]] = relationship(back_populates="assessment")
    evidences: Mapped[list["Evidence"]] = relationship(back_populates="assessment")
    artifacts: Mapped[list["ReportArtifact"]] = relationship(back_populates="assessment")


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(512))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text, default="")
    affected_asset: Mapped[str] = mapped_column(String(512), default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(128), default="")
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(24), default="UNVERIFIED")
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_notes: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_factors: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    dedupe_key: Mapped[str] = mapped_column(String(64), default="", index=True)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    assessment: Mapped["Assessment"] = relationship(back_populates="findings")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32), default="HTTP")
    source: Mapped[str] = mapped_column(String(128), default="")
    url: Mapped[str] = mapped_column(String(512), default="")
    content_json: Mapped[dict] = mapped_column(JSON, default=dict)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    assessment: Mapped["Assessment"] = relationship(back_populates="evidences")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    event: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="OK")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id"), index=True
    )
    fmt: Mapped[str] = mapped_column(String(16), default="json")  # json | html
    path: Mapped[str] = mapped_column(String(1024), default="")
    content: Mapped[str] = mapped_column(Text, default="")
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    assessment: Mapped["Assessment"] = relationship(back_populates="artifacts")
