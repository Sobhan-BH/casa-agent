"""AssessmentContext — the single state object handed from module to module.

The orchestrator creates it after authorization/scope validation and each
pipeline module reads what it needs and adds its results. Raw results are
retained so the Evidence Collector can store them verbatim.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PhaseResult:
    phase: str
    module: str
    status: str  # AssessmentPhaseStatus value
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int = 0
    summary: str = ""
    error: str | None = None
    artifact_keys: list[str] = field(default_factory=list)


@dataclass
class AssessmentContext:
    job_id: UUID
    assessment_id: UUID
    target_url: str
    base_domain: str
    scope: dict[str, Any]
    trigger: str = "INITIAL"
    mode: str = "STANDARD"
    previous_assessment_id: UUID | None = None
    baseline_findings: list[dict[str, Any]] = field(default_factory=list)
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None

    # Pipeline state
    phases: list[PhaseResult] = field(default_factory=list)
    raw_results: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    risk_summary: dict[str, Any] | None = None
    ai_summary: dict[str, Any] | None = None
    verification_summary: dict[str, Any] | None = None
    report_ids: dict[str, UUID] = field(default_factory=dict)

    # Runtime guards (orchestrator-enforced)
    step_count: int = 0
    hard_stop: bool = False
