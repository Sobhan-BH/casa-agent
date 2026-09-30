"""Data-access layer. Repositories are the only code that touches the ORM."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agent.core.enums import JobStatus
from agent.core.exceptions import (
    AuthorizationError,
    JobNotFoundError,
    TargetNotFoundError,
)
from agent.storage.models import (
    Assessment,
    AuditEvent,
    Authorization,
    Evidence,
    FindingRow,
    Job,
    ReportArtifact,
    Target,
)


# ---------------------------------------------------------------- targets


async def create_target(
    session: AsyncSession, url: str, target_type: str = "WEB_APP", label: str = ""
) -> Target:
    target = Target(url=url, target_type=target_type, label=label)
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


async def get_target(session: AsyncSession, target_id: str) -> Target:
    target = await session.get(Target, target_id)
    if not target:
        raise TargetNotFoundError(f"target {target_id} not found")
    return target


async def get_target_by_url(session: AsyncSession, url: str) -> Target | None:
    res = await session.execute(select(Target).where(Target.url == url))
    return res.scalar_one_or_none()


async def list_targets(session: AsyncSession) -> Sequence[Target]:
    res = await session.execute(select(Target).order_by(Target.created_at.desc()))
    return res.scalars().all()


# ---------------------------------------------------------- authorizations


async def create_authorization(
    session: AsyncSession,
    *,
    target_id: str,
    authorized_by: str,
    authorization_reference: str,
    allowed_domains: list[str],
    allowed_paths: list[str],
    excluded_targets: list[str],
    window_start: datetime | None,
    window_end: datetime | None,
) -> Authorization:
    authz = Authorization(
        target_id=target_id,
        authorized_by=authorized_by,
        authorization_reference=authorization_reference,
        allowed_domains=allowed_domains,
        allowed_paths=allowed_paths,
        excluded_targets=excluded_targets,
        window_start=window_start,
        window_end=window_end,
        active=True,
    )
    session.add(authz)
    await session.commit()
    await session.refresh(authz)
    return authz


async def list_authorizations(
    session: AsyncSession, target_id: str, active_only: bool = True
) -> Sequence[Authorization]:
    q = select(Authorization).where(Authorization.target_id == target_id)
    if active_only:
        q = q.where(Authorization.active.is_(True))
    q = q.order_by(Authorization.created_at.desc())
    res = await session.execute(q)
    return res.scalars().all()


async def get_active_authorization(session: AsyncSession, target_id: str) -> Authorization:
    authzs = await list_authorizations(session, target_id, active_only=True)
    if not authzs:
        raise AuthorizationError(
            f"no active authorization for target {target_id}; refusing to assess"
        )
    return authzs[0]


# ------------------------------------------------------------------- jobs


async def create_job(
    session: AsyncSession,
    *,
    target_id: str,
    authorization_id: str | None,
    trigger: str,
    previous_assessment_id: str | None = None,
    max_attempts: int = 1,
    profile: str = "STANDARD",
) -> Job:
    job = Job(
        target_id=target_id,
        authorization_id=authorization_id,
        status=JobStatus.QUEUED.value,
        trigger=trigger,
        profile=profile,
        previous_assessment_id=previous_assessment_id,
        max_attempts=max_attempts,
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)
    return job


async def get_job(session: AsyncSession, job_id: str) -> Job:
    job = await session.get(Job, job_id)
    if not job:
        raise JobNotFoundError(f"job {job_id} not found")
    return job


async def list_jobs(session: AsyncSession, limit: int = 100) -> Sequence[Job]:
    res = await session.execute(
        select(Job).order_by(Job.queued_at.desc()).limit(limit)
    )
    return res.scalars().all()


async def update_job_status(
    session: AsyncSession, job_id: str, status: str, error: str | None = None
) -> Job:
    job = await get_job(session, job_id)
    job.status = status
    if error is not None:
        job.error = error
    if status == JobStatus.RUNNING.value and job.started_at is None:
        job.started_at = datetime.now(timezone.utc)
    if status in (JobStatus.COMPLETED.value, JobStatus.FAILED.value, JobStatus.BLOCKED.value):
        job.finished_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(job)
    return job


# ------------------------------------------------------------ assessments


async def create_assessment(
    session: AsyncSession,
    *,
    job: Job,
    target: Target,
    scope_snapshot: dict[str, Any],
) -> Assessment:
    from urllib.parse import urlparse

    parsed = urlparse(target.url)
    base_domain = parsed.hostname or ""
    assessment = Assessment(
        job_id=job.id,
        target_id=target.id,
        status="RUNNING",
        trigger=job.trigger,
        previous_assessment_id=job.previous_assessment_id,
        target_url=target.url,
        base_domain=base_domain,
        scope_snapshot=scope_snapshot,
    )
    session.add(assessment)
    await session.commit()
    await session.refresh(assessment)
    return assessment


async def get_assessment(session: AsyncSession, assessment_id: str) -> Assessment:
    assessment = await session.get(Assessment, assessment_id)
    if not assessment:
        raise TargetNotFoundError(f"assessment {assessment_id} not found")
    return assessment


async def list_assessments(
    session: AsyncSession, limit: int = 10
) -> Sequence[Assessment]:
    res = await session.execute(
        select(Assessment).order_by(Assessment.started_at.desc()).limit(limit)
    )
    return res.scalars().all()


async def get_latest_assessment_for_target(
    session: AsyncSession, target_id: str
) -> Assessment | None:
    res = await session.execute(
        select(Assessment)
        .where(Assessment.target_id == target_id)
        .order_by(Assessment.started_at.desc())
        .limit(1)
    )
    return res.scalar_one_or_none()


async def finish_assessment(
    session: AsyncSession,
    assessment_id: str,
    *,
    status: str,
    security_score: float | None,
    risk_summary: dict | None,
    ai_summary: dict | None,
    verification_summary: dict | None = None,
    attack_surface: dict | None = None,
) -> Assessment:
    a = await get_assessment(session, assessment_id)
    a.status = status
    a.finished_at = datetime.now(timezone.utc)
    a.security_score = security_score
    a.risk_summary = risk_summary
    a.ai_summary = ai_summary
    if verification_summary is not None:
        a.verification_summary = verification_summary
    if attack_surface is not None:
        a.attack_surface = attack_surface
    await session.commit()
    await session.refresh(a)
    return a


# --------------------------------------------------------------- findings


async def save_findings(
    session: AsyncSession, assessment_id: str, findings: list[dict[str, Any]]
) -> list[FindingRow]:
    """Persist normalized findings; returns rows with DB ids assigned back."""
    rows: list[FindingRow] = []
    for f in findings:
        row = FindingRow(
            assessment_id=assessment_id,
            fingerprint=f["fingerprint"],
            title=f["title"],
            category=f["category"],
            severity=f["severity"],
            confidence=f["confidence"],
            description=f.get("description", ""),
            affected_asset=f.get("affected_asset", ""),
            impact=f.get("impact", ""),
            remediation=f.get("remediation", ""),
            references=f.get("references", []),
            source=f.get("source", ""),
            verified=bool(f.get("verified", False)),
            status=f.get("status", "UNVERIFIED"),
            false_positive=bool(f.get("false_positive", False)),
            ai_notes=f.get("ai_notes"),
            risk_score=f.get("risk_score"),
            risk_factors=f.get("risk_factors"),
            evidence_refs=f.get("evidence_refs", []),
            dedupe_key=f.get("dedupe_key", ""),
            metadata_json=f.get("metadata", {}),
        )
        session.add(row)
        rows.append(row)
    await session.commit()
    for row, f in zip(rows, findings):
        f["id"] = row.id
    return rows


async def list_findings(session: AsyncSession, assessment_id: str) -> Sequence[FindingRow]:
    res = await session.execute(
        select(FindingRow).where(FindingRow.assessment_id == assessment_id)
    )
    return res.scalars().all()


# --------------------------------------------------------------- evidence


async def save_evidence(
    session: AsyncSession,
    assessment_id: str,
    *,
    kind: str,
    source: str,
    url: str,
    content: dict[str, Any],
) -> Evidence:
    digest = hashlib.sha256(
        json.dumps(content, sort_keys=True, default=str).encode()
    ).hexdigest()
    ev = Evidence(
        assessment_id=assessment_id,
        kind=kind,
        source=source,
        url=url,
        content_json=content,
        sha256=digest,
    )
    session.add(ev)
    await session.commit()
    await session.refresh(ev)
    return ev


async def list_evidence(session: AsyncSession, assessment_id: str) -> Sequence[Evidence]:
    res = await session.execute(
        select(Evidence).where(Evidence.assessment_id == assessment_id)
    )
    return res.scalars().all()


# ----------------------------------------------------------------- audit


async def record_audit(
    session: AsyncSession,
    event: str,
    *,
    actor: str = "system",
    job_id: str | None = None,
    target: str | None = None,
    outcome: str = "OK",
    details: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditEvent(
            event=event,
            actor=actor,
            job_id=job_id,
            target=target,
            outcome=outcome,
            details=details or {},
        )
    )
    await session.commit()


async def list_audit_events(session: AsyncSession, limit: int = 200) -> Sequence[AuditEvent]:
    res = await session.execute(
        select(AuditEvent).order_by(AuditEvent.ts.desc()).limit(limit)
    )
    return res.scalars().all()


# -------------------------------------------------------------- artifacts


async def save_artifact(
    session: AsyncSession,
    assessment_id: str,
    *,
    fmt: str,
    path: str,
    content: str,
) -> ReportArtifact:
    art = ReportArtifact(assessment_id=assessment_id, fmt=fmt, path=path, content=content)
    session.add(art)
    await session.commit()
    await session.refresh(art)
    return art


async def get_artifact(session: AsyncSession, artifact_id: str) -> ReportArtifact:
    art = await session.get(ReportArtifact, artifact_id)
    if not art:
        raise TargetNotFoundError(f"artifact {artifact_id} not found")
    return art


async def list_artifacts(
    session: AsyncSession, assessment_id: str
) -> Sequence[ReportArtifact]:
    res = await session.execute(
        select(ReportArtifact).where(ReportArtifact.assessment_id == assessment_id)
    )
    return res.scalars().all()


# ------------------------------------------------------------------ misc


def authz_to_dict(authz: Authorization) -> dict[str, Any]:
    return {
        "id": authz.id,
        "target_id": authz.target_id,
        "authorized_by": authz.authorized_by,
        "authorization_reference": authz.authorization_reference,
        "allowed_domains": authz.allowed_domains,
        "allowed_paths": authz.allowed_paths,
        "excluded_targets": authz.excluded_targets,
        "window_start": authz.window_start.isoformat() if authz.window_start else None,
        "window_end": authz.window_end.isoformat() if authz.window_end else None,
        "active": authz.active,
    }
