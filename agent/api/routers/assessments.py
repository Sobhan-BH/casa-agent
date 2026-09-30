"""Assessment endpoints: results, findings, evidence, reports."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from agent.api.schemas import AssessmentOut, EvidenceOut, FindingOut, ReportArtifactOut
from agent.core.exceptions import CasaError
from agent.storage import repositories as repo
from agent.storage.database import get_session

router = APIRouter(prefix="/api/v1/assessments", tags=["assessments"])


def _assessment_out(a) -> AssessmentOut:
    return AssessmentOut(
        id=a.id,
        job_id=a.job_id,
        target_id=a.target_id,
        status=a.status,
        trigger=a.trigger,
        target_url=a.target_url,
        started_at=a.started_at,
        finished_at=a.finished_at,
        security_score=a.security_score,
        risk_summary=a.risk_summary,
        ai_summary=a.ai_summary,
        verification_summary=a.verification_summary,
        attack_surface=getattr(a, "attack_surface", None),
    )


@router.get("", response_model=list[AssessmentOut])
async def list_assessments(
    target_id: str | None = None, session: AsyncSession = Depends(get_session)
) -> list[AssessmentOut]:
    if target_id:
        latest = await repo.get_latest_assessment_for_target(session, target_id)
        return [_assessment_out(latest)] if latest else []
    # No global listing in MVP (kept intentionally small); use target_id filter.
    return []


@router.get("/{assessment_id}", response_model=AssessmentOut)
async def get_assessment(
    assessment_id: str, session: AsyncSession = Depends(get_session)
) -> AssessmentOut:
    try:
        a = await repo.get_assessment(session, assessment_id)
    except CasaError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    return _assessment_out(a)


@router.get("/{assessment_id}/findings", response_model=list[FindingOut])
async def list_findings(
    assessment_id: str, session: AsyncSession = Depends(get_session)
) -> list[FindingOut]:
    try:
        await repo.get_assessment(session, assessment_id)
    except CasaError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    rows = await repo.list_findings(session, assessment_id)
    return [
        FindingOut(
            id=r.id,
            title=r.title,
            category=r.category,
            severity=r.severity,
            confidence=r.confidence,
            description=r.description,
            affected_asset=r.affected_asset,
            impact=r.impact,
            remediation=r.remediation,
            references=r.references,
            source=r.source,
            verified=r.verified,
            status=r.status,
            false_positive=r.false_positive,
            risk_score=r.risk_score,
            risk_factors=r.risk_factors,
            ai_notes=r.ai_notes,
            evidence_refs=r.evidence_refs,
            fingerprint=r.fingerprint,
            metadata=r.metadata_json,
        )
        for r in rows
    ]


@router.get("/{assessment_id}/evidence", response_model=list[EvidenceOut])
async def list_evidence(
    assessment_id: str, session: AsyncSession = Depends(get_session)
) -> list[EvidenceOut]:
    try:
        await repo.get_assessment(session, assessment_id)
    except CasaError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    rows = await repo.list_evidence(session, assessment_id)
    return [
        EvidenceOut(
            id=e.id,
            kind=e.kind,
            source=e.source,
            url=e.url,
            sha256=e.sha256,
            collected_at=e.collected_at,
        )
        for e in rows
    ]


@router.get("/{assessment_id}/reports", response_model=list[ReportArtifactOut])
async def list_reports(
    assessment_id: str, session: AsyncSession = Depends(get_session)
) -> list[ReportArtifactOut]:
    artifacts = await repo.list_artifacts(session, assessment_id)
    return [
        ReportArtifactOut(
            id=a.id,
            assessment_id=a.assessment_id,
            fmt=a.fmt,
            path=a.path,
            generated_at=a.generated_at,
        )
        for a in artifacts
    ]


@router.get("/{assessment_id}/sarif")
async def get_sarif(
    assessment_id: str, session: AsyncSession = Depends(get_session)
):
    """SARIF 2.1.0 export (GitHub Code Scanning compatible)."""
    try:
        a = await repo.get_assessment(session, assessment_id)
    except CasaError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    rows = await repo.list_findings(session, assessment_id)
    from agent.reports.sarif import build_sarif_report

    findings = [
        {
            "title": r.title,
            "category": r.category,
            "severity": r.severity,
            "confidence": r.confidence,
            "description": r.description,
            "affected_asset": r.affected_asset,
            "remediation": r.remediation,
            "source": r.source,
            "status": r.status,
            "risk_score": r.risk_score,
            "fingerprint": r.fingerprint,
            "metadata": r.metadata_json or {},
        }
        for r in rows
    ]
    report = build_sarif_report(a.target_url, findings, a.security_score)
    return JSONResponse(content=report)


@router.get("/{assessment_id}/reports/{artifact_id}")
async def download_report(
    assessment_id: str, artifact_id: str, session: AsyncSession = Depends(get_session)
):
    try:
        art = await repo.get_artifact(session, artifact_id)
    except CasaError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    if art.assessment_id != assessment_id:
        raise HTTPException(status_code=404, detail="artifact does not belong to assessment")
    if art.fmt == "html":
        return HTMLResponse(content=art.content)
    return JSONResponse(content=__import__("json").loads(art.content))
