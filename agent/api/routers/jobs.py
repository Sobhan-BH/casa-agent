"""Job endpoints — the only way to start an assessment."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from agent.api.schemas import JobCreate, JobOut
from agent.api.state import get_app_state
from agent.connectors.authorization_manager import AuthorizationManager
from agent.core.enums import JobTrigger
from agent.core.exceptions import CasaError
from agent.storage import repositories as repo
from agent.storage.database import get_session

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"])


def _job_out(job, target_url: str | None = None) -> JobOut:
    return JobOut(
        id=job.id,
        target_id=job.target_id,
        status=job.status,
        trigger=job.trigger,
        profile=getattr(job, "profile", "STANDARD"),
        attempts=job.attempts,
        error=job.error,
        queued_at=job.queued_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        target_url=target_url,
    )


@router.post("", response_model=JobOut, status_code=202)
async def create_job(
    payload: JobCreate, session: AsyncSession = Depends(get_session)
) -> JobOut:
    """Validate authorization for the target and enqueue an assessment job.

    The authorization gate runs *now* (fail fast) and again when the worker
    picks the job up. A job whose target has no valid authorization is never
    queued: the request fails with 403.
    """
    try:
        target = await repo.get_target(session, payload.target_id)
        manager = AuthorizationManager(session)
        authz, _validator = await manager.resolve_for_target_url(target.url)
    except CasaError as exc:
        raise HTTPException(status_code=403, detail=f"authorization gate: {exc.message}") from exc
    # remember the URL so the response (and the dashboard history) can show it

    if payload.trigger not in (t.value for t in JobTrigger):
        raise HTTPException(status_code=400, detail="invalid trigger")

    profile = (payload.profile or "STANDARD").upper()
    if profile not in ("QUICK", "STANDARD", "DEEP"):
        raise HTTPException(status_code=400, detail="invalid profile; expected QUICK | STANDARD | DEEP")

    if payload.trigger in ("REASSESSMENT", "VERIFICATION") and not payload.previous_assessment_id:
        raise HTTPException(
            status_code=400,
            detail="previous_assessment_id is required for REASSESSMENT/VERIFICATION triggers",
        )

    job = await repo.create_job(
        session,
        target_id=target.id,
        authorization_id=authz.id,
        trigger=payload.trigger,
        profile=profile,
        previous_assessment_id=payload.previous_assessment_id,
    )
    queue = get_app_state().get("queue")
    if queue is not None:
        queue.enqueue(UUID(job.id))
    return _job_out(job, target_url=target.url)


@router.get("", response_model=list[JobOut])
async def list_jobs(
    limit: int = 50, session: AsyncSession = Depends(get_session)
) -> list[JobOut]:
    jobs = await repo.list_jobs(session, limit=min(limit, 200))
    return [_job_out(j) for j in jobs]


@router.get("/{job_id}", response_model=JobOut)
async def get_job(job_id: str, session: AsyncSession = Depends(get_session)) -> JobOut:
    try:
        job = await repo.get_job(session, job_id)
    except CasaError as exc:
        raise HTTPException(status_code=404, detail=exc.message) from exc
    return _job_out(job)
