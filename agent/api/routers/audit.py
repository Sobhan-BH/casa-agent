"""Audit endpoints — read-only visibility into the audit trail."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from agent.api.schemas import AuditEventOut
from agent.storage import repositories as repo
from agent.storage.database import get_session

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("", response_model=list[AuditEventOut])
async def list_audit(
    limit: int = 100, session: AsyncSession = Depends(get_session)
) -> list[AuditEventOut]:
    events = await repo.list_audit_events(session, limit=min(limit, 500))
    return [
        AuditEventOut(
            id=e.id,
            ts=e.ts,
            event=e.event,
            actor=e.actor,
            job_id=e.job_id,
            target=e.target,
            outcome=e.outcome,
            details=e.details,
        )
        for e in events
    ]
