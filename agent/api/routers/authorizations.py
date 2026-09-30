"""Authorization (target registration + authorization gate) endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from agent.api.schemas import AuthorizationCreate, AuthorizationOut, TargetOut
from agent.connectors.authorization_manager import AuthorizationManager
from agent.storage import repositories as repo
from agent.storage.database import get_session

router = APIRouter(prefix="/api/v1/authorizations", tags=["authorizations"])


@router.post("", response_model=AuthorizationOut, status_code=201)
async def register_authorization(
    payload: AuthorizationCreate, session: AsyncSession = Depends(get_session)
) -> AuthorizationOut:
    """Register a target and its authorization (the Authorization Gate)."""
    result = await AuthorizationManager(session).register_authorization(payload.model_dump())
    return AuthorizationOut(**result)


@router.get("", response_model=list[dict])
async def list_authorizations(
    target_id: str, session: AsyncSession = Depends(get_session)
) -> list[dict]:
    authzs = await repo.list_authorizations(session, target_id, active_only=False)
    return [repo.authz_to_dict(a) for a in authzs]


@router.get("/targets", response_model=list[TargetOut])
async def list_targets(session: AsyncSession = Depends(get_session)) -> list[TargetOut]:
    targets = await repo.list_targets(session)
    return [
        TargetOut(
            id=t.id,
            url=t.url,
            target_type=t.target_type,
            label=t.label,
            created_at=t.created_at,
        )
        for t in targets
    ]
