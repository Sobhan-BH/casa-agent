"""Router package. Adding a new resource = new module + one line below."""
from __future__ import annotations

from fastapi import APIRouter

from agent.api.routers import (
    assessments,
    audit,
    authorizations,
    dashboard,
    jobs,
    meta,
    tools,
)


def all_routers() -> list[APIRouter]:
    return [
        meta.router,
        authorizations.router,
        jobs.router,
        assessments.router,
        audit.router,
        tools.router,
        dashboard.router,
    ]
