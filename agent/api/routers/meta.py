"""Meta endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from agent import __version__
from agent.api.state import get_app_state
from agent.core.config import settings

router = APIRouter(tags=["meta"])


@router.get("/api/v1")
async def index() -> dict:
    return {
        "name": "CASA — Core Agentic Security Assessment",
        "version": __version__,
        "docs": "/docs",
        "status": "/api/v1/status",
    }


@router.get("/api/v1/status")
async def status() -> dict:
    queue = get_app_state().get("queue")
    return {
        "status": "ok",
        "env": settings.env,
        "version": __version__,
        "queue_depth": queue.depth() if queue else 0,
        "features": {
            "ai_provider": settings.llm_provider,
            "ai_analysis_enabled": settings.ai_analysis_enabled,
            "extension_points_disabled": [
                "network_assessment",
                "continuous_monitoring",
                "attack_path_analysis",
            ],
        },
    }
