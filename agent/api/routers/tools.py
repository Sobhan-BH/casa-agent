"""Tool health endpoint — which external security tools are usable right now."""
from __future__ import annotations

from fastapi import APIRouter

from agent.core.config import settings
from agent.tools.registry import PROFILE_TOOLS, tool_registry

router = APIRouter(tags=["tools"])


@router.get("/api/v1/tools")
async def tools() -> dict:
    """Per-tool availability for the dashboard Security Tools panel.

    Statuses: READY (installed + enabled), NOT_INSTALLED, DISABLED.
    """
    health = tool_registry.health()
    return {
        "tools_enabled": settings.tools_enabled,
        "tools": health,
        "profile_map": PROFILE_TOOLS,
    }
