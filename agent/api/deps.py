"""FastAPI dependencies."""
from __future__ import annotations

from agent.api.state import get_app_state
from agent.storage.database import get_session  # re-export for router convenience

__all__ = ["get_session", "get_app_state"]
