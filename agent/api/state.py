"""Application state shared across routers (lifespan-managed)."""
from __future__ import annotations

from agent.workers.queue import JobQueue

_app_state: dict = {}


def set_app_state(queue: JobQueue) -> None:
    _app_state["queue"] = queue


def get_app_state() -> dict:
    return _app_state
