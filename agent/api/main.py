"""FastAPI application entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from agent import __version__
from agent.api.routers import all_routers
from agent.api.state import set_app_state
from agent.core.config import settings
from agent.core.exceptions import CasaError
from agent.core.logging import configure_logging
from agent.storage.database import AsyncSessionLocal, engine
from agent.storage.migrations import run_migrations
from agent.storage.models import Base, Job
from agent.workers.queue import JobQueue

logger = logging.getLogger("casa.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(settings.log_level)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await run_migrations(conn)

    # Crash recovery: the in-memory queue dies with the process. Jobs left in
    # QUEUED are re-enqueued; jobs left RUNNING were interrupted mid-flight
    # and are marked FAILED so they cannot be stuck forever.
    from sqlalchemy import select

    async with AsyncSessionLocal() as s:
        stale_running = await s.execute(select(Job).where(Job.status == "RUNNING"))
        for job in stale_running.scalars():
            job.status = "FAILED"
            job.error = "interrupted by server restart"
            job.finished_at = datetime.now(timezone.utc)
        pending = await s.execute(select(Job).where(Job.status == "QUEUED"))
        pending_ids = [j.id for j in pending.scalars()]
        await s.commit()

    queue = JobQueue(AsyncSessionLocal)
    queue.start()
    for job_id in pending_ids:
        queue.enqueue(job_id)
    if pending_ids:
        logger.info("re-enqueued %d queued job(s) after restart", len(pending_ids))

    # Continuous-monitoring scheduler (disabled when interval <= 0)
    from agent.workers.scheduler import ReassessmentScheduler

    scheduler = ReassessmentScheduler(AsyncSessionLocal)
    scheduler.start()

    set_app_state(queue)
    logger.info("CASA API started (env=%s, db=%s)", settings.env, settings.database_url.split("@")[-1])
    yield
    await scheduler.stop()
    await queue.stop()
    await engine.dispose()


app = FastAPI(
    title="CASA — Core Agentic Security Assessment",
    description=(
        "Authorized-scope-only AI cybersecurity assessment agent. "
        "Every assessment requires a registered authorization; every HTTP request "
        "is scope-validated at fetch time."
    ),
    version=__version__,
    lifespan=lifespan,
)


@app.exception_handler(CasaError)
async def casa_error_handler(request: Request, exc: CasaError) -> JSONResponse:
    status_map = {
        "AUTHORIZATION_MISSING": 403,
        "SCOPE_VIOLATION": 403,
        "SCOPE_CONFIG_INVALID": 400,
        "TARGET_NOT_FOUND": 404,
        "JOB_NOT_FOUND": 404,
        "JOB_INVALID_STATE": 409,
        "VERIFICATION_CONTEXT_INVALID": 400,
        "REPORT_FAILED": 500,
        "LLM_UNAVAILABLE": 503,
        "LLM_ERROR": 502,
        "SAFETY_LIMIT": 429,
    }
    return JSONResponse(
        status_code=status_map.get(exc.code, 400),
        content={"error": exc.code, "message": exc.message},
    )


for router in all_routers():
    app.include_router(router)


# Optional API-key auth + rate limiting (no-ops unless CASA_API_KEY / CASA_RATE_LIMIT_RPM set)
from agent.api.security import install_api_security

install_api_security(app)


@app.get("/health", response_class=PlainTextResponse, tags=["meta"])
async def health() -> str:
    return "ok"
