"""Periodic re-assessment scheduler.

Implements the README's "continuous monitoring" extension point: a background
asyncio task that creates REASSESSMENT jobs for targets whose latest assessment
is older than CASA_REASSESS_INTERVAL_HOURS.

Safety:
- the scheduler *never* bypasses the authorization gate — jobs it creates go
  through the exact same gate + queue as API-created jobs
- targets without an active authorization are skipped silently (the gate
  would block them anyway)
- a job is only created when no job for that target is QUEUED/RUNNING
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agent.core.config import settings

logger = logging.getLogger("casa.scheduler")


class ReassessmentScheduler:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if settings.reassess_interval_hours <= 0:
            logger.info("scheduler disabled (CASA_REASSESS_INTERVAL_HOURS<=0)")
            return
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop(), name="casa-scheduler")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        interval = max(300, int(settings.reassess_interval_hours * 3600 / 12))
        logger.info(
            "scheduler started: interval scan every %ss, reassess after %sh",
            interval, settings.reassess_interval_hours,
        )
        while True:
            try:
                await self._scan_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — scheduler must survive
                logger.exception("scheduler scan failed")
            await asyncio.sleep(interval)

    async def _scan_once(self) -> None:
        from sqlalchemy import select

        from agent.storage import repositories as repo
        from agent.storage.models import Assessment, Authorization, Job
        from uuid import UUID

        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=settings.reassess_interval_hours
        )
        async with self._sessionmaker() as session:
            targets = await repo.list_targets(session)
            now = datetime.now(timezone.utc)

            for target in targets:
                # skip if a job is already queued/running for this target
                pending = await session.execute(
                    select(Job)
                    .where(Job.target_id == target.id)
                    .where(Job.status.in_(["QUEUED", "RUNNING", "ANALYZING", "VERIFYING"]))
                )
                if pending.scalars().first() is not None:
                    continue

                # authorization must be active and inside its window
                try:
                    authz = await repo.get_active_authorization(session, target.id)
                except Exception:  # noqa: BLE001 — no authz: skip quietly
                    continue
                if authz.window_start and now < authz.window_start:
                    continue
                if authz.window_end and now > authz.window_end:
                    continue

                latest = await session.execute(
                    select(Assessment)
                    .where(Assessment.target_id == target.id)
                    .order_by(Assessment.started_at.desc())
                    .limit(1)
                )
                last = latest.scalars().first()
                if last is not None and last.finished_at and last.finished_at > cutoff:
                    continue
                if last is not None and last.status != "COMPLETED":
                    continue

                job = await repo.create_job(
                    session,
                    target_id=target.id,
                    authorization_id=authz.id,
                    trigger="REASSESSMENT",
                    profile="STANDARD",
                    previous_assessment_id=last.id if last else None,
                )
                logger.info(
                    "scheduler enqueued REASSESSMENT job %s for %s",
                    job.id, target.url,
                )
                queue = self._queue
                if queue is not None:
                    queue.enqueue(UUID(job.id))

    @property
    def _queue(self):
        # injected lazily to avoid a circular import with app state
        from agent.api.state import get_app_state

        return get_app_state().get("queue")
