"""Job queue + worker loop.

MVP uses an in-process asyncio queue (inline backend): the API enqueues, a
background worker task executes jobs through the Orchestrator. The JobQueue
interface is intentionally narrow so a Redis/Celery backend can replace it
(extension point) without touching the API or orchestrator.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agent.core.config import settings
from agent.workers.orchestrator import Orchestrator

logger = logging.getLogger("casa.queue")


class JobQueue:
    """In-process asyncio job queue. One worker task consumes sequentially."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker
        self._queue: asyncio.Queue[UUID] = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self._in_flight: set[UUID] = set()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._worker(), name="casa-worker")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    def enqueue(self, job_id: UUID) -> None:
        self._in_flight.add(job_id)
        self._queue.put_nowait(job_id)
        logger.info("job %s queued", job_id)

    def is_queued_or_running(self, job_id: UUID) -> bool:
        return job_id in self._in_flight

    def depth(self) -> int:
        return self._queue.qsize()

    async def _worker(self) -> None:
        while True:
            job_id = await self._queue.get()
            try:
                async with self._sessionmaker() as session:
                    orchestrator = Orchestrator(session)
                    result = await orchestrator.run_job(job_id)
                    logger.info("job %s finished: %s", job_id, result.get("status"))
            except Exception:  # noqa: BLE001 - worker must survive any job failure
                logger.exception("worker failed to run job %s", job_id)
                # Ensure the job doesn't stay RUNNING forever.
                try:
                    async with self._sessionmaker() as session:
                        from agent.storage import repositories as repo

                        await repo.update_job_status(session, str(job_id), "FAILED",
                                                     error="worker-level failure")
                except Exception:  # noqa: BLE001
                    logger.exception("could not mark job %s as failed", job_id)
            finally:
                self._in_flight.discard(job_id)
                self._queue.task_done()
