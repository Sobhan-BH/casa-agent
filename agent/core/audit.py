"""Append-only audit log (JSONL) + in-DB audit trail is written by repositories.

Every authorization decision, scope decision and job lifecycle change is
recorded here. The file is append-only; entries are never modified or deleted.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from agent.core.config import settings

logger = logging.getLogger("casa.audit")


class AuditLogger:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or settings.audit_log_path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def emit(
        self,
        event: str,
        *,
        actor: str = "system",
        job_id: UUID | None = None,
        target: str | None = None,
        outcome: str = "OK",
        details: dict[str, Any] | None = None,
    ) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": actor,
            "job_id": str(job_id) if job_id else None,
            "target": target,
            "outcome": outcome,
            "details": details or {},
        }
        line = json.dumps(entry, ensure_ascii=False, default=str)
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:  # pragma: no cover - disk issues must not kill jobs
            logger.exception("failed to append audit entry")


audit_logger = AuditLogger()
