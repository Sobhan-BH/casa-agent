"""Evidence Collector — turns raw pipeline results into storable evidence.

Raw results stay on the context during the run; this module packages them into
evidence records with a stable sha256 (integrity check) so findings can cite
exactly what backs them.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from agent.core.context import AssessmentContext
from agent.core.interfaces import AssessmentModule


class EvidenceCollectorModule(AssessmentModule):
    name = "evidence_collector"
    phase = "EVIDENCE"

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        evidence: list[dict[str, Any]] = []
        for key, raw in ctx.raw_results.items():
            payload = json.dumps(raw, sort_keys=True, default=str)
            evidence.append(
                {
                    "kind": self._kind_for(key),
                    "source": key,
                    "url": (raw or {}).get("url", "") if isinstance(raw, dict) else "",
                    "content": raw,
                    "sha256": hashlib.sha256(payload.encode()).hexdigest(),
                }
            )
        # Findings keep their own inline evidence; collectors store the full raw set.
        ctx.raw_results["evidence_bundle"] = evidence

    @staticmethod
    def _kind_for(key: str) -> str:
        if key.startswith("http") or key in ("robots_txt", "sitemap"):
            return "HTTP"
        if key == "dns":
            return "DNS"
        if key == "tls":
            return "TLS"
        return "OTHER"
