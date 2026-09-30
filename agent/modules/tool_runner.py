"""Tool Runner — bridges external tool adapters into the CASA pipeline.

Implemented as an ordinary AssessmentModule so it runs under the SAME
orchestrator guards as internal modules (timeout, retry, max steps, scope
error propagation). Selection is availability-aware; a missing tool records
NOT_INSTALLED and the pipeline continues. Raw tool output is stored under
``raw_results["tools"]`` for evidence + attack-surface enrichment; normalized
findings are appended to the context and then flow through the standard
normalizer/dedupe/risk stages like every internal finding.
"""
from __future__ import annotations

import time
from typing import Any

from agent.core.config import settings
from agent.core.context import AssessmentContext
from agent.core.enums import AssessmentPhaseStatus
from agent.core.exceptions import ScopeViolationError
from agent.core.interfaces import AssessmentModule
from agent.tools.registry import tool_registry


class ToolRunnerModule(AssessmentModule):
    name = "tool_runner"
    phase = "EXTERNAL_TOOLS"

    def __init__(self, validator) -> None:
        self._validator = validator

    def applies(self, ctx: AssessmentContext) -> bool:
        return bool(settings.tools_enabled)

    async def run(self, ctx: AssessmentContext) -> None:
        tools: dict[str, Any] = {"run": {}, "skipped": {}}
        started = time.monotonic()
        budget = settings.tool_max_runtime_seconds

        for adapter in tool_registry.select(ctx):
            elapsed = time.monotonic() - started
            if elapsed > budget:
                tools["skipped"][adapter.name] = "tool runtime budget exhausted"
                continue

            request = {
                "target": ctx.target_url,
                "scope": ctx.scope,
                "timeout": settings.tool_timeout_seconds,
            }
            entry: dict[str, Any] = {"status": "OK", "findings": []}
            try:
                raw = await adapter.execute(request)
            except ScopeViolationError:
                raise  # scope escape must stay BLOCKED, never swallowed
            except Exception as exc:  # noqa: BLE001 - tool failure must not kill the job
                entry = {"status": "FAILED", "error": f"{type(exc).__name__}: {exc}"}
            else:
                entry["status"] = raw.get("status", "OK")
                if entry["status"] == "NOT_INSTALLED":
                    entry["note"] = "tool binary not found on this host"
                elif entry["status"] == "OK":
                    entry["findings"] = raw.get("findings", [])
                    entry["duration_ms"] = raw.get("duration_ms")
                    entry["tool_version"] = raw.get("tool_version")
                    # normalized, provenance-stamped findings for the pipeline
                    ctx.findings.extend(adapter.normalize_findings(raw))
                    # raw stays in evidence; oversized stdout is capped already
                tools["run"][adapter.name] = entry

            ctx.phases.append(
                _tool_phase(adapter, entry)
            )

        tools["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        ctx.raw_results["tools"] = tools
        ctx.raw_results["tool_health"] = tool_registry.health()


def _tool_phase(adapter, entry: dict[str, Any]):
    from agent.core.context import PhaseResult, utcnow

    status_map = {
        "OK": AssessmentPhaseStatus.OK.value,
        "NOT_INSTALLED": AssessmentPhaseStatus.SKIPPED.value,
    }
    return PhaseResult(
        phase=f"TOOL_{adapter.name.upper()}",
        module=f"tool:{adapter.name}",
        status=status_map.get(entry.get("status", "FAILED"), AssessmentPhaseStatus.FAILED.value),
        started_at=utcnow(),
        finished_at=utcnow(),
        duration_ms=entry.get("duration_ms", 0),
        summary=entry.get("error") or entry.get("note") or f"{len(entry.get('findings', []))} findings",
    )
