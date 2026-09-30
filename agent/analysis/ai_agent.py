"""AI Analysis Module — the reasoning layer between tools and humans.

Rules enforced here (regardless of provider):
- The LLM receives findings + risk summary; it NEVER receives raw network access
  or the ability to trigger new probes.
- The provider's output is parsed defensively; an unusable LLM response degrades
  gracefully to a minimal structured summary, never to a crash mid-assessment.
- The LLM cannot raise a finding's severity, invent findings, or strip evidence.
  It may only annotate, prioritize, correlate, and summarize.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from agent.core.context import AssessmentContext
from agent.core.exceptions import LLMError, LLMUnavailableError
from agent.core.interfaces import AssessmentModule, LLMProvider

logger = logging.getLogger("casa.ai")

SYSTEM_PROMPT = (
    "You are the analysis layer of an authorized security assessment agent. "
    "You receive structured findings produced by scanning tools. Your job: "
    "deduplicate, correlate, flag suspicious findings, prioritize, explain "
    "technical impact, provide a manager-friendly summary, and suggest "
    "confidence. You MUST NOT invent findings not present in the input, must "
    "not raise severity beyond the evidence, and must reference finding ids "
    "when you comment on them. Output STRICT JSON only."
)


class AIAnalysisModule(AssessmentModule):
    name = "ai_analysis"
    phase = "AI_ANALYSIS"

    def __init__(self, validator, provider: LLMProvider) -> None:
        self._validator = validator
        self._provider = provider

    async def run(self, ctx: AssessmentContext) -> None:
        payload = self._build_payload(ctx)
        prompt = json.dumps(payload, ensure_ascii=False, default=str)
        try:
            raw = await self._provider.analyze(prompt, SYSTEM_PROMPT)
            analysis = self._parse_provider_output(raw)
            if analysis is None:
                logger.warning("LLM output unusable; storing raw response only")
                analysis = {
                    "provider": self._provider.name,
                    "error": "unparseable LLM output; see raw_response",
                }
                ctx.ai_summary = {**analysis, "raw_response": raw[:4000]}
                return
        except LLMUnavailableError as exc:
            logger.warning("LLM unavailable (%s); assessment continues without AI layer", exc)
            ctx.ai_summary = {
                "provider": self._provider.name,
                "error": f"llm_unavailable: {exc}",
                "degraded": True,
            }
            return
        except LLMError as exc:
            logger.warning("LLM error (%s); assessment continues without AI layer", exc)
            ctx.ai_summary = {
                "provider": self._provider.name,
                "error": str(exc),
                "degraded": True,
            }
            return

        analysis["provider"] = self._provider.name
        self._apply_annotations(ctx, analysis)
        ctx.ai_summary = analysis

    # ---------------------------------------------------------------- helpers

    def _build_payload(self, ctx: AssessmentContext) -> dict[str, Any]:
        slim_findings = []
        for f in ctx.findings:
            slim_findings.append(
                {
                    "id": f.get("id"),
                    "fingerprint": f.get("fingerprint"),
                    "title": f.get("title"),
                    "category": f.get("category"),
                    "severity": f.get("severity"),
                    "confidence": f.get("confidence"),
                    "affected_asset": f.get("affected_asset"),
                    "risk_score": f.get("risk_score"),
                    "evidence_types": [e.get("type") for e in f.get("evidence", [])],
                    "source": f.get("source"),
                    "metadata": f.get("metadata", {}),
                }
            )
        return {
            "target": ctx.target_url,
            "assessment_id": str(ctx.assessment_id),
            "trigger": ctx.trigger,
            "risk_summary": ctx.risk_summary,
            "findings": slim_findings,
        }

    @staticmethod
    def _parse_provider_output(raw: str) -> dict[str, Any] | None:
        """Defensive JSON extraction from an LLM response."""
        if not raw or not raw.strip():
            return None
        text = raw.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                try:
                    data = json.loads(text[start : end + 1])
                    return data if isinstance(data, dict) else None
                except json.JSONDecodeError:
                    return None
        return None

    @staticmethod
    def _apply_annotations(ctx: AssessmentContext, analysis: dict[str, Any]) -> None:
        """Attach AI notes to findings; never let AI change severity or evidence.

        Matching prefers fingerprints (stable pre-persistence) over ids.
        """
        by_fp = {f.get("fingerprint"): f for f in ctx.findings if f.get("fingerprint")}
        by_id = {
            f.get("id"): f
            for f in ctx.findings
            if f.get("id") not in (None, "")
        }

        def _find(ref: dict[str, Any]):
            return by_fp.get(ref.get("fingerprint")) or by_id.get(ref.get("id"))

        for note in analysis.get("confidence_adjustments", []) or []:
            target = _find(note)
            if target is None:
                continue
            target.setdefault("ai_notes", {})["confidence_note"] = note.get("reason")
            suggested = note.get("suggested_confidence")
            # AI may only *suggest* confidence changes, never raise severity.
            if suggested in ("LOW", "MEDIUM", "HIGH") and suggested != target.get("confidence"):
                target["ai_notes"]["confidence_suggestion"] = suggested

        for flag in analysis.get("suspicious_findings", []) or []:
            target = _find(flag)
            if target is not None:
                target.setdefault("ai_notes", {})["suspicious_reason"] = flag.get("reason")
