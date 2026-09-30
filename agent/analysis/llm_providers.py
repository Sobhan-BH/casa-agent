"""LLM providers behind the provider-agnostic LLMProvider interface.

- HeuristicProvider: deterministic, offline, zero-cost. Produces a structured
  analysis from the findings themselves (dedupe stats, suspicious findings,
  priorities, plain-language summary). Used by default so the MVP runs with no
  external dependency.
- OpenAICompatibleProvider: works with any OpenAI-compatible endpoint
  (OpenAI, Azure, vLLM, Ollama, ...). Set CASA_LLM_PROVIDER=openai plus key.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from agent.core.config import settings
from agent.core.exceptions import LLMError, LLMUnavailableError
from agent.core.interfaces import LLMProvider

logger = logging.getLogger("casa.llm")


class HeuristicProvider(LLMProvider):
    """Offline reasoning layer. Never claims facts beyond the given findings."""

    name = "heuristic"

    def __init__(self) -> None:
        self._calls = 0

    async def analyze(self, prompt: str, system: str) -> str:
        # The heuristic provider ignores free-form prompts and instead consumes
        # the structured payload the analysis agent embeds in the prompt.
        self._calls += 1
        try:
            payload_start = prompt.index("{")
            payload = json.loads(prompt[payload_start:])
        except (ValueError, json.JSONDecodeError):
            payload = {"findings": []}
        return json.dumps(self._analyze_payload(payload))

    def _analyze_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = payload.get("findings", [])
        target = payload.get("target", "")
        risk = payload.get("risk_summary") or {}

        # 1) duplicate detection (same title+asset from different sources)
        by_title_asset: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for f in findings:
            key = (f.get("title", "").lower(), f.get("affected_asset", ""))
            by_title_asset.setdefault(key, []).append(f)
        duplicates = [
            {"title": k[0], "asset": k[1], "sources": [x.get("source") for x in group]}
            for k, group in by_title_asset.items()
            if len(group) > 1
        ]

        # 2) suspicious findings (FP risk / low confidence on high severity)
        suspicious = [
            {
                "id": f.get("id"),
                "fingerprint": f.get("fingerprint"),
                "title": f.get("title"),
                "reason": "flagged false-positive risk by normalizer",
            }
            for f in findings
            if f.get("metadata", {}).get("false_positive_risk") == "HIGH"
        ] + [
            {
                "id": f.get("id"),
                "fingerprint": f.get("fingerprint"),
                "title": f.get("title"),
                "reason": f"high severity with {f.get('confidence')} confidence; verify manually",
            }
            for f in findings
            if f.get("severity") in ("HIGH", "CRITICAL")
            and f.get("confidence") != "HIGH"
        ]

        # 3) priority ordering (severity rank, then risk score)
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        prioritized = sorted(
            findings,
            key=lambda f: (rank.get(f.get("severity", "INFO"), 9), -(f.get("risk_score") or 0)),
        )

        # 4) correlations
        correlations = self._correlate(findings)

        top = prioritized[:5]
        dist = risk.get("distribution") or {}
        dist_str = ", ".join(f"{k}: {v}" for k, v in dist.items() if v)

        executive_summary = (
            f"Assessment of {target} identified {len(findings)} findings "
            f"({dist_str}). "
            + (
                f"The most significant issue is '{top[0]['title']}' ({top[0]['severity']}). "
                if top
                else "No actionable findings were produced. "
            )
            + f"Security score is {risk.get('security_score', 'N/A')}/100 "
            f"(grade {risk.get('grade', 'N/A')}). "
            "Prioritize remediating findings with HIGH severity and HIGH confidence first; "
            "each finding includes evidence for independent validation."
        )

        return {
            "provider": self.name,
            "executive_summary": executive_summary,
            "technical_summary": (
                f"{len(findings)} normalized findings; "
                f"{len(duplicates)} duplicate groups merged upstream; "
                f"{len(suspicious)} findings flagged for manual verification."
            ),
            "prioritized_findings": [
                {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "confidence": f.get("confidence"),
                    "risk_score": f.get("risk_score"),
                    "remediation": f.get("remediation"),
                }
                for f in prioritized
            ],
            "correlations": correlations,
            "suspicious_findings": suspicious,
            "duplicates_removed": duplicates,
            "manager_summary": self._manager_summary(findings, risk, top),
            "confidence_adjustments": self._confidence_adjustments(findings),
            "ai_caveats": (
                "Generated by the offline heuristic analysis layer (no external LLM "
                "configured). All statements derive from tool evidence collected "
                "during this assessment."
            ),
        }

    @staticmethod
    def _correlate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        correlations: list[dict[str, Any]] = []
        missing_tls = any("HSTS" in f.get("title", "") for f in findings)
        weak_tls = any("Weak TLS protocol" in f.get("title", "") for f in findings)
        dev_server = any("Werkzeug" in f.get("title", "") for f in findings)
        if missing_tls:
            correlations.append(
                {
                    "pattern": "transport_protection_gap",
                    "explanation": (
                        "Missing HSTS together with the current transport setup means "
                        "clients may accept unencrypted connections."
                    ),
                    "related": ["HSTS"],
                }
            )
        if weak_tls:
            correlations.append(
                {
                    "pattern": "deprecated_transport",
                    "explanation": (
                        "A deprecated TLS protocol was negotiated; combined with other "
                        "web findings this raises overall transport risk."
                    ),
                    "related": ["TLS"],
                }
            )
        if dev_server:
            correlations.append(
                {
                    "pattern": "dev_server_in_production",
                    "explanation": (
                        "A development server was detected; combining this with exposed "
                        "files or missing headers suggests the environment is not hardened."
                    ),
                    "related": ["Werkzeug"],
                }
            )
        return correlations

    @staticmethod
    def _manager_summary(findings, risk, top) -> str:
        if not top:
            return "No high-priority issues. Continue routine monitoring."
        names = ", ".join(f"'{t['title']}'" for t in top[:3])
        return (
            f"Team should focus on {len(top)} priority items: {names}. "
            f"Overall security score is {risk.get('security_score', 'N/A')}/100. "
            "Remediation steps are listed per finding in the report."
        )

    @staticmethod
    def _confidence_adjustments(findings) -> list[dict[str, Any]]:
        adjustments = []
        for f in findings:
            meta = f.get("metadata", {})
            if meta.get("also_reported_by"):
                adjustments.append(
                    {
                        "id": f.get("id"),
                        "fingerprint": f.get("fingerprint"),
                        "title": f.get("title"),
                        "reason": f"corroborated by multiple sources: {meta['also_reported_by']}",
                        "suggested_confidence": "HIGH",
                    }
                )
        return adjustments


class OpenAICompatibleProvider(LLMProvider):
    """Talks to any OpenAI-compatible /chat/completions endpoint."""

    name = "openai-compatible"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self._api_key = api_key or settings.llm_api_key
        self._base_url = (base_url or settings.llm_base_url or "https://api.openai.com/v1").rstrip("/")
        self._model = model or settings.llm_model or "gpt-4o-mini"
        self._timeout = timeout or settings.llm_timeout_seconds

    async def analyze(self, prompt: str, system: str) -> str:
        body = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": settings.llm_max_output_tokens,
        }
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/chat/completions", json=body, headers=headers
                )
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(f"LLM endpoint unreachable: {exc}") from exc
        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected LLM response shape: {data}") from exc

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    f"{self._base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"} if self._api_key else {},
                )
                return resp.status_code < 500
        except httpx.HTTPError:
            return False


def make_llm_provider() -> LLMProvider:
    name = settings.llm_provider.lower()
    if name in ("heuristic", "offline", ""):
        return HeuristicProvider()
    if name in ("openai", "openai-compatible", "openai_compatible"):
        return OpenAICompatibleProvider()
    raise LLMError(f"unknown CASA_LLM_PROVIDER {settings.llm_provider!r}")
