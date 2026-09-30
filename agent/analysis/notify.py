"""Webhook notifications on assessment completion.

Configured via env (CASA_ prefix):
- CASA_WEBHOOK_URL          — full URL to POST the event JSON
- CASA_WEBHOOK_FORMAT       — generic | slack | discord  (default generic)
- CASA_WEBHOOK_EVENTS       — comma list, default "JOB_COMPLETED"
                             (JOB_COMPLETED | JOB_FAILED | JOB_BLOCKED)

Failure to deliver never affects the assessment result: webhook errors are
logged and recorded in the audit trail only.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from agent.core.config import settings

logger = logging.getLogger("casa.notify")

FORMATTERS = {"generic", "slack", "discord"}


def _generic_payload(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "event": event,
        "job_id": payload.get("job_id"),
        "assessment_id": payload.get("assessment_id"),
        "target": payload.get("target"),
        "status": payload.get("status"),
        "security_score": payload.get("security_score"),
        "findings": payload.get("findings"),
        "severity_distribution": payload.get("severity_distribution"),
        "report_url": payload.get("report_url"),
        "source": "casa-agent",
    }


def _slack_payload(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    sev = payload.get("severity_distribution") or {}
    sev_str = " · ".join(f"{k}: {v}" for k, v in sev.items() if v)
    score = payload.get("security_score")
    emoji = "🔴" if (score or 100) < 50 else "🟠" if (score or 100) < 75 else "🟢"
    text = (
        f"{emoji} *CASA assessment {event.replace('JOB_', '').lower()}* — "
        f"{payload.get('target')}\n"
        f"Score: *{score if score is not None else 'n/a'}/100* · Findings: "
        f"*{payload.get('findings', 0)}*"
        + (f" · {sev_str}" if sev_str else "")
    )
    return {"text": text}


def _discord_payload(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    sev = payload.get("severity_distribution") or {}
    sev_str = ", ".join(f"{k}: {v}" for k, v in sev.items() if v)
    score = payload.get("security_score")
    return {
        "content": (
            f"**CASA {event}** for {payload.get('target')}\n"
            f"Score: **{score if score is not None else 'n/a'}/100** · "
            f"Findings: **{payload.get('findings', 0)}**"
            + (f" · {sev_str}" if sev_str else "")
        )
    }


def build_payload(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    fmt = (settings.webhook_format or "generic").lower()
    if fmt == "slack":
        return _slack_payload(event, payload)
    if fmt == "discord":
        return _discord_payload(event, payload)
    return _generic_payload(event, payload)


async def send_webhook(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST the notification; never raises. Returns a delivery receipt dict."""
    url = (settings.webhook_url or "").strip()
    if not url or event not in (settings.webhook_events or ""):
        return {"sent": False, "reason": "disabled_or_unsubscribed"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=build_payload(event, payload))
        ok = 200 <= resp.status_code < 300
        logger.info("webhook %s -> %s (%s)", event, url, resp.status_code)
        return {"sent": ok, "status_code": resp.status_code}
    except (httpx.HTTPError, OSError) as exc:
        logger.warning("webhook delivery failed for %s: %s", event, exc)
        return {"sent": False, "error": str(exc)[:200]}
