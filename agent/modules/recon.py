"""Reconnaissance module — passive/low-impact only.

Collects: root HTTP probe, redirect chain, robots.txt, sitemap.xml, DNS.
Every fetch goes through SafeHttpClient (scope re-checked per request).
"""
from __future__ import annotations

from agent.core.context import AssessmentContext
from agent.core.interfaces import AssessmentModule
from agent.connectors.adapters import DnsAdapter
from agent.connectors.adapters import HttpProbeAdapter
from agent.core.safe_http import SafeHttpClient


class ReconModule(AssessmentModule):
    name = "recon"
    phase = "RECON"
    critical = True

    def __init__(self, validator) -> None:
        self._validator = validator

    def applies(self, ctx: AssessmentContext) -> bool:
        return True

    async def run(self, ctx: AssessmentContext) -> None:
        client = SafeHttpClient(self._validator)
        probe = HttpProbeAdapter(self._validator)
        dns = DnsAdapter(self._validator)

        # 1) Root document
        root = await probe.execute({"url": ctx.target_url})
        ctx.raw_results["http_root"] = root

        # 2) robots.txt (low impact, single GET)
        base = ctx.target_url.rstrip("/")
        try:
            robots = await client.get(base + "/robots.txt")
            ctx.raw_results["robots_txt"] = {
                "url": robots.url,
                "status_code": robots.status_code,
                "body": robots.body[:20000],
            }
        except Exception as exc:  # noqa: BLE001 - recon is best-effort
            ctx.raw_results["robots_txt"] = {"error": str(exc)}

        # 3) sitemap.xml
        try:
            sm = await client.get(base + "/sitemap.xml")
            ctx.raw_results["sitemap"] = {
                "url": sm.url,
                "status_code": sm.status_code,
                "body": sm.body[:20000],
            }
        except Exception as exc:  # noqa: BLE001
            ctx.raw_results["sitemap"] = {"error": str(exc)}

        # 4) DNS (passive)
        try:
            ctx.raw_results["dns"] = await dns.execute({"host": ctx.base_domain})
        except Exception as exc:  # noqa: RECEL001
            ctx.raw_results["dns"] = {"error": str(exc)}

        # Recon itself flags nothing; it feeds later modules.
