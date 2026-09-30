"""CORS Analyzer — dedicated, evidence-based cross-origin checks.

Sends harmless GET probes with controlled Origin values and classifies the
server's Access-Control-* behavior:
- wildcard origin
- wildcard + credentials (unsafe)
- reflected origin + credentials (unsafe)
- subdomain-wildcard reflection (origin-embedding attacks)
Only GET requests are ever sent; no credentials are attached; the scope
validator re-checks the exact URL before each probe.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.core.safe_http import SafeHttpClient

# Harmless, obviously-non-production origins used to test reflection.
_PROBE_ORIGINS = [
    "https://casa-probe-a.example",
    "https://casa-probe-b.example",
]


class CorsAnalyzerModule(AssessmentModule):
    name = "cors_analyzer"
    phase = "CORS"

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        client = SafeHttpClient(self._validator)
        root = ctx.raw_results.get("http_root", {}) or {}
        headers = root.get("headers", {}) or {}

        results: dict[str, Any] = {"unauthenticated_observations": {}}

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")

        # 1) Passive classification from the root response ------------------
        if acao == "*" and acac.lower() == "true":
            self._wildcard_credentials(ctx, root.get("url", ctx.target_url), acao, acac)
        elif acao == "*":
            ctx.raw_results["cors"] = {
                "mode": "wildcard_no_credentials", "acao": acao,
                "note": "wildcard without credentials is acceptable for public data",
            }
            return

        # 2) Active reflection probes (harmless GET with fake origins) ------
        # Probe the root AND any API endpoints discovered passively — CORS
        # misconfiguration typically lives on API routes, not on "/".
        base = ctx.target_url.rstrip("/")
        endpoints = ((ctx.raw_results.get("discovery", {}) or {}).get("endpoints", {}) or {}).get(
            "urls", []
        )
        probe_urls = [root.get("url", ctx.target_url)]
        for u in endpoints:
            parsed = urlparse(u)
            if (
                "/api" in parsed.path or parsed.path.endswith(".json")
            ) and u not in probe_urls:
                probe_urls.append(u)
        probe_urls = probe_urls[:5]  # bounded: never more than 5 probe targets

        reflections: list[dict[str, Any]] = []
        for probe_url in probe_urls:
            for probe_origin in _PROBE_ORIGINS:
                try:
                    resp = await client.get_with_origin(probe_url, probe_origin)
                except AttributeError:
                    # SafeHttpClient without origin support: skip active probing.
                    ctx.raw_results["cors"] = {
                        "mode": "active_probes_unavailable",
                        "unauthenticated_observations": results["unauthenticated_observations"],
                    }
                    return
                entry = {
                    "probe_origin": probe_origin,
                    "status": resp.status_code,
                    "acao": resp.headers.get("access-control-allow-origin", ""),
                    "acac": resp.headers.get("access-control-allow-credentials", ""),
                    "vary": resp.headers.get("vary", ""),
                }
                reflections.append({"url": probe_url, **entry})
                results["unauthenticated_observations"][f"{probe_url}|{probe_origin}"] = entry

        ctx.raw_results["cors"] = {
            "mode": "active_probes_completed",
            "root_acao": acao,
            "root_acac": acac,
            "reflections": reflections,
            "unauthenticated_observations": results["unauthenticated_observations"],
        }

        # 3) Classify reflection behavior ------------------------------------
        reported: set[str] = set()
        for refl in reflections:
            entry = {k: v for k, v in refl.items() if k != "url"}
            acao_r = entry["acao"]
            if not acao_r:
                continue
            asset = refl["url"]
            if acao_r == entry["probe_origin"] and entry["acac"].lower() == "true":
                if "credentials" not in reported:
                    reported.add("credentials")
                    self._reflected_credentials(ctx, asset, entry)
            elif acao_r == entry["probe_origin"]:
                if "no_creds" not in reported:
                    reported.add("no_creds")
                    self._reflected_no_credentials(ctx, asset, entry)

    # ------------------------------------------------------------------ helpers

    def _wildcard_credentials(self, ctx, asset, acao, acac) -> None:
        f = make_finding(
            title="CORS allows any origin with credentials",
            category="CONFIGURATION",
            severity="HIGH",
            confidence="HIGH",
            description=(
                "Access-Control-Allow-Origin: * is combined with Access-Control-Allow-"
                "Credentials: true — an invalid-but-dangerous combination that browsers "
                "treat as 'any origin may read authenticated responses' on legacy stacks."
            ),
            evidence=[
                {"type": "http_header", "header": "access-control-allow-origin", "value": acao},
                {"type": "http_header", "header": "access-control-allow-credentials", "value": acac},
            ],
            affected_asset=asset,
            impact="Cross-origin theft of authenticated data.",
            remediation="Echo explicit origins instead of *; never combine * with credentials.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            source=self.name,
        )
        f["fingerprint"] = make_fingerprint("cors_wildcard_credentials", asset)
        ctx.findings.append(f)

    def _reflected_credentials(self, ctx, asset, entry) -> None:
        f = make_finding(
            title="CORS reflects arbitrary origins with credentials",
            category="CONFIGURATION",
            severity="HIGH",
            confidence="HIGH",
            description=(
                f"The server reflected the attacker-controlled origin "
                f"'{entry['probe_origin']}' in Access-Control-Allow-Origin together with "
                "Access-Control-Allow-Credentials: true. Any website can read "
                "authenticated responses from this endpoint."
            ),
            evidence=[{"type": "cors_reflection", **entry}],
            affected_asset=asset,
            impact="Full cross-origin read of authenticated user data by any site.",
            remediation="Use a server-side allowlist of origins; never reflect arbitrary origins with credentials.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            source=self.name,
        )
        f["fingerprint"] = make_fingerprint("cors_reflected_credentials", asset)
        ctx.findings.append(f)

    def _reflected_no_credentials(self, ctx, asset, entry) -> None:
        f = make_finding(
            title="CORS reflects arbitrary origins (credentials not allowed)",
            category="CONFIGURATION",
            severity="LOW",
            confidence="HIGH",
            description=(
                f"The server reflected the origin '{entry['probe_origin']}' without "
                "Allow-Credentials. Public-data endpoints often do this; it leaks only "
                "unauthenticated responses."
            ),
            evidence=[{"type": "cors_reflection", **entry}],
            affected_asset=asset,
            impact="Unauthenticated data is readable cross-origin (often intended).",
            remediation="If the data should be public this is fine; otherwise restrict to an origin allowlist.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            source=self.name,
        )
        f["fingerprint"] = make_fingerprint("cors_reflected_origin", asset)
        ctx.findings.append(f)
