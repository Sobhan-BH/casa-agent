"""Passive Discovery module — robots/sitemap/security.txt/well-known/docs/API hints.

Every result is a raw result (evidence stored later by EvidenceCollector);
only high-confidence, content-confirmed detections become findings.
All network access goes through SafeHttpClient (scope re-checked per request).
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.core.safe_http import SafeHttpClient

_DOC_PATHS = [
    "/docs",
    "/swagger",
    "/swagger-ui",
    "/swagger/index.html",
    "/api-docs",
    "/openapi.json",
    "/swagger.json",
    "/api/v1/docs",
    "/api/v2/docs",
    "/graphql",
    "/.well-known/openapi",
]

_WELL_KNOWN = [
    "/.well-known/security.txt",
    "/security.txt",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/change-password",
    "/.well-known/matrix/client",
]

# Extensions that suggest source/backup exposure when referenced from body/robots.
_SOURCE_HINT_RE = re.compile(
    r"\.(?:map|bak|old|save|swp|sql|zip|tar\.gz|tgz|7z|rar|dump)(?=[\"'\s?]|$)",
    re.IGNORECASE,
)


class DiscoveryModule(AssessmentModule):
    name = "discovery"
    phase = "DISCOVERY"

    def __init__(self, validator) -> None:
        self._validator = validator

    def applies(self, ctx: AssessmentContext) -> bool:
        return True

    async def run(self, ctx: AssessmentContext) -> None:
        client = SafeHttpClient(self._validator)
        base = ctx.target_url.rstrip("/")
        discovery: dict[str, Any] = {
            "robots": ctx.raw_results.get("robots_txt", {}),
            "sitemap": ctx.raw_results.get("sitemap", {}),
        }

        # --- security.txt / well-known ----------------------------------
        well_known: dict[str, dict[str, Any]] = {}
        sec_txt = None
        for path in _WELL_KNOWN:
            entry = await self._fetch(client, base + path)
            well_known[path] = entry
            if path.endswith("security.txt") and entry.get("status_code") == 200:
                sec_txt = entry
        discovery["well_known"] = well_known
        if sec_txt is None:
            f = make_finding(
                title="security.txt is not published (RFC 9116)",
                category="RECON",
                severity="INFO",
                confidence="HIGH",
                description=(
                    "No /.well-known/security.txt (or /security.txt) was found. "
                    "This file tells researchers where to report security issues."
                ),
                evidence=[
                    {"type": "http_probe", "paths": _WELL_KNOWN[:2], "outcome": "absent"}
                ],
                affected_asset=base + "/.well-known/security.txt",
                impact="Security reports may never reach the right team.",
                remediation="Publish RFC 9116 security.txt with a Contact and Policy field.",
                references=["https://www.rfc-editor.org/rfc/rfc9116.html"],
                source=self.name,
            )
            f["fingerprint"] = make_fingerprint("security_txt_missing", ctx.base_domain)
            ctx.findings.append(f)

        # --- exposed documentation / API descriptions --------------------
        docs: dict[str, dict[str, Any]] = {}
        doc_findings: list[dict[str, Any]] = []
        for path in _DOC_PATHS:
            entry = await self._fetch(client, base + path)
            docs[path] = entry
            if entry.get("status_code") != 200:
                continue
            body = (entry.get("body") or "")[:2000]
            is_openapi = bool(
                re.search(r'"openapi"\s*:', body) or re.search(r'"swagger"\s*:', body)
            )
            is_ui = bool(
                re.search(r"swagger", body, re.IGNORECASE)
                or re.search(r"<title>.*(docs|graphql|swagger)", body, re.IGNORECASE)
                or "graphiql" in body.lower()
            )
            if not (is_openapi or is_ui):
                continue
            doc_findings.append({"path": path, "kind": "openapi" if is_openapi else "ui"})
            f = make_finding(
                title=f"API documentation is publicly accessible ({path})",
                category="CONFIGURATION",
                severity="LOW",
                confidence="HIGH",
                description=(
                    f"An API documentation endpoint is reachable without authentication "
                    f"at {path}. Documentation enumerates endpoints and parameters for "
                    "attackers."
                ),
                evidence=[
                    {
                        "type": "http_get",
                        "url": entry.get("url", base + path),
                        "status": entry.get("status_code"),
                        "kind": "openapi" if is_openapi else "ui",
                        "body_snippet": body[:300],
                    }
                ],
                affected_asset=entry.get("url", base + path),
                impact="Attackers learn the full API surface without recon effort.",
                remediation=(
                    "Require authentication for API docs in production, or restrict "
                    "docs endpoints to internal networks."
                ),
                references=["https://owasp.org/www-project-api-security/"],
                source=self.name,
            )
            f["fingerprint"] = make_fingerprint("api_docs_exposed", path, ctx.base_domain)
            ctx.findings.append(f)
        discovery["docs"] = docs
        discovery["docs_exposed"] = doc_findings

        # --- API endpoint discovery (passive, from already-fetched content) -
        endpoints = self._extract_endpoints(ctx, base)
        discovery["endpoints"] = endpoints
        ctx.raw_results["discovery"] = discovery

    # ------------------------------------------------------------------ helpers

    async def _fetch(self, client: SafeHttpClient, url: str) -> dict[str, Any]:
        try:
            resp = await client.get(url)
            return {
                "url": resp.url,
                "status_code": resp.status_code,
                "body": resp.body[:5000],
                "content_type": resp.headers.get("content-type", ""),
            }
        except Exception as exc:  # noqa: BLE001 - probes are best-effort
            return {"url": url, "error": str(exc)}

    @staticmethod
    def _extract_endpoints(ctx: AssessmentContext, base: str) -> dict[str, Any]:
        """Passive endpoint discovery from robots, sitemap, HTML and JS bodies."""
        urls: set[str] = set()
        forms: list[dict[str, str]] = []

        robots = (ctx.raw_results.get("robots_txt", {}) or {}).get("body", "") or ""
        for m in re.finditer(r"^(?:disallow|allow|sitemap):\s*(\S+)", robots, re.IGNORECASE):
            v = m.group(1)
            urls.add(v if v.startswith("http") else base + v)

        sitemap = (ctx.raw_results.get("sitemap", {}) or {}).get("body", "") or ""
        for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap, re.IGNORECASE):
            urls.add(m.group(1))

        root = ctx.raw_results.get("http_root", {}) or {}
        html = root.get("body") or ""
        for m in re.finditer(r'''(?:href|src|action)\s*=\s*["']([^"']+)["']''', html):
            v = m.group(1)
            if v.startswith(("http://", "https://", "/")):
                urls.add(v if v.startswith("http") else base + v)
        for m in re.finditer(r"""<form[^>]*>""", html, re.IGNORECASE):
            forms.append({"form_html": m.group(0)[:200], "page": root.get("url", base)})

        # Scope filter: keep only in-scope URLs (same host), drop everything else.
        host = urlparse(base).hostname or ""
        in_scope: list[str] = []
        for u in sorted(urls):
            p = urlparse(u)
            if p.scheme in ("http", "https") and (p.hostname or "") == host:
                in_scope.append(u)

        return {
            "urls": in_scope[:200],
            "forms": forms[:20],
            "source_map_or_backup_refs": sorted(
                {m.group(0) for m in _SOURCE_HINT_RE.finditer(html)}
            )[:20],
        }
