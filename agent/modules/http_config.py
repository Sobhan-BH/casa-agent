"""HTTP Security Configuration — HTTPS enforcement, redirect safety, methods.

Determines how the origin behaves on plain HTTP vs HTTPS, whether redirects
are safe, which methods the server advertises via OPTIONS, and what
server/version information leaks.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.core.safe_http import SafeHttpClient

_UNUSUAL_METHODS_HINT = re.compile(
    r"\b(PATCH|PROPFIND|TRACE|TRACK|DEBUG)\b", re.IGNORECASE
)


class HttpConfigModule(AssessmentModule):
    name = "http_config"
    phase = "HTTP_CONFIG"

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        client = SafeHttpClient(self._validator)
        is_https = ctx.target_url.startswith("https://")

        # 1) Plain-HTTP behavior
        if is_https:
            plain_url = urlparse(ctx.target_url)._replace(scheme="http").geturl()
            entry = await self._safe_get(client, plain_url)
            ctx.raw_results["http_plain_probe"] = entry
            # SafeHttpClient follows in-scope redirects and reports the FINAL
            # status. A 200 here is only a finding when the chain shows the
            # content was served over HTTP itself (no https hop happened).
            redirect_hops: list[str] = entry.get("redirects") or []
            redirected_to_https = any(
                h.startswith("https://") for h in redirect_hops
            )
            if entry.get("status_code") == 200 and not redirected_to_https:
                root_body = (ctx.raw_results.get("http_root", {}) or {}).get("body") or ""
                same_body = (entry.get("body") or "") == root_body
                f = make_finding(
                    title="Site is served over plain HTTP without redirect to HTTPS",
                    category="CONFIGURATION",
                    severity="MEDIUM",
                    confidence="HIGH",
                    description=(
                        "http:// on the same host returns a page (status 200) instead of "
                        "redirecting to HTTPS. Visitors following http:// links are "
                        "served unencrypted content."
                    ),
                    evidence=[{
                        "type": "http_get", "url": plain_url,
                        "status": entry.get("status_code"),
                        "redirects": redirect_hops,
                        "served_full_page": same_body,
                    }],
                    affected_asset=plain_url,
                    impact="Downgrade exposure for users entering via http:// links.",
                    remediation="301-redirect all HTTP traffic to HTTPS and enable HSTS.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint("http_no_redirect", ctx.base_domain)
                ctx.findings.append(f)
            elif redirected_to_https:
                ctx.raw_results["http_plain_probe"]["classification"] = "http_redirects_to_https_ok"
        else:
            ctx.raw_results["http_plain_probe"] = {
                "status_code": None, "note": "target itself is plain HTTP"
            }
            root = ctx.raw_results.get("http_root", {}) or {}
            f = make_finding(
                title="Target is served over plain HTTP (no TLS)",
                category="CONFIGURATION",
                severity="MEDIUM",
                confidence="HIGH",
                description=(
                    "The assessed URL uses http:// with no TLS. All traffic travels "
                    "unencrypted, including any credentials or session tokens."
                ),
                evidence=[{
                    "type": "http_get", "url": ctx.target_url,
                    "status": root.get("status_code"),
                }],
                affected_asset=ctx.target_url,
                impact="Traffic confidentiality and integrity are not protected.",
                remediation="Deploy TLS and redirect all HTTP traffic to HTTPS.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                source=self.name,
            )
            f["fingerprint"] = make_fingerprint("plain_http_target", ctx.base_domain)
            ctx.findings.append(f)

        # 2) Redirect safety on the primary origin
        root = ctx.raw_results.get("http_root", {}) or {}
        redirects = root.get("redirects", []) or []
        for r_url in redirects:
            if urlparse(r_url).scheme == "http":
                f = make_finding(
                    title="HTTPS origin redirects to a plain HTTP URL",
                    category="CONFIGURATION",
                    severity="MEDIUM",
                    confidence="HIGH",
                    description=f"The origin redirected through {r_url} over plain HTTP.",
                    evidence=[{"type": "redirect_chain", "hops": redirects}],
                    affected_asset=r_url,
                    impact="Users are downgraded to unencrypted traffic mid-navigation.",
                    remediation="Never redirect from HTTPS to HTTP; keep chains on HTTPS.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint("https_to_http_redirect", ctx.base_domain)
                ctx.findings.append(f)

        # 3) OPTIONS / advertised methods (single non-destructive OPTIONS)
        methods = await self._probe_options(client, ctx.target_url)
        ctx.raw_results["http_methods"] = methods
        advertised = methods.get("allow", "") or methods.get("public", "")
        if advertised and _UNUSUAL_METHODS_HINT.search(advertised):
            f = make_finding(
                title=f"Server advertises unusual methods via OPTIONS ({advertised})",
                category="CONFIGURATION",
                severity="LOW",
                confidence="MEDIUM",
                description=(
                    "The OPTIONS response lists methods beyond the standard safe set. "
                    "Some (TRACE/PROPFIND/DEBUG) are commonly disabled for security."
                ),
                evidence=[{
                    "type": "http_options", "allow": advertised,
                    "status": methods.get("status_code"),
                }],
                affected_asset=ctx.target_url,
                impact="Unusual methods may indicate legacy or misconfigured endpoints.",
                remediation="Disable TRACE/PROPFIND/DEBUG methods at the server.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                source=self.name,
            )
            f["fingerprint"] = make_fingerprint("unusual_methods", ctx.base_domain)
            ctx.findings.append(f)

        # 4) Server/version disclosure
        headers = root.get("headers", {}) or {}
        for header, label in (("server", "Server"), ("x-powered-by", "X-Powered-By")):
            value = headers.get(header, "")
            if value and re.search(r"\d+\.\d+", value):
                f = make_finding(
                    title=f"{label} header discloses a version ({value[:40]})",
                    category="TECHNOLOGY",
                    severity="LOW",
                    confidence="HIGH",
                    description=f"The {label} header discloses product/version: {value[:80]}.",
                    evidence=[{"type": "http_header", "header": header, "value": value[:80]}],
                    affected_asset=root.get("url", ctx.target_url),
                    impact="Version tokens enable targeted CVE lookup.",
                    remediation=f"Remove or generalize the {label} header.",
                    references=["https://owasp.org/www-project-secure-headers/"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint("server_version", header, ctx.base_domain)
                ctx.findings.append(f)

    # ------------------------------------------------------------------ helpers

    async def _safe_get(self, client: SafeHttpClient, url: str) -> dict[str, Any]:
        try:
            resp = await client.get(url)
            return {
                "url": resp.url,
                "status_code": resp.status_code,
                "body": resp.body[:2000],
                "redirects": resp.redirects,
            }
        except Exception as exc:  # noqa: BLE001 - probe is best-effort
            return {"url": url, "error": str(exc)}

    @staticmethod
    async def _probe_options(client: SafeHttpClient, url: str) -> dict[str, Any]:
        try:
            resp = await client.options(url)
            return {
                "status_code": resp.status_code,
                "allow": resp.headers.get("allow", ""),
                "public": resp.headers.get("public", ""),
            }
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)}
