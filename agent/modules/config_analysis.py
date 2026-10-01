"""Configuration & Security Header Analysis.

Checks the security-header baseline (HSTS, CSP, X-Content-Type-Options,
Referrer-Policy, frame options, cookies, cache control on sensitive-ish paths,
CORS wildcards, directory listing hints).
"""
from __future__ import annotations

from typing import Any

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule

_HEADER_CHECKS: list[dict[str, Any]] = [
    # NOTE: HSTS / CSP / XCTO / Referrer-Policy / frame-options live in the
    # deeper HeadersModule (which also validates directive QUALITY). Duplicating
    # them here produced identical-title double findings on every target.
]



class ConfigAnalysisModule(AssessmentModule):
    name = "config_analysis"
    phase = "CONFIG_ANALYSIS"

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        root = ctx.raw_results.get("http_root")
        if not root:
            return
        headers: dict[str, str] = root.get("headers", {})
        is_https = ctx.target_url.startswith("https://")
        asset = root.get("url", ctx.target_url)

        for check in _HEADER_CHECKS:
            if check.get("only_if_https") and not is_https:
                continue
            if headers.get(check["header"]):
                continue
            alt = check.get("alt_pattern")
            if alt and any(alt.lower() in headers.get(h, "").lower() for h in check.get("alt_headers", [])):
                continue
            f = make_finding(
                title=check["title"],
                category="CONFIGURATION",
                severity=check["severity"],
                confidence=check["confidence"],
                description=check["description"],
                evidence=[
                    {
                        "type": "http_headers_observed",
                        "source": "http_root",
                        "url": asset,
                        "missing": check["header"],
                        "observed_header_names": sorted(headers.keys()),
                    }
                ],
                affected_asset=asset,
                impact=check["impact"],
                remediation=check["remediation"],
                references=check["references"],
                source=self.name,
            )
            f["fingerprint"] = make_fingerprint(check["header"], asset)
            ctx.findings.append(f)

        self._check_cookies(ctx, headers, asset)
        self._check_cors(ctx, headers, asset)

    def _check_cookies(self, ctx, headers, asset) -> None:
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return
        for chunk in set_cookie.split(","):
            if "=" not in chunk:
                continue
            name = chunk.split("=", 1)[0].strip()
            lower = chunk.lower()
            issues = []
            if "httponly" not in lower:
                issues.append("HttpOnly")
            if "secure" not in lower:
                issues.append("Secure")
            if "samesite" not in lower:
                issues.append("SameSite")
            for missing in issues:
                severity = "MEDIUM" if name.lower().find("sess") >= 0 or name.lower().find("auth") >= 0 else "LOW"
                f = make_finding(
                    title=f"Cookie '{name}' is missing the {missing} attribute",
                    category="CONFIGURATION",
                    severity=severity,
                    confidence="HIGH",
                    description=(
                        f"Set-Cookie for '{name}' does not set {missing}. This weakens "
                        "session integrity or confidentiality depending on the attribute."
                    ),
                    evidence=[
                        {"type": "http_header", "header": "set-cookie", "cookie": name,
                         "value": chunk.strip()[:200]}
                    ],
                    affected_asset=asset,
                    impact="Session hijacking or CSRF risk depending on the missing attribute.",
                    remediation=f"Set {missing} (and Prefer SameSite=Lax or stricter) on cookies.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint("cookie_flags", name, missing, asset)
                ctx.findings.append(f)

    def _check_cors(self, ctx, headers, asset) -> None:
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            f = make_finding(
                title="CORS allows any origin with credentials",
                category="CONFIGURATION",
                severity="HIGH",
                confidence="HIGH",
                description=(
                    "Access-Control-Allow-Origin: * is combined with "
                    "Access-Control-Allow-Credentials: true, letting any origin read "
                    "authenticated responses."
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
