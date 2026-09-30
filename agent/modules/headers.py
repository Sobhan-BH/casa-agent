"""Header Security Analysis — deep analysis of security-response headers.

Goes beyond presence/absence (ConfigAnalysisModule): validates directive
quality, detects weak/conflicting/unsafe configurations, and emits one
finding per concrete misconfiguration with header-level evidence.

Cross-Origin headers: COOP, CORP, COEP (isolation hardening).
Permissions-Policy: sensitive feature delegation.
"""
from __future__ import annotations

import re
from typing import Any

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule

_MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)


def _find_missing(
    headers: dict[str, str], header: str, alternatives: list[str] | None = None
) -> bool:
    if headers.get(header):
        return False
    for alt in alternatives or []:
        if headers.get(alt):
            return False
    return True


class HeadersModule(AssessmentModule):
    name = "headers"
    phase = "HEADERS"

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        root = ctx.raw_results.get("http_root")
        if not root:
            return
        headers: dict[str, str] = root.get("headers", {})
        is_https = ctx.target_url.startswith("https://")
        asset = root.get("url", ctx.target_url)

        # --- HSTS quality -------------------------------------------------
        if is_https and _find_missing(headers, "strict-transport-security"):
            self._add(ctx, asset, "HSTS header missing (HTTPS site)", "strict-transport-security",
                      "MEDIUM", "HIGH",
                      "No Strict-Transport-Security on an HTTPS response: browsers may "
                      "allow downgrade to HTTP, enabling interception.",
                      "Protocol downgrade and cookie theft over unencrypted channels.",
                      "Send HSTS with a long max-age, e.g. max-age=31536000; includeSubDomains.",
                      ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                      "hsts_missing")
        elif is_https:
            hsts = headers.get("strict-transport-security", "")
            m = _MAX_AGE.search(hsts)
            max_age = int(m.group(1)) if m else 0
            if max_age < 31536000 and max_age > 0:
                self._add(ctx, asset, f"HSTS max-age too short ({max_age}s)", "strict-transport-security",
                          "LOW", "HIGH",
                          "HSTS max-age below one year limits the protection window.",
                          "Users lose long-term downgrade protection.",
                          "Use max-age=31536000 (one year) once the deployment is stable.",
                          ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                          "hsts_short_max_age", observed=hsts)
            if "includesubdomains" not in hsts.lower():
                self._add(ctx, asset, "HSTS lacks includeSubDomains", "strict-transport-security",
                          "INFO", "HIGH",
                          "HSTS does not cover subdomains; a subdomain takeover could "
                          "bypass transport protection.",
                          "Subdomain requests are not forced to HTTPS.",
                          "Add includeSubDomains once all subdomains support HTTPS.",
                          ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                          "hsts_no_subdomains", observed=hsts)

        # --- CSP -----------------------------------------------------------
        csp = headers.get("content-security-policy", "")
        if not csp:
            self._add(ctx, asset, "Content-Security-Policy header missing", "content-security-policy",
                      "MEDIUM", "HIGH",
                      "No CSP is sent. CSP limits the impact of XSS by restricting "
                      "script sources.",
                      "Increased XSS exploitation success and blast radius.",
                      "Define a CSP starting with default-src 'self' and tighten per app.",
                      ["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                      "csp_missing")
        else:
            directives = self._parse_csp(csp)
            if "unsafe-inline" in directives.get("script-src", []):
                self._add(ctx, asset, "CSP allows inline scripts (unsafe-inline)", "content-security-policy",
                          "MEDIUM", "HIGH",
                          "script-src contains unsafe-inline, which defeats most XSS "
                          "protection CSP would provide.",
                          "Injected inline scripts execute despite CSP.",
                          "Use nonces or hashes instead of unsafe-inline.",
                          ["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                          "csp_unsafe_inline", observed=directives.get("script-src-srcs", ""))
            if "unsafe-eval" in directives.get("script-src", []):
                self._add(ctx, asset, "CSP allows eval (unsafe-eval)", "content-security-policy",
                          "LOW", "HIGH",
                          "script-src contains unsafe-eval; CSP cannot stop eval-based "
                          "XSS gadgets.",
                          "Eval-based exploitation primitives remain available.",
                          "Remove unsafe-eval; refactor code that needs dynamic evaluation.",
                          ["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                          "csp_unsafe_eval", observed=directives.get("script-src-srcs", ""))
            if "*" in directives.get("script-src", []):
                self._add(ctx, asset, "CSP script-src uses a wildcard", "content-security-policy",
                          "MEDIUM", "HIGH",
                          "script-src includes '*', allowing scripts from any origin.",
                          "CSP provides near-zero XSS protection.",
                          "Enumerate required script origins explicitly.",
                          ["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                          "csp_wildcard_script", observed=directives.get("script-src-srcs", ""))
            if not directives:
                self._add(ctx, asset, "CSP header present but empty/unparseable", "content-security-policy",
                          "LOW", "MEDIUM",
                          "A Content-Security-Policy header was sent but contains no "
                          "recognizable directives.",
                          "Browsers ignore an empty policy; no protection is applied.",
                          "Send a valid CSP with default-src and script-src directives.",
                          ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
                          "csp_empty", observed=csp)

        # --- X-Content-Type-Options ---------------------------------------
        if _find_missing(headers, "x-content-type-options"):
            self._add(ctx, asset, "X-Content-Type-Options header missing", "x-content-type-options",
                      "LOW", "HIGH",
                      "nosniff is not set; browsers may MIME-sniff user content.",
                      "Possible drive-by execution of uploaded content.",
                      "Add X-Content-Type-Options: nosniff.",
                      ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                      "xcto_missing")
        elif headers.get("x-content-type-options", "").lower() != "nosniff":
            self._add(ctx, asset, "X-Content-Type-Options has an unexpected value", "x-content-type-options",
                      "LOW", "HIGH",
                      "The header is present but not 'nosniff'; browsers ignore invalid "
                      "values.",
                      "MIME-sniffing protection is not active.",
                      "Send exactly X-Content-Type-Options: nosniff.",
                      ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                      "xcto_invalid", observed=headers.get("x-content-type-options", ""))

        # --- Referrer-Policy ------------------------------------------------
        if _find_missing(headers, "referrer-policy"):
            self._add(ctx, asset, "Referrer-Policy header missing", "referrer-policy",
                      "LOW", "HIGH",
                      "No Referrer-Policy: URLs (with paths/tokens) may leak via Referer.",
                      "Sensitive path or token leakage to third parties.",
                      "Send Referrer-Policy: strict-origin-when-cross-origin.",
                      ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                      "referrer_missing")

        # --- Clickjacking ----------------------------------------------------
        if _find_missing(headers, "x-frame-options", alternatives=["content-security-policy"]):
            self._add(ctx, asset, "X-Frame-Options / frame-ancestors missing (clickjacking)",
                      "x-frame-options",
                      "LOW", "MEDIUM",
                      "Neither X-Frame-Options nor CSP frame-ancestors restricts framing.",
                      "Clickjacking / UI redress attacks against authenticated users.",
                      "Send X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'none'.",
                      ["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"],
                      "framing_missing")

        # --- Permissions-Policy ----------------------------------------------
        if _find_missing(headers, "permissions-policy"):
            self._add(ctx, asset, "Permissions-Policy header missing", "permissions-policy",
                      "INFO", "HIGH",
                      "No Permissions-Policy is sent; sensitive browser features "
                      "(camera, geolocation, microphone) are not explicitly restricted.",
                      "Embedded third parties could request powerful permissions.",
                      "Send Permissions-Policy denying unused features, e.g. "
                      "camera=(), microphone=(), geolocation=().",
                      ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                      "permissions_missing")

        # --- Cross-Origin isolation headers -----------------------------------
        if _find_missing(headers, "cross-origin-opener-policy"):
            self._add(ctx, asset, "Cross-Origin-Opener-Policy header missing", "cross-origin-opener-policy",
                      "INFO", "HIGH",
                      "No COOP header; cross-window attacks (XS-Leaks) are not mitigated.",
                      "Window references can leak cross-origin information.",
                      "Send Cross-Origin-Opener-Policy: same-origin.",
                      ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"],
                      "coop_missing")

        if _find_missing(headers, "cross-origin-resource-policy"):
            self._add(ctx, asset, "Cross-Origin-Resource-Policy header missing", "cross-origin-resource-policy",
                      "INFO", "HIGH",
                      "No CORP header; resources can be embedded by any site, enabling "
                      "Spectre-class side channels and XS-Leaks.",
                      "Cross-site resource inclusion is not restricted.",
                      "Send Cross-Origin-Resource-Policy: same-origin (or same-site).",
                      ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"],
                      "corp_missing")

        if _find_missing(headers, "cross-origin-embedder-policy"):
            self._add(ctx, asset, "Cross-Origin-Embedder-Policy header missing", "cross-origin-embedder-policy",
                      "INFO", "HIGH",
                      "No COEP header; the document cannot enable cross-origin isolation.",
                      "Side-channel protections (Spectre mitigations) stay unavailable.",
                      "Send Cross-Origin-Embedder-Policy: require-corp where compatible.",
                      ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"],
                      "coep_missing")

    # ------------------------------------------------------------------ helpers

    def _add(
        self,
        ctx,
        asset: str,
        title: str,
        header: str,
        severity: str,
        confidence: str,
        description: str,
        impact: str,
        remediation: str,
        references: list[str],
        key: str,
        observed: Any = "",
    ) -> None:
        root = ctx.raw_results.get("http_root", {}) or {}
        f = make_finding(
            title=title,
            category="CONFIGURATION",
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=[
                {
                    "type": "http_headers_observed",
                    "source": "http_root",
                    "url": asset,
                    "missing": header,
                    "observed": observed,
                    "observed_header_names": sorted(root.get("headers", {}).keys()),
                }
            ],
            affected_asset=asset,
            impact=impact,
            remediation=remediation,
            references=references,
            source=self.name,
        )
        f["fingerprint"] = make_fingerprint(key, asset)
        ctx.findings.append(f)

    @staticmethod
    def _parse_csp(csp: str) -> dict[str, Any]:
        directives: dict[str, Any] = {}
        for part in csp.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            name = tokens[0].lower()
            values = tokens[1:]
            if name == "script-src":
                # Normalize quotes so 'unsafe-inline' and "unsafe-eval" are
                # recognized regardless of quoting style.
                directives["script-src"] = [v.strip("'\"").lower() for v in values]
                directives["script-src-srcs"] = " ".join(values)
        return directives
