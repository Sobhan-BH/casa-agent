"""Cookie Security Analysis — deep, value-redacted cookie checks.

Parses Set-Cookie properly (multiple cookies, Expires dates) and validates:
Secure / HttpOnly / SameSite / __Host- & __Secure- prefix rules / overly long
lifetimes / domain scope. Cookie VALUES are never recorded — evidence keeps
the name, attributes and value length only (cookies may carry session data).

Fingerprints for missing-attribute checks intentionally match
ConfigAnalysisModule's ("cookie_flags" family) so duplicate detections from
both modules merge in the normalizer (cross-module deduplication).
"""
from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlparse

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule

_SESSION_HINTS = ("sess", "auth", "token", "login", "sid")
_YEAR_SECONDS = 31_536_000


def _is_session_cookie(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _SESSION_HINTS)


def parse_set_cookie(header_value: str) -> list[dict[str, Any]]:
    """Split a combined Set-Cookie header into structured cookie descriptors.

    Values are REDACTED: only name + attribute flags + value length survive.
    """
    cookies: list[dict[str, Any]] = []
    # SimpleCookie handles comma-separated cookies and Expires dates.
    jar = SimpleCookie()
    try:
        jar.load(header_value)
    except Exception:  # noqa: BLE001 - malformed cookies still get basic parse
        jar = SimpleCookie()
    for name, morsel in jar.items():
        attrs: dict[str, Any] = {}
        for key in ("secure", "httponly", "samesite", "domain", "path",
                    "expires", "max-age"):
            v = morsel[key]
            attrs[key] = v if v else None
        raw = morsel.OutputString()
        attrs["value_length"] = len(morsel.value or "")
        attrs["_raw_attrs"] = raw.split(";", 1)[1].strip() if ";" in raw else ""
        cookies.append({"name": name, **attrs})
    if not cookies and "=" in header_value:
        # Fallback: at least record the first name=value pair redacted.
        first = header_value.split(";", 1)[0]
        if "=" in first:
            n = first.split("=", 1)[0].strip()
            cookies.append({"name": n, "value_length": None})
    return cookies


class CookieSecurityModule(AssessmentModule):
    name = "cookie_security"
    phase = "COOKIES"

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        root = ctx.raw_results.get("http_root")
        if not root:
            return
        headers: dict[str, str] = root.get("headers", {})
        raw_cookie = headers.get("set-cookie", "")
        if not raw_cookie:
            return
        asset = root.get("url", ctx.target_url)
        host = urlparse(asset).hostname or ""
        is_https = ctx.target_url.startswith("https://")

        cookies = parse_set_cookie(raw_cookie)
        ctx.raw_results["cookies"] = [
            {k: v for k, v in c.items() if k != "_raw_attrs"} for c in cookies
        ]

        for c in cookies:
            name = c.get("name", "")
            lower = c.get("_raw_attrs", "").lower()
            session = _is_session_cookie(name)

            # --- attribute presence --------------------------------------
            missing: list[str] = []
            if "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite" not in lower:
                missing.append("SameSite")
            for attr in missing:
                sev = ("MEDIUM" if session else "LOW") if attr != "SameSite" else "LOW"
                f = make_finding(
                    title=f"Cookie '{name}' is missing the {attr} attribute",
                    category="CONFIGURATION",
                    severity=sev,
                    confidence="HIGH",
                    description=(
                        f"Set-Cookie for '{name}' does not set {attr}. This weakens "
                        "session integrity or confidentiality depending on the attribute."
                        + (" This appears to be a session cookie." if session else "")
                    ),
                    evidence=[{
                        "type": "http_header", "header": "set-cookie", "cookie": name,
                        "attributes_observed": c.get("_raw_attrs", "")[:200],
                        "value_redacted": True,
                        "value_length": c.get("value_length"),
                    }],
                    affected_asset=asset,
                    impact="Session hijacking or CSRF risk depending on the missing attribute.",
                    remediation=f"Set {attr} (and prefer SameSite=Lax or stricter) on cookies.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint("cookie_flags", name, attr, asset)
                ctx.findings.append(f)

            # --- __Host- / __Secure- prefix rules ------------------------
            if name.startswith("__Host-"):
                problems = []
                if "secure" not in lower:
                    problems.append("Secure")
                if c.get("domain"):
                    problems.append("no Domain attribute")
                if c.get("path") != "/":
                    problems.append("Path=/")
                if problems:
                    f = make_finding(
                        title=f"Cookie '{name}' violates __Host- prefix rules",
                        category="CONFIGURATION",
                        severity="LOW",
                        confidence="HIGH",
                        description=(
                            f"A __Host- prefixed cookie must be Secure, have Path=/ and "
                            f"no Domain attribute; missing: {', '.join(problems)}. Browsers "
                            "will REJECT this cookie entirely."
                        ),
                        evidence=[{
                            "type": "http_header", "header": "set-cookie", "cookie": name,
                            "violations": problems, "value_redacted": True,
                        }],
                        affected_asset=asset,
                        impact="The browser silently drops the cookie; sessions may not persist.",
                        remediation="Set Secure; Path=/; omit Domain for __Host- cookies.",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"],
                        source=self.name,
                    )
                    f["fingerprint"] = make_fingerprint("cookie_prefix", name, asset)
                    ctx.findings.append(f)

            # --- overly broad expiration ---------------------------------
            max_age = None
            ma = c.get("max-age")
            if ma:
                try:
                    max_age = int(str(ma).strip())
                except ValueError:
                    max_age = None
            if max_age is not None and max_age > _YEAR_SECONDS:
                self._long_lived(ctx, asset, name, f"Max-Age={max_age}s (> 1 year)")
            elif c.get("expires") and max_age is None:
                # Only flag when no Max-Age; Expires far-future detection.
                exp = str(c.get("expires", ""))
                if any(y in exp for y in ("2038", "2039", "204")):
                    self._long_lived(ctx, asset, name, f"Expires={exp}")

            # --- suspicious domain scope ---------------------------------
            domain = c.get("domain")
            if domain:
                d = domain.lstrip(".").lower()
                if host and d != host and not host.endswith("." + d):
                    f = make_finding(
                        title=f"Cookie '{name}' scoped to a foreign Domain ({d})",
                        category="CONFIGURATION",
                        severity="MEDIUM",
                        confidence="MEDIUM",
                        description=(
                            f"The cookie is set with Domain={d} but is served from {host}. "
                            "Servers should not set cookies for domains other than their own; "
                            "this may indicate misconfiguration or an injected response."
                        ),
                        evidence=[{
                            "type": "http_header", "header": "set-cookie", "cookie": name,
                            "domain_attribute": d, "served_from_host": host,
                            "value_redacted": True,
                        }],
                        affected_asset=asset,
                        impact="Cookie may be rejected, or shared to an unintended domain scope.",
                        remediation="Set cookies without a Domain attribute (host-only) unless subdomain sharing is intended.",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domain_attribute"],
                        source=self.name,
                    )
                    f["fingerprint"] = make_fingerprint("cookie_domain_scope", name, asset)
                    ctx.findings.append(f)

    def _long_lived(self, ctx, asset: str, name: str, detail: str) -> None:
        f = make_finding(
            title=f"Cookie '{name}' has an overly long lifetime",
            category="CONFIGURATION",
            severity="LOW",
            confidence="HIGH",
            description=f"The cookie lifetime is excessive: {detail}. Long-lived "
            "cookies extend the window for theft and replay.",
            evidence=[{
                "type": "http_header", "header": "set-cookie", "cookie": name,
                "detail": detail, "value_redacted": True,
            }],
            affected_asset=asset,
            impact="Stolen cookies remain usable for months or years.",
            remediation="Use session cookies or bounded lifetimes (e.g. <= 30 days) with rotation.",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
            source=self.name,
        )
        f["fingerprint"] = make_fingerprint("cookie_max_age", name, asset)
        ctx.findings.append(f)
