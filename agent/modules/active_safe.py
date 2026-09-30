"""Safe-Active Web Tests — controlled, harmless request variations.

DEEP-mode only. Allowed actions are strictly limited to:
- GET/HEAD/OPTIONS requests (no POST/PUT/DELETE is ever sent)
- harmless marker-reflection detection: the marker is a unique token plus four
  bare delimiter characters (< > " ') with NO exploit payload; it exists only
  to detect whether the application echoes values without output encoding
- HEAD vs GET response consistency (cache-behavior sanity)
- content-type vs body consistency checks

Every request passes ScopeManager validation inside SafeHttpClient before it
leaves. All tests are single-request, unauthenticated, and best-effort: a
failing probe never stops the pipeline.
"""
from __future__ import annotations

from typing import Any

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.core.safe_http import SafeHttpClient

# Unique base token (no special meaning, no payload) + delimiter characters
# that HTML escaping would transform. If they arrive raw in the response body
# next to the token, the app reflects values without encoding.
_MARKER_TOKEN = "casa7f3e"
_MARKER_VALUE = _MARKER_TOKEN + "\"'><>cho"
_SPECIALS = ("<", ">", '"', "'")


class ActiveSafeModule(AssessmentModule):
    name = "active_safe"
    phase = "ACTIVE_SAFE"

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        client = SafeHttpClient(self._validator)
        base = ctx.target_url.rstrip("/")
        root = ctx.raw_results.get("http_root", {}) or {}
        results: dict[str, Any] = {}

        # --- 1) HEAD vs GET consistency --------------------------------------
        try:
            head = await client.head(base + "/")
            get = await client.get(base + "/")
            head_len = int(head.headers.get("content-length", "0") or 0)
            get_len = len(get.body or "")
            consistent = head.status_code == get.status_code and head_len in (0, get_len)
            results["head_get"] = {
                "head_status": head.status_code,
                "get_status": get.status_code,
                "declared_length": head_len,
                "get_length": get_len,
                "consistent": consistent,
            }
            if not consistent:
                f = make_finding(
                    title="HEAD and GET responses are inconsistent",
                    category="WEB",
                    severity="INFO",
                    confidence="MEDIUM",
                    description=(
                        "HEAD declares a different status/length than GET. Caches and "
                        "middleware that rely on HEAD can behave unexpectedly."
                    ),
                    evidence=[{"type": "http_method_comparison", **results["head_get"]}],
                    affected_asset=base + "/",
                    impact="Potential cache-desync or filtering edge cases.",
                    remediation="Ensure HEAD mirrors GET status and Content-Length.",
                    references=["https://datatracker.ietf.org/doc/html/rfc9110#name-head"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint("head_get_mismatch", ctx.base_domain)
                ctx.findings.append(f)
        except Exception as exc:  # noqa: BLE001 - active tests are best-effort
            results["head_get"] = {"error": str(exc)}

        # --- 2) Marker reflection on a discovered parameterized URL ----------
        target = self._pick_parameterized_url(ctx)
        if target:
            probe_url = self._with_marker(target)
            if probe_url:
                entry = await self._probe_reflection(client, probe_url)
                results["reflection"] = entry
                if entry.get("reflected_unencoded"):
                    f = make_finding(
                        title="Query parameter value is reflected without context-encoding",
                        category="WEB",
                        severity="MEDIUM",
                        confidence="MEDIUM",
                        description=(
                            "A harmless marker sent in a query parameter is reflected in "
                            "the response with raw delimiter characters (no output "
                            "encoding). This is a prerequisite for XSS — exploitation "
                            "was NOT attempted."
                        ),
                        evidence=[{
                            "type": "marker_reflection",
                            "url": entry.get("url"),
                            "status": entry.get("status"),
                            "raw_special_chars": entry.get("raw_special_chars", []),
                            "marker_token": _MARKER_TOKEN,
                            "payload": "none (delimiter characters only)",
                        }],
                        affected_asset=entry.get("url", probe_url),
                        impact="Reflection without encoding may enable XSS in this context.",
                        remediation="HTML-encode reflected values for the response context.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                        source=self.name,
                    )
                    f["fingerprint"] = make_fingerprint(
                        "query_reflection", entry.get("url", probe_url)
                    )
                    ctx.findings.append(f)

        # --- 3) Content-type vs body consistency (root document) ---------------
        body = root.get("body") or ""
        ctype = (root.get("headers", {}) or {}).get("content-type", "")
        looks_html = "<html" in body.lower() or "<body" in body.lower()
        looks_json = body.strip().startswith("{") or body.strip().startswith("[")
        declared_html = "text/html" in ctype.lower()
        declared_json = "application/json" in ctype.lower()
        mismatch = (looks_json and declared_html) or (looks_html and declared_json)
        results["content_type_consistency"] = {
            "declared": ctype,
            "looks_html": looks_html,
            "looks_json": looks_json,
            "mismatch": mismatch,
        }

        ctx.raw_results["active_safe"] = results

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _pick_parameterized_url(ctx: AssessmentContext) -> str | None:
        """Pick one discovered same-host URL that already carries a query string."""
        discovery = ctx.raw_results.get("discovery", {}) or {}
        urls = (discovery.get("endpoints", {}) or {}).get("urls", []) or []
        for u in urls:
            if "?" in u:
                return u
        return None  # nothing to test reflectively; stay conservative

    @staticmethod
    def _with_marker(url: str) -> str | None:
        """Replace the last query parameter's value with the harmless marker."""
        if "?" not in url:
            return None
        path, qs = url.split("?", 1)
        params = qs.split("&")
        last = params[-1]
        key = last.split("=", 1)[0]
        params[-1] = f"{key}={_MARKER_VALUE}"
        return path + "?" + "&".join(params)

    @staticmethod
    async def _probe_reflection(client: SafeHttpClient, url: str) -> dict[str, Any]:
        out: dict[str, Any] = {"url": url}
        try:
            resp = await client.get(url)
            body = resp.body or ""
            out["status"] = resp.status_code
            out["reflected"] = _MARKER_TOKEN in body
            raw_specials = [c for c in _SPECIALS if (_MARKER_TOKEN + c) in body]
            out["raw_special_chars"] = raw_specials
            out["reflected_unencoded"] = out["reflected"] and bool(raw_specials)
        except Exception as exc:  # noqa: BLE001
            out["error"] = str(exc)
        return out
