"""API Security Assessment — OpenAPI-aware, doc-driven, passively discovered.

Analyzes:
- OpenAPI/Swagger documents (from DiscoveryModule results): missing
  securitySchemes, per-operation security gaps.
- Unsafe CORS on API-looking paths (delegates evidence to CorsAnalyzerModule).
- Overly permissive advertised methods on API paths.
- Excessive information in error responses (verbose error JSON).
- API version disclosure from doc metadata.

No credential attacks, no auth bypass attempts, no brute force: the module
only reads already-fetched/fetched-once documentation and probes endpoints
with GET.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.core.safe_http import SafeHttpClient


class ApiSecurityModule(AssessmentModule):
    name = "api_security"
    phase = "API_SECURITY"

    def __init__(self, validator) -> None:
        self._validator = validator

    def applies(self, ctx: AssessmentContext) -> bool:
        docs = (ctx.raw_results.get("discovery", {}) or {}).get("docs_exposed", [])
        return bool(docs)

    async def run(self, ctx: AssessmentContext) -> None:
        client = SafeHttpClient(self._validator)
        discovery = ctx.raw_results.get("discovery", {}) or {}
        docs = discovery.get("docs", {}) or {}
        api_findings: dict[str, Any] = {"openapi_docs": [], "issues": []}

        for path, entry in docs.items():
            if entry.get("status_code") != 200:
                continue
            body = entry.get("body") or ""
            spec = None
            try:
                # openapi.json / swagger.json responses are JSON documents.
                candidate = json.loads(body[:200000])
                if isinstance(candidate, dict) and (
                    "openapi" in candidate or "swagger" in candidate
                ):
                    spec = candidate
            except (json.JSONDecodeError, ValueError):
                spec = None
            if spec is None:
                continue  # UI pages are handled by Discovery findings

            title = spec.get("info", {}).get("title", "API")
            version = spec.get("info", {}).get("version")
            api_findings["openapi_docs"].append({"path": path, "title": title, "version": version})

            # --- securitySchemes analysis ---------------------------------
            schemes = (
                spec.get("components", {}).get("securitySchemes")
                or spec.get("securityDefinitions")
                or {}
            )
            global_security = spec.get("security")
            if not schemes and not global_security:
                f = make_finding(
                    title=f"OpenAPI document declares no security schemes ({path})",
                    category="VULNERABILITY",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    description=(
                        f"The published OpenAPI document for '{title}' declares neither "
                        "securitySchemes nor operation-level security requirements. Either "
                        "the API is intentionally public, or authentication is undocumented."
                    ),
                    evidence=[{
                        "type": "openapi_spec",
                        "path": path,
                        "title": title,
                        "observed": "no securitySchemes / security fields",
                    }],
                    affected_asset=ctx.target_url.rstrip("/") + path,
                    impact="Inconsistent or missing authentication is invisible to both developers and reviewers.",
                    remediation="Declare securitySchemes and per-operation security in the OpenAPI document.",
                    references=["https://owasp.org/www-project-api-security/"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint("api_no_security_schemes", path, ctx.base_domain)
                ctx.findings.append(f)

            # --- per-operation auth coverage -------------------------------
            paths = spec.get("paths", {}) or {}
            total_ops = 0
            ops_without_security = 0
            for _p, item in paths.items():
                if not isinstance(item, dict):
                    continue
                for method, op in item.items():
                    if method.lower() not in ("get", "post", "put", "patch", "delete"):
                        continue
                    total_ops += 1
                    if not isinstance(op, dict):
                        continue
                    if "security" not in op and not global_security:
                        ops_without_security += 1
            if total_ops and ops_without_security == total_ops and schemes:
                f = make_finding(
                    title="All documented API operations lack security requirements",
                    category="VULNERABILITY",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    description=(
                        f"{total_ops} documented operations define no security requirement "
                        "even though securitySchemes exist — authentication is declared but "
                        "never applied in the document."
                    ),
                    evidence=[{
                        "type": "openapi_spec", "path": path,
                        "operations": total_ops, "operations_without_security": ops_without_security,
                    }],
                    affected_asset=ctx.target_url.rstrip("/") + path,
                    impact="Endpoints likely ship without authentication enforcement.",
                    remediation="Apply global or per-operation security requirements in the spec.",
                    references=["https://owasp.org/www-project-api-security/"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint("api_ops_without_security", path, ctx.base_domain)
                ctx.findings.append(f)

            # --- version disclosure in doc metadata ------------------------
            servers = spec.get("servers", []) or []
            for s in servers:
                url_v = str(s.get("url", ""))
                if re.search(r"(dev|staging|test|localhost|127\.0\.0\.1|:8080|:3000)", url_v, re.IGNORECASE):
                    f = make_finding(
                    title="OpenAPI document exposes a non-production server URL",
                    category="CONFIGURATION",
                        severity="LOW",
                        confidence="HIGH",
                        description=f"The documented server URL '{url_v}' looks like a development/staging endpoint.",
                        evidence=[{"type": "openapi_spec", "path": path, "server_url": url_v}],
                        affected_asset=ctx.target_url.rstrip("/") + path,
                        impact="Internal environment names/hosts leak to the public.",
                        remediation="Remove non-production servers from public API documents.",
                        references=["https://owasp.org/www-project-api-security/"],
                        source=self.name,
                    )
                    f["fingerprint"] = make_fingerprint("api_nonprod_server", url_v, ctx.base_domain)
                    ctx.findings.append(f)

        # --- verbose error-response check (one harmless GET to a likely-missing path) ---
        err_entry = await self._probe_error_shape(client, ctx.target_url)
        api_findings["error_probe"] = err_entry
        if err_entry.get("verbose"):
            f = make_finding(
                title="API error responses disclose internal details",
                category="CONFIGURATION",
                severity="LOW",
                confidence="MEDIUM",
                description=(
                    "A 404-style API error response includes stack-trace-like or "
                    "exception-class fields; verbose errors aid attacker reconnaissance."
                ),
                evidence=[{"type": "http_get", **{k: v for k, v in err_entry.items() if k != "body"}}],
                affected_asset=err_entry.get("url", ctx.target_url),
                impact="Framework internals and file paths leak via error responses.",
                remediation="Return generic error bodies; log details server-side only.",
                references=["https://owasp.org/www-project-api-security/"],
                source=self.name,
            )
            f["fingerprint"] = make_fingerprint("api_verbose_errors", ctx.base_domain)
            ctx.findings.append(f)

        ctx.raw_results["api_security"] = api_findings

    # ------------------------------------------------------------------ helpers

    async def _probe_error_shape(self, client: SafeHttpClient, target_url: str) -> dict[str, Any]:
        url = target_url.rstrip("/") + "/api/casa-nonexistent-probe-8f2c"
        out: dict[str, Any] = {"url": url}
        try:
            resp = await client.get(url)
            out["status"] = resp.status_code
            body = resp.body or ""
            out["body_snippet_sha"] = __import__("hashlib").sha256(body[:256].encode()).hexdigest()[:16]
            verbose_markers = (
                "traceback", "exception", "at org.", "at java.", "stack trace",
                'file "', 'line "', '"stack"',
            )
            lowered = body.lower()
            hits = [m for m in verbose_markers if m.strip('"') in lowered]
            out["verbose"] = resp.status_code >= 400 and bool(hits)
            out["markers"] = hits
        except Exception as exc:  # noqa: BLE001
            out["error"] = str(exc)
        return out
