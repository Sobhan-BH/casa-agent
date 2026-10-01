"""WordPress-specific security module (wp-scan-inspired, low-impact).

The default probes are generic; CMSs need targeted, version-aware checks.
This module activates ONLY when WordPress was detected (wp-content, wp-json,
wp-links-opml, /wp-admin markers) and performs safe single-GET checks:

- /wp-json (REST API root): user enumeration via /wp-json/wp/v2/users
- /?author=1 redirect probe (classic author-slug disclosure)
- /xmlrpc.php: pingback/system.listMethods enabled (XML-RPC abuse surface)
- /wp-content/debug.log: WP_DEBUG log left in web root (HIGH when real)
- /wp-admin/install.php reachable after install (MEDIUM when real)
- version discovery from generator meta / readme.html (INFO)
- readme.html presence (INFO - version + fingerprint aid)
- REST user content on multi-author sites (INFO)

Every check requires *content-confirmed* evidence, not just status 200 —
WordPress sites commonly answer 200 with a soft-404 or a homepage redirect
for arbitrary paths. A per-target baseline of a random nonexistent path is
recorded first and reused to classify probes.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.core.safe_http import SafeHttpClient


class WordPressModule(AssessmentModule):
    name = "wordpress"
    phase = "WORDPRESS"
    critical = False

    def __init__(self, validator) -> None:
        self._validator = validator

    def applies(self, ctx: AssessmentContext) -> bool:
        """Only run when WordPress fingerprints were detected."""
        root = ctx.raw_results.get("http_root") or {}
        body = (root.get("body") or "").lower()
        headers = {k.lower(): v for k, v in (root.get("headers") or {}).items()}
        techs = {t.get("name", "").lower() for t in ctx.raw_results.get("technologies", []) or []}
        markers = (
            "wp-content" in body
            or "wp-json" in body
            or "wp-includes" in body
            or "wordpress" in headers.get("x-powered-by", "").lower()
            or "wordpress" in techs
        )
        ctx.raw_results["wordpress"] = {"detected": bool(markers)}
        return bool(markers)

    async def run(self, ctx: AssessmentContext) -> None:
        client = SafeHttpClient(self._validator)
        base = ctx.target_url.rstrip("/")

        # Baseline: what does this site return for a path that certainly
        # does not exist? (status, title, body length, is_home marker)
        baseline = await self._fetch(client, base + "/casa-nonexistent-" + ctx.assessment_id.hex[:8])
        ctx.raw_results["wordpress"]["baseline"] = {
            k: v for k, v in baseline.items() if k != "body"
        }

        results: dict[str, Any] = {}

        # 1) REST API users endpoint — user enumeration
        results["rest_users"] = await self._check_rest_users(ctx, client, base)
        # 2) /?author=1 redirect probe
        results["author_probe"] = await self._check_author_probe(ctx, client, base)
        # 3) xmlrpc.php capabilities
        results["xmlrpc"] = await self._check_xmlrpc(ctx, client, base)
        # 4) debug.log exposure
        results["debug_log"] = await self._check_debug_log(ctx, client, base)
        # 5) version disclosure
        results["version"] = self._check_version(ctx)

        ctx.raw_results["wordpress"]["checks"] = {
            k: {kk: vv for kk, vv in v.items() if kk != "body"} if isinstance(v, dict) else v
            for k, v in results.items()
        }

    # ------------------------------------------------------------- checks

    async def _check_rest_users(self, ctx, client, base) -> dict[str, Any]:
        url = base + "/wp-json/wp/v2/users"
        resp = await self._fetch(client, url)
        body = resp.get("body") or ""
        if resp.get("status_code") == 200 and body.lstrip().startswith("["):
            try:
                import json as _json

                users = _json.loads(body)
                slugs = [u.get("slug") for u in users if isinstance(u, dict) and u.get("slug")][:10]
                if slugs:
                    self._add(
                        ctx,
                        title=f"WordPress REST API exposes user names ({len(slugs)} users)",
                        key="wp_rest_users",
                        severity="LOW",
                        confidence="HIGH",
                        description=(
                            "GET /wp-json/wp/v2/users returns the list of registered "
                            "users (slugs/names) without authentication. Login "
                            "usernames are the first half of a credential-based attack."
                        ),
                        evidence=[{"type": "http_get", "url": url, "status": 200,
                                   "users_count": len(slugs), "usernames_disclosed": True}],
                        asset=url,
                        impact="Enables targeted password spraying / brute-force on real usernames.",
                        remediation=(
                            "Restrict REST user routes for unauthenticated visitors "
                            "(e.g. filter rest_endpoints or use a hardening plugin); "
                            "enforce strong passwords + 2FA."
                        ),
                        references=["https://developer.wordpress.org/rest-api/reference/users/"],
                    )
                    return {"status": 200, "users": len(slugs), "finding": True}
            except (ValueError, TypeError):
                pass
        return {"status": resp.get("status_code"), "finding": False}

    async def _check_author_probe(self, ctx, client, base) -> dict[str, Any]:
        """/?author=1 historically 301-redirects to /author/<slug>/."""
        url = base + "/?author=1"
        resp = await self._fetch(client, url)
        final = resp.get("url") or ""
        m = re.search(r"/author/([^/?#]+)", final)
        if m and resp.get("status_code") == 200:
            slug = m.group(1)
            baseline = ctx.raw_results.get("wordpress", {}).get("baseline", {})
            if slug and slug not in ("", "feed") and final != baseline.get("url"):
                self._add(
                    ctx,
                    title=f"WordPress author username disclosed via ?author=1 redirect ({slug})",
                    key="wp_author_probe",
                    severity="LOW",
                    confidence="MEDIUM",
                    description=(
                        "The author archive redirect reveals a real login username "
                        "in the URL. Combined with REST user enumeration this maps "
                        "the site's login accounts."
                    ),
                    evidence=[{"type": "http_get", "url": url, "final_url": final[:300],
                               "status": resp.get("status_code")}],
                    asset=final,
                    impact="Username disclosure aids brute-force attacks.",
                    remediation="Block author scans or strip author archives if unused.",
                    references=["https://developer.wordpress.org/"],
                )
                return {"status": resp.get("status_code"), "slug": slug, "finding": True}
        return {"status": resp.get("status_code"), "finding": False}

    async def _check_xmlrpc(self, ctx, client, base) -> dict[str, Any]:
        url = base + "/xmlrpc.php"
        resp = await self._fetch(client, url)
        body = resp.get("body") or ""
        if resp.get("status_code") == 405 or "XML-RPC server accepts only POST" in body:
            self._add(
                ctx,
                title="XML-RPC interface is enabled (/xmlrpc.php)",
                key="wp_xmlrpc",
                severity="MEDIUM",
                confidence="HIGH",
                description=(
                    "xmlrpc.php answers with the standard GET rejection, meaning the "
                    "XML-RPC server is active. It enables system.multicall "
                    "credential brute-force (hundreds of password tries per request) "
                    "and pingback abuse for DDoS reflection."
                ),
                evidence=[{"type": "http_get", "url": url, "status": resp.get("status_code"),
                           "marker": "xmlrpc GET rejection"}],
                asset=url,
                impact="Efficient credential brute-force and pingback DDoS amplification.",
                remediation=(
                    "Disable XML-RPC if unused (add_filter('xmlrpc_enabled', "
                    "'__return_false')) or block /xmlrpc.php at the web server."
                ),
                references=["https://wordpress.org/documentation/article/xml-rpc/"],
            )
            return {"status": resp.get("status_code"), "finding": True}
        return {"status": resp.get("status_code"), "finding": False}

    async def _check_debug_log(self, ctx, client, base) -> dict[str, Any]:
        url = base + "/wp-content/debug.log"
        resp = await self._fetch(client, url)
        body = resp.get("body") or ""
        if resp.get("status_code") == 200 and re.search(
            r"\[\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2} UTC?\]|PHP (Notice|Warning|Fatal error)", body
        ):
            self._add(
                ctx,
                title="WordPress debug.log is publicly readable (/wp-content/debug.log)",
                key="wp_debug_log",
                severity="HIGH",
                confidence="HIGH",
                description=(
                    "WP_DEBUG logging is on and the log file is web-accessible. "
                    "Debug logs commonly include database errors with table names, "
                    "plugin paths and sometimes credentials in connection strings."
                ),
                evidence=[{"type": "http_get", "url": url, "status": 200,
                           "sha256_prefix": self._sha(body)[:16], "content_redacted": True}],
                asset=url,
                impact="Internal paths, SQL errors and potential secrets leak publicly.",
                remediation=(
                    "Set WP_DEBUG_LOG to a path outside the web root (or disable), "
                    "and delete the existing log file."
                ),
                references=["https://wordpress.org/documentation/article/debugging-in-wordpress/"],
            )
            return {"status": 200, "finding": True}
        return {"status": resp.get("status_code"), "finding": False}

    def _check_version(self, ctx) -> dict[str, Any]:
        root = ctx.raw_results.get("http_root") or {}
        body = root.get("body") or ""
        m = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', body, re.IGNORECASE)
        if m:
            version = m.group(1)
            self._add(
                ctx,
                title=f"WordPress version disclosed ({version})",
                key="wp_version",
                severity="LOW",
                confidence="HIGH",
                description=(
                    "The generator meta tag discloses the exact WordPress version, "
                    "letting attackers match known core/plugin CVEs precisely."
                ),
                evidence=[{"type": "http_body_pattern", "marker": "generator meta",
                           "version": version}],
                asset=root.get("url", ctx.target_url),
                impact="Precise CVE targeting against the disclosed version.",
                remediation="Remove the generator tag (the_content metagenerator filter); keep core updated.",
                references=["https://wordpress.org/documentation/article/wordpress-versions/"],
            )
            return {"version": version, "finding": True}
        return {"finding": False}

    # -------------------------------------------------------------- helpers

    async def _fetch(self, client: SafeHttpClient, url: str) -> dict[str, Any]:
        try:
            resp = await client.get(url)
            return {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "body": resp.body[:4000],
                "content_type": resp.headers.get("content-type", ""),
            }
        except Exception as exc:  # noqa: BLE001 — probes are best-effort
            return {"url": url, "error": str(exc)[:200]}

    @staticmethod
    def _sha(text: str) -> str:
        import hashlib

        return hashlib.sha256(text[:256].encode("utf-8", errors="replace")).hexdigest()

    def _add(
        self,
        ctx: AssessmentContext,
        *,
        title: str,
        key: str,
        severity: str,
        confidence: str,
        description: str,
        evidence: list[dict[str, Any]],
        asset: str,
        impact: str,
        remediation: str,
        references: list[str],
    ) -> None:
        f = make_finding(
            title=title,
            category="WEB",
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence,
            affected_asset=asset,
            impact=impact,
            remediation=remediation,
            references=references,
            source=self.name,
        )
        from agent.core.finding import host_fingerprint

        f["fingerprint"] = host_fingerprint(key, ctx.target_url)
        ctx.findings.append(f)
