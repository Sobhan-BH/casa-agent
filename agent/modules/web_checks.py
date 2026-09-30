"""Web Security Checks (low-impact).

A small, fixed set of single-GET checks — deliberately NOT a spider/bruteforcer:
- sensitive paths disclosed in robots.txt
- directory listing enabled on web root
- exposed .git/HEAD (source disclosure)
- exposed .env (credential-like file disclosure)
- exposed /server-status (Apache)

Each check is exactly one GET to the authorized origin, results are evidence
with a status code, and only *confirmed* exposures (200 + matching content)
create HIGH-confidence findings.
"""
from __future__ import annotations

import re

from agent.core.context import AssessmentContext
from agent.core.finding import host_fingerprint, make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.core.safe_http import SafeHttpClient

_SENSITIVE_ROBOT_PATTERNS = [
    (r"/admin", "admin panel path disclosed in robots.txt"),
    (r"/private", "private path disclosed in robots.txt"),
    (r"/backup", "backup path disclosed in robots.txt"),
    (r"\.env", "environment file disclosed in robots.txt"),
    (r"/config", "configuration path disclosed in robots.txt"),
]

_EXPOSURE_CHECKS = [
    {
        "key": "git_exposed",
        "path": "/.git/HEAD",
        "title": "Git repository metadata is publicly exposed (/.git/HEAD)",
        "body_regex": r"ref:\s*refs/",
        "severity": "HIGH",
        "description": (
            "/.git/HEAD is served with content matching a Git repository. The whole "
            "commit history and source may be reconstructible by third parties."
        ),
        "impact": "Source code and potential secrets leak; full repository reconstruction is possible.",
        "remediation": "Block serving of .git and other VCS directories at the web server.",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    {
        "key": "env_exposed",
        "path": "/.env",
        "title": "Environment file is publicly exposed (/.env)",
        "body_regex": r"(?im)^\s*[A-Z0-9_]+\s*=",
        "severity": "CRITICAL",
        "description": "/.env is served and contains KEY=VALUE pairs, often including secrets.",
        "impact": "Database credentials, API keys and app secrets may be directly exposed.",
        "remediation": "Never serve dotfiles; move secrets out of the web root and rotate any leaked values.",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    {
        "key": "server_status",
        "path": "/server-status",
        "title": "Apache server-status page is publicly exposed (/server-status)",
        "body_regex": r"Apache Server Status",
        "severity": "MEDIUM",
        "description": "mod_status server-status is reachable without restrictions.",
        "impact": "Leaks request paths, client IPs and worker state to anonymous visitors.",
        "remediation": "Restrict /server-status to localhost or an authenticated monitoring network.",
        "references": ["https://httpd.apache.org/docs/2.4/mod/mod_status.html"],
    },
]


class WebChecksModule(AssessmentModule):
    name = "web_checks"
    phase = "WEB_CHECKS"

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        client = SafeHttpClient(self._validator)
        base = ctx.target_url.rstrip("/")

        self._check_robots(ctx)
        await self._check_directory_listing(ctx, client)

        checks_results: dict = {}
        for check in _EXPOSURE_CHECKS:
            url = base + check["path"]
            entry: dict = {"url": url}
            try:
                resp = await client.get(url)
                entry["status_code"] = resp.status_code
                entry["matches"] = bool(
                    resp.status_code == 200 and re.search(check["body_regex"], resp.body)
                )
                entry["body_snippet"] = resp.body[:300]
            except Exception as exc:  # noqa: BLE001 - single check failing must not stop pipeline
                entry["error"] = str(exc)
            checks_results[check["key"]] = entry

            if entry.get("matches"):
                f = make_finding(
                    title=check["title"],
                    category="WEB",
                    severity=check["severity"],
                    confidence="HIGH",
                    description=check["description"],
                    evidence=[
                        {
                            "type": "http_get",
                            "url": url,
                            "status": entry["status_code"],
                            "body_snippet": entry["body_snippet"],
                        }
                    ],
                    affected_asset=url,
                    impact=check["impact"],
                    remediation=check["remediation"],
                    references=check["references"],
                    source=self.name,
                )
                f["fingerprint"] = host_fingerprint(check["key"], base)
                ctx.findings.append(f)

        ctx.raw_results["web_checks"] = checks_results

    def _check_robots(self, ctx: AssessmentContext) -> None:
        robots = ctx.raw_results.get("robots_txt", {})
        body = robots.get("body", "") or ""
        if robots.get("status_code") != 200 or not body:
            return
        for pattern, label in _SENSITIVE_ROBOT_PATTERNS:
            for line in body.splitlines():
                if re.search(pattern, line, re.IGNORECASE) and line.lower().startswith(
                    ("disallow", "allow", "sitemap")
                ):
                    f = make_finding(
                        title=f"Sensitive path disclosed: {label}",
                        category="WEB",
                        severity="INFO",
                        confidence="MEDIUM",
                        description=(
                            f"robots.txt contains an entry matching a sensitive area: {line.strip()!r}. "
                            "robots.txt is public; listing private paths there helps attackers recon."
                        ),
                        evidence=[{"type": "robots_txt", "line": line.strip()}],
                        affected_asset=robots.get("url", ""),
                        impact="Provides a map of sensitive endpoints to attackers.",
                        remediation="Remove sensitive paths from robots.txt; enforce access control server-side.",
                        references=["https://www.rfc-editor.org/rfc/rfc9309.html"],
                        source=self.name,
                    )
                    f["fingerprint"] = make_fingerprint(
                        "robots_disclosure", label, ctx.base_domain
                    )
                    ctx.findings.append(f)

    _LISTING_RE = r"<title>Index of /</title>|Directory listing for /"

    async def _check_directory_listing(self, ctx: AssessmentContext, client: SafeHttpClient) -> None:
        # The web root is checked first; if it is not an index, one extra
        # low-impact GET at the most common autoindex path (/files) is made.
        candidates: list[dict] = [ctx.raw_results.get("http_root", {})]
        root = candidates[0]
        if not (
            root.get("status_code") == 200
            and re.search(self._LISTING_RE, root.get("body", "") or "", re.IGNORECASE)
        ):
            try:
                resp = await client.get(ctx.target_url.rstrip("/") + "/files")
                candidates.append(
                    {"url": resp.url, "status_code": resp.status_code, "body": resp.body}
                )
            except Exception:  # noqa: BLE001 - single probe must not stop the pipeline
                pass

        hit = next(
            (
                r
                for r in candidates
                if r.get("status_code") == 200
                and re.search(self._LISTING_RE, r.get("body", "") or "", re.IGNORECASE)
            ),
            None,
        )
        if hit is not None:
            body = hit.get("body", "") or ""
            listing_url = hit.get("url", ctx.target_url)
            from urllib.parse import urlparse as _urlparse

            listing_path = _urlparse(listing_url).path or "/"
            f = make_finding(
                title=f"Directory listing is enabled at {listing_path}",
                category="WEB",
                severity="MEDIUM",
                confidence="HIGH",
                description="The web server serves an auto-generated file index at this path.",
                evidence=[
                    {
                        "type": "http_get",
                        "url": listing_url,
                        "status": hit.get("status_code"),
                        "body_snippet": body[:300],
                    }
                ],
                affected_asset=listing_url,
                impact="Visitors can enumerate and download files not intended to be public.",
                remediation="Disable autoindex; serve an application-controlled index.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                source=self.name,
            )
            f["fingerprint"] = host_fingerprint("dir_listing", ctx.target_url)
            ctx.findings.append(f)
