"""Information Disclosure — safe, non-destructive existence checks.

Rules probe for the PRESENCE of debug pages, backup/config/source files,
source-maps and framework error pages. Evidence records status code, content
type and a tiny SHA-256 of the first bytes for reproducibility — contents are
NEVER quoted into findings, and never downloaded beyond a small snippet cap
(enforced by SafeHttpClient), so no secret value is ever stored.

SafeHttpClient re-validates scope on every probe; methods are GET-only.
"""
from __future__ import annotations

import re
from typing import Any

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.core.safe_http import SafeHttpClient

_DEBUG_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python traceback in response", "HIGH"),
    (r"at [\w$.]+\([\w./]+:\d+:\d+\)", "Java/JS stack trace in response", "MEDIUM"),
    (r"Warning: [\w\s]+ in /var/www", "PHP warning with server paths", "MEDIUM"),
    (r"django\.debug|DEBUG = True", "Django debug-mode indicator", "MEDIUM"),
    (
        r"<title>ASP\.NET.*Error|Server Error in .* Application",
        "ASP.NET error page (yellow screen)",
        "MEDIUM",
    ),
    (r"WHOOPS|Whoops,\s*looks like something went wrong", "Laravel debug error page", "MEDIUM"),
]

_FRAMEWORK_ERROR_TITLES = [
    ("Welcome to nginx", "nginx default page"),
    ("Apache2 Ubuntu Default Page", "Apache default page"),
    ("Index of /", "autoindex"),
]


def _sha256_prefix(text: str, n: int = 256) -> str:
    import hashlib

    return hashlib.sha256(text[:n].encode("utf-8", errors="replace")).hexdigest()[:16]


class InfoDisclosureModule(AssessmentModule):
    name = "info_disclosure"
    phase = "INFO_DISCLOSURE"

    # (path, category key, severity, what it indicates)
    SENSITIVE_PATHS: list[tuple[str, str, str]] = [
        ("/.env", "env_file", "CRITICAL"),
        ("/.env.local", "env_file", "HIGH"),
        ("/.git/HEAD", "git_metadata", "HIGH"),
        ("/.git/config", "git_metadata", "HIGH"),
        ("/.svn/entries", "git_metadata", "MEDIUM"),
        ("/.DS_Store", "metadata", "LOW"),
        ("/web.config", "config_file", "HIGH"),
        ("/config.php", "config_file", "HIGH"),
        ("/settings.py", "config_file", "MEDIUM"),
        ("/wp-config.php", "config_file", "CRITICAL"),
        ("/.htaccess", "config_file", "MEDIUM"),
        ("/server-status", "server_status", "MEDIUM"),
        ("/server-info", "server_status", "MEDIUM"),
        ("/debug", "debug_endpoint", "MEDIUM"),
        ("/debug/vars", "debug_endpoint", "HIGH"),
        ("/_debug/bar", "debug_endpoint", "MEDIUM"),
        ("/actuator/env", "debug_endpoint", "HIGH"),
        ("/actuator/heapdump", "debug_endpoint", "HIGH"),
        ("/dump.env", "backup", "MEDIUM"),
        ("/backup.zip", "backup", "MEDIUM"),
        ("/backup.tar.gz", "backup", "MEDIUM"),
        ("/db.sql", "backup", "HIGH"),
        ("/database.sql", "backup", "HIGH"),
        ("/dump.sql", "backup", "HIGH"),
        ("/site.bak", "backup", "MEDIUM"),
        ("/index.php.bak", "backup", "MEDIUM"),
        ("/app.js.map", "source_map", "LOW"),
        ("/main.js.map", "source_map", "LOW"),
    ]

    # Align fingerprints with WebChecksModule so overlapping detections
    # (/.env, /.git/HEAD, /server-status) merge instead of duplicating.
    _SHARED_FP_KEYS = {
        "/.env": "env_exposed",
        "/.git/HEAD": "git_exposed",
        "/server-status": "server_status",
    }

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        client = SafeHttpClient(self._validator)
        base = ctx.target_url.rstrip("/")
        results: dict[str, Any] = {}

        # Soft-404 baseline: probe a path that certainly does not exist and
        # remember what "not found" looks like on THIS site (status, length,
        # title). WordPress and many CMSs answer 200 with homepage/marketing
        # content for arbitrary paths — the baseline is the reliable filter.
        baseline = await self._probe(client, base + "/casa-nonexistent-" + ctx.assessment_id.hex[:8])
        baseline_len = len((baseline.get("body") or ""))
        baseline_status = baseline.get("status_code")
        results["__baseline__"] = {k: v for k, v in baseline.items() if k != "body"}

        for path, kind, severity in self.SENSITIVE_PATHS:
            url = base + path
            entry = await self._probe(client, url)
            results[path] = entry
            if entry.get("status_code") != 200:
                continue
            body = entry.get("body") or ""
            ctype = entry.get("content_type", "")

            # Existence must be content-plausible, not just a 200: many apps
            # return 200 + a soft-404 HTML page for everything.
            if self._looks_like_soft_404(body, entry):
                entry["classification"] = "soft_404_ignored"
                continue
            # Baseline similarity: same status AND near-identical body length
            # as the nonexistent-path response => this is the site's standard
            # "anything" page, not a real file. Only applies to HTML bodies
            # (CMS soft-404 pages); real config/backup files are plain text or
            # binary and must never be dropped by this rule.
            looks_html = "html" in (ctype or "").lower() or "<html" in body.lower()
            if (
                looks_html
                and entry.get("status_code") == baseline_status == 200
                and baseline_len > 0
                and abs(len(body) - baseline_len) <= max(64, baseline_len // 10)
            ):
                entry["classification"] = "baseline_similarity_ignored"
                continue

            if kind == "env_file" and not re.search(
                r"(?m)^\s*[A-Z0-9_]+\s*=", body
            ):
                continue  # must look like KEY=VALUE content
            if kind == "git_metadata" and path.endswith("HEAD") and not body.startswith("ref:"):
                continue
            if kind == "backup" and ctype.startswith("text/html") and "<html" in body.lower():
                continue  # backup probes must not "confirm" via custom 404 pages
            if kind == "source_map" and '"sources"' not in body and '"version"' not in body:
                continue
            if kind == "debug_endpoint" and not re.search(
                r"traceback|exception|stack", body, re.IGNORECASE
            ):
                continue  # debug endpoints must look debuggy, not be soft-404s

            if kind == "debug_endpoint":
                # Classify WHAT is leaked: scan the confirmed debug body for
                # concrete stack-trace patterns. One classification per
                # endpoint; content itself is never reproduced.
                for pattern, label, dbg_severity in _DEBUG_PATTERNS:
                    if re.search(pattern, body):
                        f = make_finding(
                            title=f"Debug information disclosed: {label}",
                            category="WEB",
                            severity=dbg_severity,
                            confidence="HIGH",
                            description=(
                                f"The debug endpoint {path} returns a response matching "
                                f"'{label}'. Stack traces expose paths, versions and "
                                "internal structure."
                            ),
                            evidence=[{
                                "type": "http_body_pattern",
                                "url": url,
                                "pattern": pattern,
                                "sha256_prefix": _sha256_prefix(body),
                                "content_redacted": True,
                            }],
                            affected_asset=url,
                            impact="Internal implementation details leak to anonymous visitors.",
                            remediation="Disable debug endpoints and generic-error pages in production.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                            source=self.name,
                        )
                        f["fingerprint"] = make_fingerprint(
                            "debug_disclosure", label, ctx.base_domain
                        )
                        ctx.findings.append(f)
                        break

            f = make_finding(
                title=self._title_for(path, kind),
                category="WEB",
                severity=severity,
                confidence="HIGH",
                description=(
                    f"{path} is publicly reachable and its content matches the expected "
                    f"format ({kind}). Raw content is NOT reproduced in this report."
                ),
                evidence=[{
                    "type": "http_probe",
                    "url": url,
                    "status": entry["status_code"],
                    "content_type": ctype,
                    "sha256_prefix": _sha256_prefix(body),
                    "content_redacted": True,
                }],
                affected_asset=url,
                impact=self._impact_for(kind),
                remediation=self._remediation_for(kind),
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                source=self.name,
            )
            shared_key = self._SHARED_FP_KEYS.get(path)
            if shared_key:
                from agent.core.finding import host_fingerprint

                f["fingerprint"] = host_fingerprint(shared_key, ctx.target_url)
            else:
                f["fingerprint"] = make_fingerprint(
                    "sensitive_path", path, ctx.base_domain
                )
            ctx.findings.append(f)

        # --- debug / error-page analysis on the root document ---------------
        root = ctx.raw_results.get("http_root", {}) or {}
        root_body = root.get("body") or ""
        for pattern, label, severity in _DEBUG_PATTERNS:
            if re.search(pattern, root_body):
                f = make_finding(
                    title=f"Debug information disclosed: {label}",
                    category="WEB",
                    severity=severity,
                    confidence="MEDIUM",
                    description=f"The root response contains {label}. Stack traces and "
                    "paths help attackers fingerprint and exploit the stack.",
                    evidence=[{
                        "type": "http_body_pattern",
                        "url": root.get("url", ctx.target_url),
                        "pattern": pattern,
                        "sha256_prefix": _sha256_prefix(root_body),
                        "content_redacted": True,
                    }],
                    affected_asset=root.get("url", ctx.target_url),
                    impact="Internal details leak to anonymous visitors.",
                    remediation="Disable debug mode and custom-error pages in production.",
                    references=["https://owasp.org/www-project-project-secure-headers/"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint(
                    "debug_disclosure", label, ctx.base_domain
                )
                ctx.findings.append(f)

        for marker, label in _FRAMEWORK_ERROR_TITLES:
            if marker.lower() in root_body.lower():
                # default pages are LOW/informational
                f = make_finding(
                    title=f"Default server page exposed ({label})",
                    category="WEB",
                    severity="INFO",
                    confidence="MEDIUM",
                    description=f"The web root serves the {label}; this indicates an "
                    "incomplete or default deployment.",
                    evidence=[{
                        "type": "http_body_pattern", "url": root.get("url", ctx.target_url),
                        "marker": marker, "content_redacted": True,
                    }],
                    affected_asset=root.get("url", ctx.target_url),
                    impact="Signals an unconfigured server; no direct impact.",
                    remediation="Replace default pages with the real application.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint("default_page", label, ctx.base_domain)
                ctx.findings.append(f)

        ctx.raw_results["info_disclosure"] = {
            path: {k: v for k, v in entry.items() if k != "body"} | {"probed": True}
            for path, entry in results.items()
        }

    # ------------------------------------------------------------------ helpers

    async def _probe(self, client: SafeHttpClient, url: str) -> dict[str, Any]:
        try:
            resp = await client.get(url)
            return {
                "url": resp.url,
                "status_code": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "body": resp.body[:2000],
            }
        except Exception as exc:  # noqa: BLE001 - probes are best-effort
            return {"url": url, "error": str(exc)}

    @staticmethod
    def _looks_like_soft_404(body: str, entry: dict[str, Any]) -> bool:
        ctype = (entry.get("content_type") or "").lower()
        # Title/length heuristics only make sense for HTML pages; tiny
        # plain-text/JSON config files must NOT be discarded by them.
        looks_html = "html" in ctype or "<html" in body.lower()
        if looks_html:
            title = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            title_text = (title.group(1) if title else "").strip().lower()
            markers = ("404", "not found", "page not", "error")
            if title_text and any(m in title_text for m in markers):
                return True
            if len(body.strip()) < 50:
                return True
        return False

    @staticmethod
    def _title_for(path: str, kind: str) -> str:
        titles = {
            "env_file": f"Environment file is publicly exposed ({path})",
            "git_metadata": f"Version-control metadata is publicly exposed ({path})",
            "config_file": f"Configuration file is publicly exposed ({path})",
            "backup": f"Backup-looking file is publicly exposed ({path})",
            "source_map": f"Source map is publicly exposed ({path})",
            "server_status": f"Server status endpoint is publicly exposed ({path})",
            "debug_endpoint": f"Debug endpoint is publicly exposed ({path})",
            "metadata": f"System metadata file is publicly exposed ({path})",
        }
        return titles.get(kind, f"Sensitive path is publicly exposed ({path})")

    @staticmethod
    def _impact_for(kind: str) -> str:
        impacts = {
            "env_file": "Secrets and credentials may be directly exposed.",
            "git_metadata": "Source code and history may be reconstructible.",
            "config_file": "Application configuration and credentials may leak.",
            "backup": "Full site copies (with secrets) may be downloadable.",
            "source_map": "Original source code becomes reconstructible.",
            "server_status": "Runtime internals and request data leak.",
            "debug_endpoint": "Runtime secrets/heap data may leak.",
            "metadata": "Fingerprinting and path enumeration aid.",
        }
        return impacts.get(kind, "Sensitive data may be exposed.")

    @staticmethod
    def _remediation_for(kind: str) -> str:
        fixes = {
            "env_file": "Never serve dotfiles; rotate any leaked values.",
            "git_metadata": "Block .git/.svn at the web server; never deploy VCS dirs.",
            "config_file": "Move config files out of the web root; restrict access.",
            "backup": "Remove backups from the web root; store off-server encrypted.",
            "source_map": "Do not deploy .map files to production; strip sourceMappingURL comments.",
            "server_status": "Restrict status endpoints to localhost/monitoring networks.",
            "debug_endpoint": "Disable debug endpoints in production.",
            "metadata": "Remove OS metadata files from deployments.",
        }
        return fixes.get(kind, "Remove or restrict the exposed file.")
