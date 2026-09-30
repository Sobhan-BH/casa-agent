"""Technology detection — passive fingerprinting from response headers/body.

No active probing (no /wp-admin guessing etc.): MVP derives tech from evidence
the server already returns. Signature table is local and extensible.
"""
from __future__ import annotations

import re
from typing import Any

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule

# (name, category, header_name, regex) — first match wins per signature entry
HEADER_SIGNATURES: list[tuple[str, str, str, str]] = [
    ("PHP", "language/runtime", "x-powered-by", r"PHP/([\d.]+)?"),
    ("ASP.NET", "language/runtime", "x-powered-by", r"ASP.NET"),
    ("Express", "framework", "x-powered-by", r"Express"),
    ("Next.js", "framework", "x-powered-by", r"Next\.js"),
    ("Flask", "framework", "server", r"Werkzeug"),
    ("Werkzeug dev server", "server", "server", r"Werkzeug"),
    ("nginx", "server", "server", r"nginx/?([\d.]+)?"),
    ("Apache", "server", "server", r"Apache/?([\d.]+)?"),
    ("Microsoft-IIS", "server", "server", r"Microsoft-IIS/?([\d.]+)?"),
    ("gunicorn", "server", "server", r"gunicorn/?([\d.]+)?"),
    ("uvicorn", "server", "server", r"uvicorn/?([\d.]+)?"),
    ("cloudflare", "cdn/waf", "server", r"cloudflare"),
]

BODY_SIGNATURES: list[tuple[str, str, str]] = [
    ("jQuery", "js-library", r"jquery[.\-]?([\d.]+)?\.js"),
    ("Bootstrap", "css-framework", r"bootstrap[.\-]?([\d.]+)?\.(?:min\.)?(?:css|js)"),
    ("React", "js-framework", r"/react(?:-dom)?[.@-]([\d.]+)?"),
    ("Vue.js", "js-framework", r"/vue(?:\.runtime)?[.@-]?([\d.]+)?"),
    ("WordPress", "cms", r"wp-content"),
    ("Drupal", "cms", r"/sites/default/files"),
    ("Joomla", "cms", r"/media/jui/"),
    ("Google Analytics", "analytics", r"google-analytics\.com|googletagmanager\.com"),
]


class TechDetectionModule(AssessmentModule):
    name = "tech_detection"
    phase = "TECH_DETECTION"

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        root = ctx.raw_results.get("http_root")
        if not root:
            return

        technologies: list[dict[str, Any]] = []
        headers = root.get("headers", {})
        body = root.get("body", "") or ""

        for name, category, header, pattern in HEADER_SIGNATURES:
            value = headers.get(header, "")
            m = re.search(pattern, value, re.IGNORECASE)
            if m:
                technologies.append(
                    {
                        "name": name,
                        "category": category,
                        "source": f"header:{header}",
                        "version": m.group(1) if m.lastindex else None,
                    }
                )

        for name, category, pattern in BODY_SIGNATURES:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                technologies.append(
                    {
                        "name": name,
                        "category": category,
                        "source": "body",
                        "version": m.group(1) if m.lastindex else None,
                    }
                )

        ctx.raw_results["technologies"] = technologies

        # Informational findings for version-disclosing headers only.
        for tech in technologies:
            if tech.get("version") and tech["source"].startswith("header:"):
                f = make_finding(
                    title=f"Server technology discloses version: {tech['name']} {tech['version']}",
                    category="TECHNOLOGY",
                    severity="INFO",
                    confidence="MEDIUM",
                    description=(
                        f"The {tech['name']} version ({tech['version']}) is disclosed via "
                        f"the {tech['source'].split(':', 1)[1]} response header. Version "
                        "disclosure helps attackers match known CVEs."
                    ),
                    evidence=[
                        {
                            "type": "http_header",
                            "source": tech["source"],
                            "header": tech["source"].split(":", 1)[1],
                            "value": headers.get(tech["source"].split(":", 1)[1], ""),
                        }
                    ],
                    affected_asset=ctx.target_url,
                    impact="Enables targeted vulnerability lookup against the disclosed version.",
                    remediation="Configure the server to suppress version tokens in headers.",
                    references=["https://owasp.org/www-project-secure-headers/"],
                    source=self.name,
                )
                f["fingerprint"] = make_fingerprint(
                    "tech_version_disclosure", tech["name"], ctx.base_domain
                )
                ctx.findings.append(f)
