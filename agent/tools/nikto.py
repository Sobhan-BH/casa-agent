"""Nikto adapter — safe web-server checks, parsed to CASA findings.

Nikto's default scan is kept (request-based checks; the MVP policy does not
enable tuning/exploit plugins); its text output is parsed item-by-item into
CASA findings with evidence retention. Nikto's OSVDB references are preserved
when present. Nikto output NEVER directly sets final CASA severity: parsed
findings carry Nikto's hint, but the CASA Risk Engine re-derives risk
deterministically from its own factor tables.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from agent.core.exceptions import ScopeViolationError
from agent.tools.base import ToolAdapterBase

# Nikto lines:  + OSVDB-877: /path — description
_ITEM_RE = re.compile(r"^\s*\+\s*(?:(OSVDB-\d+)\s*:\s*)?(?P<target>/\S*)?\s*(?P<desc>.+)$")

_SEVERITY_HINTS = [
    (re.compile(r"(?i)default account|anonymous\s*(?:ftp|login)|traversal"), "HIGH"),
    (re.compile(r"(?i)directory indexing|debugging|backup|\.bak|phpinfo"), "MEDIUM"),
    (re.compile(r"(?i)X-Frame-Options|X-Content-Type|HSTS|CSP|Referrer|cookie(?! secure)"), "LOW"),
    (re.compile(r"(?i)server.*(version|banner)|RFC|icon|Default page"), "INFO"),
]


class NiktoAdapter(ToolAdapterBase):
    name = "nikto"
    binary = "nikto"
    version = "unknown"
    capabilities = ("web_server_checks", "misconfiguration_detection")

    def validate_scope(self, url: str, scope: dict) -> None:
        parsed = urlparse(url)
        if (parsed.port or (443 if parsed.scheme == "https" else 80)) not in (
            80, 443, 8000, 8001, 8080, 8081, 8443, 8888, 3000, 5000,
        ):
            raise ScopeViolationError("tool nikto: port outside web assessment policy")

    def build_command(self, request: dict) -> list[str]:
        parsed = urlparse(request["target"])
        host_port = parsed.netloc
        return [
            self.binary,
            "-h", f"{parsed.scheme}://{host_port}",  # scope-validated target
            "-Format", "txt",
            "-nointeractive",
            "-ask=no",
            "-timeout", "5",
            "-Pause", "1",          # gentle pacing toward the target
        ]

    def parse_output(self, raw: dict) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        items = self._parse_items(raw.get("stdout", ""))
        raw["items"] = items

        for item in items:
            severity = self._severity_for(item["description"])
            references = []
            if item.get("osvdb"):
                references.append(f"https://vulners.com/osvdb/{item['osvdb']}")
            findings.append(
                {
                    "title": item["description"][:160],
                    "category": "CONFIGURATION",
                    "severity": severity,
                    "confidence": "MEDIUM",  # scanner verdict, CASA re-checks
                    "description": (
                        f"Nikto reported: {item['description']} "
                        + (f"(OSVDB {item['osvdb']})" if item.get("osvdb") else "")
                    ),
                    "evidence": [
                        {
                            "type": "nikto_item",
                            "target": item.get("target", ""),
                            "osvdb": item.get("osvdb"),
                            "raw_line": item["raw"][:300],
                        }
                    ],
                    "affected_asset": item.get("target") or raw.get("target", ""),
                    "impact": "Web-server misconfiguration identified by Nikto.",
                    "remediation": "Review and correct the reported configuration item.",
                    "references": references,
                    "fingerprint": "",
                }
            )
        return findings

    def _parse_items(self, stdout: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            if not line.strip().startswith("+"):
                continue
            m = _ITEM_RE.match(line)
            if not m:
                continue
            desc = (m.group("desc") or "").strip()
            if not desc or desc.startswith(("Nikto", "Target", "Scan", "Start", "+ End")):
                continue
            if "OSVDB-0" in desc and "does not match" in desc:
                continue  # noisy banner-mismatch line
            items.append(
                {
                    "target": m.group("target") or "",
                    "osvdb": m.group(1),
                    "description": desc,
                    "raw": line.strip(),
                }
            )
        return items

    @staticmethod
    def _severity_for(desc: str) -> str:
        for pattern, severity in _SEVERITY_HINTS:
            if pattern.search(desc):
                return severity
        return "LOW"
