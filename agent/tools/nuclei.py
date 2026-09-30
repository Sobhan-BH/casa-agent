"""Nuclei adapter — template scanner behind a strict policy.

Only templates matching the configured allowed tags run; excluded tags and
severity filtering are enforced via CLI flags, plus rate-limit and concurrency
caps. JSONL results are normalized to CASA findings that retain template-id,
matched-at URL, references and evidence. Nuclei's severity is treated as an
ADVISORY hint: the CASA Risk Engine re-derives severity-weighted risk with
its own deterministic factors.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from agent.core.config import settings
from agent.core.exceptions import ScopeViolationError
from agent.tools.base import ToolAdapterBase


class NucleiAdapter(ToolAdapterBase):
    name = "nuclei"
    binary = "nuclei"
    version = "unknown"
    capabilities = ("template_scanning", "vulnerability_detection")

    def validate_scope(self, url: str, scope: dict) -> None:
        parsed = urlparse(url)
        if (parsed.port or (443 if parsed.scheme == "https" else 80)) not in (
            80, 443, 8000, 8001, 8080, 8081, 8443, 8888, 3000, 5000,
        ):
            raise ScopeViolationError("tool nuclei: port outside web assessment policy")

    def build_command(self, request: dict) -> list[str]:
        allowed = [t.strip() for t in settings.nuclei_allowed_tags.split(",") if t.strip()]
        excluded = [t.strip() for t in settings.nuclei_excluded_tags.split(",") if t.strip()]
        severities = [
            s.strip()
            for s in settings.nuclei_severity_filter.split(",")
            if s.strip()
        ]
        argv = [
            self.binary,
            "-target", request["target"],     # scope-validated URL
            "-jsonl",                          # machine-readable lines
            "-silent",
            "-ni",                             # no interactive updates
            "-rl", str(settings.nuclei_rate_limit),
            "-c", str(settings.nuclei_max_concurrency),
            "-timeout", "5",
            "-tags", ",".join(allowed) if allowed else "",
            "-exclude-tags", ",".join(excluded) if excluded else "",
            "-severity", ",".join(severities) if severities else "",
            "-du",                             # disable updates
        ]
        # drop empty-flag values
        cleaned: list[str] = []
        i = 0
        while i < len(argv):
            if argv[i] in ("-tags", "-exclude-tags", "-severity") and (
                i + 1 >= len(argv) or argv[i + 1] == ""
            ):
                i += 2
                continue
            cleaned.append(argv[i])
            i += 1
        return cleaned

    def parse_output(self, raw: dict) -> list[dict[str, Any]]:
        events = self._parse_jsonl(raw.get("stdout", ""))
        raw["events"] = events
        findings: list[dict[str, Any]] = []
        for ev in events:
            template_id = ev.get("template-id") or ev.get("templateID") or ""
            info = ev.get("info") or {}
            name = info.get("name") or template_id or "nuclei hit"
            matched_at = ev.get("matched-at") or ev.get("host") or raw.get("target", "")
            # Nuclei severity is ADVISORY only; keep it in evidence + metadata.
            advisory_severity = str(info.get("severity", "unknown")).upper()
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            findings.append(
                {
                    "title": f"[{template_id}] {name}",
                    "category": "VULNERABILITY",
                    "severity": "MEDIUM",  # neutral placeholder; Risk Engine decides
                    "confidence": "HIGH",  # a template matched against live content
                    "description": (
                        f"Nuclei template '{template_id}' matched at {matched_at}. "
                        f"Scanner advisory severity: {advisory_severity}. "
                        "CASA risk is re-computed deterministically from evidence."
                    ),
                    "evidence": [
                        {
                            "type": "nuclei_match",
                            "template_id": template_id,
                            "matched_at": matched_at,
                            "advisory_severity": advisory_severity,
                            "extracted": ev.get("extracted-results") or [],
                            "curl": (ev.get("request") or "").get("curl", "")[:200]
                            if isinstance(ev.get("request"), dict)
                            else "",
                        }
                    ],
                    "affected_asset": matched_at,
                    "impact": str(info.get("description") or "")[:400]
                    or "Template-based detection of a potential issue.",
                    "remediation": "Review the matched template guidance and apply vendor fixes.",
                    "references": refs or ["https://nuclei.projectdiscovery.io/"],
                    "fingerprint": "",
                    "metadata": {
                        "nuclei_template_id": template_id,
                        "nuclei_advisory_severity": advisory_severity,
                        "nuclei_classifier": (ev.get("classification") or {}),
                    },
                }
            )
        return findings

    def _parse_jsonl(self, stdout: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            data = self._json_loads(line)
            if isinstance(data, dict):
                events.append(data)
        return events
