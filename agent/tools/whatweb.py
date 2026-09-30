"""WhatWeb adapter — technology fingerprinting into the Technology Inventory.

WhatWeb's JSON output is parsed into CASA Technology Inventory entries:
technology, version, confidence and evidence. Technology detection by itself
is never a vulnerability — inventory entries feed the attack surface and may
correlate with the local Knowledge Base (with explicit evidence + confidence).
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from agent.core.exceptions import ScopeViolationError
from agent.tools.base import ToolAdapterBase

_PLUGIN_WEIGHT = {
    "aggressive": "HIGH",
    "plugin_match": "MEDIUM",
    "pattern_match": "MEDIUM",
    "passive": "LOW",
}

_VERSION_RE = re.compile(r"(?i)^([^\[\]]+?)\s*\[([^\]]*)\]$")


class WhatWebAdapter(ToolAdapterBase):
    name = "whatweb"
    binary = "whatweb"
    version = "unknown"
    capabilities = ("technology_fingerprinting",)

    def validate_scope(self, url: str, scope: dict) -> None:
        parsed = urlparse(url)
        if (parsed.port or (443 if parsed.scheme == "https" else 80)) not in (
            80, 443, 8000, 8001, 8080, 8081, 8443, 8888, 3000, 5000,
        ):
            raise ScopeViolationError("tool whatweb: port outside web assessment policy")

    def build_command(self, request: dict) -> list[str]:
        return [
            self.binary,
            "--log-json", "-",            # JSON to stdout
            "--no-errors",
            "-q",
            request["target"],            # scope-validated URL, single argv element
        ]

    def parse_output(self, raw: dict) -> list[dict[str, Any]]:
        inventory = self._parse_json(raw.get("stdout", ""))
        raw["technologies"] = inventory
        # Technology presence alone is NOT a finding; it enriches the surface.
        return []

    def _parse_json(self, stdout: str) -> list[dict[str, Any]]:
        data = self._json_loads(stdout)
        if isinstance(data, list) and data:
            data = data[0]
        if not isinstance(data, dict):
            return []
        inventory: list[dict[str, Any]] = []
        for name, detail in (data.get("plugins") or {}).items():
            version: str = ""
            if isinstance(detail, dict):
                versions = detail.get("version") or []
                version = str(versions[0]) if versions else ""
                certainty = (detail.get("certainty") or [100])[0]
                confidence = self._confidence(str(certainty))
            else:
                confidence = "LOW"
            inventory.append(
                {
                    "technology": name,
                    "version": version,
                    "confidence": confidence,
                    "source": self.name,
                    "evidence": {
                        "type": "whatweb_plugin",
                        "plugin": name,
                        "version": version,
                        "string": str(detail)[:200],
                    },
                }
            )
        return inventory

    @staticmethod
    def _confidence(certainty: str) -> str:
        try:
            value = int(float(certainty))
        except (TypeError, ValueError):
            value = 50
        if value >= 100:
            return "HIGH"
        if value >= 50:
            return "MEDIUM"
        return "LOW"
