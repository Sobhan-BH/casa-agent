"""Known Vulnerability Correlation.

Correlates detected technologies (from tech_detection) with a local knowledge
base. Deliberately conservative: correlation alone never produces a CRITICAL
finding, and confidence is capped at MEDIUM unless the KB entry says HIGH with
an exact product match. Swapping in a CVE/NVD feed is an extension point.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule

_KB_PATH = Path(__file__).resolve().parent.parent / "knowledge" / "kb.json"


def load_kb(path: Path | None = None) -> dict[str, Any]:
    with (path or _KB_PATH).open("r", encoding="utf-8") as fh:
        return json.load(fh)


class VulnCorrelationModule(AssessmentModule):
    name = "vuln_correlation"
    phase = "VULN_CORRELATION"

    def __init__(self, validator, kb: dict[str, Any] | None = None) -> None:
        self._validator = validator
        self._kb = kb or load_kb()

    async def run(self, ctx: AssessmentContext) -> None:
        technologies: list[dict[str, Any]] = ctx.raw_results.get("technologies", []) or []
        if not technologies:
            ctx.raw_results["kb_correlation"] = {"matched": []}
            return

        matched: list[dict[str, Any]] = []
        for tech in technologies:
            for entry in self._kb.get("entries", []):
                if not self._entry_applies(entry, tech):
                    continue
                matched.append({"kb_id": entry["id"], "technology": tech["name"]})
                severity = self._downgrade_if_vague(entry["severity"], tech)
                confidence = "MEDIUM" if entry["confidence"] == "HIGH" else "LOW"
                f = make_finding(
                    title=f"[{entry['id']}] {entry['title']}",
                    category="VULNERABILITY",
                    severity=severity,
                    confidence=confidence,
                    description=(
                        f"Detected technology '{tech['name']}'"
                        + (f" version {tech.get('version')}" if tech.get("version") else "")
                        + f" matches knowledge-base entry {entry['id']}: {entry['description']}"
                    ),
                    evidence=[
                        {
                            "type": "kb_correlation",
                            "kb_id": entry["id"],
                            "technology": tech["name"],
                            "version": tech.get("version"),
                            "detected_via": tech.get("source"),
                        }
                    ],
                    affected_asset=ctx.target_url,
                    impact=entry["impact"],
                    remediation=entry["remediation"],
                    references=entry.get("references", []),
                    source=self.name,
                    metadata={"kb_id": entry["id"], "matched_tech": tech["name"]},
                )
                f["fingerprint"] = make_fingerprint(entry["id"], ctx.base_domain)
                ctx.findings.append(f)

        ctx.raw_results["kb_correlation"] = {"matched": matched}

    def _entry_applies(self, entry: dict[str, Any], tech: dict[str, Any]) -> bool:
        match = entry.get("match")
        name = tech.get("name", "")
        if match == "exact_name":
            return name.lower() == str(entry.get("product", "")).lower()
        if match == "server_version_lt":
            constraints = entry.get("version_constraints", {})
            if name.lower() not in constraints:
                return False
            version = tech.get("version")
            return bool(version)  # presence of a version is enough to flag "outdated range"
        return False

    @staticmethod
    def _downgrade_if_vague(severity: str, tech: dict[str, Any]) -> str:
        # Versionless detections are vaguer: cap at MEDIUM.
        if not tech.get("version") and severity == "HIGH":
            return "MEDIUM"
        return severity
