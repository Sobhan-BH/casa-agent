"""CVE enrichment via OSV.dev (osv-scanner-inspired).

Queries the free, key-less OSV.dev API for known vulnerabilities affecting the
technologies detected by tech_detection / whatweb. Findings from this module
are UNVERIFIED advisories: they state that a *disclosed* version string of a
component matches a known affected range, not that the target is exploitable.

Safety properties:
- one bounded POST per technology, small page size, hard timeouts
- failures degrade silently (results simply marked as unavailable)
- never runs without an authorization (it is inside the normal pipeline)
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from agent.core.context import AssessmentContext
from agent.core.enums import Confidence, Severity
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.core.safe_http import SafeHttpClient  # noqa: F401 — kept for API symmetry

logger = logging.getLogger("casa.osv")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_WEB_BASE = "https://osv.dev/vulnerability/"
PAGE_SIZE = 5
MAX_TECHS = 12


def _version_tuple(version: str | None) -> tuple[int, ...] | None:
    if not version:
        return None
    parts = []
    for chunk in version.split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits == "":
            break
        parts.append(int(digits))
    return tuple(parts) if parts else None


def _in_range(version: tuple[int, ...] | None, event: dict[str, Any]) -> bool:
    """Conservative check of an OSV range event against a parsed version."""
    if version is None:
        return True  # unknown version -> rely on advisory, keep it UNVERIFIED
    kind = event.get("type")
    val = _version_tuple(str(event.get("value", "")))
    if val is None:
        return False
    if kind == "ECOSYSTEM":
        return version == val
    if kind == "GIT":
        return False
    op = {"LT": version < val, "LE": version <= val, "EQ": version == val}.get(kind)
    return bool(op)


def _version_affected(version: str | None, affected: dict[str, Any]) -> bool | None:
    """Return True/False when decidable, None when version info is missing."""
    vt = _version_tuple(version)
    if vt is None:
        return None
    for a in affected.get("ranges", []):
        events = a.get("events", [])
        introduced = None
        fixed = None
        for ev in events:
            if "introduced" in ev:
                introduced = ev["introduced"]
            if "fixed" in ev:
                fixed = ev["fixed"]
        intro_v = _version_tuple(introduced) if introduced else (0,)
        if intro_v and vt >= intro_v:
            if fixed is None:
                return True
            fixed_v = _version_tuple(fixed)
            if fixed_v and vt < fixed_v:
                return True
    return False


class OsvEnrichmentModule(AssessmentModule):
    name = "osv_enrichment"
    phase = "OSV_ENRICHMENT"
    critical = False

    def __init__(self, validator) -> None:
        self._validator = validator

    def applies(self, ctx: AssessmentContext) -> bool:
        technologies = ctx.raw_results.get("technologies") or []
        return bool(technologies)

    async def run(self, ctx: AssessmentContext) -> None:
        technologies: list[dict[str, Any]] = ctx.raw_results.get("technologies") or []
        results: list[dict[str, Any]] = []

        for tech in technologies[:MAX_TECHS]:
            name = (tech.get("name") or "").strip()
            if not name:
                continue
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.post(
                        OSV_QUERY_URL,
                        json={"package": {"name": name}},
                        headers={"Content-Type": "application/json"},
                    )
                if resp.status_code != 200:
                    results.append(
                        {"technology": name, "status": "UNAVAILABLE",
                         "detail": f"osv responded {resp.status_code}"}
                    )
                    continue
                vulns = (resp.json() or {}).get("vulns", [])[:PAGE_SIZE]
            except (httpx.HTTPError, ValueError, OSError) as exc:
                results.append(
                    {"technology": name, "status": "UNAVAILABLE", "detail": str(exc)[:200]}
                )
                continue

            matched: list[dict[str, Any]] = []
            for vuln in vulns:
                affected = vuln.get("affected", []) or []
                decidable = [
                    _version_affected(tech.get("version"), a) for a in affected
                ]
                if decidable and all(d is False for d in decidable):
                    continue  # version known and clearly not affected
                aliases = [
                    i for i in (vuln.get("aliases") or []) if i.startswith("CVE-")
                ]
                matched.append(
                    {
                        "id": vuln.get("id", ""),
                        "cve": aliases[0] if aliases else None,
                        "summary": (vuln.get("summary") or vuln.get("details") or "")[:300],
                        "severity": self._cvss_severity(vuln),
                        "references": [
                            r.get("url") for r in (vuln.get("references") or [])[:3]
                        ],
                    }
                )

            results.append(
                {
                    "technology": name,
                    "version": tech.get("version"),
                    "status": "OK" if matched else "CLEAN",
                    "advisories": matched,
                }
            )
            for adv in matched:
                severity = adv.get("severity") or Severity.LOW.value
                f = make_finding(
                    title=f"Known advisory matches {name}: {adv['cve'] or adv['id']}",
                    category="VULNERABILITY",
                    severity=severity if severity in Severity.__members__ else "LOW",
                    confidence="LOW",
                    description=(
                        f"The disclosed component {name}"
                        + (f" {tech.get('version')}" if tech.get("version") else "")
                        + " matches known vulnerability advisories in OSV.dev "
                        f"({adv['cve'] or adv['id']}). Presence of the advisory does not "
                        "prove exploitability of this deployment; verify manually."
                    ),
                    evidence=[
                        {
                            "type": "osv_advisory",
                            "id": adv["id"],
                            "cve": adv["cve"],
                            "summary": adv["summary"],
                        }
                    ],
                    affected_asset=ctx.target_url,
                    impact="Unpatched known vulnerabilities may allow remote compromise depending on the code path.",
                    remediation=(
                        f"Update {name} to the latest stable release and confirm the "
                        "advisory no longer applies to the deployed version."
                    ),
                    references=[OSV_WEB_BASE + adv["id"], *(adv.get("references") or [])],
                    source=self.name,
                    metadata={"advisory_id": adv["id"], "cve": adv["cve"]},
                )
                f["fingerprint"] = make_fingerprint(self.name, ctx.base_domain, adv["id"])
                ctx.findings.append(f)

        ctx.raw_results["osv"] = {
            "queried": len(results),
            "results": results,
        }

    @staticmethod
    def _cvss_severity(vuln: dict[str, Any]) -> str | None:
        """Derive a coarse severity label from OSV severity entries if present."""
        for sev in vuln.get("severity", []) or []:
            score_str = sev.get("score", "")
            if isinstance(score_str, str) and score_str.startswith("CVSS:"):
                from agent.core.cvss import CVSS31

                try:
                    return CVSS31.parse(score_str).severity
                except Exception:  # noqa: BLE001 — advisory data can be malformed
                    continue
        return None
