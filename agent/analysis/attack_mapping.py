"""MITRE ATT&CK mapping — ties CASA findings to adversary techniques.

Inspired by projects like attack-mapping / MITRE csv exports. This is a
deterministic, local mapping (no network): each CASA finding category/title
pattern maps to ATT&CK Enterprise techniques relevant to exposed web
infrastructure. Mappings are annotations only: they never change severity.
"""
from __future__ import annotations

import re
from typing import Any

from agent.core.context import AssessmentContext
from agent.core.interfaces import AssessmentModule

# (compiled regex on title, technique id, technique name, tactic)
_RULES: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"\.env|\.git|backup|sourcemap|debug", re.I), "T1552", "Unsecured Credentials", "Credential Access"),
    (re.compile(r"directory listing|listing enabled", re.I), "T1083", "File and Directory Discovery", "Discovery"),
    (re.compile(r"hsts|strict-transport", re.I), "T1557", "Adversary-in-the-Middle", "Credential Access"),
    (re.compile(r"csp|content-security", re.I), "T1189", "Drive-by Compromise", "Initial Access"),
    (re.compile(r"cookie.*(secure|httponly|samesite)", re.I), "T1539", "Steal Web Session Cookie", "Credential Access"),
    (re.compile(r"cors.*credential|reflect", re.I), "T1189", "Drive-by Compromise", "Initial Access"),
    (re.compile(r"clickjacking|frame|x-frame", re.I), "T1189", "Drive-by Compromise", "Initial Access"),
    (re.compile(r"tls|ssl|certificate", re.I), "T1589", "Gather Victim Identity Information", "Reconnaissance"),
    (re.compile(r"open redirect|redirect", re.I), "T1566", "Phishing", "Initial Access"),
    (re.compile(r"path.*disclosed|sensitive path|exposed", re.I), "T1083", "File and Directory Discovery", "Discovery"),
    (re.compile(r"server version|discloses version|technology discloses", re.I), "T1592", "Gather Victim Host Information", "Reconnaissance"),
    (re.compile(r"spf|dmarc|dkim|email spoof", re.I), "T1589.002", "Email Addresses", "Reconnaissance"),
    (re.compile(r"waf|edge protection", re.I), "T1595", "Active Scanning", "Reconnaissance"),
]


class AttackMappingModule(AssessmentModule):
    """Runs after normalization: enriches each finding with ATT&CK refs."""

    name = "attack_mapping"
    phase = "ATTACK_MAPPING"
    critical = False

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        mapped = 0
        for f in ctx.findings:
            title = f.get("title", "")
            techniques: list[dict[str, str]] = []
            for rx, tid, name, tactic in _RULES:
                if rx.search(title):
                    techniques.append(
                        {
                            "id": tid,
                            "name": name,
                            "tactic": tactic,
                            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                        }
                    )
            if not techniques:
                continue
            meta = f.setdefault("metadata", {})
            meta["mitre_attack"] = techniques
            refs = f.setdefault("references", [])
            for t in techniques:
                if t["url"] not in refs:
                    refs.append(t["url"])
            mapped += 1

        ctx.raw_results["attack_mapping"] = {"mapped_findings": mapped, "rules": len(_RULES)}
