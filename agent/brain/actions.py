"""CASA-Brain — structured action space.

The Brain can only propose actions from this vocabulary. Every action carries
structured parameters; nothing free-form (no shell commands, no raw URLs, no
request crafting) can be expressed. The Policy Gate validates each proposal
against authorization/scope/policy before anything executes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ActionType(str, Enum):
    """The complete vocabulary of what the Brain may propose."""

    RUN_MODULE = "RUN_MODULE"                    # run a CASA module by registry name
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"  # re-run an evidence-producing module
    CORRELATE_FINDINGS = "CORRELATE_FINDINGS"    # re-run correlation over current findings
    VERIFY_FINDING = "VERIFY_FINDING"            # schedule a finding for verification stage
    ENRICH_TECHNOLOGY = "ENRICH_TECHNOLOGY"      # OSV/exploit enrichment for a detected tech
    REASSESS = "REASSESS"                        # plan a REASSESSMENT job after remediation
    STOP_ASSESSMENT = "STOP_ASSESSMENT"          # declare diminishing returns


# Modules the Brain may (re)request via RUN_MODULE / REQUEST_MORE_EVIDENCE.
# This is a fixed allowlist — the Brain cannot invent module names.
RUNNABLE_MODULES = frozenset(
    {
        "recon",
        "discovery",
        "tech_detection",
        "config_analysis",
        "headers",
        "cookies",
        "http_config",
        "tls_analysis",
        "cors_analyzer",
        "api_security",
        "info_disclosure",
        "web_checks",
        "active_safe",
        "dns_security",
        "waf_detect",
        "wordpress",
        "vuln_correlation",
    }
)

# Modules that may serve as "more evidence" for a finding category.
EVIDENCE_MODULE_BY_CATEGORY = {
    "CONFIGURATION": "headers",
    "TLS": "tls_analysis",
    "WEB": "info_disclosure",
    "VULNERABILITY": "vuln_correlation",
    "RECON": "discovery",
    "TECHNOLOGY": "tech_detection",
    "DNS": "dns_security",
    "OTHER": "web_checks",
}


@dataclass
class BrainAction:
    """A structured, parameterized proposal. Never executed directly."""

    action_type: ActionType
    params: dict[str, Any] = field(default_factory=dict)
    # decision metadata (explainability — filled by the engine)
    reason_codes: list[str] = field(default_factory=list)
    expected_information_gain: float = 0.0
    confidence: float = 0.0
    related_findings: list[str] = field(default_factory=list)  # fingerprints
    expected_evidence: str = ""

    @property
    def type_name(self) -> str:
        return self.action_type.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action_type.value,
            "params": self.params,
            "reason_codes": self.reason_codes,
            "expected_information_gain": round(self.expected_information_gain, 3),
            "confidence": round(self.confidence, 3),
            "related_findings": self.related_findings,
            "expected_evidence": self.expected_evidence,
        }

    # ---------------------------------------------------------- validation
    def validate_shape(self) -> list[str]:
        """Structural validation (types/enums), independent of policy."""
        errors: list[str] = []
        t = self.action_type
        if t in (ActionType.RUN_MODULE, ActionType.REQUEST_MORE_EVIDENCE):
            mod = self.params.get("module")
            if mod not in RUNNABLE_MODULES:
                errors.append(f"module {mod!r} not in Brain action-space allowlist")
        if t == ActionType.ENRICH_TECHNOLOGY:
            if not str(self.params.get("technology", "")).strip():
                errors.append("ENRICH_TECHNOLOGY requires a technology name")
            if self.params.get("enricher") not in ("osv", "exploitdb"):
                errors.append("enricher must be 'osv' or 'exploitdb'")
        if t == ActionType.VERIFY_FINDING:
            if not str(self.params.get("fingerprint", "")).strip():
                errors.append("VERIFY_FINDING requires a finding fingerprint")
        if t == ActionType.STOP_ASSESSMENT and not self.reason_codes:
            errors.append("STOP_ASSESSMENT requires reason codes")
        return errors
