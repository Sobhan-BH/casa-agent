"""CASA-Brain — explicit assessment state (the world model).

The Brain never sees raw network traffic. It reasons over a structured,
JSON-serializable snapshot of what the assessment currently knows. The
orchestrator rebuilds this state after every module execution, so decisions
are made from state *transitions* rather than isolated prompts:

    STATE0 -> ACTION0 -> EVIDENCE0 -> STATE1 -> ACTION1 -> ...

Hard boundary: this file is read-only with respect to the authorization and
scope snapshot. The Brain can observe them but can never alter them.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


def _digest(state_dict: dict[str, Any]) -> str:
    canonical = json.dumps(state_dict, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


@dataclass
class BrainState:
    """The complete, serializable assessment world-model."""

    # Fixed, read-only context (Brain may never change these)
    job_id: str = ""
    assessment_id: str = ""
    target_url: str = ""
    profile: str = "STANDARD"
    authorization: dict[str, Any] = field(default_factory=dict)  # scope snapshot
    allowed_modules: list[str] = field(default_factory=list)  # profile-legal modules

    # Observations
    technologies: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    attack_surface: dict[str, Any] = field(default_factory=dict)
    evidence_counts: dict[str, int] = field(default_factory=dict)  # module -> count
    executed_modules: list[str] = field(default_factory=list)
    phase_status: dict[str, str] = field(default_factory=dict)  # module -> OK/WARNING/SKIPPED/FAILED

    # Derived (recomputed by compute_derived())
    step: int = 0
    max_steps: int = 0
    open_findings: int = 0
    critical_high: int = 0
    unverified_high_value: int = 0
    pending_modules: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    state_hash: str = ""

    # ------------------------------------------------------------- builders
    @classmethod
    def from_context(cls, ctx, validator) -> "BrainState":
        """Snapshot an AssessmentContext. Read-only w.r.t. scope/authorization."""
        risk = ctx.risk_summary or {}
        findings = ctx.findings or []
        exec_mods = [p.module for p in ctx.phases if p.status != "SKIPPED"]
        phase_status = {p.module: p.status for p in ctx.phases}
        from agent.workers.orchestrator import PROFILES, AssessmentMode

        profile = str(getattr(ctx, "mode", "") or AssessmentMode.STANDARD.value).upper()
        allowed = list(PROFILES.get(profile) or PROFILES[AssessmentMode.STANDARD.value])
        evidence_counts: dict[str, int] = {}
        for key, val in (ctx.raw_results or {}).items():
            if isinstance(val, dict):
                evidence_counts[key] = sum(1 for v in val.values() if v)
            elif isinstance(val, list):
                evidence_counts[key] = len(val)

        state = cls(
            job_id=str(ctx.job_id),
            assessment_id=str(ctx.assessment_id),
            target_url=ctx.target_url,
            profile=profile,
            authorization={
                "allowed_domains": list(validator.allowed_domains),
                "allowed_paths": list(validator.allowed_paths),
                "excluded_targets": list(validator.excluded_targets),
                "window_start": validator.window_start.isoformat() if validator.window_start else None,
                "window_end": validator.window_end.isoformat() if validator.window_end else None,
            },
            allowed_modules=allowed,
            technologies=list(ctx.raw_results.get("technologies") or []),
            findings=[
                {
                    "fingerprint": f.get("fingerprint", ""),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", "INFO"),
                    "confidence": f.get("confidence", "LOW"),
                    "category": f.get("category", "OTHER"),
                    "source": f.get("source", ""),
                    "affected_asset": f.get("affected_asset", ""),
                    "evidence_count": len(f.get("evidence") or []),
                    "status": f.get("status", "UNVERIFIED"),
                    "cvss_score": (f.get("cvss") or {}).get("score"),
                    "verified": bool(f.get("verified")),
                }
                for f in findings
            ],
            attack_surface=_summarize_surface(ctx.raw_results),
            evidence_counts=evidence_counts,
            executed_modules=exec_mods,
            phase_status=phase_status,
            step=len(exec_mods),
            max_steps=int(getattr(__import__("agent.core.config", fromlist=["settings"]), "settings").job_max_steps),
        )
        state.compute_derived()
        return state

    # -------------------------------------------------------------- derived
    def compute_derived(self) -> None:
        self.open_findings = sum(1 for f in self.findings if f["severity"] != "INFO")
        self.critical_high = sum(
            1 for f in self.findings if f["severity"] in ("HIGH", "CRITICAL")
        )
        # High-value = HIGH/CRIT or MEDIUM with weak evidence or low confidence:
        # these are exactly the findings the Brain may want to strengthen.
        self.unverified_high_value = sum(
            1
            for f in self.findings
            if f["severity"] in ("HIGH", "CRITICAL")
            or (
                f["severity"] == "MEDIUM"
                and (f["evidence_count"] == 0 or f["confidence"] != "HIGH")
            )
        )
        self.pending_modules = [
            m for m in self.allowed_modules
            if m not in self.executed_modules and self.phase_status.get(m) != "FAILED"
        ]
        self.uncertainties = self._compute_uncertainties()
        self.state_hash = _digest(self.to_dict(include_derived=False))

    def _compute_uncertainties(self) -> list[str]:
        """Explicit, auditable list of what the assessment does not know yet."""
        out: list[str] = []
        tech_names = {t.get("name", "").lower() for t in self.technologies}
        if not self.technologies:
            out.append("no_technology_fingerprint")
        if not self.attack_surface.get("endpoints"):
            out.append("no_endpoint_map")
        cms = any(c in tech_names for c in ("wordpress", "joomla", "drupal", "shopify"))
        if cms:
            out.append("cms_present_version_unconfirmed")
        if self.critical_high and not self.evidence_counts.get("active_safe"):
            out.append("high_severity_without_active_verification")
        known_hosts = self.attack_surface.get("subdomains") or []
        if not known_hosts:
            out.append("dns_surface_unmapped")
        if self.profile in ("STANDARD", "DEEP") and not self.evidence_counts.get("tls"):
            out.append("tls_not_analyzed")
        return out

    # ------------------------------------------------------------ serialize
    def to_dict(self, include_derived: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "job_id": self.job_id,
            "assessment_id": self.assessment_id,
            "target_url": self.target_url,
            "profile": self.profile,
            "authorization": self.authorization,
            "allowed_modules": self.allowed_modules,
            "technologies": self.technologies,
            "findings": self.findings,
            "attack_surface": self.attack_surface,
            "evidence_counts": self.evidence_counts,
            "executed_modules": self.executed_modules,
            "phase_status": self.phase_status,
        }
        if include_derived:
            d.update(
                {
                    "step": self.step,
                    "max_steps": self.max_steps,
                    "open_findings": self.open_findings,
                    "critical_high": self.critical_high,
                    "unverified_high_value": self.unverified_high_value,
                    "pending_modules": self.pending_modules,
                    "uncertainties": self.uncertainties,
                    "state_hash": self.state_hash,
                }
            )
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


def _summarize_surface(raw: dict[str, Any]) -> dict[str, Any]:
    """Compact attack-surface summary for the Brain (no raw bodies)."""
    surface = raw.get("attack_surface") or {}
    discovery = raw.get("discovery") or {}
    endpoints = discovery.get("endpoints") or {}
    return {
        "domains": surface.get("domains", {}).get("primary") if isinstance(surface.get("domains"), dict) else None,
        "subdomains": (surface.get("domains", {}) or {}).get("in_scope_subdomains", []),
        "endpoints": len(endpoints.get("urls", []) or []),
        "forms": len(endpoints.get("forms", []) or []),
        "technologies_count": len(raw.get("technologies") or []),
        "tools_used": surface.get("tools_used", []),
    }
