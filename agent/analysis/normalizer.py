"""Finding Normalizer — the last gate before persistence.

Responsibilities:
1. Validate/coerce every finding into the canonical schema (invalid ones are dropped).
2. Assign stable fingerprints (type+asset identity) for cross-assessment matching.
3. Deduplicate findings from different modules describing the same issue.
4. Flag obvious false-positive shapes (empty evidence on non-INFO findings).
5. NEW: aggregate evidence across duplicates, group related findings into
   root-cause clusters, and compute a deterministic confidence from evidence
   quality + corroboration.
"""
from __future__ import annotations

import logging
from typing import Any

from agent.core.context import AssessmentContext
from agent.core.enums import Confidence, Severity
from agent.core.finding import make_finding
from agent.core.interfaces import AssessmentModule

logger = logging.getLogger("casa.normalizer")

# Related-finding groups: keys are fingerprint key prefixes (before the first
# make_fingerprint component match) OR title substrings.
_ROOT_CAUSE_RULES: list[dict[str, Any]] = [
    {
        "group_id": "transport_protection_gap",
        "title": "Transport protection gap (HTTP allowed / no HSTS)",
        "match_any": ["hsts", "plain http", "without redirect", "http url"],
        "explanation": (
            "These findings combine into one root cause: clients can reach or be "
            "downgraded to unencrypted HTTP. Fixing HTTPS enforcement + HSTS "
            "addresses all of them together."
        ),
    },
    {
        "group_id": "xss_readiness",
        "title": "XSS prerequisites (CSP weak + reflection without encoding)",
        "match_any": ["content-security-policy", "csp ", "reflected without"],
        "explanation": (
            "Weak CSP combined with unencoded reflection lowers the barrier for "
            "successful XSS. Treat them as one remediation theme."
        ),
    },
    {
        "group_id": "secrets_exposure",
        "title": "Secrets/source exposure cluster",
        "match_any": ["publicly exposed", "directory listing"],
        "explanation": (
            "Multiple exposure findings usually share one root cause: the web "
            "root contains files that should never be deployable artifacts. "
            "Fix deployment hygiene rather than each file individually."
        ),
    },
    {
        "group_id": "email_spoofing",
        "title": "Email anti-spoofing gap (SPF/DMARC)",
        "match_any": ["spf", "dmarc"],
        "explanation": (
            "Missing or permissive SPF/DMARC together indicate the domain can be "
            "used for spoofed email; one DNS hardening effort covers both."
        ),
    },
]


def _evidence_quality(evidence: list[dict[str, Any]]) -> float:
    """Deterministic evidence-quality score in [0, 1]."""
    if not evidence:
        return 0.0
    score = 0.4
    kinds = {str(e.get("type", "")) for e in evidence}
    if any(k in ("http_get", "http_probe", "http_options", "cors_reflection") for k in kinds):
        score += 0.3
    if any(e.get("status") or e.get("status_code") for e in evidence):
        score += 0.15
    if len(evidence) > 1 or any(e.get("body_snippet") or e.get("observed_header_names") for e in evidence):
        score += 0.15
    return min(1.0, score)


def _confidence_from(quality: float, corroborated: bool, severity: str) -> str:
    """Deterministic confidence: evidence quality + corroboration."""
    if corroborated and quality >= 0.7:
        return Confidence.HIGH.value
    if quality >= 0.8:
        return Confidence.HIGH.value
    if quality >= 0.5:
        return Confidence.MEDIUM.value
    return Confidence.LOW.value


class FindingNormalizerModule(AssessmentModule):
    name = "finding_normalizer"
    phase = "NORMALIZATION"
    critical = True

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        normalized: list[dict[str, Any]] = []
        seen: dict[str, dict[str, Any]] = {}
        dropped = 0
        fp_flagged = 0

        for raw in ctx.findings:
            try:
                candidate = make_finding(
                    title=raw["title"],
                    category=raw["category"],
                    severity=raw["severity"],
                    confidence=raw["confidence"],
                    description=raw.get("description", ""),
                    evidence=raw.get("evidence") or [],
                    affected_asset=raw.get("affected_asset", ""),
                    impact=raw.get("impact", ""),
                    remediation=raw.get("remediation", ""),
                    references=raw.get("references") or [],
                    source=raw.get("source", "unknown"),
                    verified=raw.get("verified", False),
                    metadata=raw.get("metadata") or {},
                )
            except (KeyError, ValueError) as exc:
                dropped += 1
                logger.warning("dropping invalid finding: %s", exc)
                continue

            candidate["fingerprint"] = raw.get("fingerprint") or self._fallback_fp(candidate)
            candidate["metadata"] = {**(raw.get("metadata") or {})}

            # False-positive heuristics: a non-INFO finding with zero evidence
            # is flagged, not trusted.
            no_evidence = not candidate["evidence"]
            is_info = candidate["severity"] == Severity.INFO.value
            if no_evidence and not is_info:
                candidate["metadata"]["false_positive_risk"] = "HIGH"
                candidate["confidence"] = Confidence.LOW.value
                fp_flagged += 1
            else:
                # Deterministic confidence from evidence quality/corroboration.
                corroborated = (
                    bool(candidate["metadata"].get("also_reported_by"))
                    or bool(candidate["metadata"].get("affected_assets"))
                )
                q = _evidence_quality(candidate["evidence"])
                calculated = _confidence_from(q, corroborated, candidate["severity"])
                declared = candidate["confidence"]
                # Never silently upgrade the detector's claim by more than one step,
                # but always allow evidence to *downgrade* weak evidence.
                if Confidence[declared].rank - Confidence[calculated].rank > 1:
                    candidate["confidence"] = calculated
                    candidate["metadata"]["confidence_recalculated"] = declared

            key = candidate["fingerprint"]
            if key in seen:
                existing = seen[key]
                # Evidence aggregation across duplicate detections.
                existing_evs = existing.setdefault("evidence", [])
                for ev in candidate.get("evidence", []):
                    if ev not in existing_evs:
                        existing_evs.append(ev)
                existing.setdefault("metadata", {}).setdefault("also_reported_by", [])
                # also_reported_by lists *additional* detectors beyond the
                # primary `source` (which stays on the finding itself).
                if candidate["source"] not in existing["metadata"]["also_reported_by"]:
                    existing["metadata"]["also_reported_by"].append(candidate["source"])
                # Affected-endpoint aggregation.
                assets = existing["metadata"].setdefault("affected_assets", [])
                if candidate.get("affected_asset") and candidate["affected_asset"] not in assets:
                    assets.append(candidate["affected_asset"])
                # Severity escalation: keep the highest severity across
                # duplicates so a HIGH detector is not hidden by an INFO one.
                if Severity[candidate["severity"]].rank > Severity[existing["severity"]].rank:
                    existing["severity"] = candidate["severity"]
                continue
            seen[key] = candidate
            normalized.append(candidate)

        # Cross-module header dedupe: different header modules emit findings
        # with different fingerprint keys but identical titles; merge them by
        # title so the report shows one finding per real issue.
        by_title: dict[str, dict[str, Any]] = {}
        title_deduped: list[dict[str, Any]] = []
        for f in normalized:
            tkey = f.get("title", "").strip().lower()
            if tkey in by_title:
                prim = by_title[tkey]
                prim.setdefault("metadata", {}).setdefault("also_reported_by", [])
                if f.get("source") and f["source"] not in prim["metadata"]["also_reported_by"]:
                    prim["metadata"]["also_reported_by"].append(f["source"])
                assets = prim["metadata"].setdefault("affected_assets", [])
                if f.get("affected_asset") and f["affected_asset"] not in assets:
                    assets.append(f["affected_asset"])
                if Severity[f["severity"]].rank > Severity[prim["severity"]].rank:
                    prim["severity"] = f["severity"]
                continue
            by_title[tkey] = f
            title_deduped.append(f)
        normalized = title_deduped

        groups = self._attach_root_cause_groups(normalized)
        ctx.raw_results["root_cause_groups"] = groups
        ctx.findings = normalized
        ctx.raw_results["normalization"] = {
            "input": len(normalized) + dropped,
            "normalized": len(normalized),
            "dropped_invalid": dropped,
            "false_positive_flagged": fp_flagged,
            "root_cause_groups": [g["group_id"] for g in groups],
        }

    def _attach_root_cause_groups(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Group related findings under a root cause (deterministic, title-based).

        Title matching is used because fingerprints are hashes; the titles are
        produced by our own modules, so substrings are stable and auditable.
        """
        groups: list[dict[str, Any]] = []
        for rule in _ROOT_CAUSE_RULES:
            needles = [n.lower() for n in rule["match_any"]]
            members = [
                f for f in findings
                if any(n in f.get("title", "").lower() for n in needles)
            ]
            if len(members) < 1:
                continue
            for f in members:
                f.setdefault("metadata", {})["root_cause_group"] = rule["group_id"]
            groups.append({
                "group_id": rule["group_id"],
                "title": rule["title"],
                "explanation": rule["explanation"],
                "finding_fingerprints": [f["fingerprint"] for f in members],
                "finding_titles": [f["title"] for f in members],
            })
        return groups

    @staticmethod
    def _fallback_fp(f: dict[str, Any]) -> str:
        from agent.core.finding import make_fingerprint

        return make_fingerprint(f["title"].lower(), f["affected_asset"] or f["category"])
