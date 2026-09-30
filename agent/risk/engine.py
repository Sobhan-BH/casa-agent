"""Risk Engine — deterministic, explainable, LLM-free.

Security Score (0-100, higher = more secure) is computed from per-finding risk
scores:

    finding_risk = 100 * severity_weight
                   * confidence_factor
                   * exposure_factor
                   * exploitability_factor
                   * asset_importance_factor
                   * evidence_factor
                   * auth_factor
                   * reachability_factor

    security_score = round(100 - min(100, sum(finding_risks) / divisor))

Every factor is a fixed table lookup, so any score can be walked backwards to
the exact contributing findings — a requirement for a defensible product.

Category scores (Web Security, TLS/HTTPS, Headers, Cookies, Info Disclosure,
API Security, DNS Security, Configuration, Exposure) are computed with the
same formula restricted to each category's findings — also deterministic.
"""
from __future__ import annotations

from typing import Any

from agent.core.enums import Confidence, Severity

SEVERITY_WEIGHT = {
    Severity.INFO.value: 0.0,
    Severity.LOW.value: 0.05,
    Severity.MEDIUM.value: 0.12,
    Severity.HIGH.value: 0.25,
    Severity.CRITICAL.value: 0.45,
}

CONFIDENCE_FACTOR = {
    Confidence.HIGH.value: 1.0,
    Confidence.MEDIUM.value: 0.7,
    Confidence.LOW.value: 0.4,
}

EVIDENCE_FACTOR = {
    # evidence count buckets (deterministic)
    0: 0.5,   # no evidence: half weight (likely FP, flagged upstream anyway)
    1: 0.85,
    2: 1.0,
}

AUTH_FACTOR = {
    "authenticated": 0.7,   # findings requiring auth to reach are less exposed
    "anonymous": 1.0,
}

# Exposure multipliers derived from affected_asset shape.
EXPOSURE_FACTORS = {
    "internet": 1.0,
    "internal": 0.7,
}

EXPLOITABILITY_KEYWORDS = {
    "exposed", "publicly", "credentials", "secret", "expired",
    "wildcard", "execution", "injection", "reflected", "spoof",
}

ASSET_IMPORTANCE = {
    "login": 1.2,
    "auth": 1.2,
    "admin": 1.2,
    "api": 1.15,
    "payment": 1.3,
    "dashboard": 1.1,
}

DIVISOR = 3.0  # tuning constant: diminishing returns for finding pile-ups
FP_SEVERITIES = {Severity.INFO.value}

# Report categories (Phase 12) and the finding categories that roll into each.
CATEGORY_MAP: dict[str, set[str]] = {
    "Web Security": {"WEB"},
    "TLS/HTTPS": {"TLS"},
    "Headers": {"CONFIGURATION"},  # header findings carry CONFIGURATION category
    "Cookies": set(),              # matched by fingerprint key "cookie"
    "Information Disclosure": {"WEB", "RECON"},
    "API Security": {"VULNERABILITY"},
    "DNS Security": {"OTHER"},
    "Configuration": set(),        # fallback remainder bucket
    "Exposure": set(),             # matched by root-cause/exposure metadata
}


class RiskEngine:
    name = "deterministic_risk_engine"

    def score_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        severity = finding.get("severity", Severity.LOW.value)
        confidence = finding.get("confidence", Confidence.LOW.value)
        asset = (finding.get("affected_asset") or "").lower()
        text = (
            (finding.get("title", "") + " " + finding.get("description", "")).lower()
        )
        evidence = finding.get("evidence") or []
        meta = finding.get("metadata", {}) or {}

        severity_weight = SEVERITY_WEIGHT.get(severity, SEVERITY_WEIGHT[Severity.LOW.value])
        confidence_factor = CONFIDENCE_FACTOR.get(confidence, 0.4)
        exposure_factor = self._exposure(asset)
        exploitability_factor = self._exploitability(text)
        importance_factor = self._importance(asset)
        evidence_factor = self._evidence(len(evidence))
        auth_factor = AUTH_FACTOR.get(str(meta.get("auth_requirement", "anonymous")), 1.0)
        # Reachability: multiple affected endpoints raise exposure (capped).
        endpoint_count = max(1, len(meta.get("affected_assets", []) or [asset]))
        reachability_factor = min(1.3, 1.0 + 0.1 * (endpoint_count - 1))

        if severity in FP_SEVERITIES:
            raw = 0.0
        else:
            raw = (
                100
                * severity_weight
                * confidence_factor
                * exposure_factor
                * exploitability_factor
                * importance_factor
                * evidence_factor
                * auth_factor
                * reachability_factor
            )

        factors = {
            "severity_weight": severity_weight,
            "confidence_factor": confidence_factor,
            "exposure_factor": exposure_factor,
            "exploitability_factor": exploitability_factor,
            "asset_importance_factor": importance_factor,
            "evidence_factor": evidence_factor,
            "auth_factor": auth_factor,
            "reachability_factor": reachability_factor,
        }

        # CVSS v3.1 companion score (industry standard). Uses vendor vector
        # metadata when present, else a synthetic vector from CASA severity.
        cvss_data: dict[str, Any] | None = None
        try:
            from agent.core.cvss import CVSS31, severity_to_synthetic_vector

            vector = meta.get("cvss_vector")
            if isinstance(vector, str) and vector.startswith("CVSS:3"):
                parsed = CVSS31.parse(vector)
            else:
                parsed = CVSS31.parse(severity_to_synthetic_vector(severity))
            cvss_data = parsed.to_dict()
        except Exception:  # noqa: BLE001 — CVSS must never break scoring
            cvss_data = None

        return {
            "risk_score": round(raw, 1),
            "risk_factors": factors,
            "cvss": cvss_data,
        }

    def compute(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        distribution = {s.value: 0 for s in Severity}
        total_risk = 0.0
        scored: list[dict[str, Any]] = []

        for f in findings:
            result = self.score_finding(f)
            f["risk_score"] = result["risk_score"]
            f["risk_factors"] = result["risk_factors"]
            if result.get("cvss"):
                f["cvss"] = result["cvss"]
            total_risk += result["risk_score"]
            if f.get("metadata", {}).get("false_positive_risk") == "HIGH":
                # FP-suspected findings count at 25% weight until verified.
                total_risk -= result["risk_score"] * 0.75
            distribution[f.get("severity", "INFO")] = (
                distribution.get(f.get("severity", "INFO"), 0) + 1
            )
            scored.append(f)

        raw_score = 100 - min(100.0, total_risk / DIVISOR)
        security_score = round(max(0.0, min(100.0, raw_score)), 1)

        drivers = [
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "risk_score": f.get("risk_score"),
            }
            for f in sorted(
                scored, key=lambda x: x.get("risk_score", 0), reverse=True
            )[:5]
        ]

        cvss_scores = [
            f.get("cvss", {}).get("score")
            for f in scored
            if f.get("cvss")
        ]
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else None

        return {
            "security_score": security_score,
            "grade": self._grade(security_score),
            "distribution": distribution,
            "category_scores": self._category_scores(scored),
            "total_raw_risk": round(total_risk, 1),
            "divisor": DIVISOR,
            "avg_cvss_base_score": avg_cvss,
            "method": (
                "sum(finding_risk)/divisor subtracted from 100; finding_risk = "
                "severity * confidence * exposure * exploitability * importance "
                "* evidence * auth * reachability (all deterministic lookups)"
            ),
            "top_risk_drivers": drivers,
        }

    # ------------------------------------------------------------- categories

    def _category_scores(self, scored: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Deterministic per-category scores using the same finding formula."""
        buckets: dict[str, list[dict[str, Any]]] = {name: [] for name in CATEGORY_MAP}
        for f in scored:
            for cat in self._finding_categories(f):
                buckets[cat].append(f)

        out: dict[str, dict[str, Any]] = {}
        for name, members in buckets.items():
            total = sum(f.get("risk_score", 0.0) for f in members)
            score = round(max(0.0, 100.0 - min(100.0, total / DIVISOR)), 1)
            out[name] = {
                "score": score,
                "findings": len(members),
                "top": sorted(
                    ({"title": f.get("title"), "risk_score": f.get("risk_score")}
                     for f in members),
                    key=lambda x: x.get("risk_score") or 0, reverse=True,
                )[:3],
            }
        return out

    @staticmethod
    def _finding_categories(f: dict[str, Any]) -> list[str]:
        """Map a finding to one or more report categories (deterministic)."""
        cats: set[str] = set()
        category = f.get("category", "")
        title = (f.get("title") or "").lower()
        fp = f.get("fingerprint", "")

        if category == "TLS":
            cats.add("TLS/HTTPS")
        if category == "WEB":
            cats.add("Web Security")
            cats.add("Information Disclosure")
        if category == "CONFIGURATION":
            cats.add("Headers")
            cats.add("Configuration")
        if category == "VULNERABILITY":
            cats.add("API Security")
        if category == "OTHER":
            cats.add("DNS Security")
        if category == "RECON":
            cats.add("Information Disclosure")
        if category == "TECHNOLOGY":
            cats.add("Configuration")

        if "cookie" in title or "cookie" in fp:
            cats.add("Cookies")
        if any(k in title for k in ("exposed", "publicly", "disclosed")):
            cats.add("Exposure")
        if not cats:
            cats.add("Configuration")
        return sorted(cats)

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _evidence(count: int) -> float:
        if count >= 2:
            return EVIDENCE_FACTOR[2]
        return EVIDENCE_FACTOR.get(count, 1.0)

    @staticmethod
    def _exposure(asset: str) -> float:
        return EXPOSURE_FACTORS["internal"] if "internal" in asset else EXPOSURE_FACTORS["internet"]

    @staticmethod
    def _exploitability(text: str) -> float:
        hits = sum(1 for kw in EXPLOITABILITY_KEYWORDS if kw in text)
        return min(1.3, 1.0 + 0.1 * hits)

    @staticmethod
    def _importance(asset: str) -> float:
        for kw, factor in ASSET_IMPORTANCE.items():
            if kw in asset:
                return factor
        return 1.0

    @staticmethod
    def _grade(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 55:
            return "D"
        if score >= 40:
            return "E"
        return "F"
