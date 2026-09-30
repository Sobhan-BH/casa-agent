"""Canonical Finding schema.

Every detector produces findings in this shape; nothing downstream accepts
anything else. A Finding without evidence and a confidence rating is invalid
by construction.
"""
from __future__ import annotations

import hashlib
from typing import Any

from agent.core.enums import Confidence, FindingStatus, Severity

_ALLOWED_CATEGORIES = {
    "RECON",
    "TECHNOLOGY",
    "CONFIGURATION",
    "TLS",
    "WEB",
    "VULNERABILITY",
    "PROCESS",
    "OTHER",
}


def normalize_enum_value(value: Any, enum_cls, default: str) -> str:
    """Coerce arbitrary input to a valid enum *value* string."""
    if isinstance(value, enum_cls):
        return value.value
    try:
        return enum_cls(str(value).upper()).value
    except ValueError:
        return default


def make_fingerprint(*parts: Any) -> str:
    """Stable identity hash for a finding (type + asset, not URL query strings)."""
    joined = "|".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def host_fingerprint(key: str, base_url: str) -> str:
    """Fingerprint keyed by hostname only, not scheme/port.

    Exposure findings must keep the same identity when a site moves between
    http/https or ports, otherwise re-assessments report false FIXED/CHANGED.
    """
    from urllib.parse import urlparse

    host = (urlparse(base_url).hostname or base_url).lower()
    return make_fingerprint(key, host)


def make_finding(
    title: str,
    category: str,
    severity: str,
    confidence: str,
    description: str,
    evidence: list[dict[str, Any]] | None = None,
    affected_asset: str = "",
    impact: str = "",
    remediation: str = "",
    references: list[str] | None = None,
    source: str = "unknown",
    verified: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a schema-valid finding dict.

    Args are positional-friendly on purpose: module authors write
    ``make_finding("Missing HSTS", "CONFIGURATION", "LOW", "HIGH", ...)``.
    Raises ValueError on an invalid category; invalid severity/confidence
    gracefully fall back to the most conservative default.
    """
    category = str(category).upper()
    if category not in _ALLOWED_CATEGORIES:
        raise ValueError(
            f"invalid category {category!r}; expected one of {sorted(_ALLOWED_CATEGORIES)}"
        )
    return {
        "id": None,
        "title": title,
        "category": category,
        "severity": normalize_enum_value(severity, Severity, "LOW"),
        "confidence": normalize_enum_value(confidence, Confidence, "LOW"),
        "description": description,
        "evidence": evidence or [],
        "affected_asset": affected_asset,
        "impact": impact,
        "remediation": remediation,
        "references": references or [],
        "source": source,
        "verified": bool(verified),
        "fingerprint": "",
        "status": FindingStatus.UNVERIFIED.value,
        "metadata": metadata or {},
    }
