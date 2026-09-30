"""CVSS v3.1 scoring engine (FIRST.org specification).

Self-contained implementation of the CVSS v3.1 Base Metric Group so CASA can
express finding severity in the industry-standard scale alongside its own
deterministic risk score. Implements the exact specification math:

- Exploitability = 8.22 * AV * AC * PR * UI
- Impact (Scope Unchanged) = 6.42 * ISCbase
- Impact (Scope Changed)   = 7.52 * (ISCbase - 0.029) - 3.25 * (ISCbase - 0.02)^15
- Base Score (U) = Roundup(min(Impact + Exploitability, 10))
- Base Score (C) = Roundup(min(1.08 * (Impact + Exploitability), 10))

References: https://www.first.org/cvss/v3.1/specification-document
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from agent.core.exceptions import CasaError


class CVSSVectorError(CasaError):
    code = "CVSS_VECTOR_INVALID"

    def __init__(self, message: str) -> None:
        self.code = "CVSS_VECTOR_INVALID"
        self.message = message
        super().__init__(message)


# metric value -> weight tables (spec §2)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.27}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/"
    r"AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$"
)

_SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (-1.0, "INFO"),
)


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest 1-decimal number >= value (spec appendix A)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


@dataclass
class CVSS31:
    """A parsed CVSS v3.1 base vector with score computation."""

    metrics: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------- parsing
    @classmethod
    def parse(cls, vector: str) -> "CVSS31":
        if not isinstance(vector, str):
            raise CVSSVectorError("vector must be a string")
        v = vector.strip()
        if not _VECTOR_RE.match(v):
            raise CVSSVectorError(f"malformed CVSS v3.1 vector: {vector!r}")
        metrics: dict[str, str] = {}
        for part in v.split("/")[1:]:
            key, _, val = part.partition(":")
            metrics[key] = val
        return cls(metrics=metrics)

    @classmethod
    def from_parts(
        cls,
        av: str,
        ac: str,
        pr: str,
        ui: str,
        scope: str,
        c: str,
        i: str,
        a: str,
    ) -> "CVSS31":
        m = {
            "AV": av.upper(),
            "AC": ac.upper(),
            "PR": pr.upper(),
            "UI": ui.upper(),
            "S": scope.upper(),
            "C": c.upper(),
            "I": i.upper(),
            "A": a.upper(),
        }
        instance = cls(metrics=m)
        instance.validate()
        return instance

    def validate(self) -> None:
        allowed = {
            "AV": _AV, "AC": _AC, "UI": _UI, "C": _CIA, "I": _CIA, "A": _CIA,
            "S": {"U", "C"},
            "PR": set(_PR_UNCHANGED),
        }
        for key, table in allowed.items():
            value = self.metrics.get(key)
            if value not in table:
                raise CVSSVectorError(f"invalid value {value!r} for metric {key}")

    # -------------------------------------------------------------- vector
    @property
    def vector(self) -> str:
        return "CVSS:3.1/" + "/".join(
            f"{k}:{self.metrics[k]}" for k in _METRIC_ORDER if k in self.metrics
        )

    # --------------------------------------------------------------- score
    @property
    def score(self) -> float:
        self.validate()
        changed = self.metrics["S"] == "C"
        av = _AV[self.metrics["AV"]]
        ac = _AC[self.metrics["AC"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[self.metrics["PR"]]
        ui = _UI[self.metrics["UI"]]
        exploitability = 8.22 * av * ac * pr * ui

        isc_base = min(
            1 - (1 - _CIA[self.metrics["C"]])
            * (1 - _CIA[self.metrics["I"]])
            * (1 - _CIA[self.metrics["A"]]),
            0.915,
        )
        impact = 6.42 * isc_base if not changed else 7.52 * (isc_base - 0.029) - 3.25 * (
            (isc_base - 0.02) ** 15
        )
        if impact <= 0:
            return 0.0
        if not changed:
            return _roundup(min(impact + exploitability, 10))
        return _roundup(min(1.08 * (impact + exploitability), 10))

    @property
    def severity(self) -> str:
        return score_to_severity(self.score)

    def to_dict(self) -> dict[str, Any]:
        return {"vector": self.vector, "score": self.score, "severity": self.severity}


def score_to_severity(score: float) -> str:
    """Map a 0-10 CVSS score to CASA's severity scale (qualitative severity
    rating scale, spec §5)."""
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "INFO"


def severity_to_synthetic_vector(severity: str) -> str:
    """Map a CASA severity label to a representative CVSS v3.1 vector.

    Used when a finding has no vendor CVSS data: gives every finding a
    consistent, explainable industry-standard score.
    """
    mapping = {
        "CRITICAL": ("N", "L", "N", "N", "C", "H", "H", "H"),   # 10.0
        "HIGH": ("N", "L", "L", "N", "U", "H", "L", "L"),        # ~7.9
        "MEDIUM": ("N", "L", "L", "N", "U", "L", "N", "L"),      # ~6.5
        "LOW": ("N", "H", "H", "R", "U", "L", "N", "L"),         # ~3.5
        "INFO": ("P", "H", "H", "R", "U", "N", "N", "N"),        # 0.0
    }
    if severity not in mapping:
        raise CVSSVectorError(f"unknown severity {severity!r}")
    av, ac, pr, ui, s, c, i, a = mapping[severity]
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
