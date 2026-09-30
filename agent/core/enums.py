"""Domain enumerations shared across CASA."""
from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """String enum with JSON-friendly repr."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    ANALYZING = "ANALYZING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class JobTrigger(StrEnum):
    INITIAL = "INITIAL"
    REASSESSMENT = "REASSESSMENT"
    VERIFICATION = "VERIFICATION"


class AssessmentMode(StrEnum):
    """Assessment profiles: each explicitly defines which modules execute.

    See Orchestrator.PROFILES for the authoritative module lists.
    """

    QUICK = "QUICK"
    STANDARD = "STANDARD"
    DEEP = "DEEP"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]


class TargetType(StrEnum):
    WEB_APP = "WEB_APP"
    API = "API"
    HOST = "HOST"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    FIXED = "FIXED"
    STILL_PRESENT = "STILL_PRESENT"
    CHANGED = "CHANGED"
    UNVERIFIED = "UNVERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AssessmentPhase(StrEnum):
    AUTHORIZATION = "AUTHORIZATION"
    SCOPE = "SCOPE"
    RECON = "RECON"
    DISCOVERY = "DISCOVERY"
    TECH_DETECTION = "TECH_DETECTION"
    CONFIG_ANALYSIS = "CONFIG_ANALYSIS"
    HEADERS = "HEADERS"
    COOKIES = "COOKIES"
    HTTP_CONFIG = "HTTP_CONFIG"
    TLS_ANALYSIS = "TLS_ANALYSIS"
    CORS = "CORS"
    API_SECURITY = "API_SECURITY"
    INFO_DISCLOSURE = "INFO_DISCLOSURE"
    WEB_CHECKS = "WEB_CHECKS"
    ACTIVE_SAFE = "ACTIVE_SAFE"
    DNS_SECURITY = "DNS_SECURITY"
    VULN_CORRELATION = "VULN_CORRELATION"
    EVIDENCE = "EVIDENCE"
    NORMALIZATION = "NORMALIZATION"
    RISK = "RISK"
    AI_ANALYSIS = "AI_ANALYSIS"
    REPORT = "REPORT"
    VERIFICATION = "VERIFICATION"
    DONE = "DONE"


class AssessmentPhaseStatus(StrEnum):
    SKIPPED = "SKIPPED"
    OK = "OK"
    WARNING = "WARNING"
    FAILED = "FAILED"


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}
