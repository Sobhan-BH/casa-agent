"""Custom exception hierarchy for CASA.

The API layer maps these to HTTP errors; the orchestrator maps them to job outcomes.
"""
from __future__ import annotations


class CasaError(Exception):
    """Base class for all CASA errors."""

    code = "CASA_ERROR"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code


class AuthorizationError(CasaError):
    """No valid authorization exists for the requested target."""

    code = "AUTHORIZATION_MISSING"


class ScopeViolationError(CasaError):
    """A requested action escapes the registered scope."""

    code = "SCOPE_VIOLATION"


class ScopeConfigurationError(CasaError):
    """Malformed scope / authorization input."""

    code = "SCOPE_CONFIG_INVALID"


class TargetNotFoundError(CasaError):
    code = "TARGET_NOT_FOUND"


class JobNotFoundError(CasaError):
    code = "JOB_NOT_FOUND"


class JobStateError(CasaError):
    """Illegal job lifecycle transition."""

    code = "JOB_INVALID_STATE"


class ModuleExecutionError(CasaError):
    code = "MODULE_FAILED"


class VerificationContextError(CasaError):
    code = "VERIFICATION_CONTEXT_INVALID"


class ReportGenerationError(CasaError):
    code = "REPORT_FAILED"


class LLMError(CasaError):
    code = "LLM_ERROR"


class LLMUnavailableError(LLMError):
    code = "LLM_UNAVAILABLE"


class SafetyLimitError(CasaError):
    """Raised when a safety guardrail (rate limit, time window, etc.) trips."""

    code = "SAFETY_LIMIT"


class ToolExecutionError(CasaError):
    """An external tool failed to start, timed out, or crashed."""

    code = "TOOL_FAILED"
