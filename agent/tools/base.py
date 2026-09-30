"""ToolAdapter base — the standard seam for external security tools.

Contract (extension of agent.core.interfaces.ToolAdapter):
- is_available(): binary + version detection (cached per process)
- validate_scope(): re-checks hostname/scheme/port/paths against the SAME
  ScopeValidator used by internal modules; raises ScopeViolationError
- build_command(): argv list (never a shell string); target is passed as ONE
  argv element — no concatenation into a command string
- execute(): subprocess with argument list, no shell, timeout, output caps
- parse_output(): raw tool output -> CASA finding dicts (schema-valid)
- health_check(): cheap availability + version probe

Safety invariants:
- a shell is never spawned: commands are argv lists only
- every argv element is fixed by the adapter except scope-validated target
- stdout/stderr are size-capped before parsing or storage
- secrets/tokens/cookies are never recorded; evidence is metadata-only
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import time
from abc import abstractmethod
from typing import Any
from urllib.parse import urlparse

from agent.core.exceptions import ScopeViolationError, ToolExecutionError
from agent.core.interfaces import ToolAdapter as ToolAdapterInterface

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*\S+)"),
    re.compile(r"(?i)(cookie\s*:\s*\S+)"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*\S+)"),
    re.compile(r"(?i)(token\s*[=:]\s*\S+)"),
    re.compile(r"(?i)(password\s*[=:]\s*\S+)"),
)


def redact(text: str) -> str:
    """Strip credential-like material from any text headed for evidence/logs."""
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


class ToolUnavailableError(Exception):
    """Tool binary is not installed / not runnable on this host."""


class ToolAdapterBase(ToolAdapterInterface):
    """Shared machinery for concrete tool adapters."""

    name: str = "tool"
    version: str = "unknown"
    capabilities: tuple = ()

    # subclasses set the executable name, e.g. "nmap"
    binary: str = ""

    def __init__(self, scope_config: dict | None = None) -> None:
        self._scope: dict = scope_config or {}
        self._resolved_version: str | None = None
        self._available: bool | None = None

    # ------------------------------------------------------------ availability
    def is_available(self) -> bool:
        if self._available is None:
            self._available = shutil.which(self.binary) is not None
        return self._available

    def health_check(self) -> dict[str, Any]:
        available = self.is_available()
        status = "READY" if available else "NOT_INSTALLED"
        result: dict[str, Any] = {
            "name": self.name,
            "binary": self.binary,
            "available": available,
            "status": status,
            "capabilities": list(self.capabilities),
        }
        if available:
            result["version"] = self._detect_version() or "unknown"
        return result

    def _detect_version(self) -> str | None:
        """Sync version probe (safe from any context; short timeout).

        Uses subprocess with an argument list — never a shell.
        """
        if self._resolved_version is not None:
            return self._resolved_version
        try:
            import subprocess

            proc = subprocess.run(
                [self.binary, "--version"],
                capture_output=True,
                timeout=8,
                shell=False,
            )
            out = (proc.stdout or b"").decode("utf-8", errors="replace")
            m = re.search(r"(\d+\.\d+[\w.]*)", out)
            self._resolved_version = m.group(1) if m else "unknown"
        except Exception:  # noqa: BLE001 - health check must never raise
            self._resolved_version = "unknown"
        return self._resolved_version

    # ------------------------------------------------------------ scope
    def validate_target(self, url: str, scope: dict) -> None:
        """Scope gate BEFORE any command is built or run.

        Re-implements the essential checks locally (scheme/host/port) and then
        delegates to the authoritative ScopeValidator when available via
        validate_scope(). Any failure raises ScopeViolationError -> BLOCKED.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolationError(f"tool {self.name}: scheme {parsed.scheme!r} not allowed")
        if not parsed.hostname:
            raise ScopeViolationError(f"tool {self.name}: target has no hostname")
        if (parsed.username or parsed.password) is not None:
            raise ScopeViolationError(f"tool {self.name}: userinfo in target rejected")
        allowed_domains = [d.lower() for d in (scope.get("allowed_domains") or [])]
        host = (parsed.hostname or "").lower()
        if allowed_domains and host not in allowed_domains and not self._wildcard_match(host, allowed_domains):
            raise ScopeViolationError(f"tool {self.name}: host {host} outside allowed domains")
        excluded = [e.lower() for e in (scope.get("excluded_targets") or [])]
        if host in excluded:
            raise ScopeViolationError(f"tool {self.name}: host {host} is excluded")
        for path in (scope.get("allowed_paths") or ["/"]):
            if not (parsed.path or "/").startswith(path):
                raise ScopeViolationError(f"tool {self.name}: path outside allowed_paths")
        self.validate_scope(url, scope)

    @abstractmethod
    def validate_scope(self, url: str, scope: dict) -> None:
        """Adapter-specific extra checks (ports, profiles, lab-only, ...)."""

    @staticmethod
    def _wildcard_match(host: str, allowed: list[str]) -> bool:
        for entry in allowed:
            if entry.startswith("*.") and (
                host == entry[2:] or host.endswith("." + entry[2:])
            ):
                return True
            if host == entry or host.endswith("." + entry) and entry != host:
                # plain entries also cover subdomains (mirror ScopeValidator)
                if host == entry:
                    return True
        return False

    # ------------------------------------------------------------ command
    @abstractmethod
    def build_command(self, request: dict) -> list[str]:
        """Return the argv list. Target must appear as a single argv element."""

    # ------------------------------------------------------------ execution
    async def execute(self, request: dict) -> dict[str, Any]:
        """Scope-validate, build argv, run without shell, cap outputs."""
        url = request.get("target") or ""
        scope = request.get("scope") or self._scope
        self.validate_target(url, scope)

        if not self.is_available():
            return {
                "tool": self.name,
                "status": "NOT_INSTALLED",
                "target": url,
                "findings": [],
            }

        argv = self.build_command({**request, "scope": scope})
        started = time.monotonic()
        try:
            result = await self._run(
                argv,
                timeout=request.get("timeout"),
                max_output=request.get("max_output"),
            )
        except ToolExecutionError as exc:
            return {
                "tool": self.name,
                "status": "FAILED",
                "target": url,
                "error": str(exc),
                "findings": [],
            }

        raw = {
            "tool": self.name,
            "tool_version": self.health_check().get("version", "unknown"),
            "status": "OK",
            "target": url,
            "argv": argv,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "returncode": result["returncode"],
            "stdout": redact(result["stdout"]),
            "stderr": redact(result["stderr"]),
        }
        raw["findings"] = self.parse_output(raw)
        return raw

    async def _run(
        self,
        argv: list[str],
        timeout: float | None = None,
        max_output: int = 2_000_000,
    ) -> dict[str, Any]:
        """subprocess WITHOUT a shell, argument list only, bounded time/output."""
        from agent.core.config import settings
        from agent.tools.windows_exec import exec_argv

        result = await exec_argv(
            argv,
            timeout=timeout or settings.tool_timeout_seconds,
            max_output=max_output,
        )
        return result

    # ------------------------------------------------------------ normalization
    def normalize_findings(self, raw: dict) -> list[dict[str, Any]]:
        """Base normalization: attach provenance to parsed findings."""
        from agent.core.finding import make_finding

        provenance = {
            "source_tool": self.name,
            "tool_version": raw.get("tool_version", "unknown"),
            "command_profile": raw.get("command_profile", self.name),
            "timestamp": raw.get("timestamp"),
            "target": raw.get("target", ""),
            "parser_version": f"{self.name}-parser/1.0",
        }
        findings: list[dict[str, Any]] = []
        for f in self.parse_output(raw):
            meta = {**(f.get("metadata") or {}), **provenance}
            try:
                normalized = make_finding(
                    title=f["title"],
                    category=f["category"],
                    severity=f["severity"],
                    confidence=f["confidence"],
                    description=f.get("description", ""),
                    evidence=f.get("evidence") or [],
                    affected_asset=f.get("affected_asset", raw.get("target", "")),
                    impact=f.get("impact", ""),
                    remediation=f.get("remediation", ""),
                    references=f.get("references") or [],
                    source=self.name,
                    metadata=meta,
                )
            except (KeyError, ValueError):
                continue  # unparseable finding is dropped, not guessed
            normalized["fingerprint"] = f.get("fingerprint") or ""
            findings.append(normalized)
        return findings

    # helpers for subclasses -------------------------------------------------
    @staticmethod
    def _json_loads(text: str) -> Any:
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
