"""Metasploit LAB-ONLY adapter — validation fixture, not an attack feature.

This adapter exists so the ToolAdapter contract can be validated end-to-end
against the LOCAL vulnerable lab. It is structurally incapable of running
against real targets:

- validate_target() refuses every URL whose host is not the local lab host
  (127.0.0.1 / localhost on a lab port) — production/real targets are BLOCKED
- it is never selected by the registry for any profile
- execute() only ever prints a harmless lab banner via the local msfconsole
  IF present; no modules are loaded, no exploits run, no payloads configured

There is no exploit execution, no persistence, no credential theft, and no
destructive action anywhere in this file. It intentionally does NOT accept a
module/payload option.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from agent.core.exceptions import ScopeViolationError
from agent.tools.base import ToolAdapterBase

_LAB_HOSTS = {"127.0.0.1", "localhost", "::1"}
_LAB_PORTS = {8001, 8081}


class MetasploitLabAdapter(ToolAdapterBase):
    name = "metasploit_lab"
    binary = "msfconsole"
    version = "unknown"
    capabilities = ("lab_validation_only",)

    def validate_target(self, url: str, scope: dict) -> None:
        # HARD REJECT anything that is not the local lab, before any other
        # logic. This adapter cannot be pointed at a real target by design.
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port or 80
        if host not in _LAB_HOSTS or port not in _LAB_PORTS:
            raise ScopeViolationError(
                f"tool metasploit_lab: {host}:{port} is not the local lab; "
                "this adapter is LAB-ONLY and refuses real targets"
            )

    def validate_scope(self, url: str, scope: dict) -> None:  # pragma: no cover
        # validate_target already rejects everything non-lab.
        return None

    def build_command(self, request: dict) -> list[str]:
        # Harmless identity probe only: print version and exit. No modules,
        # no resources, no payloads — and it only ever runs against the lab.
        return [self.binary, "--version"]

    def parse_output(self, raw: dict) -> list[dict[str, Any]]:
        return []  # validation fixture: produces no findings by design
