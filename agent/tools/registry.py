"""Tool Registry — discovery of installed tools + profile mapping.

The registry instantiates every known adapter, runs cheap availability
checks and exposes:
- health(): per-tool status (READY / NOT_INSTALLED) for the /api/tools view
- for_profile(profile): which tools a QUICK/STANDARD/DEEP assessment may use
- select(ctx): intelligent selection based on assessment context (HTTPS-only
  web target -> no content-discovery tools unless DEEP, API docs found ->
  Nuclei useful, etc.)

A missing tool NEVER fails the pipeline: adapters report NOT_INSTALLED and
the orchestrator skips them.
"""
from __future__ import annotations

from typing import Any

from agent.core.config import settings
from agent.tools.base import ToolAdapterBase


def _all_adapters() -> dict[str, type[ToolAdapterBase]]:
    # Imported lazily so the package import stays cheap and cycle-free.
    from agent.tools.ffuf import FfufAdapter
    from agent.tools.gobuster import GobusterAdapter
    from agent.tools.metasploit_lab import MetasploitLabAdapter
    from agent.tools.nikto import NiktoAdapter
    from agent.tools.nmap import NmapAdapter
    from agent.tools.nuclei import NucleiAdapter
    from agent.tools.whatweb import WhatWebAdapter

    return {
        "nmap": NmapAdapter,
        "gobuster": GobusterAdapter,
        "ffuf": FfufAdapter,
        "nikto": NiktoAdapter,
        "whatweb": WhatWebAdapter,
        "nuclei": NucleiAdapter,
        "metasploit_lab": MetasploitLabAdapter,
    }


# Profile -> tool mapping (Phase 11 of the tool integration spec).
# metasploit_lab is NEVER part of a profile; it is LAB-environment only.
PROFILE_TOOLS: dict[str, list[str]] = {
    "QUICK": ["whatweb"],
    "STANDARD": ["nmap", "whatweb", "nikto", "nuclei"],
    "DEEP": ["nmap", "whatweb", "nikto", "nuclei", "gobuster", "ffuf"],
}


class ToolRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapterBase] = {}
        for name, cls in _all_adapters().items():
            self._adapters[name] = cls()

    # ------------------------------------------------------------ health
    def health(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for name, adapter in self._adapters.items():
            entry = adapter.health_check()
            if not settings.tools_enabled or not self._allowed(name):
                entry["status"] = "DISABLED"
                entry["available"] = False
            out[name] = entry
        return out

    def _allowed(self, name: str) -> bool:
        allowlist = [t.strip() for t in settings.tools_allowed.split(",") if t.strip()]
        return not allowlist or name in allowlist

    def get(self, name: str) -> ToolAdapterBase | None:
        adapter = self._adapters.get(name)
        if adapter is None or not self._allowed(name):
            return None
        return adapter

    def available(self) -> list[str]:
        return [
            name
            for name, adapter in self._adapters.items()
            if self._allowed(name) and adapter.is_available()
        ]

    # ------------------------------------------------------------ selection
    def for_profile(self, profile: str) -> list[str]:
        tools = list(PROFILE_TOOLS.get(profile.upper(), PROFILE_TOOLS["STANDARD"]))
        return [t for t in tools if self._allowed(t)]

    def select(self, ctx) -> list[ToolAdapterBase]:
        """Intelligent selection: profile + context signals, availability-aware.

        Selection logic (never a crash source):
        - profile defines the candidate set
        - web-only targets skip Nmap in STANDARD (it runs in DEEP for surface
          enrichment) — an HTTPS web target mainly needs WhatWeb/Nikto/Nuclei
        - API docs discovered -> Nuclei is kept (API-relevant templates)
        - tools not installed are silently skipped (NOT_INSTALLED is recorded
          in raw results by the runner)
        """
        profile = str(getattr(ctx, "mode", "STANDARD") or "STANDARD").upper()
        candidates = self.for_profile(profile)

        selected: list[ToolAdapterBase] = []
        for name in candidates:
            adapter = self._adapters.get(name)
            if adapter is None or not adapter.is_available():
                continue
            if name == "nmap" and profile == "STANDARD":
                # service discovery adds value mainly in DEEP enrichment
                continue
            selected.append(adapter)

        # Metasploit lab adapter is appended ONLY by the lab runner path
        # (environment == LAB); never by target selection.
        return selected


tool_registry = ToolRegistry()
