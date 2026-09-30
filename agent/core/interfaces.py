"""Abstract interfaces - the seams of CASA.

New modules, tool adapters and LLM providers plug in by subclassing these.
The core never imports concrete implementations (dependency inversion).
"""
from __future__ import annotations

import abc
from typing import Any

from agent.core.context import AssessmentContext


class AssessmentModule(abc.ABC):
    """A pipeline step: reads context, appends findings and raw_results."""

    name: str = "module"
    phase: str = ""
    critical: bool = False

    @abc.abstractmethod
    async def run(self, ctx: AssessmentContext) -> None:
        """Execute the module against the authorized target."""

    def applies(self, ctx: AssessmentContext) -> bool:
        """Return False to skip this module for a given context."""
        return True


class ToolAdapter(abc.ABC):
    """Adapter around an external or built-in tool.

    Contract:
    - validate_target must raise ScopeViolationError for out-of-scope targets.
    - execute returns a raw result dict.
    - parse_output converts raw output into schema-valid finding dicts.
    - Adapters never write storage and never call the LLM.
    """

    name: str = "adapter"
    version: str = "0.0.0"
    capabilities: tuple = ()

    @abc.abstractmethod
    def validate_target(self, url: str, scope: dict) -> None:
        ...

    @abc.abstractmethod
    async def execute(self, request: dict) -> dict:
        ...

    @abc.abstractmethod
    def parse_output(self, raw: dict) -> list:
        ...


class LLMProvider(abc.ABC):
    """Provider-agnostic LLM seam. The agent never depends on a vendor SDK."""

    name: str = "provider"

    @abc.abstractmethod
    async def analyze(self, prompt: str, system: str) -> str:
        """Return raw model text for the given prompt."""

    async def health(self) -> bool:
        return True


class StorageBackend(abc.ABC):
    """Extension point: swap SQL storage for something else later."""
