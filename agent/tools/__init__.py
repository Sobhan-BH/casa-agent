"""ToolAdapter package — external security tools behind one seam."""
from agent.tools.base import ToolAdapterBase, ToolUnavailableError, redact
from agent.tools.registry import ToolRegistry, tool_registry

__all__ = [
    "ToolAdapterBase",
    "ToolUnavailableError",
    "redact",
    "ToolRegistry",
    "tool_registry",
]
