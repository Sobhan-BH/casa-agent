"""Platform-safe argv execution for the tool layer.

POSIX: exec the argv directly (no shell).
Windows: ``create_subprocess_exec`` cannot spawn ``.cmd``/``.bat`` files
directly (CreateProcess restriction); those must be routed through
``cmd /c``. Only files whose extension is .cmd/.bat take that path — real
tools (.exe) are exec'd directly, keeping the no-shell invariant.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path


async def exec_argv(
    argv: list[str],
    stdin_payload: bytes | None = None,
    timeout: float = 300.0,
    max_output: int = 2_000_000,
) -> dict:
    """Run argv without a shell (Windows .cmd/.bat via cmd /c wrapper)."""
    executable = argv[0]
    run_argv = argv
    if sys.platform == "win32" and executable.lower().endswith((".cmd", ".bat")):
        run_argv = ["cmd", "/c", *argv]

    try:
        proc = await asyncio.create_subprocess_exec(
            *run_argv,
            stdin=asyncio.subprocess.PIPE if stdin_payload is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        from agent.core.exceptions import ToolExecutionError

        raise ToolExecutionError(f"cannot start {executable!r} ({exc})") from exc

    try:
        if stdin_payload is not None:
            stdout, stderr = await asyncio.wait_for(
                _communicate_with_stdin(proc, stdin_payload), timeout=timeout
            )
        else:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        from agent.core.exceptions import ToolExecutionError

        raise ToolExecutionError(f"{executable}: timed out after {timeout}s")

    return {
        "returncode": proc.returncode,
        "stdout": stdout.decode("utf-8", errors="replace")[:max_output],
        "stderr": stderr.decode("utf-8", errors="replace")[:200_000],
    }


async def _communicate_with_stdin(proc, payload: bytes):
    """Write payload to stdin, close it, then collect outputs (no deadlock:
    stdin write runs as its own task so large payloads cannot block reads)."""
    import asyncio

    write_task = asyncio.create_task(_write_stdin(proc, payload))
    stdout, stderr = await proc.communicate()
    await write_task
    return stdout, stderr


async def _write_stdin(proc, payload: bytes) -> None:
    try:
        if proc.stdin is not None:
            proc.stdin.write(payload)
            await proc.stdin.drain()
    except (BrokenPipeError, ConnectionResetError, AttributeError):
        pass
    finally:
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except Exception:  # noqa: BLE001
                pass
