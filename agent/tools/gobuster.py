"""Gobuster adapter — authorized directory/file content discovery.

MVP policy: dir mode over a small built-in wordlist with hard caps on
requests/threads and timeout. Credential brute-force modes are never used.
Results become endpoint discoveries (attack-surface entries), each carrying
status + length evidence; confirmed sensitive hits may become findings.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from agent.core.config import settings
from agent.core.exceptions import ScopeViolationError
from agent.tools.base import ToolAdapterBase

_INTERESTING = re.compile(
    r"(?i)(admin|backup|config|\.env|\.git|debug|api|docs|private|test|dump)"
)


class GobusterAdapter(ToolAdapterBase):
    name = "gobuster"
    binary = "gobuster"
    version = "unknown"
    capabilities = ("directory_discovery", "file_discovery")

    def validate_scope(self, url: str, scope: dict) -> None:
        parsed = urlparse(url)
        if (parsed.port or (443 if parsed.scheme == "https" else 80)) not in (
            80, 443, 8000, 8001, 8080, 8081, 8443, 8888, 3000, 5000,
        ):
            raise ScopeViolationError("tool gobuster: port outside web assessment policy")

    def build_command(self, request: dict) -> list[str]:
        parsed = urlparse(request["target"])
        root = f"{parsed.scheme}://{parsed.netloc}"
        return [
            self.binary,
            "dir",
            "--url", root,                     # scope-validated origin only
            "--wordlist", "-",                 # words piped on stdin (small set)
            "--threads", str(min(4, settings.tool_max_concurrency)),
            "--timeout", "5s",
            "--no-progress",
            "--quiet",                         # machine-readable lines only
        ]

    async def execute(self, request: dict) -> dict[str, Any]:
        # Feed the built-in wordlist over stdin: no on-disk wordlist file is
        # required and the request count is bounded by construction.
        words = "\n".join(
            [
                "admin", "api", "backup", "config", "debug", "docs", ".env",
                ".git", "private", "test", "dump", "files", "assets", "old",
            ]
        ).encode()
        url = request.get("target") or ""
        scope = request.get("scope") or self._scope
        self.validate_target(url, scope)
        if not self.is_available():
            return {"tool": self.name, "status": "NOT_INSTALLED", "target": url, "findings": []}

        import time as _t

        argv = self.build_command({**request, "scope": scope})
        started = _t.monotonic()
        try:
            proc = await asyncio_create(argv, stdin_payload=words)
        except Exception as exc:  # noqa: BLE001
            return {
                "tool": self.name, "status": "FAILED", "target": url,
                "error": str(exc), "findings": [],
            }
        stdout, stderr, returncode = proc
        raw = {
            "tool": self.name,
            "tool_version": self.health_check().get("version", "unknown"),
            "status": "OK",
            "target": url,
            "argv": argv,
            "duration_ms": int((_t.monotonic() - started) * 1000),
            "returncode": returncode,
            "stdout": self.redact(stdout),
            "stderr": self.redact(stderr),
        }
        raw["findings"] = self.parse_output(raw)
        return raw

    @staticmethod
    def redact(text: str) -> str:
        from agent.tools.base import redact as _redact

        return _redact(text)

    def parse_output(self, raw: dict) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        parsed = self._parse_lines(raw.get("stdout", ""))
        raw["endpoints"] = parsed

        for entry in parsed:
            if entry["status"] in (200, 204, 301, 302, 401, 403):
                is_interesting = bool(_INTERESTING.search(entry["path"]))
                if not is_interesting:
                    # plain discovered path -> attack-surface entity only
                    continue
                findings.append(
                    {
                        "title": f"Sensitive path discovered: {entry['path']}",
                        "category": "RECON",
                        "severity": "LOW",
                        "confidence": "MEDIUM",
                        "description": (
                            f"Content discovery found {entry['path']} "
                            f"(HTTP {entry['status']}, {entry['length']} bytes). "
                            "Name-based triage suggests it may be sensitive."
                        ),
                        "evidence": [
                            {
                                "type": "gobuster_hit",
                                "url": entry["url"],
                                "status": entry["status"],
                                "length": entry["length"],
                            }
                        ],
                        "affected_asset": entry["url"],
                        "impact": "Undocumented paths expand the attack surface; some may expose data.",
                        "remediation": "Review the path; restrict or remove anything unintended.",
                        "references": [],
                        "fingerprint": "",
                    }
                )
        return findings

    def _parse_lines(self, stdout: str) -> list[dict[str, Any]]:
        # gobuster --quiet emits:  STATUS<TAB>SIZE<TAB>URL  (v3) or "PATH (Status)" variants
        base = self._base_of(raw_target := "")  # set below via raw
        return self._parse_lines_from(stdout)

    def _parse_lines_from(self, stdout: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^(?P<status>\d{3})\s+(?P<size>\d+)\s+(?P<url>\S+)$", line)
            if not m:
                m2 = re.match(r"^(?P<path>/\S+)\s+\(status:(?P<status>\d{3})\)\s+\[size:(?P<size>\d+)\]", line)
                if not m2:
                    continue
                path, status, size = m2.group("path"), int(m2.group("status")), int(m2.group("size"))
                entries.append({"path": path, "status": status, "length": size, "url": ""})
                continue
            url = m.group("url")
            path = urlparse(url).path or "/"
            entries.append(
                {
                    "path": path,
                    "status": int(m.group("status")),
                    "length": int(m.group("size")),
                    "url": url,
                }
            )
        return entries

    def _base_of(self, target: str) -> str:
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target


async def asyncio_create(argv: list[str], stdin_payload: bytes = b""):
    """Run gobuster with the wordlist piped over stdin (no shell)."""
    from agent.core.config import settings
    from agent.tools.windows_exec import exec_argv

    result = await exec_argv(
        argv, stdin_payload=stdin_payload, timeout=settings.tool_timeout_seconds
    )
    return result["stdout"], result["stderr"], result["returncode"]
