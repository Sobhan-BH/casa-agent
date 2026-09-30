"""ffuf adapter — authorized content/endpoint discovery.

MVP policy: GET-only fuzzing of a small built-in path set with JSON output,
bounded concurrency and a hard stop on runtime. Response-size clustering
filters soft-404s: paths whose response length matches the dominant 404-size
cluster are discarded before anything becomes a finding.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from agent.core.config import settings
from agent.core.exceptions import ScopeViolationError
from agent.tools.base import ToolAdapterBase
from collections import Counter

_INTERESTING = re.compile(
    r"(?i)(admin|backup|config|\.env|\.git|debug|api|docs|private|test|dump)"
)


class FfufAdapter(ToolAdapterBase):
    name = "ffuf"
    binary = "ffuf"
    version = "unknown"
    capabilities = ("directory_discovery", "endpoint_discovery")

    def validate_scope(self, url: str, scope: dict) -> None:
        parsed = urlparse(url)
        if (parsed.port or (443 if parsed.scheme == "https" else 80)) not in (
            80, 443, 8000, 8001, 8080, 8081, 8443, 8888, 3000, 5000,
        ):
            raise ScopeViolationError("tool ffuf: port outside web assessment policy")

    def build_command(self, request: dict) -> list[str]:
        parsed = urlparse(request["target"])
        root = f"{parsed.scheme}://{parsed.netloc}"
        return [
            self.binary,
            "-u", f"{root}/FUZZ",           # scope-validated origin only
            "-w", "-",                      # wordlist piped on stdin
            "-X", "GET",                    # GET-only, by policy
            "-t", str(min(4, settings.tool_max_concurrency)),
            "-timeout", "5",
            "-of", "json",
            "-o", "-",                      # JSON to stdout
            "-s",                           # silent banner
        ]

    async def execute(self, request: dict) -> dict[str, Any]:
        words = "\n".join(
            ["admin", "api", "backup", "debug", "docs", ".env", ".git", "test",
             "old", "config", "private", "assets", "files", "dump"]
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
            stdout, stderr, returncode = await _run_ffuf(argv, words)
        except Exception as exc:  # noqa: BLE001
            return {
                "tool": self.name, "status": "FAILED", "target": url,
                "error": str(exc), "findings": [],
            }
        raw = {
            "tool": self.name,
            "tool_version": self.health_check().get("version", "unknown"),
            "status": "OK",
            "target": url,
            "argv": argv,
            "duration_ms": int((_t.monotonic() - started) * 1000),
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
        raw["findings"] = self.parse_output(raw)
        return raw

    def parse_output(self, raw: dict) -> list[dict[str, Any]]:
        parsed = self._parse_json(raw.get("stdout", ""))
        raw["endpoints"] = parsed

        if not parsed:
            return []
        # --- soft-404 filtering: cluster by response length ----------------
        sizes = Counter(r.get("length", 0) for r in parsed)
        if len(sizes) > 1:
            dominant_404 = sizes.most_common(1)[0][0]
        else:
            dominant_404 = None

        findings: list[dict[str, Any]] = []
        for r in parsed:
            if dominant_404 is not None and r.get("length") == dominant_404 and len(sizes) > 1:
                continue  # matches the uniform soft-404 size -> filtered
            if r["status"] not in (200, 204, 301, 302, 401, 403):
                continue
            if not _INTERESTING.search(r["path"]):
                continue  # non-sensitive hits -> surface entities only
            findings.append(
                {
                    "title": f"Sensitive path discovered: {r['path']}",
                    "category": "RECON",
                    "severity": "LOW",
                    "confidence": "MEDIUM",
                    "description": (
                        f"ffuf discovered {r['path']} (HTTP {r['status']}, "
                        f"{r['length']} bytes) after soft-404 filtering."
                    ),
                    "evidence": [
                        {
                            "type": "ffuf_hit",
                            "url": r["url"],
                            "status": r["status"],
                            "length": r["length"],
                            "words": r.get("words"),
                            "lines": r.get("lines"),
                        }
                    ],
                    "affected_asset": r["url"],
                    "impact": "Undocumented paths expand the attack surface.",
                    "remediation": "Review the path; restrict or remove anything unintended.",
                    "references": [],
                    "fingerprint": "",
                }
            )
        return findings

    def _parse_json(self, stdout: str) -> list[dict[str, Any]]:
        data = self._json_loads(stdout)
        if not isinstance(data, dict):
            return []
        base = (data.get("config") or {}).get("url", "")
        base = base.replace("/FUZZ", "")
        results = data.get("results") or []
        parsed: list[dict[str, Any]] = []
        for r in results:
            url = r.get("url", "")
            path = urlparse(url).path or "/"
            parsed.append(
                {
                    "path": path,
                    "url": url or (base + path),
                    "status": int(r.get("status", 0) or 0),
                    "length": int(r.get("length", 0) or 0),
                    "words": r.get("words"),
                    "lines": r.get("lines"),
                }
            )
        return parsed


async def _run_ffuf(argv: list[str], stdin_payload: bytes):
    from agent.core.config import settings
    from agent.tools.windows_exec import exec_argv

    result = await exec_argv(
        argv, stdin_payload=stdin_payload, timeout=settings.tool_timeout_seconds
    )
    return result["stdout"], result["stderr"], result["returncode"]
