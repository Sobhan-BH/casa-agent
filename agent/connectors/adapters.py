"""Built-in tool adapters. Each wraps one data source and normalizes output.

Adapters enforce scope on every outbound call via SafeHttpClient/ScopeValidator.
"""
from __future__ import annotations

import socket
import ssl
from typing import Any

from agent.core.interfaces import ToolAdapter
from agent.core.safe_http import SafeHttpClient
from agent.core.target import ScopeValidator


class HttpProbeAdapter(ToolAdapter):
    """Fetches a URL (GET) and returns status/headers/body metadata."""

    name = "http_probe"
    version = "0.1.0"
    capabilities = ("http", "headers", "redirects")

    def __init__(self, validator: ScopeValidator) -> None:
        self._validator = validator

    def validate_target(self, url: str, scope: dict) -> None:
        self._validator.check_all(url)

    async def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        url = request["url"]
        self.validate_target(url, {})
        client = SafeHttpClient(self._validator)
        resp = await client.get(url)
        return resp.to_dict()

    def parse_output(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        return []  # raw output only; modules derive findings


class DnsAdapter(ToolAdapter):
    """Local DNS lookups (A/AAAA via getaddrinfo, PTR reverse) — passive."""

    name = "dns"
    version = "0.1.0"
    capabilities = ("dns",)

    def __init__(self, validator: ScopeValidator) -> None:
        self._validator = validator

    def validate_target(self, url: str, scope: dict) -> None:
        self._validator.check_url(url)

    async def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        host = request["host"]
        result: dict[str, Any] = {"host": host, "addresses": [], "reverse": []}
        try:
            infos = await _run_in_thread(
                socket.getaddrinfo, host, None
            )
            seen: set[str] = set()
            for info in infos:
                addr = info[4][0]
                if addr not in seen:
                    seen.add(addr)
                    result["addresses"].append({"address": addr, "family": info[0].name})
        except socket.gaierror as exc:
            result["error"] = f"dns resolution failed: {exc}"
        try:
            # Must run off the event loop: gethostbyaddr can block for many
            # seconds on hosts without PTR records and would freeze the API.
            host_by_addr = await _run_in_thread(socket.gethostbyaddr, host)
            result["reverse"] = list(host_by_addr[1])
        except (socket.herror, socket.gaierror, OSError):
            pass
        return result

    def parse_output(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        return []


class TlsInfoAdapter(ToolAdapter):
    """Collects TLS certificate metadata + supported protocol info (handshake only)."""

    name = "tls_info"
    version = "0.1.0"
    capabilities = ("tls", "certificate")

    def __init__(self, validator: ScopeValidator) -> None:
        self._validator = validator

    def validate_target(self, url: str, scope: dict) -> None:
        self._validator.check_all(url)

    async def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        import asyncio
        from urllib.parse import urlparse

        url = request["url"]
        self.validate_target(url, {})
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        return await asyncio.get_running_loop().run_in_executor(
            None, self._probe_sync, host, port
        )

    def _probe_sync(self, host: str, port: int) -> dict[str, Any]:
        out: dict[str, Any] = {"host": host, "port": port}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    out["tls_version"] = tls.version()
                    out["cipher"] = tls.cipher()[0] if tls.cipher() else None
                    out["subject"] = dict(x[0] for x in cert.get("subject", []))
                    out["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    out["not_before"] = cert.get("notBefore")
                    out["not_after"] = cert.get("notAfter")
                    out["sans"] = list(cert.get("subjectAltName", ()))
        except ssl.SSLCertVerificationError as exc:
            out["error"] = f"certificate verification failed: {exc.verify_message}"
        except (OSError, ssl.SSLError) as exc:
            out["error"] = f"tls handshake failed: {exc}"
        return out

    def parse_output(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        return []


async def _run_in_thread(fn, *args):
    import asyncio

    return await asyncio.get_running_loop().run_in_executor(None, fn, *args)
