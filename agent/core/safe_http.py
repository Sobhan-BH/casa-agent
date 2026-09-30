"""Hardened async HTTP client used by every module.

Safety properties:
- re-validates every URL (including redirect hops) against the scope at fetch time
- only follows redirects that stay inside the authorized scope
- enforces per-request timeout and response-size caps
- GET/HEAD only: this agent assesses, it does not attack
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from agent.core.config import settings
from agent.core.exceptions import ScopeViolationError
from agent.core.target import ScopeValidator

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


@dataclass
class SafeHttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    redirects: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "elapsed_ms": self.elapsed_ms,
            "redirects": self.redirects,
        }


class SafeHttpClient:
    """httpx wrapper enforcing scope + resource limits on every request."""

    def __init__(self, validator: ScopeValidator) -> None:
        self._validator = validator
        self._limits = httpx.Limits(max_connections=settings.http_max_concurrency)

    async def _request(
        self, method: str, url: str, extra_headers: dict[str, str] | None = None
    ) -> SafeHttpResponse:
        if method not in SAFE_METHODS:
            raise ScopeViolationError(f"method {method} is not permitted by CASA safety policy")
        self._validator.check_all(url)  # raises ScopeViolationError when out of scope

        redirects: list[str] = []
        async with httpx.AsyncClient(
            timeout=settings.http_timeout_seconds,
            limits=self._limits,
            follow_redirects=False,
            headers={"User-Agent": settings.user_agent},
        ) as client:
            current = url
            for _hop in range(6):  # bounded redirect chain
                self._validator.check_all(current)
                # Extra headers (e.g. CORS probe Origin) go per-request so each
                # hop carries them; the client itself stays neutral.
                if extra_headers:
                    resp = await client.request(method, current, headers=extra_headers)
                else:
                    resp = await client.request(method, current)
                if resp.is_redirect:
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    # Resolve relative Location headers against the current URL;
                    # the scope check at the top of the next iteration rejects
                    # any hop that escapes the authorization.
                    next_url = str(httpx.URL(current).join(location))
                    redirects.append(next_url)
                    current = next_url
                    continue
                body = resp.text
                if len(body) > settings.http_max_bytes:
                    body = body[: settings.http_max_bytes]
                return SafeHttpResponse(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=body,
                    elapsed_ms=int(resp.elapsed.total_seconds() * 1000),
                    redirects=redirects,
                )
            raise ScopeViolationError(f"redirect chain for {url} never settled in scope")

    async def get(self, url: str) -> SafeHttpResponse:
        return await self._request("GET", url)

    async def head(self, url: str) -> SafeHttpResponse:
        return await self._request("HEAD", url)

    async def options(self, url: str) -> SafeHttpResponse:
        return await self._request("OPTIONS", url)

    async def get_with_origin(self, url: str, origin: str) -> SafeHttpResponse:
        """GET with a controlled Origin header (CORS reflection probes).

        The origin value is a harmless synthetic marker origin; no credentials
        or cookies are ever attached.
        """
        return await self._request("GET", url, extra_headers={"Origin": origin})
