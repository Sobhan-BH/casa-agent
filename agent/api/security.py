"""API security layer: optional API-key auth + rate limiting.

Philosophy:
- CASA ships open by default (single-operator/lab posture) but production
  deployments can lock the write-paths down with CASA_API_KEY and rate-limit
  every route with CASA_RATE_LIMIT_RPM.
- Key comparison is constant-time; the key never appears in logs or errors.
- The rate limiter is an in-memory token bucket (per process) - a real
  deployment should back it with Redis; the seam is the middleware class.
"""
from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agent.core.config import settings


class RateLimiter:
    """Simple sliding-window rate limiter keyed by client IP."""

    def __init__(self, requests_per_minute: int) -> None:
        self.rpm = max(1, int(requests_per_minute))
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        window = 60.0
        hits = self._hits[key]
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) >= self.rpm:
            retry_after = int(window - (now - hits[0])) + 1
            return False, retry_after
        hits.append(now)
        return True, 0

    def _prune_all(self) -> None:
        now = time.monotonic()
        for key in list(self._hits):
            hits = self._hits[key]
            while hits and now - hits[0] > 120:
                hits.popleft()
            if not hits:
                del self._hits[key]


def install_api_security(app: FastAPI) -> None:
    """Attach optional API-key enforcement + rate limiting to the FastAPI app."""

    @app.middleware("http")
    async def api_security_middleware(
        request: Request, call_next: Callable[[Request], Awaitable]
    ):
        # 1) rate limit (cheap, always on when configured)
        rpm = settings.rate_limit_rpm
        if rpm > 0:
            limiter: RateLimiter = getattr(app.state, "rate_limiter", None) or RateLimiter(rpm)
            app.state.rate_limiter = limiter
            client_ip = request.client.host if request.client else "unknown"
            allowed, retry_after = limiter.check(client_ip)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                    content={"error": "RATE_LIMITED", "message": "too many requests"},
                )

        # 2) API-key auth (only when a key is configured)
        api_key = settings.api_key
        if api_key:
            path = request.url.path
            # health + docs stay reachable so uptime checks don't need the key
            open_paths = ("/health", "/docs", "/redoc", "/openapi.json", "/dashboard")
            requires_auth = not any(
                path == p or path.startswith(p + "/") for p in open_paths
            )
            if requires_auth:
                provided = request.headers.get("X-API-Key", "")
                if not hmac.compare_digest(provided, api_key):
                    return JSONResponse(
                        status_code=401,
                        content={
                            "error": "UNAUTHORIZED",
                            "message": "missing or invalid X-API-Key header",
                        },
                    )
        return await call_next(request)
