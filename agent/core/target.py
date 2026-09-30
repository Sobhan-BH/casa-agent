"""Target parsing and scope validation primitives.

Every network-touching component validates the exact URL it is about to fetch
through ScopeValidator *at fetch time* (not only at registration time), so a
redirect or a crafted link cannot silently escape the authorized scope.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from urllib.parse import urlparse

from agent.core.exceptions import ScopeViolationError, ScopeConfigurationError

ALLOWED_SCHEMES = ("http", "https")


@dataclass
class ParsedTarget:
    url: str
    scheme: str
    host: str
    port: int
    path: str

    @property
    def origin(self) -> str:
        if (self.scheme == "http" and self.port == 80) or (
            self.scheme == "https" and self.port == 443
        ):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"


def parse_target_url(url: str) -> ParsedTarget:
    """Parse and hard-validate a target URL (scheme, host, no userinfo, no fragments)."""
    if not url or not isinstance(url, str):
        raise ScopeConfigurationError("target url must be a non-empty string")
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ScopeConfigurationError(
            f"unsupported scheme {parsed.scheme!r}; allowed: {', '.join(ALLOWED_SCHEMES)}"
        )
    if not parsed.hostname:
        raise ScopeConfigurationError("target url must include a hostname")
    if parsed.username or parsed.password:
        raise ScopeConfigurationError("userinfo in target urls is not allowed")
    if parsed.fragment:
        raise ScopeConfigurationError("fragments are not allowed in target urls")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    path = parsed.path or "/"
    return ParsedTarget(
        url=url if parsed.query is None else url,
        scheme=parsed.scheme,
        host=parsed.hostname.lower(),
        port=port,
        path=path,
    )


def _is_ip(host: str) -> bool:
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return all(0 <= int(p) <= 255 for p in parts)
    return False


def _matches_domain(host: str, allowed: str) -> bool:
    """Subdomain-aware domain match: a.b.example.com matches example.com."""
    allowed = allowed.lower().lstrip(".")
    if allowed.startswith("*."):
        suffix = allowed[2:]
        return host.endswith("." + suffix)
    return host == allowed or host.endswith("." + allowed)


@dataclass
class ScopeValidator:
    """Validates URLs against an authorization record's scope fields."""

    allowed_domains: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=lambda: ["/"])
    window_start: datetime | None = None
    window_end: datetime | None = None

    @classmethod
    def from_authorization(cls, authz: dict) -> "ScopeValidator":
        def _as_list(v) -> list[str]:
            if v is None:
                return []
            if isinstance(v, str):
                return [s.strip() for s in v.split(",") if s.strip()]
            return [str(s).strip() for s in v if str(s).strip()]

        def _as_dt(v):
            if v in (None, ""):
                return None
            if isinstance(v, datetime):
                return v if v.tzinfo else v.replace(tzinfo=__import__("datetime").timezone.utc)
            if isinstance(v, date):
                return datetime(v.year, v.month, v.day, tzinfo=__import__("datetime").timezone.utc)
            try:
                return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ScopeConfigurationError(f"invalid datetime {v!r}") from exc

        domains = _as_list(authz.get("allowed_domains"))
        if not domains:
            raise ScopeConfigurationError("allowed_domains must contain at least one entry")
        return cls(
            allowed_domains=[d.lower() for d in domains],
            excluded_targets=[e.lower() for e in _as_list(authz.get("excluded_targets"))],
            allowed_paths=_as_list(authz.get("allowed_paths")) or ["/"],
            window_start=_as_dt(authz.get("window_start")),
            window_end=_as_dt(authz.get("window_end")),
        )

    def check_url(self, url: str) -> None:
        """Raise ScopeViolationError if this exact URL is out of scope."""
        t = parse_target_url(url)
        host = t.host
        if _is_ip(host):
            # IPs are only in scope if explicitly listed in allowed_domains.
            if host not in self.allowed_domains:
                raise ScopeViolationError(
                    f"IP target {host} is not explicitly listed in allowed_domains"
                )
        else:
            if not any(_matches_domain(host, d) for d in self.allowed_domains):
                raise ScopeViolationError(f"host {host!r} is outside allowed_domains")
        if t.path is not None and t.path not in self.allowed_paths:
            # Allow sub-paths of an allowed path prefix.
            if not any(t.path == p or t.path.startswith(p.rstrip("/") + "/") for p in self.allowed_paths):
                raise ScopeViolationError(f"path {t.path!r} is outside allowed_paths")
        for excl in self.excluded_targets:
            if _matches_domain(host, excl) or url.lower().startswith(excl):
                raise ScopeViolationError(f"target matches excluded_targets entry {excl!r}")

    def check_window(self, now: datetime | None = None) -> None:
        """Raise ScopeViolationError if `now` is outside the authorized window.

        Defensive against DB round-trips: SQLite may hand back naive datetimes
        while `now` is timezone-aware; both sides are coerced before compare.
        """
        def _aware(dt):
            if dt is None or dt.tzinfo is not None:
                return dt
            return dt.replace(tzinfo=timezone.utc)

        now = _aware(now) or datetime.now(timezone.utc)
        if self.window_start and now < _aware(self.window_start):
            raise ScopeViolationError(
                f"assessment window opens at {self.window_start.isoformat()}"
            )
        if self.window_end and now > _aware(self.window_end):
            raise ScopeViolationError(f"assessment window closed at {self.window_end.isoformat()}")

    def check_all(self, url: str) -> None:
        self.check_url(url)
        self.check_window()
