"""Authorization Manager — the Authorization Gate.

No assessment may start without:
1. an active Authorization record for the target, and
2. a ScopeValidator built from that record that re-checks every future URL.

The gate is enforced here (job submission) AND again at fetch time (SafeHttp),
so even a bug in a module cannot push traffic out of scope.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from agent.core.audit import audit_logger
from agent.core.exceptions import (
    AuthorizationError,
    ScopeConfigurationError,
    ScopeViolationError,
)
from agent.core.target import ScopeValidator, parse_target_url
from agent.storage import repositories as repo
from agent.storage.models import Authorization


class AuthorizationManager:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @staticmethod
    def _coerce_window(value: Any, field: str) -> datetime | None:
        """Accept ISO-8601 strings or datetimes; raise on anything else.

        Naive datetimes are interpreted as UTC so the comparison in
        ScopeValidator (timezone-aware) stays consistent.
        """
        if value is None:
            return None
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            except ValueError as exc:
                raise ScopeConfigurationError(
                    f"{field} is not a valid ISO-8601 datetime: {value!r}"
                ) from exc
        else:
            raise ScopeConfigurationError(f"{field} must be an ISO-8601 string or datetime")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    async def register_authorization(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Register target + authorization. Returns both as dicts."""
        url = str(payload.get("target", "")).strip()
        if not url:
            raise ScopeViolationError("target url is required")
        parsed = parse_target_url(url)  # hard-validates scheme/host

        target = await repo.get_target_by_url(self._session, parsed.url)
        if target is None:
            target = await repo.create_target(
                self._session,
                url=parsed.url,
                target_type=str(payload.get("target_type", "WEB_APP")),
                label=str(payload.get("label", "")),
            )

        allowed_domains = payload.get("allowed_domains") or []
        if isinstance(allowed_domains, str):
            allowed_domains = [d.strip() for d in allowed_domains.split(",") if d.strip()]
        if not allowed_domains:
            allowed_domains = [parsed.host]  # safest default: only this exact host

        allowed_paths = payload.get("allowed_paths") or ["/"]
        if isinstance(allowed_paths, str):
            allowed_paths = [p.strip() for p in allowed_paths.split(",") if p.strip()]

        authz = await repo.create_authorization(
            self._session,
            target_id=target.id,
            authorized_by=str(payload.get("authorized_by", "")),
            authorization_reference=str(payload.get("authorization_reference", "")),
            allowed_domains=[d.lower() for d in allowed_domains],
            allowed_paths=allowed_paths,
            excluded_targets=[
                e.lower()
                for e in (payload.get("excluded_targets") or [])
                if str(e).strip()
            ],
            window_start=self._coerce_window(payload.get("window_start"), "window_start"),
            window_end=self._coerce_window(payload.get("window_end"), "window_end"),
        )

        audit_logger.emit(
            "AUTHORIZATION_REGISTERED",
            target=parsed.url,
            details={
                "authorization_id": authz.id,
                "authorized_by": authz.authorized_by,
                "reference": authz.authorization_reference,
            },
        )
        await repo.record_audit(
            self._session,
            "AUTHORIZATION_REGISTERED",
            target=parsed.url,
            details={"authorization_id": authz.id},
        )
        return {
            "target_id": target.id,
            "target_url": target.url,
            "authorization": repo.authz_to_dict(authz),
        }

    async def resolve_for_target_url(self, target_url: str) -> tuple[Authorization, ScopeValidator]:
        """Load the active authorization for a URL and build its validator."""
        parsed = parse_target_url(target_url)
        target = await repo.get_target_by_url(self._session, parsed.url)
        if target is None:
            raise AuthorizationError(
                f"target {parsed.url} is not registered; register an authorization first"
            )
        authz = await repo.get_active_authorization(self._session, target.id)
        validator = ScopeValidator.from_authorization(repo.authz_to_dict(authz))
        # The registered target itself must be inside its own declared scope.
        validator.check_all(parsed.url)
        audit_logger.emit(
            "AUTHORIZATION_RESOLVED",
            target=parsed.url,
            details={"authorization_id": authz.id},
        )
        return authz, validator

    @staticmethod
    def base_domain_of(url: str) -> str:
        return urlparse(url).hostname or ""
