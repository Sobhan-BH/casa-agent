"""ScopeValidator / parse_target_url tests."""
import pytest

from agent.core.exceptions import ScopeConfigurationError, ScopeViolationError
from agent.core.target import ScopeValidator, parse_target_url


def _validator(**kw) -> ScopeValidator:
    return ScopeValidator(
        allowed_domains=kw.get("domains", ["example.com"]),
        allowed_paths=kw.get("paths", ["/"]),
        excluded_targets=kw.get("excluded", []),
        window_start=kw.get("start"),
        window_end=kw.get("end"),
    )


def test_parse_rejects_bad_scheme():
    with pytest.raises(ScopeConfigurationError):
        parse_target_url("ftp://example.com")


def test_parse_rejects_userinfo():
    with pytest.raises(ScopeConfigurationError):
        parse_target_url("http://user:pass@example.com")


def test_scope_allows_subdomain():
    v = _validator()
    v.check_url("https://api.example.com/x")  # should not raise


def test_scope_rejects_other_domain():
    v = _validator()
    with pytest.raises(ScopeViolationError):
        v.check_url("https://evil.com/")


def test_scope_rejects_similar_domain_attack():
    v = _validator()
    with pytest.raises(ScopeViolationError):
        v.check_url("https://example.com.evil.com/")


def test_scope_path_enforcement():
    v = _validator(paths=["/app"])
    v.check_url("http://example.com/app/one")  # in scope
    with pytest.raises(ScopeViolationError):
        v.check_url("http://example.com/other")


def test_excluded_targets():
    v = _validator(excluded=["http://example.com/admin"])
    with pytest.raises(ScopeViolationError):
        v.check_url("http://example.com/admin")


def test_ip_requires_explicit_allow():
    v = _validator()
    with pytest.raises(ScopeViolationError):
        v.check_url("http://127.0.0.1:8001/")
    v2 = _validator(domains=["127.0.0.1"])
    v2.check_url("http://127.0.0.1:8001/")  # ok


def test_window_enforced():
    from datetime import datetime, timedelta, timezone

    v = _validator(end=datetime.now(timezone.utc) - timedelta(days=1))
    with pytest.raises(ScopeViolationError):
        v.check_all("http://example.com/")


def test_wildcard_domain():
    v = _validator(domains=["*.staging.example.com"])
    v.check_url("https://app.staging.example.com/")  # ok
    with pytest.raises(ScopeViolationError):
        v.check_url("https://staging.example.com/")  # wildcard does not cover apex
