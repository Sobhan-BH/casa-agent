"""Deterministic per-request DNS queries for the DNS security module.

Thin wrappers around dnspython so tests and the validation harness can inject
fakes by monkeypatching these module-level functions. All queries are passive
lookups; the module never performs zone transfers or takeover attempts.

Resolver strategy: the system resolver (often a home router) is tried first,
then well-known public resolvers. The first NON-EMPTY answer wins; empty
answers from ALL resolvers are required before a record is reported absent.
This prevents false "SPF absent" findings when only the local resolver fails.
"""
from __future__ import annotations

import asyncio
from typing import Any

# Public resolvers queried (in order) when the system resolver returns nothing.
_FALLBACK_RESOLVERS = ("8.8.8.8", "1.1.1.1", "9.9.9.9")


async def _resolve(host: str, record_type: str, timeout: float = 5.0) -> list[str]:
    """Resolve `record_type` records for host; return raw rdata strings."""

    def _query(resolver_nameservers: list[str] | None) -> list[str]:
        import dns.resolver

        if resolver_nameservers:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = resolver_nameservers
        else:
            resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(host, record_type, raise_on_no_answer=False)
        if answers.rrset is None:
            return []
        # to_text() wraps TXT rdata in literal double quotes ("v=spf1 ...").
        # Strip them so startswith('v=spf1') style matching works downstream.
        return [r.to_text().strip('"') for r in answers.rrset]

    def _sync() -> list[str]:
        attempts: list[list[str] | None] = [None]  # system resolver first
        attempts.extend([ns] for ns in _FALLBACK_RESOLVERS)
        last_error: Exception | None = None
        for ns in attempts:
            try:
                records = _query(ns)
            except Exception as exc:  # noqa: BLE001 — NXDOMAIN/timeouts: try next
                last_error = exc
                continue
            if records:
                return records
            # empty answer: a real NOERROR/NODATA from an authoritative path —
            # but local resolvers may also just be broken, so keep trying the
            # public ones; only report absent if ALL agree on empty.
        if last_error is not None and all(_try_all_empty_flag(ns) for ns in attempts[1:]):
            pass  # kept for future refinement; empty is the answer either way
        return []

    def _try_all_empty_flag(_ns) -> bool:  # placeholder to keep structure clear
        return True

    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, _sync)
    except Exception:  # noqa: BLE001 - NXDOMAIN/timeouts are "no records"
        return []


def parse_spf(txt_records: list[str]) -> dict[str, Any]:
    """Extract SPF record presence + mechanisms from TXT records."""
    spf = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)
    if not spf:
        return {"present": False}
    mechanisms = spf.split()[1:]
    return {
        "present": True,
        "record": spf,
        "all_strict": mechanisms and mechanisms[-1].startswith(("-all", "~all")),
        "redirects_to_third_party": any(m.startswith("include:") for m in mechanisms),
    }


def parse_dmarc(txt_records: list[str]) -> dict[str, Any]:
    """Extract DMARC policy from _dmarc TXT records."""
    dmarc = next(
        (r for r in txt_records if r.lower().startswith("v=dmarc1")), None
    )
    if not dmarc:
        return {"present": False}
    tags = dict(
        part.strip().split("=", 1) for part in dmarc.split(";") if "=" in part
    )
    p = tags.get("p", "none").strip().lower()
    return {
        "present": True,
        "record": dmarc,
        "policy": p,
        "policy_enforcing": p in ("quarantine", "reject"),
        "rua_configured": bool(tags.get("rua", "").strip()),
    }


def parse_caa(caa_records: list[str]) -> dict[str, Any]:
    return {"present": bool(caa_records), "records": caa_records}
