"""Deterministic per-request DNS queries for the DNS security module.

Thin wrappers around dnspython so tests and the validation harness can inject
fakes by monkeypatching these module-level functions. All queries are passive
lookups; the module never performs zone transfers or takeover attempts.
"""
from __future__ import annotations

import asyncio
from typing import Any


async def _resolve(host: str, record_type: str, timeout: float = 5.0) -> list[str]:
    """Resolve `record_type` records for host; return raw rdata strings."""

    def _sync() -> list[str]:
        import dns.exception
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(host, record_type, raise_on_no_answer=False)
        if answers.rrset is None:
            return []
        return [r.to_text() for r in answers.rrset]

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
