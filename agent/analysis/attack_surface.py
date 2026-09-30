"""Attack Surface Map — structured JSON representation of the assessed target.

Built deterministically from pipeline raw_results + findings so the future UI
can visualize domains, endpoints, technologies, exposed services/APIs,
security controls and findings without recomputing anything.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def build_attack_surface(ctx) -> dict[str, Any]:
    """Build the attack-surface snapshot from an AssessmentContext."""
    parsed = urlparse(ctx.target_url)
    discovery = ctx.raw_results.get("discovery", {}) or {}
    cookies = ctx.raw_results.get("cookies", []) or []
    techs = ctx.raw_results.get("technologies", []) or []
    methods = ctx.raw_results.get("http_methods", {}) or {}
    docs_exposed = discovery.get("docs_exposed", []) or []
    endpoints = discovery.get("endpoints", {}) or {}

    # --- domains & in-scope subdomains -------------------------------------
    domains = {
        "primary": parsed.hostname or "",
        "in_scope_subdomains": sorted(
            {urlparse(u).hostname or "" for u in endpoints.get("urls", [])
             if (urlparse(u).hostname or "").endswith(parsed.hostname or "")
             and urlparse(u).hostname != parsed.hostname}
        ),
    }

    # --- external tool results (Tool Integration layer) ---------------------
    tool_results = ctx.raw_results.get("tools", {}).get("run", {}) or {}
    tool_health = ctx.raw_results.get("tool_health", {}) or {}
    tools_used = sorted(
        name for name, entry in tool_results.items()
        if entry.get("status") in ("OK", "FAILED")
    )
    tools_not_installed = sorted(
        name for name, entry in tool_health.items()
        if entry.get("status") == "NOT_INSTALLED"
    )

    # --- endpoints ----------------------------------------------------------
    endpoint_list = [
        {"url": u, "source": "discovery"} for u in endpoints.get("urls", [])[:100]
    ]
    # Content-discovery endpoints (gobuster/ffuf) merge into the surface map.
    seen_urls = {e["url"] for e in endpoint_list}
    for tool_name in ("gobuster", "ffuf"):
        for hit in (tool_results.get(tool_name, {}) or {}).get("endpoints") or []:
            url = hit.get("url") or ""
            if url and url not in seen_urls:
                seen_urls.add(url)
                endpoint_list.append(
                    {"url": url, "source": tool_name, "status": hit.get("status")}
                )

    # --- exposed services / APIs --------------------------------------------
    apis = [
        {"path": d.get("path"), "kind": d.get("kind")} for d in docs_exposed
    ]
    services = []
    tls = ctx.raw_results.get("tls", {}) or {}
    if tls:
        services.append({
            "service": "https",
            "port": parsed.port or 443,
            "tls_version": tls.get("tls_version"),
        })
    # Nmap open services enrich the surface (source: nmap).
    for svc in (tool_results.get("nmap", {}) or {}).get("services") or []:
        if svc.get("state") == "open":
            services.append(
                {
                    "service": svc.get("service") or "unknown",
                    "port": svc.get("port"),
                    "product": svc.get("product") or "",
                    "version": svc.get("version") or "",
                    "source": "nmap",
                }
            )

    # --- security controls observed ------------------------------------------
    root_headers = (ctx.raw_results.get("http_root", {}) or {}).get("headers", {}) or {}
    controls = [
        {"control": h, "observed": True}
        for h in (
            "strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options", "referrer-policy",
            "permissions-policy", "cross-origin-opener-policy",
            "cross-origin-resource-policy", "cross-origin-embedder-policy",
        )
        if root_headers.get(h)
    ]
    spf = (ctx.raw_results.get("dns_security", {}) or {}).get("spf", {}) or {}
    dmarc = (ctx.raw_results.get("dns_security", {}) or {}).get("dmarc", {}) or {}
    if spf.get("present"):
        controls.append({"control": "spf", "observed": True})
    if dmarc.get("present"):
        controls.append({"control": "dmarc", "observed": True})

    # --- findings summary ------------------------------------------------------
    findings_summary = [
        {
            "id": f.get("id"),
            "fingerprint": f.get("fingerprint"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "confidence": f.get("confidence"),
            "category": f.get("category"),
            "risk_score": f.get("risk_score"),
            "root_cause_group": (f.get("metadata", {}) or {}).get("root_cause_group"),
        }
        for f in ctx.findings
    ]

    return {
        "target": ctx.target_url,
        "mode": ctx.mode,
        "domains": domains,
        "endpoints": endpoint_list,
        "technologies": [
            {"name": t.get("name"), "category": t.get("category"),
             "version": t.get("version"), "source": t.get("source")}
            for t in techs
        ] + [
            # WhatWeb inventory merged in (Tool Integration layer)
            {"name": t.get("technology"), "category": "fingerprint",
             "version": t.get("version"), "source": t.get("source", "whatweb"),
             "confidence": t.get("confidence")}
            for t in tool_results.get("whatweb", {}).get("technologies") or []
        ],
        "tools_used": tools_used,
        "tools_not_installed": tools_not_installed,
        "tool_provenance": {
            name: {
                "status": entry.get("status"),
                "tool_version": entry.get("tool_version"),
                "duration_ms": entry.get("duration_ms"),
                "findings": len(entry.get("findings") or []),
            }
            for name, entry in tool_results.items()
        },
        "exposed_services": services,
        "apis": apis,
        "cookies": [
            {"name": c.get("name"), "attributes": {
                k: v for k, v in c.items() if k not in ("name", "value_length")
            }}
            for c in cookies
        ],
        "advertised_methods": methods,
        "security_controls": controls,
        "findings": findings_summary,
        "root_cause_groups": ctx.raw_results.get("root_cause_groups", []),
        "forms": endpoints.get("forms", []),
        "notes": (
            "Structure-only snapshot; contains no secret values. Cookie and "
            "evidence entries are redacted by their producing modules."
        ),
    }
