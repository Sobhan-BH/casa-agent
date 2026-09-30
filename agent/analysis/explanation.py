"""Finding Explanation Enrichment — the "what/why/how" layer.

Every confirmed finding leaves the pipeline with a complete, self-contained
explanation stored in metadata:

- vulnerability:    what this weakness actually is (plain language)
- attack_scenario:  step-by-step how an attacker would abuse it
- business_impact:  what the organization risks (concrete outcomes)
- exploitability:   how easy to weaponize + required preconditions
- cvss_rationale:   why the CVSS vector has the values it has
- remediation_plan: ordered, concrete fix steps
- verification:     how to confirm the fix worked

Deterministic, local, LLM-free: the explanations are curated per finding
category/fingerprint key so reports can be handed directly to developers and
management without an analyst rewriting them.
"""
from __future__ import annotations

import re
from typing import Any

from agent.core.context import AssessmentContext
from agent.core.interfaces import AssessmentModule

# Each rule: (title regex, explanation dict). First match wins.
_EXPLANATIONS: list[tuple[re.Pattern[str], dict[str, Any]]] = [
    (
        re.compile(r"\.env", re.I),
        {
            "vulnerability": (
                "The application serves its environment-configuration file (.env) over "
                "HTTP. This file stores runtime configuration as KEY=VALUE pairs — "
                "typically database credentials, API keys, SMTP passwords, cloud "
                "provider tokens and application secrets. It should never be reachable "
                "from the network."
            ),
            "attack_scenario": [
                "Attacker requests https://target/.env directly in a browser or curl.",
                "The web server returns the file contents instead of a 403/404.",
                "Attacker extracts database credentials and connects to the DB (often "
                "reachable from the same network), or uses found API keys against "
                "third-party services (email, storage, payments).",
                "With app secrets (e.g. APP_KEY, JWT_SECRET) the attacker can forge "
                "sessions or decrypt stored data.",
            ],
            "business_impact": (
                "Full database compromise, account takeover via forged tokens, abuse of "
                "paid third-party services, and potential pivoting into internal "
                "infrastructure using leaked credentials. Often a full-breach scenario."
            ),
            "exploitability": (
                "Trivial — a single unauthenticated GET request. No special tooling or "
                "prerequisites beyond the file being served."
            ),
            "remediation_plan": [
                "Block all dotfiles at the web server (nginx: location ~ /\\.; deny all; "
                "Apache: .htaccess <FilesMatch '^\\.'> require all denied).</FilesMatch>",
                "Move .env out of the web root entirely; the app should load it via its "
                "own working directory, not a public folder.",
                "Rotate EVERY value that was exposed: database passwords, API keys, "
                "APP_KEY/JWT secrets — assume they are compromised.",
                "Audit access logs for historical requests to /.env and investigate "
                "any hits.",
            ],
            "verification": (
                "Request /.env from an external network: it must return 403 or 404, and "
                "the file must not exist under the web root at all."
            ),
        },
    ),
    (
        re.compile(r"\.git", re.I),
        {
            "vulnerability": (
                "The web server exposes the internal Git repository metadata (/.git/HEAD "
                "and related objects). Git exposes the complete revision history, source "
                "code, commit messages and often embedded credentials in config files "
                "or history."
            ),
            "attack_scenario": [
                "Attacker fetches /.git/HEAD to confirm the repository is exposed.",
                "Using tools like git-dumper, the attacker walks refs and fetches every "
                "object file under /.git/objects/.",
                "The attacker reconstructs the full repository locally with 'git checkout'.",
                "Source code, git config (sometimes with deploy tokens), historic "
                "credentials and internal logic are now in the attacker's hands.",
            ],
            "business_impact": (
                "Source-code disclosure accelerates every other attack: hardcoded "
                "secrets, internal endpoints and logic flaws become visible. Combined "
                "with leaked credentials this can escalate to full infrastructure "
                "compromise."
            ),
            "exploitability": (
                "Easy — automated tools (git-dumper, GitHack) do all the work in "
                "seconds; only network access is required."
            ),
            "remediation_plan": [
                "Deny serving of VCS directories at the web server level "
                "(nginx: location ~ /\\.git { deny all; }).",
                "Ensure deployment pipelines never copy the .git folder into the web "
                "root; use artifact builds instead of git archives.",
                "Rotate any secrets that ever existed in the repository history "
                "(use git-secrets/trufflehog to scan).",
            ],
            "verification": (
                "Request /.git/HEAD from outside: it must return 403/404. Also verify "
                "/.git/config and a known object path are blocked."
            ),
        },
    ),
    (
        re.compile(r"directory listing", re.I),
        {
            "vulnerability": (
                "The web server generates an automatic file index (autoindex) for this "
                "directory, listing all files and subdirectories to any visitor."
            ),
            "attack_scenario": [
                "Attacker opens the listed URL and reads the index of files.",
                "Backups, dumps, uncompressed archives, user uploads or administrative "
                "scripts that live in the folder become directly downloadable.",
                "File names also reveal technology stack and naming conventions useful "
                "for further attacks.",
            ],
            "business_impact": (
                "Any file in the listed directory is exposed — this frequently leaks "
                "database dumps, credentials in archived config files, or sensitive "
                "user data in upload folders."
            ),
            "exploitability": (
                "Trivial — just browsing. Impact depends entirely on what the listed "
                "directory contains."
            ),
            "remediation_plan": [
                "Disable autoindex (nginx: autoindex off; Apache: Options -Indexes).",
                "If a browsable archive is intentionally needed, gate it behind "
                "authentication and audit its contents.",
                "Review the directory contents for anything that should not be "
                "web-accessible (dumps, backups, .env copies).",
            ],
            "verification": (
                "Reload the directory URL: it must return a default page, 403, or the "
                "application route — no file index."
            ),
        },
    ),
    (
        re.compile(r"HSTS", re.I),
        {
            "vulnerability": (
                "The site is served over HTTPS but does not send the "
                "Strict-Transport-Security header (or sends a weak one). HSTS instructs "
                "browsers to refuse plain-HTTP connections to this host, preventing "
                "protocol-downgrade interception."
            ),
            "attack_scenario": [
                "Victim on hostile Wi-Fi (café, airport) types the domain or clicks an "
                "http:// link.",
                "The attacker's machine-in-the-middle intercepts the initial HTTP "
                "request and proxies/mutates content, or strips the secure connection.",
                "Cookies without Secure flag and user input flow through the attacker; "
                "session hijacking becomes possible.",
            ],
            "business_impact": (
                "Session hijacking of users on untrusted networks, credential capture "
                "and content injection — invisibly to the user."
            ),
            "exploitability": (
                "Requires a network position (rogue AP, ARP spoofing, DNS control) but "
                "is then reliable and undetectable to victims."
            ),
            "remediation_plan": [
                "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                "on every HTTPS response.",
                "Ensure every subdomain is HTTPS-capable before enabling includeSubDomains.",
                "Consider preloading via hstspreload.org after validating the rollout.",
            ],
            "verification": (
                "curl -sI https://target | grep -i strict-transport-security must show "
                "a long max-age; test with securityheaders.com for an A/A+ grade."
            ),
        },
    ),
    (
        re.compile(r"cookie", re.I),
        {
            "vulnerability": (
                "Session cookies are set without the protective attributes Secure, "
                "HttpOnly and/or SameSite. Missing Secure sends the cookie over plain "
                "HTTP; missing HttpOnly allows JavaScript theft (XSS escalation); "
                "missing SameSite enables cross-site request attachment (CSRF)."
            ),
            "attack_scenario": [
                "Without Secure: the cookie leaks when the victim hits any http:// URL "
                "to this host through an attacker's network tap.",
                "Without HttpOnly: a single stored/reflected XSS lets the attacker read "
                "document.cookie and exfiltrate the session.",
                "Without SameSite: a malicious page can make the victim's browser send "
                "authenticated cross-site requests (CSRF) with the session attached.",
            ],
            "business_impact": (
                "Account takeover through session theft or CSRF — customer accounts, "
                "admin panels and any authenticated area are in scope."
            ),
            "exploitability": (
                "Easy in combination: any XSS (or network tap for missing Secure) turns "
                "into immediate session compromise."
            ),
            "remediation_plan": [
                "Set every session cookie with: Secure; HttpOnly; SameSite=Lax (or "
                "Strict for sensitive apps); Path limited to the app scope.",
                "Regenerate session IDs on login and privilege change.",
                "Add a short session lifetime and re-authentication for critical actions.",
            ],
            "verification": (
                "Inspect Set-Cookie in the login response; all three attributes must be "
                "present on session cookies."
            ),
        },
    ),
    (
        re.compile(r"CORS", re.I),
        {
            "vulnerability": (
                "The server reflects arbitrary Origin headers with Access-Control-"
                "Allow-Origin, optionally with credentials enabled. This turns the "
                "same-origin policy off for attacker-controlled sites."
            ),
            "attack_scenario": [
                "Attacker hosts evil.example and makes a logged-in victim visit it.",
                "evil.example's JavaScript fetches https://target/api/user with "
                "credentials:'include' and Origin: https://evil.example.",
                "The target reflects the origin and returns the victim's data; the "
                "attacker's page reads it cross-origin.",
                "Personal data, tokens and CSRF protection bypass follow.",
            ],
            "business_impact": (
                "Silent data exfiltration of any authenticated user's data from a "
                "simple link-click; potential account takeover if tokens are readable."
            ),
            "exploitability": (
                "Easy — requires only luring a logged-in user to a malicious page."
            ),
            "remediation_plan": [
                "Never reflect the Origin header verbatim; maintain a strict allowlist "
                "of trusted origins.",
                "Set 'Vary: Origin' so caches don't poison cross-origin responses.",
                "Disallow credentials (Access-Control-Allow-Credentials) unless a flow "
                "absolutely requires it.",
            ],
            "verification": (
                "Send Origin: https://evil.example — the response must not echo it in "
                "Access-Control-Allow-Origin."
            ),
        },
    ),
    (
        re.compile(r"clickjacking|X-Frame", re.I),
        {
            "vulnerability": (
                "The page can be embedded in an attacker's site inside an iframe (no "
                "X-Frame-Options / frame-ancestors protection), enabling user-interface "
                "redressing."
            ),
            "attack_scenario": [
                "Attacker builds a page with the target site in a transparent iframe "
                "under a decoy button ('Win a prize').",
                "Victim clicks; the clicks actually land on the target's hidden UI "
                "(transfer confirmation, settings change, delete).",
                "The victim performs actions they never intended, authenticated by "
                "their own session.",
            ],
            "business_impact": (
                "Unauthorized state-changing actions attributed to real users: money "
                "transfers, permission grants, data deletion."
            ),
            "exploitability": (
                "Easy for state-changing pages; needs the target page to be frameable "
                "and actions to be single-click."
            ),
            "remediation_plan": [
                "Send 'Content-Security-Policy: frame-ancestors \"none\"' (or "
                "'self'/'allowlist') on all sensitive pages.",
                "Add 'X-Frame-Options: DENY' as a legacy fallback.",
            ],
            "verification": (
                "Attempt to iframe a sensitive page from another origin — it must not "
                "render; securityheaders.com grade check."
            ),
        },
    ),
    (
        re.compile(r"version discloses|server version|disclosed version", re.I),
        {
            "vulnerability": (
                "Response headers disclose exact software versions (e.g. Server, "
                "X-Powered-By). Version disclosure alone is not a vulnerability but "
                "materially accelerates attacks by enabling precise CVE lookup."
            ),
            "attack_scenario": [
                "Attacker fingerprints the stack from headers/banner pages.",
                "They query CVE databases for that exact version and run known "
                "exploits without trial-and-error.",
                "Patching state is also mapped: unpatched components are prioritized.",
            ],
            "business_impact": (
                "Shortens attack time dramatically; serves as a force multiplier for "
                "every other weakness."
            ),
            "exploitability": (
                "Trivial (one request); severity derives from what known CVEs match."
            ),
            "remediation_plan": [
                "Suppress version tokens: nginx 'server_tokens off;', Apache "
                "'ServerTokens Prod', remove X-Powered-By (PHP: expose_php=Off; "
                "Express: app.disable('x-powered-by')).",
            ],
            "verification": (
                "curl -sI target no longer reveals version numbers."
            ),
        },
    ),
    (
        re.compile(r"SQL|database error", re.I),
        {
            "vulnerability": (
                "Detailed database error output is returned to users (stack traces or "
                "SQL fragments), indicating unsanitized input reaching the database "
                "and verbose error handling."
            ),
            "attack_scenario": [
                "Attacker sends malformed input (quote, UNION, sleep payloads) to "
                "parameters suspected of reaching SQL.",
                "Verbose errors confirm injectable context and reveal schema/table "
                "names from the error text.",
                "Armed with schema knowledge the attacker escalates to data extraction.",
            ],
            "business_impact": (
                "Database takeover potential: full read (and often write) access to "
                "all stored data."
            ),
            "exploitability": (
                "Easy with automation (sqlmap) once an injectable parameter is found."
            ),
            "remediation_plan": [
                "Use parameterized queries/prepared statements everywhere — never "
                "string-concatenate SQL.",
                "Return generic error pages; log full details server-side only.",
                "Deploy WAF rules as defense-in-depth while fixing root causes.",
            ],
            "verification": (
                "Trigger an error with malformed input: response must be generic, no "
                "SQL or stack details."
            ),
        },
    ),
    (
        re.compile(r"backup|dump|\.sql", re.I),
        {
            "vulnerability": (
                "A backup or database dump file is web-accessible. Backup archives "
                "typically contain full source, configuration with credentials, and "
                "sometimes data exports."
            ),
            "attack_scenario": [
                "Attacker probes common backup names (/backup.zip, /db.sql, "
                "/database.sql, /site.bak).",
                "The file downloads; archives are unpacked offline.",
                "Credentials inside configs are harvested and used against live systems.",
            ],
            "business_impact": (
                "Equivalent to source + configuration + data disclosure at once — "
                "routinely a full compromise."
            ),
            "exploitability": (
                "Trivial — one unauthenticated download."
            ),
            "remediation_plan": [
                "Remove the backup from the web root immediately.",
                "Rotate every credential contained in it.",
                "Store future backups off-web-root with strict access control; block "
                "archive extensions at the server.",
            ],
            "verification": (
                "All probed backup paths return 403/404 from outside."
            ),
        },
    ),
    (
        re.compile(r"debug|traceback|stack", re.I),
        {
            "vulnerability": (
                "A debug endpoint or verbose error page exposes stack traces and "
                "internal state (framework debug mode, /debug/vars, actuator, "
                "tracebacks). This reveals source paths, dependency versions, "
                "environment variables and sometimes live data."
            ),
            "attack_scenario": [
                "Attacker opens the debug endpoint from a normal browser.",
                "The returned traceback/configuration leaks module paths, library "
                "versions and internal hostnames.",
                "Some endpoints (heapdump, /debug/vars) directly hand over secrets in "
                "memory.",
            ],
            "business_impact": (
                "Blueprint of the internal application; often direct credential leak "
                "via memory dumps or env access."
            ),
            "exploitability": (
                "Trivial — direct URL access, no exploitation skill needed."
            ),
            "remediation_plan": [
                "Disable debug mode in production (DEBUG=False, prod WSGI config).",
                "Restrict debug/actuator endpoints to localhost or VPN with auth.",
                "Replace framework default error pages with generic ones.",
            ],
            "verification": (
                "Debug URLs return 403/404 externally; error pages are generic."
            ),
        },
    ),
    (
        re.compile(r"CSP|content-security", re.I),
        {
            "vulnerability": (
                "No (or weak) Content-Security-Policy: the browser has no whitelist of "
                "where scripts may load from, so injected inline/remote scripts "
                "execute freely if any HTML-injection bug exists."
            ),
            "attack_scenario": [
                "Attacker finds any HTML injection point (comment field, URL fragment "
                "reflected, stored value).",
                "Injected <script src=//evil/x.js> runs because CSP doesn't block it.",
                "Full session/keystroke theft follows from the injected script.",
            ],
            "business_impact": (
                "XSS consequences without mitigation: account takeover, data theft, "
                "malware distribution to users."
            ),
            "exploitability": (
                "Depends on an injection flaw existing; CSP is the last line of "
                "defense — its absence removes that layer."
            ),
            "remediation_plan": [
                "Deploy a nonce-based CSP: default-src 'self'; script-src 'self' "
                "'nonce-...'; object-src 'none'; frame-ancestors 'none'.",
                "Start in report-only mode (Content-Security-Policy-Report-Only), "
                "tune, then enforce.",
            ],
            "verification": (
                "securityheaders.com or curl -sI shows a strict CSP; inline scripts "
                "without nonce are blocked in browser console."
            ),
        },
    ),
]


def _cvss_rationale(cvss: dict[str, Any] | None) -> str:
    """Human rationale for the chosen vector (or the synthetic default)."""
    if not cvss:
        return ""
    vector = cvss.get("vector", "")
    score = cvss.get("score")
    parts = []
    if "AV:N" in vector:
        parts.append("remotely exploitable over the network (AV:N)")
    if "PR:N" in vector:
        parts.append("no privileges required (PR:N)")
    if "UI:N" in vector:
        parts.append("no user interaction needed (UI:N)")
    if "S:C" in vector:
        parts.append("impact crosses security boundaries (S:C)")
    if "C:H" in vector:
        parts.append("high confidentiality impact (C:H)")
    if "I:H" in vector:
        parts.append("high integrity impact (I:H)")
    if "A:H" in vector:
        parts.append("high availability impact (A:H)")
    rationale = "CVSS " + str(score) if score is not None else "CVSS"
    if parts:
        rationale += ": " + ", ".join(parts) + "."
    return rationale


class ExplanationModule(AssessmentModule):
    """Runs after normalization; never adds findings, only enriches them."""

    name = "explanation"
    phase = "EXPLANATION"
    critical = False

    def __init__(self, validator) -> None:
        self._validator = validator

    async def run(self, ctx: AssessmentContext) -> None:
        enriched = 0
        for f in ctx.findings:
            title = f.get("title", "")
            meta = f.setdefault("metadata", {})
            explanation: dict[str, Any] | None = None
            for rx, exp in _EXPLANATIONS:
                if rx.search(title):
                    explanation = dict(exp)
                    break

            if explanation is None:
                # Fallback: a complete generic scaffold from existing fields so
                # every finding is still self-contained.
                explanation = {
                    "vulnerability": (
                        f.get("description")
                        or "A security-relevant condition was observed on this target."
                    ),
                    "attack_scenario": [
                        "An attacker reconnoiters the target using public information "
                        "and this condition.",
                        "The observed weakness is combined with other findings "
                        "(version disclosure, exposed paths) to plan exploitation.",
                    ],
                    "business_impact": f.get("impact") or "Increases exposure of the system.",
                    "exploitability": "Manual analysis required; see description and evidence.",
                    "remediation_plan": [f.get("remediation") or "Review and harden the affected component."],
                    "verification": "Re-run the assessment after remediation; the finding should report FIXED.",
                }
            rationale = _cvss_rationale(f.get("cvss"))
            if rationale:
                explanation["cvss_rationale"] = rationale
            meta["explanation"] = explanation
            enriched += 1

        ctx.raw_results["explanations"] = {"enriched": enriched, "curated_rules": len(_EXPLANATIONS)}
