# CASA — Core Agentic Security Assessment

An **authorized-scope-only** AI cybersecurity assessment agent.

CASA performs low-impact web security assessments against targets **only** when a
registered authorization covers them, produces evidence-backed findings, a
deterministic security score **plus industry-standard CVSS v3.1 scores**, an
AI-generated analysis (via a swappable LLM provider), and client-ready
JSON + HTML + **SARIF 2.1.0** reports. A local, deliberately vulnerable lab app
is included so the entire flow runs with **no internet access and no third-party
targets**.

## What's new in v0.5.0

| Feature | Description |
|---|---|
| **Full ExploitDB index + version-matching engine** | One-command fetcher (`python scripts/fetch_exploitdb.py`) downloads the complete ~47,000-entry ExploitDB index with a mirror fallback chain; rewritten matching engine (subject-adjacency, version bands `1.3.9 < 1.4.0`, operator bounds `<= 2.4.49`, ranges `3.0 - 4.1.1`, dotted-prefix, official `codes` CVE extraction) so an Apache 2.4.50 detection maps to EDB-50406/CVE-2021-42013 — not to unrelated plugin rows sharing the platform name |
| **Brain exploit-first priority** | When versioned technologies are detected and no exploit correlation exists yet, the Brain suppresses diminishing-returns STOPs and proposes the offline ExploitDB enrichment first (highest information gain); OSV is only proposed afterwards if still useful — the deterministic strategy now knows "what to do now" |
| **Brain decisions in the console** | The Brain pass report is persisted into the assessment `risk_summary` and rendered as a 🧠 decisions card in the web console (per-decision action, gain, policy verdict; approved/denied/executed counters) |
| **HTTP-only targets** | The console auto-detects the scheme: bare hosts are probed over https first and transparently fall back to http before registering the authorization, so http-only sites assess end-to-end (the whole pipeline already branches on the target scheme) |
| **Level-2 dataset pipeline** | `python scripts/build_brain_dataset.py` curates recorded Brain trajectories (policy-approved AND executed-OK only, duplicates and execution-link records dropped/joined) into a chat-format fine-tuning JSONL (`data/brain-dataset-level2.jsonl`) |

## What's new in v0.4.0

| Feature | Description |
|---|---|
| **CASA-Brain** | Native, local-first decision engine (no external LLM required): explicit assessment state, structured action space, deterministic strategy with information-gain-oriented next-action selection, and STOP decisions when further steps add no value |
| **Policy/Safety Gate for Brain** | The Brain only *proposes* actions; a deterministic gate (rules R0–R7: shape, scope, authorization, repetition, step limits) independently validates every proposal — Brain cannot expand scope, bypass policy, or execute anything arbitrary |
| **Trajectory recording** | Every Brain pass records state → selected action → policy result → execution result → outcome as JSONL (`data/brain-trajectories.jsonl`) — the future training corpus for a CASA-specific model, with curation hooks (`load_curated`) |
| **Optional local-model interface** | `CASA_BRAIN_MODEL` selects a strategy: `deterministic` (default, fully offline) or a local model strategy that re-ranks candidates but can never invent actions outside CASA's controlled action space |
| **ExploitDB correlation** | Version→exploit *correlation/annotation only* (no active exploitation): when a versioned technology is detected, CASA queries a local ExploitDB CSV index (`CASA_EXPLOITDB_CSV_PATH`, or auto-detected at `/usr/share/exploitdb`, `/opt/exploitdb`, `data/files_exploits.csv`) and attaches EDB references to findings |
| **Brain orchestration** | Enabled with `CASA_BRAIN_ENABLED=1`; after the standard pipeline, the Brain pass proposes up to a bounded number of follow-up actions (evidence requests, verification, correlation, enrichment) — all executed through the same module registry, timeout and audit paths |
| **Accuracy fixes** (v0.3.x, verified on a live authorized target) | TXT-record quote stripping (SPF false-negative fixed), DNS resolver fallbacks, soft-404 baseline (kills bogus ".env open" style claims), finding merge/escalation in the normalizer, redirect-aware HTTP probe |

### Brain at a glance

```
Authorization → Scope → Assessment State → CASA-Brain (strategy) → Proposed Action
     → Deterministic Policy/Safety Gate → Approved Module → Evidence
     → Updated Assessment State → CASA-Brain → … → STOP_ASSESSMENT
```

Explainability: every decision carries reason codes, expected evidence, expected
information gain and confidence — generated from structured state, not free-form text.

> ⚠️ **This is a defensive assessment tool.** It only issues GET/HEAD requests,
> refuses targets without authorization, and contains no exploit, auth-bypass,
> credential, persistence, or malware functionality. Assess only systems you own
> or are contractually authorized to test.

---

## What's new in v0.2.0

| Feature | Description |
|---|---|
| **CVSS v3.1 engine** | Full FIRST.org spec implementation — every finding carries an industry-standard base score (vendor vector respected when present) |
| **WAF/CDN detection** | wafw00f-inspired passive fingerprinting of edge protection from headers/cookies/block pages |
| **CVE enrichment (OSV.dev)** | Known advisories matched against detected technologies via the free OSV.dev API (osv-scanner-inspired; degrades gracefully offline) |
| **MITRE ATT&CK mapping** | Every finding annotated with relevant Enterprise techniques + tactics |
| **SARIF 2.1.0 export** | GitHub Code Scanning-compatible output: `GET /api/v1/assessments/{id}/sarif` |
| **API-key auth + rate limiting** | Optional hardening: `CASA_API_KEY`, `CASA_RATE_LIMIT_RPM` (constant-time key check, 429 + Retry-After) |
| **Web dashboard** | Read-only operational view at `/dashboard` (no JS frameworks, no CDN) |
| **Webhook notifications** | Slack/Discord/generic payloads on completion: `CASA_WEBHOOK_URL` |
| **Continuous monitoring** | Built-in scheduler re-assesses stale targets: `CASA_REASSESS_INTERVAL_HOURS` |

## 1. Architecture

```
                         ┌──────────────────────────────────────────┐
                         │                FastAPI API                │
                         │  authorizations · jobs · assessments ·    │
                         │  findings · evidence · reports · audit    │
                         └───────────────┬──────────────────────────┘
                                         │ enqueue
                                         ▼
┌────────────────────────┐   ┌───────────────────────────┐
│ JobQueue (inline worker│──▶│       Orchestrator        │
│ Redis/Celery = ext. pt)│   │  auth gate → pipeline →   │
└────────────────────────┘   │  risk → AI → verify →     │
                             │  reports                  │
                             └───────┬───────────────────┘
                                     │ AssessmentContext
     ┌───────────────────────────────┼────────────────────────────────┐
     ▼            ▼            ▼           ▼            ▼            ▼
  Recon      Tech detect   Config/    TLS analysis  Web checks   Vuln corr.
  (module)   (module)      headers    (module)      (module)     (module + KB)
                             (module)
     └───────────────┬───────────┴────────────┬───────────────┘
                     ▼                        ▼
            Evidence Collector          Finding Normalizer
                     └───────────┬───────────┘
                                 ▼
                     Risk Engine (deterministic, LLM-free)
                                 ▼
                     AI Analysis Layer (LLMProvider interface)
                                 ▼
                     Verification Engine ← baseline findings
                                 ▼
                     Report Generator (JSON + HTML)
                                 ▼
                     Storage (SQLAlchemy: SQLite | PostgreSQL) + Audit Log
```

### Modules (all behind `AssessmentModule` interface)

| # | Module | Role |
|---|--------|------|
| 1 | Target Manager | target registry (via authorizations router) |
| 2 | Authorization Manager | the Authorization Gate |
| 3 | Recon | root probe, robots.txt, sitemap, DNS (passive) |
| 4 | Tech Detection | passive fingerprinting (headers + body) |
| 5 | Config Analysis | security headers, cookies, CORS |
| 6 | TLS Analysis | cert expiry, weak protocols/ciphers, mismatch |
| 7 | Web Checks | fixed single-GET exposure checks (.git, .env, listing) |
| 8 | Vuln Correlation | local KB correlation (CVE feed = extension point) |
| 9 | Evidence Collector | raw results → sha256-stamped evidence |
| 10 | Finding Normalizer | schema validation, dedupe, FP flagging |
| 11 | Risk Engine | explainable deterministic score (0–100) |
| 12 | AI Analysis | reasoning layer over findings (provider-agnostic) |
| 13 | Verification Engine | OPEN/FIXED/STILL_PRESENT/CHANGED/UNVERIFIED |
| 14 | Report Generator | JSON + HTML |
| 15 | Job/Task Manager | QUEUED→RUNNING→ANALYZING→VERIFYING→COMPLETED/FAILED/BLOCKED |
| 16 | Audit | append-only JSONL + DB audit events |
| 17 | **Discovery** | robots/sitemap/security.txt/well-known/docs + passive endpoint extraction (links, forms, JS refs) |
| 18 | **Headers (deep)** | CSP/HSTS/XCTO/frame/Referrer/Permissions/COOP/CORP/COEP quality analysis (weak, conflicting, unsafe variants) |
| 19 | **Cookie Security** | Secure/HttpOnly/SameSite, scope, expiry, session-cookie weakness (values redacted) |
| 20 | **HTTP Config** | plain-HTTP exposure, redirect behavior, method advertisement, server/version disclosure |
| 21 | **Info Disclosure** | safe existence probes: env/config/backup/sourcemaps/debug endpoints, soft-404 resistant |
| 22 | **CORS Analyzer** | wildcard/credential combos + harmless origin-reflection probes |
| 23 | **API Security** | OpenAPI analysis: missing securitySchemes, non-prod server URLs, verbose errors |
| 24 | **Active Safe Tests** | DEEP-only: OPTIONS/HEAD/GET comparisons, harmless reflection markers, error-shape analysis |
| 25 | **DNS Security** | SPF/DMARC/CAA/DNSSEC/DKIM indicators (passive lookups only, IP targets skipped) |
| 26 | Attack Surface Map | structured JSON surface: domains, endpoints, techs, APIs, controls, findings |
| 27 | **WAF Detect** | passive WAF/CDN/proxy fingerprinting (headers, cookies, block-page markers) |
| 28 | **OSV Enrichment** | CVE advisory matching against detected techs via OSV.dev (UNVERIFIED by design) |
| 29 | **ATT&CK Mapping** | MITRE ATT&CK technique/tactic annotations on every mappable finding |

### Assessment profiles (Phase 14)

| Profile | Modules executed | Use case |
|---|---|---|
| `QUICK` | recon, tech_detection, headers, tls_analysis | fast passivity-first snapshot |
| `STANDARD` | + discovery, config_analysis, cookies, http_config, cors_analyzer, info_disclosure, web_checks, dns_security, vuln_correlation | full web security assessment |
| `DEEP` | + api_security, active_safe | expanded authorized assessment with safe-active checks |

Set via `POST /api/v1/jobs {"profile": "QUICK\|STANDARD\|DEEP"}` (default `STANDARD`).

### Directory layout

```
agent/
    core/         config, enums, exceptions, interfaces, finding schema,
                  target/scope, safe_http, audit, context
    connectors/   authorization_manager, tool adapters (http/dns/tls)
    modules/      recon, tech_detection, config_analysis, tls_analysis,
                  web_checks, vuln_correlation, discovery, headers, cookies,
                  http_config, info_disclosure, cors_analyzer, api_security,
                  active_safe, dns_security, dns_queries
    knowledge/    kb.json (local vulnerability KB)
    analysis/     evidence_collector, normalizer, ai_agent, llm_providers
    risk/         engine.py
    verification/ engine.py
    reports/      generator.py (JSON + HTML)
    storage/      database, models, repositories
    api/          main, routers/, schemas, state
    workers/      orchestrator, queue
lab/              deliberately vulnerable local target (+ Dockerfile)
tests/            unit + integration tests
```

---

## 2. Safety model (Authorization Gate)

1. A target is registered **together with** an authorization:
   `authorized_by`, `authorization_reference`, `allowed_domains`,
   `allowed_paths`, `excluded_targets`, `window_start/window_end`.
2. Creating a job resolves the active authorization; **no authorization →
   HTTP 403 and no job is created**.
3. When the worker runs the job, the gate runs **again**; failures set the job
   to `BLOCKED` (audited).
4. During the assessment, **every single HTTP request** (including redirect
   hops) is re-validated against the scope by `SafeHttpClient`; any escape
   raises `ScopeViolationError`, aborting the assessment. Redirect chains are
   bounded and must stay in scope.
5. Only `GET`/`HEAD` are permitted — enforced in code, not by convention.
6. Resource guards: per-step timeout, retry limit, max pipeline steps, response
   size cap, max connections.
7. Every gate decision and lifecycle change is written to the audit log (JSONL
   file + `audit_events` table, exposed via `GET /api/v1/audit`).

### Explicitly out of scope (by design)

Auth bypass, credential theft, persistence, malware, destructive actions,
exploitation. Findings are declarative: what was observed, with evidence, and
how to fix it.

---

## 3. Quickstart (local, no Docker)

### One command (recommended)

```bash
python run.py            # interactive launcher — starts lab + API + menu
```

The launcher handles everything: checks Python + dependencies (offers to
install them), starts the vulnerable lab and the CASA API as managed
subprocesses (logs in `data/launcher-*.log`), reuses services that are already
running, and on exit shuts down what it started. Menu options: demo assessment,
custom authorized target (requires typing the hostname to confirm you are
authorized), Swagger UI, latest HTML report, pytest, validation harness.

Non-interactive:

```bash
python run.py --demo                          # full demo assessment, then exit
python run.py --demo --profile DEEP           # with external tools + safe-active tests
python run.py --target https://example.com    # assess an authorized target
python run.py --target https://example.com --profile DEEP
python run.py --tools                         # Security Tools status table
python run.py --check                         # preflight checks only
```

### Manual (two terminals)

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 1) start the vulnerable lab (terminal 1)
python -m lab.vulnerable_app         # http://127.0.0.1:8001

# 2) start the CASA API + inline worker (terminal 2)
uvicorn agent.api.main:app --reload --port 8000
```

### Run a full assessment

```bash
# 2a. register target + authorization
curl -s -X POST http://127.0.0.1:8000/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://127.0.0.1:8001",
    "authorized_by": "Security Team",
    "authorization_reference": "TICKET-1234",
    "allowed_domains": ["127.0.0.1"],
    "allowed_paths": ["/"]
  }'

# → {"target_id": "...", "authorization": {...}}
TARGET_ID="<paste target_id>"

# 2b. create the job (authorization gate runs here)
curl -s -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d "{\"target_id\": \"$TARGET_ID\", \"trigger\": \"INITIAL\"}"
JOB_ID="<paste job id>"

# 2c. poll status: QUEUED → RUNNING → ANALYZING → VERIFYING → COMPLETED
curl -s http://127.0.0.1:8000/api/v1/jobs/$JOB_ID

# 2d. results
curl -s "http://127.0.0.1:8000/api/v1/assessments?target_id=$TARGET_ID"
curl -s "http://127.0.0.1:8000/api/v1/assessments/<assessment_id>/findings"
curl -s "http://127.0.0.1:8000/api/v1/assessments/<assessment_id>/reports"
# open the HTML report artifact in a browser
```

Swagger UI: `http://127.0.0.1:8000/docs`

---

## 4. Docker Compose (Postgres + API + lab)

```bash
docker compose up --build
# API:      http://localhost:8000  (docs at /docs)
# Lab:      http://localhost:8001  (target to authorize)
```

Register the lab target exactly as above but with target
`http://lab:8001` **from inside the api container**, or authorize the
host-mapped `http://127.0.0.1:8001` if testing from the host.

```bash
docker compose exec api curl -s -X POST http://localhost:8000/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{"target":"http://lab:8001","authorized_by":"Security Team",
       "authorization_reference":"COMPOSE-1","allowed_domains":["lab"]}'
```

---

## 5. Re-assessment & verification

After remediating (or changing the lab), run a verification assessment:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d "{
    \"target_id\": \"$TARGET_ID\",
    \"trigger\": \"VERIFICATION\",
    \"previous_assessment_id\": \"<first assessment id>\"
  }"
```

The new report's **Verification Status** section compares every baseline
finding: `FIXED`, `STILL_PRESENT`, `CHANGED`, `OPEN` (new), `UNVERIFIED`.

---

## 5b. External security tools (Tool Integration layer)

CASA can orchestrate external tools through a uniform adapter seam
(`agent/tools/`). Every adapter re-validates the target against the same
Authorization Gate + Scope Manager before building its command; commands are
argv lists executed **without a shell** (no `shell=True` anywhere), with
per-tool timeout, output caps and secret redaction.

| Tool | Purpose | Profile |
|---|---|---|
| Nmap | safe service/port discovery (`-Pn -sT -sV --top-ports 100`, no `-A`/scripts) | STANDARD* / DEEP |
| WhatWeb | technology fingerprinting -> inventory | QUICK+ |
| Nikto | safe web-server checks -> findings (advisory severity) | STANDARD+ |
| Nuclei | template scan with tag/severity policy, rate-limited | STANDARD+ |
| Gobuster | directory discovery (bounded wordlist, piped stdin) | DEEP |
| ffuf | content discovery with soft-404 size filtering | DEEP |
| Metasploit | **LAB-ONLY validation adapter** — hard-refuses any non-lab host | never auto-selected |

\* Nmap is skipped for web-only targets in STANDARD (runs in DEEP).

**Availability:** missing tools never fail an assessment — they are recorded
as `NOT_INSTALLED` and skipped. Check what is usable right now:

```bash
curl -s http://127.0.0.1:8000/api/v1/tools
# { "tools": { "nmap": {"available": true, "status": "READY", "version": "7.94"},
#              "nikto": {"available": false, "status": "NOT_INSTALLED"}, ... },
#   "profile_map": { "QUICK": ["whatweb"], ... } }
```

The HTML report shows **Security Tools** (tools used, versions, durations,
finding counts) and the Attack Surface Map is enriched with Nmap services,
WhatWeb inventory and gobuster/ffuf endpoints. Every tool finding carries full
provenance (`source_tool`, `tool_version`, `command_profile`, `timestamp`,
`parser_version`) and flows through the standard normalizer/dedupe/risk
stages — a scanner's verdict never sets final CASA severity.

Tool configuration (env, `CASA_` prefix): `TOOL_TIMEOUT_SECONDS`,
`TOOL_MAX_CONCURRENCY`, `TOOL_RATE_LIMIT`, `TOOL_MAX_REQUESTS`,
`TOOL_MAX_RUNTIME_SECONDS`, `TOOLS_ENABLED`, `TOOLS_ALLOWED`,
`NUCLEI_ALLOWED_TAGS`, `NUCLEI_EXCLUDED_TAGS`, `NUCLEI_SEVERITY_FILTER`,
`NUCLEI_RATE_LIMIT`, `NUCLEI_MAX_CONCURRENCY`.

---

## 6. AI layer (provider-agnostic)

Default is the offline **heuristic provider** (zero cost, deterministic):
dedupe stats, correlations, suspicious-finding flags, prioritization,
executive + manager summaries, confidence suggestions.

To use any OpenAI-compatible endpoint (OpenAI, Azure, vLLM, Ollama…):

```env
CASA_LLM_PROVIDER=openai
CASA_LLM_API_KEY=sk-...
CASA_LLM_MODEL=gpt-4o-mini
CASA_LLM_BASE_URL=https://api.openai.com/v1   # or your own endpoint
```

Contract enforced in code: the LLM receives only structured findings + risk
summary, can only **annotate/prioritize/summarize** (never invent findings,
raise severity, or touch evidence), and its failure degrades gracefully —
the assessment still completes.

---

## 7. Risk model (deterministic, explainable)

```
finding_risk = 100 × severity_weight × confidence × exposure
                     × exploitability × asset_importance
security_score = 100 − min(100, Σ finding_risk / 3)
```

All factors are fixed table lookups documented in `agent/risk/engine.py`; every
score in a report traces back to exact contributing findings via
`risk_factors` and `top_risk_drivers`. The LLM never produces the score.

---

## 8. Finding schema

```json
{
  "id": "uuid",
  "title": "...",
  "category": "CONFIGURATION|TLS|WEB|VULNERABILITY|TECHNOLOGY|RECON|PROCESS|OTHER",
  "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": "LOW|MEDIUM|HIGH",
  "description": "...",
  "evidence": [{"type": "http_header", "...": "..."}],
  "affected_asset": "http://...",
  "impact": "...", "remediation": "...", "references": ["..."],
  "source": "module name", "verified": false,
  "fingerprint": "stable-identity-hash",
  "status": "UNVERIFIED|OPEN|FIXED|STILL_PRESENT|CHANGED|FALSE_POSITIVE"
}
```

Non-INFO findings without evidence are automatically flagged
(`false_positive_risk: HIGH`, confidence lowered) by the normalizer.

---

## 9. Configuration

All settings are env vars with the `CASA_` prefix (see `.env.example`):
database URL (SQLite default, Postgres in compose), LLM provider, timeouts,
HTTP limits, audit log path, lab URL.

### ExploitDB offline index (one command)

```bash
python scripts/fetch_exploitdb.py   # downloads files_exploits.csv (~10 MB) to data/
```

Downloads the complete official ExploitDB index (mirror fallback chain,
integrity-checked ≥10,000 rows, atomic write) so exploit correlation works
fully offline. The index is signature-cached and hot-reloads when refreshed.

### CASA-Brain dataset (Level-2)

```bash
python scripts/build_brain_dataset.py              # default paths
python scripts/build_brain_dataset.py --stats-only # curation statistics
python scripts/build_brain_dataset.py --min-gain 0.5
```

Curates recorded Brain trajectories (`data/brain-trajectories.jsonl`) into a
chat-format fine-tuning JSONL (`data/brain-dataset-level2.jsonl`): only
policy-approved AND executed-OK transitions, duplicates dropped, execution
outcomes joined from their link records. Each line is `{schema, messages:
[system, user, assistant], meta}`.

---

## 10. Tests & Validation

```bash
pytest -v                    # unit + integration suite
python scripts/validate.py   # 30+ executable end-to-end validation checks
```

`scripts/validate.py` proves the whole system **executes**, in one process,
against a temp SQLite DB and the in-process lab: imports & routes, DB CRUD,
authorization gate matrix (no-authz / out-of-scope host / closed window /
allowed-path / valid), scope evasion blocks, SafeHttpClient (unsafe methods,
pre-flight rejection, redirect-escape block, in-scope redirect follow), the
**full pipeline E2E** (authz → modules → risk → AI → reports → COMPLETED),
evidence sha256 integrity, lab detection severities, finding schema
completeness, dedupe + fingerprint-matched AI annotations, hand-verified risk
math + determinism + LLM-cannot-override-risk, offline AI provider, graceful
LLM degradation, JSON/HTML artifacts, STILL_PRESENT **and real FIXED** E2E
verification (lab remediation simulated, re-assessed, finding → FIXED),
audit (DB + JSONL), API endpoints (201/200/202/400/403/404), and security
review checks (no hardcoded secrets, SSRF guards, no subprocess/eval, path
safety).

- **Unit**: scope validator (subdomain tricks, path/window/IP rules), finding
  schema, risk engine determinism & bounds, verification statuses.
- **Integration**: SafeHttpClient scope/redirect enforcement; the **full
  pipeline** (authorization → modules → risk → AI → verification → reports)
  against the in-process lab app; unauthorized-target BLOCKED path.

---

## 11. Extension points (not implemented in MVP)

| Area | Hook |
|------|------|
| Network assessment | add a module + adapter; register in `MODULE_REGISTRY` |
| ~~Continuous monitoring~~ **done in v0.2.0** | `ReassessmentScheduler` (built-in; Redis/Celery optional upgrade) |
| Attack-path analysis | graph module consuming normalized findings |
| ~~CVE/NVD feeds~~ **done in v0.2.0** | OSV.dev enrichment module (local KB still first) |
| Celery/Redis queue | implement `JobQueue` against a broker |
| Signed authorizations | `CASA_REQUIRE_SIGNED_AUTHORIZATIONS` flag prepared |
| Redis-backed rate limiting | swap the in-memory limiter in `agent/api/security.py` |

## 12. Tests & Validation (v0.2.0)

```bash
pytest -v                    # 119 tests (94 original + 25 for v0.2.0 features)
python scripts/validate.py   # 50 executable end-to-end validation checks
```

v0.2.0 test coverage includes: official CVSS vectors verified against the FIRST
spec, synthetic-vector band containment, WAF signature matching (and
non-matching), ATT&CK rule mapping, SARIF structure + MITRE tags, API-key
middleware (401/429/open-path), rate-limiter window math, webhook payload
formats, dashboard rendering, SARIF endpoint, and OSV version-range parsing.

## 13. Roadmap beyond v0.2.0

Network/infrastructure modules, authenticated scanning (cookie-based,
owner-provided), CI/CD integration (GitHub Actions + code-scanning upload of
the SARIF artifact), multi-tenant RBAC, PDF export, finding lifecycle
workflows, and a Next.js dashboard on the existing REST API.
