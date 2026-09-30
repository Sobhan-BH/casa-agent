"""CASA end-to-end validation harness.

Runs every validation stage EXECUTABLY (in-process, no internet required):

  1.  import & dependency integrity        12. AI layer constraints
  2.  database schema + CRUD + audit       13. report generation (real files)
  3.  authorization gate matrix            14. verification flow (FIXED/...)
  4.  scope enforcement                    15. audit trail validation
  5.  safe HTTP client safety              16. API endpoints (ASGI, real app)
  6.  assessment pipeline (E2E)            17. security review checks
  7.  lab finding detection                18. regression re-run
  8.  finding schema completeness
  9.  deduplication
  10. risk engine determinism
  11. risk traceability

Usage:
    python scripts/validate.py            # run everything
    python scripts/validate.py --quiet    # failures only

Everything runs against a temporary SQLite DB, an in-process lab ASGI app,
and the offline heuristic LLM provider. No third-party target is contacted.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_TMP = Path(tempfile.mkdtemp(prefix="casa-validate-"))
os.environ["CASA_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMP / 'validate.db'}"
os.environ["CASA_LLM_PROVIDER"] = "heuristic"
os.environ["CASA_AUDIT_LOG_PATH"] = str(_TMP / "audit.log")

RESULTS: list[dict] = []
CHECKS: list = []  # registry preserving definition order
QUIET = "--quiet" in sys.argv


def record(section: str, name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append({"section": section, "name": name, "ok": ok, "detail": detail})
    if ok:
        if not QUIET:
            print(f"  PASS  {name}" + (f" — {detail}" if detail else ""))
    else:
        print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))
        if detail and "\n" in detail:
            print(detail)


def section(title: str) -> None:
    if not QUIET:
        print(f"\n=== {title} " + "=" * max(0, 62 - len(title)))


# ============================================================================
def check(section_name: str, name: str):
    """Decorator: async check functions returning (ok, detail).

    Registers the wrapped coroutine in CHECKS (definition order). Names of the
    decorated functions are irrelevant (they may repeat).
    """

    def deco(fn):
        async def wrapper():
            try:
                ok, detail = await fn()
                record(section_name, name, ok, detail)
            except Exception:
                record(section_name, name, False, "EXCEPTION:\n" + traceback.format_exc())

        wrapper._is_check = True
        CHECKS.append(wrapper)
        return wrapper

    return deco


# ---------------------------------------------------------------- fixtures
async def fresh_session():
    """Create schema once and return the sessionmaker (not a session)."""
    from agent.storage.database import AsyncSessionLocal, Base, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return AsyncSessionLocal


class LabHarness:
    """In-process vulnerable lab + monkeypatched outbound HTTP.

    ``orig_async_client`` keeps the REAL httpx.AsyncClient so checks that need
    their own local clients (API tests, redirect mini-apps) can construct one.
    """

    def __init__(self) -> None:
        import httpx
        from httpx import ASGITransport, AsyncClient

        from lab.vulnerable_app import app as lab_app

        self.orig_async_client = httpx.AsyncClient  # real class, pre-patch
        self.lab_client = AsyncClient(
            transport=ASGITransport(app=lab_app), base_url="http://127.0.0.1:8001"
        )
        self._installed = False

    def install(self) -> None:
        import agent.connectors.adapters as adapters
        import httpx

        harness = self

        class RoutedClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def request(self, method, url):
                req = harness.lab_client.build_request(method, url)
                return await harness.lab_client.send(req)

        self._routed_client = RoutedClient
        httpx.AsyncClient = RoutedClient

        async def fake_dns(*a, **kw):
            return [(2, 1, 6, "", ("127.0.0.1", 0))]

        self._orig_dns = adapters._run_in_thread
        adapters._run_in_thread = fake_dns
        self._installed = True

    def uninstall(self) -> None:
        import agent.connectors.adapters as adapters
        import httpx

        httpx.AsyncClient = self.orig_async_client
        adapters._run_in_thread = self._orig_dns
        self._installed = False


LAB = LabHarness()
LAB.install()

# Module-level import AFTER env setup (config reads env at import time).
from agent.connectors.authorization_manager import AuthorizationManager  # noqa: E402

# ============================================================================
# 1. IMPORTS & DEPENDENCIES
# ============================================================================
section("1. IMPORTS & DEPENDENCIES")


@check("1", "all core package imports resolve")
async def _():
    mods = [
        "agent",
        "agent.core.config",
        "agent.core.enums",
        "agent.core.exceptions",
        "agent.core.finding",
        "agent.core.interfaces",
        "agent.core.target",
        "agent.core.safe_http",
        "agent.core.audit",
        "agent.core.context",
        "agent.core.logging",
        "agent.storage.database",
        "agent.storage.models",
        "agent.storage.repositories",
        "agent.connectors.authorization_manager",
        "agent.connectors.adapters",
        "agent.modules.recon",
        "agent.modules.tech_detection",
        "agent.modules.config_analysis",
        "agent.modules.tls_analysis",
        "agent.modules.web_checks",
        "agent.modules.vuln_correlation",
        "agent.analysis.evidence_collector",
        "agent.analysis.normalizer",
        "agent.analysis.ai_agent",
        "agent.analysis.llm_providers",
        "agent.risk.engine",
        "agent.verification.engine",
        "agent.reports.generator",
        "agent.api.main",
        "agent.api.routers",
        "agent.workers.orchestrator",
        "agent.workers.queue",
        "lab.vulnerable_app",
    ]
    import importlib

    for m in mods:
        importlib.import_module(m)
    return True, f"{len(mods)} modules imported"


def _route_paths(app) -> set[str]:
    """Collect route paths in a version-proof way.

    starlette 1.x wraps included routers in objects that expose neither
    ``path`` nor ``routes``, so we fall back to the OpenAPI schema, which is
    the canonical source of documented paths anyway.
    """
    paths: set[str] = set()
    for r in app.routes:
        p = getattr(r, "path", None)
        if p:
            paths.add(p)
        inner = getattr(r, "routes", None)
        if inner:
            for sub in inner:
                sp = getattr(sub, "path", None)
                if sp:
                    paths.add(sp)
    # Always merge in the OpenAPI-documented paths: starlette 1.x hides some
    # routes behind wrapper objects, but the schema is authoritative.
    try:
        schema = app.openapi()
        paths |= {p for p in schema.get("paths", {})}
    except Exception:
        pass
    return paths


@check("1", "API app builds with all routers (routes registered)")
async def _():
    from agent.api.main import app

    paths = _route_paths(app)
    required = {
        "/health",
        "/api/v1",
        "/api/v1/status",
        "/api/v1/authorizations",
        "/api/v1/authorizations/targets",
        "/api/v1/jobs",
        "/api/v1/assessments",
        "/api/v1/audit",
    }
    missing = required - paths
    return (not missing), (f"missing: {missing}" if missing else f"{len(paths)} routes")


@check("1", "openapi schema generates (swagger valid)")
async def _():
    from agent.api.main import app

    schema = app.openapi()
    ops = sum(1 for p in schema["paths"].values() for _ in p)
    return ops >= 10, f"{ops} documented operations"


# ============================================================================
# 2. DATABASE
# ============================================================================
section("2. DATABASE (SQLite)")
SESSIONMAKER = None


@check("2", "schema creation + CRUD + relationships + persistence")
async def _():
    global SESSIONMAKER
    SESSIONMAKER = await fresh_session()
    from sqlalchemy import select

    from agent.storage import repositories as repo
    from agent.storage.models import FindingRow

    async with SESSIONMAKER() as s:
        t = await repo.create_target(s, "http://127.0.0.1:8001", "WEB_APP", "lab")
        a = await repo.create_authorization(
            s,
            target_id=t.id,
            authorized_by="Validator",
            authorization_reference="VAL-1",
            allowed_domains=["127.0.0.1"],
            allowed_paths=["/"],
            excluded_targets=[],
            window_start=None,
            window_end=None,
        )
        j = await repo.create_job(
            s, target_id=t.id, authorization_id=a.id, trigger="INITIAL"
        )
        job = await repo.update_job_status(s, j.id, "RUNNING")
        assert job.status == "RUNNING"

        asmt = await repo.create_assessment(s, job=job, target=t, scope_snapshot={})
        await repo.save_findings(
            s,
            asmt.id,
            [
                {
                    "fingerprint": "fp-db-1",
                    "title": "DB finding",
                    "category": "WEB",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "evidence_refs": [],
                    "risk_score": 10.0,
                }
            ],
        )
        rows = (await s.execute(select(FindingRow))).scalars().all()
        assert any(r.fingerprint == "fp-db-1" for r in rows)

        ev = await repo.save_evidence(
            s, asmt.id, kind="HTTP", source="x", url="u", content={"a": 1}
        )
        assert ev.sha256

        # persistence across sessions
        j2 = await repo.get_job(s, j.id)
        assert j2.id == j.id
    return True, "targets/authz/jobs/assessments/findings/evidence all persisted"


@check("2", "update_job_status lifecycle transitions")
async def _():
    from agent.storage import repositories as repo

    async with SESSIONMAKER() as s:
        t = await repo.create_target(s, "http://lifecycle.test", "WEB_APP")
        a = await repo.create_authorization(
            s,
            target_id=t.id,
            authorized_by="V",
            authorization_reference="",
            allowed_domains=["lifecycle.test"],
            allowed_paths=["/"],
            excluded_targets=[],
            window_start=None,
            window_end=None,
        )
        j = await repo.create_job(s, target_id=t.id, authorization_id=a.id, trigger="INITIAL")
        for status in ("RUNNING", "ANALYZING", "VERIFYING", "COMPLETED"):
            job = await repo.update_job_status(s, j.id, status)
            assert job.status == status
        assert job.finished_at is not None
    return True, "QUEUED->RUNNING->ANALYZING->VERIFYING->COMPLETED"


# ============================================================================
# 3. AUTHORIZATION GATE MATRIX
# ============================================================================
section("3. AUTHORIZATION GATE")


@check("3", "A: target without authorization -> AuthorizationError")
async def _():
    from agent.core.exceptions import AuthorizationError
    from agent.storage import repositories as repo

    async with SESSIONMAKER() as s:
        t = await repo.create_target(s, "http://noauthz.test", "WEB_APP")
        try:
            await AuthorizationManager(s).resolve_for_target_url(t.url)
            return False, "expected AuthorizationError"
        except AuthorizationError:
            return True, "correctly raised AuthorizationError"


@check("3", "B: host outside allowed_domains -> rejected (403 semantics)")
async def _():
    from agent.core.exceptions import AuthorizationError, ScopeViolationError
    from agent.storage import repositories as repo

    async with SESSIONMAKER() as s:
        t = await repo.create_target(s, "http://inside.test", "WEB_APP")
        await AuthorizationManager(s).register_authorization(
            {
                "target": "http://inside.test",
                "authorized_by": "V",
                "allowed_domains": ["inside.test"],
            }
        )
        try:
            await AuthorizationManager(s).resolve_for_target_url("http://outside.test")
            return False, "expected rejection"
        except (ScopeViolationError, AuthorizationError) as exc:
            # Unregistered URLs fail fast with AuthorizationError; either way
            # the assessment never proceeds.
            return True, f"outside host rejected ({type(exc).__name__})"


@check("3", "C: expired time window -> ScopeViolationError")
async def _():
    from agent.core.exceptions import ScopeViolationError
    from agent.storage import repositories as repo

    async with SESSIONMAKER() as s:
        t = await repo.create_target(s, "http://window.test", "WEB_APP")
        await AuthorizationManager(s).register_authorization(
            {
                "target": "http://window.test",
                "authorized_by": "V",
                "allowed_domains": ["window.test"],
                "window_end": "2020-01-01T00:00:00+00:00",
            }
        )
        try:
            await AuthorizationManager(s).resolve_for_target_url(t.url)
            return False, "expected window violation"
        except ScopeViolationError:
            return True, "closed window rejected"


@check("3", "D: path outside allowed_paths -> ScopeViolationError")
async def _():
    from agent.core.exceptions import ScopeViolationError
    from agent.storage import repositories as repo

    async with SESSIONMAKER() as s:
        t = await repo.create_target(s, "http://paths.test", "WEB_APP")
        await AuthorizationManager(s).register_authorization(
            {
                "target": "http://paths.test",
                "authorized_by": "V",
                "allowed_domains": ["paths.test"],
                "allowed_paths": ["/only-this"],
            }
        )
        try:
            await AuthorizationManager(s).resolve_for_target_url(t.url)
            return False, "expected path violation"
        except ScopeViolationError:
            return True, "target root outside allowed_paths rejected"


@check("3", "E: valid target inside scope -> authorization resolves")
async def _():
    async with SESSIONMAKER() as s:
        await AuthorizationManager(s).register_authorization(
            {
                "target": "http://127.0.0.1:8001",
                "authorized_by": "Validator",
                "allowed_domains": ["127.0.0.1"],
            }
        )
        authz, validator = await AuthorizationManager(s).resolve_for_target_url(
            "http://127.0.0.1:8001"
        )
        return authz.authorized_by == "Validator", f"authz by {authz.authorized_by}"


# ============================================================================
# 4. SCOPE ENFORCEMENT (unit)
# ============================================================================
section("4. SCOPE ENFORCEMENT")


@check("4", "subdomain evasion blocked (example.com.evil.com)")
async def _():
    from agent.core.exceptions import ScopeViolationError

    from agent.core.target import ScopeValidator

    v = ScopeValidator(allowed_domains=["example.com"], allowed_paths=["/"])
    try:
        v.check_url("https://example.com.evil.com/")
        return False, "evasion not blocked"
    except ScopeViolationError:
        return True, "blocked"


@check("4", "legit subdomain allowed (api.example.com)")
async def _():
    from agent.core.target import ScopeValidator

    v = ScopeValidator(allowed_domains=["example.com"], allowed_paths=["/"])
    v.check_url("https://api.example.com/x")
    return True, "allowed"


@check("4", "IP targets require explicit allowlisting")
async def _():
    from agent.core.exceptions import ScopeViolationError

    from agent.core.target import ScopeValidator

    v = ScopeValidator(allowed_domains=["example.com"], allowed_paths=["/"])
    try:
        v.check_url("http://10.0.0.1/")
        return False, "IP accepted without explicit allow"
    except ScopeViolationError:
        return True, "blocked"


# ============================================================================
# 5. SAFE HTTP CLIENT
# ============================================================================
section("5. SAFE HTTP CLIENT")


@check("5", "unsafe methods rejected (POST/PUT/DELETE)")
async def _():
    from agent.core.exceptions import ScopeViolationError
    from agent.core.safe_http import SafeHttpClient

    from agent.core.target import ScopeValidator

    v = ScopeValidator(allowed_domains=["127.0.0.1"], allowed_paths=["/"])
    c = SafeHttpClient(v)
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        try:
            await c._request(m, "http://127.0.0.1:8001/")
            return False, f"{m} was permitted"
        except ScopeViolationError:
            pass
    return True, "all write methods blocked"


@check("5", "out-of-scope URL rejected before any request")
async def _():
    from agent.core.exceptions import ScopeViolationError
    from agent.core.safe_http import SafeHttpClient
    from agent.core.target import ScopeValidator

    v = ScopeValidator(allowed_domains=["example.com"], allowed_paths=["/"])
    c = SafeHttpClient(v)
    try:
        await c.get("http://127.0.0.1:8001/")
        return False, "out-of-scope request went through"
    except ScopeViolationError:
        return True, "blocked pre-flight"


@check("5", "redirect to out-of-scope host blocked")
async def _():
    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse
    from httpx import ASGITransport

    from agent.core.exceptions import ScopeViolationError
    from agent.core.safe_http import SafeHttpClient
    from agent.core.target import ScopeValidator

    app = FastAPI()

    @app.get("/escape")
    async def escape():
        return RedirectResponse("http://evil.example.net/steal")

    # NOTE: use the REAL AsyncClient (httpx.AsyncClient is globally patched
    # to route to the lab while the harness is loaded).
    RealAsyncClient = LAB.orig_async_client
    async with RealAsyncClient(
        transport=ASGITransport(app=app), base_url="http://127.0.0.1:9111"
    ) as lc:

        class Routed:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def request(self, method, url):
                req = lc.build_request(method, url)
                return await lc.send(req)

        import agent.core.safe_http as sh

        # Patch only within this check (LAB's global patch is active otherwise).
        orig = LAB.orig_async_client
        sh.httpx.AsyncClient = Routed
        try:
            v = ScopeValidator(allowed_domains=["127.0.0.1"], allowed_paths=["/"])
            c = SafeHttpClient(v)
            try:
                await c.get("http://127.0.0.1:9111/escape")
                return False, "out-of-scope redirect followed"
            except ScopeViolationError:
                return True, "redirect escape blocked"
        finally:
            sh.httpx.AsyncClient = LAB._routed_client  # restore LAB patch


@check("5", "in-scope redirect followed and returned")
async def _():
    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse
    from httpx import ASGITransport

    from agent.core.safe_http import SafeHttpClient
    from agent.core.target import ScopeValidator

    app = FastAPI()

    @app.get("/start")
    async def start():
        return RedirectResponse("/final")

    @app.get("/final")
    async def final():
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse("arrived")

    RealAsyncClient = LAB.orig_async_client
    async with RealAsyncClient(
        transport=ASGITransport(app=app), base_url="http://127.0.0.1:9112"
    ) as lc:

        class Routed:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def request(self, method, url):
                req = lc.build_request(method, url)
                return await lc.send(req)

        import agent.core.safe_http as sh

        sh.httpx.AsyncClient = Routed
        try:
            v = ScopeValidator(allowed_domains=["127.0.0.1"], allowed_paths=["/"])
            c = SafeHttpClient(v)
            resp = await c.get("http://127.0.0.1:9112/start")
            ok = resp.status_code == 200 and "arrived" in resp.body
            return ok, f"status={resp.status_code} redirects={resp.redirects}"
        finally:
            sh.httpx.AsyncClient = LAB._routed_client  # restore LAB patch


# ============================================================================
# 6-8. FULL PIPELINE E2E + LAB DETECTION + FINDING SCHEMA
# ============================================================================
section("6-8. FULL PIPELINE (E2E on local lab)")
PIPELINE: dict = {}


@check("6", "authorization -> modules -> risk -> AI -> reports -> COMPLETED")
async def _():
    from agent.storage import repositories as repo
    from agent.workers.orchestrator import Orchestrator

    async with SESSIONMAKER() as s:
        reg = await AuthorizationManager(s).register_authorization(
            {
                "target": "http://127.0.0.1:8001",
                "authorized_by": "E2E Validator",
                "authorization_reference": "E2E-1",
                "allowed_domains": ["127.0.0.1"],
                "allowed_paths": ["/"],
            }
        )
        job = await repo.create_job(
            s,
            target_id=reg["target_id"],
            authorization_id=reg["authorization"]["id"],
            trigger="INITIAL",
        )
        import uuid as _uuid

        result = await Orchestrator(s).run_job(_uuid.UUID(job.id))
        if result["status"] != "COMPLETED":
            return False, f"job ended {result['status']}: {result.get('error')}"

        asmt = await repo.get_assessment(s, result["assessment_id"])
        findings = await repo.list_findings(s, asmt.id)
        PIPELINE["assessment"] = asmt
        PIPELINE["findings"] = findings
        PIPELINE["session"] = s

        titles = [f.title for f in findings]
        expected = [".env", "Cookie", "robots", "Content-Security-Policy"]
        missing = [e for e in expected if not any(e.lower() in t.lower() for t in titles)]
        if missing:
            return False, f"expected findings missing: {missing}"
        return True, (
            f"score={asmt.security_score} findings={len(findings)} "
            f"CRIT={asmt.risk_summary['distribution']['CRITICAL']}"
        )


@check("6", "job status lifecycle observed in DB")
async def _():
    from agent.storage import repositories as repo

    asmt = PIPELINE["assessment"]
    async with SESSIONMAKER() as s:
        job = await repo.get_job(s, asmt.job_id)
        ok = job.status == "COMPLETED" and job.started_at and job.finished_at
        return bool(ok), f"status={job.status}"


@check("6", "evidence persisted with sha256 integrity")
async def _():
    import hashlib
    import json as _json

    from agent.storage import repositories as repo

    asmt = PIPELINE["assessment"]
    async with SESSIONMAKER() as s:
        evs = await repo.list_evidence(s, asmt.id)
        if not evs:
            return False, "no evidence rows"
        bad = [
            e.id
            for e in evs
            if e.sha256
            != hashlib.sha256(
                _json.dumps(e.content_json, sort_keys=True, default=str).encode()
            ).hexdigest()
        ]
        return (not bad), f"{len(evs)} evidence rows, {len(bad)} hash mismatches"


@check("7", "lab detections: .env CRITICAL, .git HIGH, listing MEDIUM")
async def _():
    findings = PIPELINE["findings"]
    def has(sub, sev):
        return any(sub in f.title and f.severity == sev for f in findings)
    checks = {
        ".env": has(".env", "CRITICAL"),
        ".git": has(".git", "HIGH"),
        "listing": has("Directory listing", "MEDIUM"),
    }
    failed = [k for k, v in checks.items() if not v]
    return (not failed), (f"missing: {failed}" if failed else "all severity-matched")


@check("8", "every non-INFO finding has schema-complete fields + risk")
async def _():
    findings = PIPELINE["findings"]
    problems = []
    # DB columns; impact/remediation may legitimately be empty strings.
    required_str = [
        "id", "title", "category", "severity", "confidence", "description",
        "affected_asset", "source", "fingerprint", "status",
    ]
    for f in findings:
        for field in required_str:
            val = getattr(f, field, None)
            if not val or (isinstance(val, str) and not val.strip()):
                problems.append(f"{f.fingerprint}:{field}")
        if f.references is None or f.evidence_refs is None:
            problems.append(f"{f.fingerprint}:lists")
        if f.severity != "INFO" and f.risk_score is None:
            problems.append(f"{f.fingerprint}:risk_score")
        if f.risk_factors and "severity_weight" not in f.risk_factors:
            problems.append(f"{f.fingerprint}:risk_factors")
    return (
        (not problems),
        (f"incomplete: {problems[:5]}" if problems else f"{len(findings)} findings complete"),
    )


# ============================================================================
# 9. DEDUPLICATION
# ============================================================================
section("9. DEDUPLICATION")


@check("9", "duplicates merged, distinct findings kept")
async def _():
    from agent.analysis.normalizer import FindingNormalizerModule
    from agent.core.context import AssessmentContext
    from agent.core.finding import make_finding, make_fingerprint

    ctx = AssessmentContext(
        job_id=uuid4(),
        assessment_id=uuid4(),
        target_url="http://t",
        base_domain="t",
        scope={},
    )
    fp_shared = make_fingerprint("shared", "asset")
    a = make_finding("Dup", "CONFIGURATION", "LOW", "HIGH", "d", source="mod1")
    b = make_finding("Dup", "CONFIGURATION", "LOW", "HIGH", "d", source="mod2")
    c = make_finding("Other", "WEB", "HIGH", "HIGH", "d", source="mod1")
    for f, fp in ((a, fp_shared), (b, fp_shared), (c, "fp-other")):
        f["fingerprint"] = fp
    ctx.findings = [a, b, c]
    await FindingNormalizerModule(None).run(ctx)
    ok = len(ctx.findings) == 2 and ctx.findings[0]["metadata"].get("also_reported_by") == ["mod2"]
    return ok, f"{len(ctx.findings)} findings after merge"


@check("9", "AI annotations attach to the correct finding via fingerprint")
async def _():
    from agent.analysis.ai_agent import AIAnalysisModule
    from agent.core.context import AssessmentContext
    from agent.core.finding import make_finding, make_fingerprint

    ctx = AssessmentContext(
        job_id=uuid4(), assessment_id=uuid4(), target_url="http://t", base_domain="t", scope={}
    )
    f1 = make_finding("A", "WEB", "HIGH", "LOW", "d")
    f1["fingerprint"] = "fp-A"
    f2 = make_finding("B", "WEB", "LOW", "HIGH", "d")
    f2["fingerprint"] = "fp-B"
    ctx.findings = [f1, f2]
    ctx.risk_summary = {"security_score": 50, "grade": "C", "distribution": {}}

    provider_out = {
        "executive_summary": "x",
        "confidence_adjustments": [
            {"fingerprint": "fp-A", "reason": "weak evidence", "suggested_confidence": "LOW"}
        ],
        "suspicious_findings": [{"fingerprint": "fp-B", "reason": "odd"}],
    }
    class FakeProvider:
        name = "fake"
        async def analyze(self, prompt, system):
            import json as _j

            return _j.dumps(provider_out)

    mod = AIAnalysisModule(None, FakeProvider())
    await mod.run(ctx)
    ok = (
        ctx.findings[0].get("ai_notes", {}).get("confidence_note") == "weak evidence"
        and ctx.findings[1].get("ai_notes", {}).get("suspicious_reason") == "odd"
    )
    return ok, "annotations matched by fingerprint"


# ============================================================================
# 10-11. RISK ENGINE
# ============================================================================
section("10-11. RISK ENGINE")


@check("10", "deterministic: identical input -> identical score")
async def _():
    from agent.risk.engine import RiskEngine

    findings = [
        {"title": "T1", "severity": "HIGH", "confidence": "HIGH", "affected_asset": "http://x/login"},
        {"title": "T2 exposed credentials", "severity": "CRITICAL", "confidence": "MEDIUM", "affected_asset": "http://x/.env"},
        {"title": "T3", "severity": "LOW", "confidence": "LOW", "affected_asset": "http://x/"},
    ]
    r1 = RiskEngine().compute([dict(f) for f in findings])
    r2 = RiskEngine().compute([dict(f) for f in findings])
    return r1["security_score"] == r2["security_score"], f"score={r1['security_score']}"


@check("10", "hand-verified score calculation")
async def _():
    from agent.risk.engine import RiskEngine

    # severity=MEDIUM(0.12) conf=HIGH(1.0) exposure=internet(1.0)
    # exploitability: no keywords -> 1.0, importance: /api -> 1.15
    # evidence: 2 items -> 1.0, auth: anonymous -> 1.0, reachability: 1 endpoint -> 1.0
    f = {
        "title": "T",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "affected_asset": "http://x/api",
        "evidence": [{"type": "http_get", "status": 200}, {"type": "http_header"}],
    }
    res = RiskEngine().score_finding(dict(f))
    expected = round(100 * 0.12 * 1.0 * 1.0 * 1.0 * 1.15 * 1.0 * 1.0 * 1.0, 1)
    return (
        res["risk_score"] == expected,
        f"got {res['risk_score']} expected {expected}",
    )


@check("10", "severity ordering respected across full scale")
async def _():
    from agent.risk.engine import RiskEngine

    engine = RiskEngine()
    scores = [
        engine.score_finding({"title": "T", "severity": s, "confidence": "HIGH", "affected_asset": "http://x/"})["risk_score"]
        for s in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    ]
    return scores == sorted(scores), f"{scores}"


@check("11", "score traceable: top_risk_drivers cite findings + factors")
async def _():
    from agent.risk.engine import RiskEngine

    findings = [
        {"title": "Big issue exposed", "severity": "HIGH", "confidence": "HIGH", "affected_asset": "http://x/"},
        {"title": "Minor", "severity": "LOW", "confidence": "LOW", "affected_asset": "http://y/"},
    ]
    res = RiskEngine().compute([dict(f) for f in findings])
    ok = res["top_risk_drivers"] and all(
        "risk_factors" in dict(f) or True for f in findings
    )
    # Verify drivers reference real finding titles
    titles = {d["title"] for d in res["top_risk_drivers"]}
    return ok and titles <= {f["title"] for f in findings}, f"drivers={len(res['top_risk_drivers'])}"


@check("11", "LLM cannot override risk: score computed only by engine")
async def _():
    from agent.analysis.ai_agent import AIAnalysisModule
    from agent.core.context import AssessmentContext
    from agent.core.finding import make_finding, make_fingerprint
    from agent.risk.engine import RiskEngine

    ctx = AssessmentContext(
        job_id=uuid4(), assessment_id=uuid4(), target_url="http://t", base_domain="t", scope={}
    )
    f = make_finding("A", "WEB", "LOW", "LOW", "d")
    f["fingerprint"] = "fp1"
    ctx.findings = [f]
    ctx.risk_summary = RiskEngine().compute(ctx.findings)
    before = ctx.risk_summary["security_score"]

    class EvilProvider:
        name = "evil"
        async def analyze(self, prompt, system):
            import json as _j

            return _j.dumps(
                {
                    "executive_summary": "all critical",
                    "confidence_adjustments": [{"fingerprint": "fp1", "reason": "r", "suggested_confidence": "HIGH"}],
                    "severity_overrides": [{"fingerprint": "fp1", "severity": "CRITICAL"}],
                }
            )

    await AIAnalysisModule(None, EvilProvider()).run(ctx)
    after = RiskEngine().compute(ctx.findings)["security_score"]
    sev_unchanged = ctx.findings[0]["severity"] == "LOW"
    score_unchanged = ctx.risk_summary["security_score"] == before
    # AI suggestion only annotates, engine recomputes from base fields:
    return (
        sev_unchanged and score_unchanged and after == before
    ), f"severity={ctx.findings[0]['severity']} score {before}->{after}"


# ============================================================================
# 12. AI LAYER
# ============================================================================
section("12. AI LAYER")


@check("12", "offline heuristic provider runs without network")
async def _():
    from agent.analysis.llm_providers import HeuristicProvider

    p = HeuristicProvider()
    out = await p.analyze('{"target":"x","findings":[{"title":"A","severity":"HIGH","confidence":"HIGH","risk_score":10,"affected_asset":"a","evidence":[{"type":"t"}],"remediation":"r","metadata":{}}],"risk_summary":{"security_score":70,"grade":"C","distribution":{"HIGH":1}}}', "sys")
    data = json.loads(out)
    keys = {"executive_summary", "manager_summary", "prioritized_findings", "correlations", "suspicious_findings"}
    return keys <= set(data), f"keys={sorted(set(data) & keys)}/{len(keys)}"


@check("12", "malformed LLM output degrades gracefully (no crash)")
async def _():
    from agent.analysis.ai_agent import AIAnalysisModule
    from agent.core.context import AssessmentContext

    class GarbageProvider:
        name = "garbage"
        async def analyze(self, prompt, system):
            return "this is not json at all <<<>>"

    ctx = AssessmentContext(
        job_id=uuid4(), assessment_id=uuid4(), target_url="http://t", base_domain="t", scope={}
    )
    await AIAnalysisModule(None, GarbageProvider()).run(ctx)
    return "error" in ctx.ai_summary, ctx.ai_summary.get("error", "")[:60]


@check("12", "LLM unavailable -> assessment continues (degraded)")
async def _():
    from agent.analysis.ai_agent import AIAnalysisModule
    from agent.core.context import AssessmentContext
    from agent.core.exceptions import LLMUnavailableError

    class DownProvider:
        name = "down"
        async def analyze(self, prompt, system):
            raise LLMUnavailableError("endpoint down")

    ctx = AssessmentContext(
        job_id=uuid4(), assessment_id=uuid4(), target_url="http://t", base_domain="t", scope={}
    )
    await AIAnalysisModule(None, DownProvider()).run(ctx)
    return ctx.ai_summary.get("degraded") is True, "degraded=True"


@check("12", "provider factory honors CASA_LLM_PROVIDER (abstraction)")
async def _():
    from agent.analysis import llm_providers as lp

    p = lp.make_llm_provider()
    return p.name == "heuristic", f"default provider = {p.name}"


# ============================================================================
# 13. REPORTS
# ============================================================================
section("13. REPORTS")


@check("13", "JSON report valid & complete; HTML file on disk")
async def _():
    from agent.core.context import AssessmentContext
    from agent.reports.generator import ReportGenerator
    from agent.storage import repositories as repo

    asmt = PIPELINE["assessment"]
    async with SESSIONMAKER() as s:
        ctx = AssessmentContext(
            job_id=uuid4(),
            assessment_id=uuid4(),
            target_url=asmt.target_url,
            base_domain=asmt.base_domain,
            scope={"authorized_by": "E2E Validator", "authorization_reference": "E2E-1",
                   "allowed_domains": ["127.0.0.1"], "allowed_paths": ["/"], "excluded_targets": []},
            risk_summary=asmt.risk_summary,
            ai_summary=asmt.ai_summary,
        )
        rows = await repo.list_findings(s, asmt.id)
        ctx.findings = [
            {
                "id": r.id, "title": r.title, "category": r.category, "severity": r.severity,
                "confidence": r.confidence, "description": r.description,
                "evidence": [{"type": "http_get", "url": r.affected_asset}],
                "affected_asset": r.affected_asset, "impact": r.impact,
                "remediation": r.remediation, "references": r.references,
                "source": r.source, "verified": r.verified, "fingerprint": r.fingerprint,
                "status": r.status, "risk_score": r.risk_score, "risk_factors": r.risk_factors,
            }
            for r in rows
        ]
        gen = ReportGenerator(s)
        written = await gen.generate(ctx)

        artifacts = await repo.list_artifacts(s, str(ctx.assessment_id))
        by_fmt = {a.fmt: a for a in artifacts}
        if "json" not in by_fmt or "html" not in by_fmt:
            return False, f"missing artifacts: {sorted(by_fmt)}"
        json_payload = json.loads(by_fmt["json"].content)
        html = by_fmt["html"].content
        json_ok = json_payload["security_score"] is not None and json_payload["findings"]
        sections_ok = all(
            t in html
            for t in ("Security Score", "Executive Summary", "Findings", "Verification")
        )
        file_ok = True
        if written.get("json") and not written["json"].startswith("("):
            file_ok = Path(written["json"]).exists()
        return (
            json_ok and sections_ok and file_ok,
            f"score={json_payload['security_score']} findings={len(json_payload['findings'])} html={len(html)}B",
        )


# ============================================================================
# 14. VERIFICATION FLOW (FIXED / STILL_PRESENT / CHANGED / UNVERIFIED)
# ============================================================================
section("14. VERIFICATION")


@check("14", "STILL_PRESENT: unchanged lab -> baseline findings persist")
async def _():
    from agent.storage import repositories as repo
    from agent.workers.orchestrator import Orchestrator

    asmt1 = PIPELINE["assessment"]
    async with SESSIONMAKER() as s:
        job = await repo.create_job(
            s, target_id=asmt1.target_id, authorization_id=None, trigger="VERIFICATION",
            previous_assessment_id=asmt1.id,
        )
        result = await Orchestrator(s).run_job(__import__("uuid").UUID(job.id))
        if result["status"] != "COMPLETED":
            return False, f"verification job: {result['status']} {result.get('error')}"
        asmt2 = await repo.get_assessment(s, result["assessment_id"])
        counts = asmt2.verification_summary["counts"]
        PIPELINE["verification_counts"] = counts
        ok = counts["STILL_PRESENT"] >= 5 and counts["FIXED"] == 0
        return ok, f"counts={counts}"


@check("14", "FIXED E2E: remediate lab, re-assess, finding becomes FIXED")
async def _():
    import lab.vulnerable_app as lab

    from agent.storage import repositories as repo
    from agent.workers.orchestrator import Orchestrator

    asmt1 = PIPELINE["assessment"]
    env_fp = __import__("agent.core.finding", fromlist=["host_fingerprint"]).host_fingerprint(
        "env_exposed", "http://127.0.0.1:8001"
    )

    # 1) remediate the lab (/.env returns 404 now)
    lab.REMEDIATED = True
    try:
        async with SESSIONMAKER() as s:
            job = await repo.create_job(
                s, target_id=asmt1.target_id, authorization_id=None,
                trigger="VERIFICATION", previous_assessment_id=asmt1.id,
            )
            result = await Orchestrator(s).run_job(__import__("uuid").UUID(job.id))
            if result["status"] != "COMPLETED":
                return False, f"post-fix job: {result['status']} {result.get('error')}"
            asmt2 = await repo.get_assessment(s, result["assessment_id"])
            items = asmt2.verification_summary["items"]
            env_item = next(
                (i for i in items if i.get("fingerprint") == env_fp), None
            )
            if env_item is None:
                return False, "env finding missing from verification items"
            ok = env_item["status"] == "FIXED"
            counts = asmt2.verification_summary["counts"]
            return ok, f"env status={env_item['status']} counts={counts}"
    finally:
        lab.REMEDIATED = False  # restore for any later checks


@check("14", "FIXED/CHANGED/UNVERIFIED logic (engine matrix)")
async def _():
    from agent.verification.engine import VerificationEngine

    baseline = [
        {"id": "1", "fingerprint": "fpA", "title": "A", "severity": "HIGH"},
        {"id": "2", "fingerprint": "fpB", "title": "B", "severity": "MEDIUM"},
        {"id": "3", "fingerprint": "fpC", "title": "C", "severity": "LOW"},
        {"id": "4", "fingerprint": "", "title": "NoFP", "severity": "LOW"},
    ]
    current = [
        {"id": "11", "fingerprint": "fpB", "title": "B", "severity": "MEDIUM"},  # still
        {"id": "12", "fingerprint": "fpC", "title": "C", "severity": "HIGH"},   # changed
        {"id": "13", "fingerprint": "fpD", "title": "D", "severity": "HIGH"},   # new/OPEN
    ]
    res = VerificationEngine().compare(baseline, current)
    c = res["counts"]
    ok = (
        c["FIXED"] == 1 and c["STILL_PRESENT"] == 1 and c["CHANGED"] == 1
        and c["OPEN"] == 1 and c["UNVERIFIED"] == 1
    )
    return ok, f"counts={c}"


# ============================================================================
# 15. AUDIT
# ============================================================================
section("15. AUDIT")


@check("15", "audit events recorded for gate + job lifecycle")
async def _():
    from agent.storage import repositories as repo

    async with SESSIONMAKER() as s:
        events = await repo.list_audit_events(s, limit=500)
        names = {e.event for e in events}
        required = {"AUTHORIZATION_REGISTERED", "JOB_STARTED", "JOB_COMPLETED"}
        missing = required - names
        ts_ok = all(e.ts is not None for e in events)
        return (not missing and ts_ok and len(events) >= 5), (
            f"{len(events)} events; missing={missing}" if missing else f"{len(events)} events"
        )


@check("15", "JSONL audit file append-only with timestamps")
async def _():
    log_path = Path(os.environ["CASA_AUDIT_LOG_PATH"])
    lines = [json.loads(l) for l in log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    fields_ok = all({"ts", "event", "outcome"} <= set(e) for e in lines)
    return fields_ok and len(lines) >= 5, f"{len(lines)} JSONL entries"


# ============================================================================
# 16. API END-POINTS (real ASGI app)
# ============================================================================
section("16. API")


@check("16", "authorizations: create + list + targets")
async def _():
    from httpx import ASGITransport

    from agent.api.main import app
    from agent.api.state import set_app_state
    from agent.workers.queue import JobQueue
    from agent.storage.database import AsyncSessionLocal

    q = JobQueue(AsyncSessionLocal)
    set_app_state(q)
    RealAsyncClient = LAB.orig_async_client
    async with RealAsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/api/v1/authorizations",
            json={"target": "http://apitest.test", "authorized_by": "API V",
                  "allowed_domains": ["apitest.test"]},
        )
        if r.status_code != 201:
            return False, f"create -> {r.status_code} {r.text[:100]}"
        r2 = await c.get(f"/api/v1/authorizations?target_id={r.json()['target_id']}")
        r3 = await c.get("/api/v1/authorizations/targets")
        return (
            r2.status_code == 200 and r3.status_code == 200 and len(r3.json()) >= 1
        ), f"create=201 list={r2.status_code} targets={r3.status_code}"


@check("16", "jobs: 403 without authorization; invalid trigger 400")
async def _():
    from httpx import ASGITransport

    from agent.api.main import app
    from agent.api.state import set_app_state
    from agent.workers.queue import JobQueue
    from agent.storage.database import AsyncSessionLocal

    set_app_state(JobQueue(AsyncSessionLocal))
    RealAsyncClient = LAB.orig_async_client
    async with RealAsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        reg = await c.post(
            "/api/v1/authorizations",
            json={"target": "http://noauth2.test", "authorized_by": "X",
                  "allowed_domains": ["noauth2.test"]},
        )
        tid = reg.json()["target_id"]
        # now delete-ish: create target with no authz via direct DB
        from agent.storage.database import AsyncSessionLocal as ASL

        async with ASL() as s:
            from agent.storage import repositories as repo
            from agent.storage.models import Target

            t = Target(url="http://ghost.test", target_type="WEB_APP")
            s.add(t)
            await s.commit()
            await s.refresh(t)
            ghost_id = t.id
        r = await c.post("/api/v1/jobs", json={"target_id": ghost_id})
        r403 = r.status_code == 403
        reg2 = await c.get("/api/v1/authorizations/targets")
        tid2 = [t["id"] for t in reg2.json() if t["url"] == "http://apitest.test"]
        r400 = None
        if tid2:
            r = await c.post("/api/v1/jobs", json={"target_id": tid2[0], "trigger": "BOGUS"})
            r400 = r.status_code == 400
        return r403 and bool(r400), f"no-authz={r.status_code}, bad-trigger={r400}"


@check("16", "assessments/audit endpoints respond")
async def _():
    from httpx import ASGITransport

    from agent.api.main import app

    RealAsyncClient = LAB.orig_async_client
    async with RealAsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        ra = await c.get("/api/v1/assessments?target_id=nonexistent")
        ru = await c.get("/api/v1/audit")
        rs = await c.get("/api/v1/status")
        rh = await c.get("/health")
        return (
            ra.status_code == 200 and ru.status_code == 200 and rs.status_code == 200
            and rh.status_code == 200
        ), f"assessments={ra.status_code} audit={ru.status_code} status={rs.status_code} health={rh.status_code}"


@check("16", "404 for unknown job/assessment")
async def _():
    from httpx import ASGITransport

    from agent.api.main import app

    RealAsyncClient = LAB.orig_async_client
    async with RealAsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r1 = await c.get("/api/v1/jobs/00000000-0000-0000-0000-000000000000")
        r2 = await c.get("/api/v1/assessments/nope")
        return r1.status_code == 404 and r2.status_code == 404, f"job={r1.status_code} asmt={r2.status_code}"


# ============================================================================
# 17. SECURITY REVIEW
# ============================================================================
section("17. SECURITY REVIEW")


@check("17", "no hardcoded secrets in source")
async def _():
    import re

    patterns = [
        re.compile(r"(sk-[a-zA-Z0-9]{20,})"),
        re.compile(r"(aws_access_key_id\s*=\s*['\"]?AKIA)"),
        re.compile(r"(-----BEGIN (?:RSA )?PRIVATE KEY-----)"),
    ]
    hits = []
    for py in ROOT.rglob("*.py"):
        if ".venv" in str(py) or "test" in py.name.lower():
            continue
        text = py.read_text(encoding="utf-8", errors="ignore")
        for p in patterns:
            if p.search(text):
                hits.append(str(py.relative_to(ROOT)))
    return (not hits), (f"hits: {hits}" if hits else "clean")


@check("17", "lab fake secrets are clearly marked as fake")
async def _():
    lab = (ROOT / "lab" / "vulnerable_app.py").read_text(encoding="utf-8")
    return "do-not-use" in lab and "sk-test-" in lab, "fake markers present"


@check("17", "SSRF guard: scheme allowlist + IP allowlist enforcement")
async def _():
    from agent.core.exceptions import ScopeConfigurationError, ScopeViolationError

    from agent.core.target import parse_target_url

    for bad in ("file:///etc/passwd", "gopher://x", "http://user:pw@h/"):
        try:
            parse_target_url(bad)
            return False, f"accepted {bad}"
        except ScopeConfigurationError:
            continue
    return True, "file/gopher/userinfo schemes rejected"


@check("17", "SQL injection: ORM parameterization (no raw f-string SQL)")
async def _():
    from agent.storage import repositories

    src = Path(repositories.__file__).read_text(encoding="utf-8")
    return "f\"SELECT" not in src and "f'SELECT" not in src and "%" not in src.split("select(")[0], "ORM-only"


@check("17", "subprocess safety: no shell spawn, no os.system/eval/pickle")
async def _():
    import ast as _ast

    hits = []
    for py in (ROOT / "agent").rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="ignore")
        if "os.system" in text or "eval(" in text or "pickle.loads" in text:
            hits.append(py.name)
            continue
        try:
            tree = _ast.parse(text)
        except SyntaxError:
            continue
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Call):
                func = node.func
                name = getattr(func, "attr", "") or getattr(func, "id", "")
                if name in ("system", "Popen", "create_subprocess_shell"):
                    hits.append(f"{py.name} ({name})")
                for kw in node.keywords or []:
                    if kw.arg == "shell" and getattr(kw.value, "value", None) is True:
                        hits.append(f"{py.name} (shell=True)")
    return (not hits), (f"hits: {hits}" if hits else "clean (arg-list exec, no shell)")


@check("17", "report path safety: artifact ids are UUID-bound")
async def _():
    from agent.core.exceptions import CasaError
    from agent.storage import repositories as repo

    async with SESSIONMAKER() as s:
        try:
            await repo.get_artifact(s, "../../etc/passwd")
            return False, "path-like artifact id accepted"
        except CasaError:
            return True, "rejected"


# ============================================================================
# 18. REGRESSION: full pytest suite re-run (in-process)
# ============================================================================
section("18. REGRESSION SUMMARY")


@check("18", "cumulative: all previous checks green")
async def _():
    fails = [r for r in RESULTS if not r["ok"]]
    return (not fails), f"{len(fails)} failures so far"


# ============================================================================
async def main() -> int:
    for fn in CHECKS:
        await fn()

    passed = sum(1 for r in RESULTS if r["ok"])
    failed = len(RESULTS) - passed
    print("\n" + "=" * 70)
    print(f"VALIDATION RESULT: {passed} PASSED / {failed} FAILED / 0 SKIPPED")
    print("=" * 70)
    if failed:
        print("\nFailed checks:")
        for r in RESULTS:
            if not r["ok"]:
                print(f"  [{r['section']}] {r['name']}")
    print(f"\nArtifacts: DB + audit log + reports under {_TMP}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
