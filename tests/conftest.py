"""Shared pytest fixtures."""
from __future__ import annotations

import os
import tempfile

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

_TMP = tempfile.mkdtemp(prefix="casa-test-")
os.environ.setdefault("CASA_DATABASE_URL", f"sqlite+aiosqlite:///{_TMP}/casa-test.db")
os.environ.setdefault("CASA_LLM_PROVIDER", "heuristic")
os.environ.setdefault("CASA_AUDIT_LOG_PATH", _TMP + "/audit.log")


@pytest_asyncio.fixture
async def db_session():
    from agent.storage import models  # noqa: F401 — register tables on Base.metadata
    from agent.storage.database import AsyncSessionLocal, Base, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def validator():
    from agent.core.target import ScopeValidator

    return ScopeValidator(
        allowed_domains=["127.0.0.1"],
        allowed_paths=["/"],
        excluded_targets=[],
    )


@pytest.fixture
def sample_finding():
    from agent.core.finding import make_finding, make_fingerprint

    def _make(**overrides):
        f = make_finding(
            title="Test finding",
            category="CONFIGURATION",
            severity="MEDIUM",
            confidence="HIGH",
            description="desc",
            evidence=[{"type": "http_header", "value": "x"}],
            affected_asset="http://127.0.0.1:8001",
            source="unit-test",
        )
        f["fingerprint"] = make_fingerprint("unit", "test")
        for k, v in overrides.items():
            f[k] = v
        return f

    return _make


@pytest_asyncio.fixture
async def lab_client():
    from lab.vulnerable_app import app as lab_app

    async with AsyncClient(
        transport=ASGITransport(app=lab_app), base_url="http://127.0.0.1:8001"
    ) as ac:
        yield ac


@pytest.fixture
def wired_http(lab_client, monkeypatch):
    """Route all outbound SafeHttpClient/httpx + DNS calls to the in-process lab."""
    import agent.core.safe_http as sh
    import agent.connectors.adapters as ad
    import agent.modules.dns_queries as dq

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None):
            req = lab_client.build_request(method, url, headers=headers or {})
            return await lab_client.send(req)

    monkeypatch.setattr(sh.httpx, "AsyncClient", FakeAsyncClient)

    async def fake_dns(fn=None, *a, **kw):
        return [(2, 1, 6, "", ("127.0.0.1", 0))]

    async def fake_resolve(host, rtype, timeout=5.0):
        if rtype == "TXT" and not host.startswith("_dmarc"):
            return ["v=spf1 include:_spf.lab.test ~all"]
        if rtype == "TXT":
            return ["v=DMARC1; p=reject; rua=mailto:d@lab.test"]
        if rtype == "CAA":
            return ['0 issue "letsencrypt.org"']
        return ["0"]

    monkeypatch.setattr(ad, "_run_in_thread", fake_dns)
    monkeypatch.setattr(dq, "_resolve", fake_resolve)
    yield


@pytest_asyncio.fixture
async def client(db_session):
    from agent.api.main import app
    from agent.api.state import set_app_state
    from agent.workers.queue import JobQueue
    from agent.storage.database import AsyncSessionLocal

    queue = JobQueue(AsyncSessionLocal)
    queue.start()
    set_app_state(queue)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    await queue.stop()
