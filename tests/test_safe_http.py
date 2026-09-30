"""SafeHttpClient tests with a real local HTTP server (no internet)."""
import asyncio

import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from httpx import ASGITransport, AsyncClient

from agent.core.exceptions import ScopeViolationError
from agent.core.safe_http import SafeHttpClient
from agent.core.target import ScopeValidator


@pytest.fixture
def local_app():
    app = FastAPI()

    @app.get("/")
    async def root():
        return PlainTextResponse("hello")

    @app.get("/redirect-escape")
    async def redirect_escape():
        # redirect to a host outside any sane scope
        from fastapi.responses import RedirectResponse
        return RedirectResponse("http://evil.example.com/steal")

    return app


@pytest.fixture
def real_client(local_app):
    return AsyncClient(transport=ASGITransport(app=local_app), base_url="http://127.0.0.1:9999")


def test_safe_methods_only(validator):
    client = SafeHttpClient(validator)
    with pytest.raises(ScopeViolationError):
        asyncio.run(client._request("POST", "http://127.0.0.1:9999/"))


def test_out_of_scope_url_rejected_immediately():
    v = ScopeValidator(allowed_domains=["example.com"], allowed_paths=["/"])
    client = SafeHttpClient(v)
    with pytest.raises(ScopeViolationError):
        asyncio.run(client.get("http://127.0.0.1:9999/"))


@pytest.mark.asyncio
async def test_get_in_scope(real_client, monkeypatch):
    v = ScopeValidator(allowed_domains=["127.0.0.1"], allowed_paths=["/"])
    client = SafeHttpClient(v)

    import agent.core.safe_http as sh

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None):
            req = real_client.build_request(method, url)
            return await real_client.send(req)

    monkeypatch.setattr(sh.httpx, "AsyncClient", FakeAsyncClient)
    resp = await client.get("http://127.0.0.1:9999/")
    assert resp.status_code == 200
    assert "hello" in resp.body


@pytest.mark.asyncio
async def test_redirect_out_of_scope_blocked(real_client, monkeypatch):
    v = ScopeValidator(allowed_domains=["127.0.0.1"], allowed_paths=["/"])
    client = SafeHttpClient(v)

    import agent.core.safe_http as sh

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, headers=None):
            req = real_client.build_request(method, url)
            return await real_client.send(req)

    monkeypatch.setattr(sh.httpx, "AsyncClient", FakeAsyncClient)
    with pytest.raises(ScopeViolationError):
        await client.get("http://127.0.0.1:9999/redirect-escape")
