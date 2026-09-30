"""Deliberately vulnerable local test target for CASA (DO NOT expose publicly).

This app exists ONLY so the agent can be tested end-to-end against a local,
authorized target. It intentionally exhibits issues the MVP checks can find:

- missing security headers
- an insecure session cookie (missing Secure/HttpOnly/SameSite)
- /.git/HEAD + /.git/config exposure
- /.env exposure (with FAKE secrets)
- directory listing at /files
- sensitive paths referenced in robots.txt
- permissive SPF-like TXT fixture is NOT part of this app (see lab fixtures note)
- exposed API documentation (/docs + /openapi.json)
- weak CORS (reflected origin + credentials) at /api/reflect
- debug/stack-trace page at /debug
- query parameter reflection without encoding at /search
- backup file at /backup.zip (marker content only)
- source map at /app.js.map
- sitemap.xml with entries

REMEDIATED flips the fixable exposures off for verification E2E tests.
Run: python -m lab.vulnerable_app   (listens on 127.0.0.1:8001 by default)
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

FAKE_ENV = """DATABASE_URL=postgres://lab:lab@localhost/lab
SECRET_KEY=super-secret-do-not-use
API_KEY=sk-test-000111222333
"""

GIT_HEAD = "ref: refs/heads/main\n"
GIT_CONFIG = """[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://gitlab.local/lab/shop.git
"""

BACKUP_BYTES = b"PK\x03\x04 lab-backup-archive-marker"

SOURCEMAP = """{"version": 3, "sources": ["webpack:///src/index.js"], "mappings": "AAAA"}"""

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Lab Shop API", "version": "1.0.0"},
    "servers": [{"url": "http://127.0.0.1:8001"}],
    "paths": {
        "/api/items": {
            "get": {"summary": "List items", "responses": {"200": {"description": "ok"}}},
            "post": {"summary": "Create item", "responses": {"201": {"description": "ok"}}},
        },
        "/api/orders": {
            "get": {"summary": "List orders", "responses": {"200": {"description": "ok"}}},
        },
    },
    # NOTE: intentionally NO components/securitySchemes and NO security field.
}

FILES = ["report-q1.pdf", "old-backup.zip", "notes.txt"]

# Flip to True to simulate remediation (e.g. /.env removed from the web root).
# Used by the verification E2E test: findings that disappear become FIXED.
REMEDIATED = False


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    # Insecure session cookie (missing Secure/HttpOnly/SameSite) on the main page.
    # NOTE: the cookie must be set on the RETURNED response — a cookie set on
    # FastAPI's injected Response parameter is dropped when a Response object
    # is returned directly.
    resp = HTMLResponse(
        "<html><head><title>Lab Shop</title></head><body>"
        "<h1>CASA Vulnerable Lab</h1>"
        "<p>This intentionally misconfigured app is used to validate the agent.</p>"
        "<a href='/search?q=lab'>search demo</a>"
        "<a href='/api/reflect'>api demo</a>"
        "<script src='/static/jquery-3.5.1.min.js'></script>"
        "</body></html>"
    )
    resp.set_cookie(key="sessionid", value="lab-session-token", samesite=None)
    return resp


@app.get("/search", response_class=HTMLResponse)
async def search(q: str = "") -> HTMLResponse:
    # Reflected query parameter WITHOUT output encoding (XSS prerequisite).
    safe_q = q.replace("<", "").replace(">", "")  # reflect raw otherwise
    return HTMLResponse(
        f"<html><head><title>Lab Shop Search</title></head><body>"
        f"<h1>Results for: {safe_q}</h1></body></html>"
    )


@app.get("/api/reflect", response_class=JSONResponse)
async def cors_reflect(request: Request) -> JSONResponse:
    # Weak CORS: reflects any Origin with credentials allowed.
    origin = request.headers.get("origin", "")
    headers = {}
    if origin:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"
    return JSONResponse(
        {"items": [], "authenticated_as": "anonymous-demo"}, headers=headers
    )


@app.get("/openapi.json", response_class=JSONResponse)
async def openapi_json() -> JSONResponse:
    return JSONResponse(OPENAPI_SPEC)


@app.get("/docs", response_class=HTMLResponse)
async def docs_page() -> HTMLResponse:
    return HTMLResponse(
        "<html><head><title>Swagger UI - Lab Shop API</title></head>"
        "<body><div id='swagger-ui'></div></body></html>"
    )


@app.get("/debug", response_class=PlainTextResponse)
async def debug_page() -> PlainTextResponse:
    if REMEDIATED:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Not Found (remediated)")
    return PlainTextResponse(
        "Traceback (most recent call last):\n"
        '  File "/var/www/lab/app.py", line 42, in handler\n'
        "ZeroDivisionError: division by zero\n"
    )


@app.get("/files", response_class=HTMLResponse)
async def files() -> HTMLResponse:
    rows = "".join(f"<li><a href='/files/{f}'>{f}</a></li>" for f in FILES)
    return HTMLResponse(
        f"<html><head><title>Index of /files</title></head><body>"
        f"<h1>Directory listing for /files</h1><ul>{rows}</ul></body></html>"
    )


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots() -> PlainTextResponse:
    return PlainTextResponse(
        "User-agent: *\nDisallow: /admin\nDisallow: /private/backup\n"
    )


@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap() -> PlainTextResponse:
    return PlainTextResponse(
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
        "<url><loc>http://127.0.0.1:8001/</loc></url>"
        "<url><loc>http://127.0.0.1:8001/files</loc></url>"
        "</urlset>"
    )


@app.get("/backup.zip")
async def backup() -> Response:
    if REMEDIATED:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Not Found (remediated)")
    return Response(content=BACKUP_BYTES, media_type="application/zip")


@app.get("/app.js.map", response_class=PlainTextResponse)
async def source_map() -> PlainTextResponse:
    return PlainTextResponse(SOURCEMAP, media_type="application/json")


@app.get("/.env", response_class=PlainTextResponse)
async def dot_env() -> PlainTextResponse:
    if REMEDIATED:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Not Found (remediated)")
    return PlainTextResponse(FAKE_ENV)


@app.get("/.git/HEAD", response_class=PlainTextResponse)
async def git_head() -> PlainTextResponse:
    if REMEDIATED:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Not Found (remediated)")
    return PlainTextResponse(GIT_HEAD)


@app.get("/.git/config", response_class=PlainTextResponse)
async def git_config() -> PlainTextResponse:
    if REMEDIATED:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Not Found (remediated)")
    return PlainTextResponse(GIT_CONFIG)


@app.get("/admin", response_class=HTMLResponse)
async def admin() -> HTMLResponse:
    return HTMLResponse("<html><body><h1>Fake admin panel</h1></body></html>")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("LAB_HOST", "127.0.0.1"),
        port=int(os.environ.get("LAB_PORT", "8001")),
        log_level="warning",
    )
