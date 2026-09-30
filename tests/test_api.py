"""API-level tests: authorization gate on job creation, assessment read APIs."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_authorize_and_run_via_api(db_session, client, wired_http):
    # register authorization
    resp = await client.post(
        "/api/v1/authorizations",
        json={
            "target": "http://127.0.0.1:8001",
            "authorized_by": "API Test",
            "authorization_reference": "API-1",
            "allowed_domains": ["127.0.0.1"],
            "allowed_paths": ["/"],
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["authorization"]["authorized_by"] == "API Test"
    target_id = body["target_id"]

    # create job -> 202, worker runs it inline
    resp = await client.post(
        "/api/v1/jobs", json={"target_id": target_id, "trigger": "INITIAL"}
    )
    assert resp.status_code == 202
    job_id = resp.json()["id"]

    # the inline worker is async; poll briefly
    import asyncio

    final = None
    for _ in range(50):
        await asyncio.sleep(0.05)
        r = await client.get(f"/api/v1/jobs/{job_id}")
        if r.json()["status"] in ("COMPLETED", "FAILED", "BLOCKED"):
            final = r.json()
            break
    assert final and final["status"] == "COMPLETED", final

    # fetch assessment by target
    r = await client.get(f"/api/v1/assessments?target_id={target_id}")
    assert r.status_code == 200
    assessment = r.json()[0]
    assert assessment["security_score"] is not None

    r = await client.get(f"/api/v1/assessments/{assessment['id']}/findings")
    findings = r.json()
    assert findings
    assert any(".env" in f["title"] for f in findings)

    r = await client.get(f"/api/v1/assessments/{assessment['id']}/reports")
    reports = r.json()
    assert {a["fmt"] for a in reports} == {"json", "html"}

    r = await client.get(f"/api/v1/assessments/{assessment['id']}/evidence")
    assert r.status_code == 200
    assert r.json(), "evidence bundle should be persisted"


@pytest.mark.asyncio
async def test_job_without_authorization_403(db_session, client):
    from agent.storage import repositories as repo
    from agent.storage.models import Target

    target = Target(
        url="http://gate-test.example.internal:8001", target_type="WEB_APP"
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    resp = await client.post(
        "/api/v1/jobs", json={"target_id": target.id, "trigger": "INITIAL"}
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_path_window_enforced_at_job_creation(db_session, client):
    """Authorization whose allowed_paths exclude the target root must 403 fast."""
    resp = await client.post(
        "/api/v1/authorizations",
        json={
            "target": "http://127.0.0.1:8001",
            "authorized_by": "Scope Test",
            "authorization_reference": "SC-1",
            "allowed_domains": ["127.0.0.1"],
            "allowed_paths": ["/admin"],
        },
    )
    assert resp.status_code == 201
    target_id = resp.json()["target_id"]

    # Target root is outside allowed_paths [/admin] -> gate rejects at creation.
    resp = await client.post(
        "/api/v1/jobs", json={"target_id": target_id, "trigger": "INITIAL"}
    )
    assert resp.status_code == 403
    assert "gate" in resp.json()["detail"].lower()
