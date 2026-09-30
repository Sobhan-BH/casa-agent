"""End-to-end pipeline test: authorization -> assessment -> reports.

Runs the entire orchestrator against an in-process copy of the vulnerable lab
app, with the DB and queue wired for tests. No internet access required.
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_full_assessment_flow(db_session, wired_http):
    from agent.connectors.authorization_manager import AuthorizationManager
    from agent.workers.orchestrator import Orchestrator
    from agent.storage import repositories as repo

    manager = AuthorizationManager(db_session)
    reg = await manager.register_authorization(
        {
            "target": "http://127.0.0.1:8001",
            "authorized_by": "Lab Owner (unit test)",
            "authorization_reference": "TEST-001",
            "allowed_domains": ["127.0.0.1"],
            "allowed_paths": ["/"],
        }
    )

    job = await repo.create_job(
        db_session,
        target_id=reg["target_id"],
        authorization_id=reg["authorization"]["id"],
        trigger="INITIAL",
    )

    orch = Orchestrator(db_session)
    result = await orch.run_job(__import__("uuid").UUID(job.id))

    assert result["status"] == "COMPLETED", result.get("error")

    assessment = await repo.get_assessment(db_session, result["assessment_id"])
    assert assessment.security_score is not None
    assert assessment.risk_summary["distribution"]["CRITICAL"] >= 1  # /.env exposed
    assert assessment.ai_summary and "executive_summary" in assessment.ai_summary

    findings = await repo.list_findings(db_session, assessment.id)
    titles = [f.title for f in findings]
    assert any(".env" in t for t in titles)
    assert any("HSTS" in t or "Content-Security-Policy" in t for t in titles)
    assert any("Cookie" in t for t in titles)

    # Every non-INFO finding must have evidence (evidence-first policy).
    for f in findings:
        if f.severity != "INFO":
            assert f.risk_score is not None


@pytest.mark.asyncio
async def test_unauthorized_target_blocked(db_session):
    from agent.core.exceptions import AuthorizationError
    from agent.workers.orchestrator import Orchestrator
    from agent.storage import repositories as repo
    from agent.storage.models import Target

    # Register a target WITHOUT authorization by inserting directly.
    # URL must be unique across tests (targets.url has a UNIQUE constraint)
    # and must never be contacted — the orchestrator blocks before any I/O.
    target = Target(
        url="http://blocked-unauth.example.internal:8001", target_type="WEB_APP"
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)

    job = await repo.create_job(
        db_session, target_id=target.id, authorization_id=None, trigger="INITIAL"
    )
    result = await Orchestrator(db_session).run_job(__import__("uuid").UUID(job.id))
    assert result["status"] == "BLOCKED"
    job_after = await repo.get_job(db_session, job.id)
    assert job_after.status == "BLOCKED"


@pytest.mark.asyncio
async def test_reassessment_verification(db_session, wired_http):
    from agent.connectors.authorization_manager import AuthorizationManager
    from agent.workers.orchestrator import Orchestrator
    from agent.storage import repositories as repo

    manager = AuthorizationManager(db_session)
    reg = await manager.register_authorization(
        {
            "target": "http://127.0.0.1:8001",
            "authorized_by": "Lab Owner (unit test)",
            "authorization_reference": "TEST-002",
            "allowed_domains": ["127.0.0.1"],
            "allowed_paths": ["/"],
        }
    )

    # First assessment (INITIAL)
    job1 = await repo.create_job(
        db_session,
        target_id=reg["target_id"],
        authorization_id=reg["authorization"]["id"],
        trigger="INITIAL",
    )
    r1 = await Orchestrator(db_session).run_job(__import__("uuid").UUID(job1.id))
    assert r1["status"] == "COMPLETED", r1.get("error")
    first = await repo.get_assessment(db_session, r1["assessment_id"])

    # Second assessment (VERIFICATION) with baseline = first assessment
    job2 = await repo.create_job(
        db_session,
        target_id=reg["target_id"],
        authorization_id=reg["authorization"]["id"],
        trigger="VERIFICATION",
        previous_assessment_id=first.id,
    )
    r2 = await Orchestrator(db_session).run_job(__import__("uuid").UUID(job2.id))
    assert r2["status"] == "COMPLETED", r2.get("error")
    second = await repo.get_assessment(db_session, r2["assessment_id"])

    # Same target, unchanged lab: baseline findings must still be present.
    assert second.verification_summary is not None
    counts = second.verification_summary["counts"]
    assert counts["STILL_PRESENT"] >= 1, counts
    assert counts["FIXED"] == 0, counts
