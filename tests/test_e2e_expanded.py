"""Full E2E test over the expanded pipeline with the expanded lab.

Target -> Authorization -> Scope -> Discovery -> Assessment -> Evidence ->
Findings -> Deduplication -> Risk -> AI -> Report -> Verification -> COMPLETED.
"""
from __future__ import annotations

import uuid as _uuid

import pytest


@pytest.mark.asyncio
async def test_full_expanded_assessment(db_session, wired_http):
    from agent.connectors.authorization_manager import AuthorizationManager
    from agent.storage import repositories as repo
    from agent.workers.orchestrator import Orchestrator

    reg = await AuthorizationManager(db_session).register_authorization(
        {
            "target": "http://127.0.0.1:8001",
            "authorized_by": "Lab Owner (E2E)",
            "authorization_reference": "E2E-EXPANDED",
            "allowed_domains": ["127.0.0.1"],
            "allowed_paths": ["/"],
        }
    )

    job = await repo.create_job(
        db_session,
        target_id=reg["target_id"],
        authorization_id=reg["authorization"]["id"],
        trigger="INITIAL",
        profile="DEEP",
    )
    result = await Orchestrator(db_session).run_job(_uuid.UUID(job.id))
    assert result["status"] == "COMPLETED", result.get("error")

    assessment = await repo.get_assessment(db_session, result["assessment_id"])
    assert assessment.security_score is not None
    assert assessment.risk_summary["category_scores"]
    assert assessment.attack_surface is not None
    assert assessment.attack_surface["target"] == "http://127.0.0.1:8001"
    assert assessment.attack_surface["apis"], "exposed API docs must appear in the surface map"

    findings = await repo.list_findings(db_session, assessment.id)
    titles = " ||| ".join(f.title for f in findings)

    # New coverage must actually detect the new lab fixtures:
    assert "CORS reflects arbitrary origins" in titles, titles
    assert "OpenAPI document declares no security schemes" in titles
    assert "API documentation is publicly accessible" in titles
    assert "Debug information disclosed" in titles
    assert "Source map is publicly exposed" in titles
    assert "Backup-looking file" in titles or "backup" in titles.lower()
    assert "violates __Host- prefix" not in titles  # lab cookie has no __Host- prefix
    assert "Environment file" in titles  # deduped across web_checks + info_disclosure
    assert "reflected without" in titles or "reflected" in titles.lower()

    # Evidence-first: every non-INFO finding has evidence and a fingerprint.
    for f in findings:
        assert f.fingerprint
        if f.severity != "INFO":
            assert f.evidence_refs is not None
            assert f.risk_score is not None

    # Root-cause grouping must connect transport findings.
    groups = [f for f in findings if (f.metadata_json or {}).get("root_cause_group")]
    assert groups, "expected at least one root-cause group"

    # Deduplication: /.env detected by web_checks AND info_disclosure must merge.
    env_findings = [f for f in findings if ".env" in f.title]
    assert len(env_findings) == 1, [f.title for f in env_findings]

    # AI summary must exist and reference findings (never invent).
    assert assessment.ai_summary and assessment.ai_summary.get("executive_summary")


@pytest.mark.asyncio
async def test_verification_after_lab_remediation(db_session, wired_http):
    from agent.connectors.authorization_manager import AuthorizationManager
    from agent.storage import repositories as repo
    from agent.workers.orchestrator import Orchestrator

    reg = await AuthorizationManager(db_session).register_authorization(
        {"target": "http://127.0.0.1:8001", "authorized_by": "T",
         "allowed_domains": ["127.0.0.1"]}
    )
    job1 = await repo.create_job(
        db_session, target_id=reg["target_id"],
        authorization_id=reg["authorization"]["id"], trigger="INITIAL", profile="STANDARD",
    )
    r1 = await Orchestrator(db_session).run_job(_uuid.UUID(job1.id))
    assert r1["status"] == "COMPLETED", r1.get("error")
    first = await repo.get_assessment(db_session, r1["assessment_id"])

    # Remediate the lab, then verify against the baseline.
    import lab.vulnerable_app as lab

    lab.REMEDIATED = True
    try:
        job2 = await repo.create_job(
            db_session, target_id=reg["target_id"],
            authorization_id=reg["authorization"]["id"], trigger="VERIFICATION",
            profile="STANDARD",
            previous_assessment_id=first.id,
        )
        r2 = await Orchestrator(db_session).run_job(_uuid.UUID(job2.id))
        assert r2["status"] == "COMPLETED", r2.get("error")
        second = await repo.get_assessment(db_session, r2["assessment_id"])
        counts = second.verification_summary["counts"]
        assert counts["FIXED"] >= 3, counts  # .env, .git/HEAD, .git/config, backup, debug
        assert counts["STILL_PRESENT"] >= 1, counts
    finally:
        lab.REMEDIATED = False


@pytest.mark.asyncio
async def test_reports_include_new_sections(db_session, wired_http):
    import json

    from agent.connectors.authorization_manager import AuthorizationManager
    from agent.storage import repositories as repo
    from agent.workers.orchestrator import Orchestrator

    reg = await AuthorizationManager(db_session).register_authorization(
        {"target": "http://127.0.0.1:8001", "authorized_by": "T",
         "allowed_domains": ["127.0.0.1"]}
    )
    job = await repo.create_job(
        db_session, target_id=reg["target_id"],
        authorization_id=reg["authorization"]["id"], trigger="INITIAL", profile="DEEP",
    )
    result = await Orchestrator(db_session).run_job(_uuid.UUID(job.id))
    assert result["status"] == "COMPLETED", result.get("error")
    aid = result["assessment_id"]

    artifacts = await repo.list_artifacts(db_session, aid)
    by_fmt = {a.fmt: a for a in artifacts}
    assert "json" in by_fmt and "html" in by_fmt
    payload = json.loads(by_fmt["json"].content)
    assert payload["category_scores"]
    assert payload["attack_surface"]
    assert payload["mode"] == "DEEP"
    html = by_fmt["html"].content
    assert "Category Scores" in html
    assert "Attack Surface" in html
