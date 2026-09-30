"""FindingNormalizer tests."""
import pytest

from agent.analysis.normalizer import FindingNormalizerModule
from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint


def _ctx() -> AssessmentContext:
    from uuid import uuid4

    return AssessmentContext(
        job_id=uuid4(),
        assessment_id=uuid4(),
        target_url="http://127.0.0.1:8001",
        base_domain="127.0.0.1",
        scope={},
    )


@pytest.mark.asyncio
async def test_dedupes_by_fingerprint():
    fp = make_fingerprint("x", "y")
    a = make_finding("Same title", "CONFIGURATION", "LOW", "HIGH", "d", source="mod_a")
    b = make_finding("Same title", "CONFIGURATION", "LOW", "HIGH", "d", source="mod_b")
    a["fingerprint"] = fp
    b["fingerprint"] = fp
    ctx = _ctx()
    ctx.findings = [a, b]
    await FindingNormalizerModule(None).run(ctx)
    assert len(ctx.findings) == 1
    assert ctx.findings[0]["metadata"]["also_reported_by"] == ["mod_b"]


@pytest.mark.asyncio
async def test_flags_evidenceless_findings():
    f = make_finding("No evidence", "WEB", "HIGH", "HIGH", "d")
    f["fingerprint"] = make_fingerprint("noev", "1")
    ctx = _ctx()
    ctx.findings = [f]
    await FindingNormalizerModule(None).run(ctx)
    assert ctx.findings[0]["metadata"]["false_positive_risk"] == "HIGH"
    assert ctx.findings[0]["confidence"] == "LOW"


@pytest.mark.asyncio
async def test_drops_invalid_category():
    bad = {"title": "x", "category": "BOGUS", "severity": "HIGH", "confidence": "HIGH"}
    ctx = _ctx()
    ctx.findings = [bad]
    await FindingNormalizerModule(None).run(ctx)
    assert ctx.findings == []
    assert ctx.raw_results["normalization"]["dropped_invalid"] == 1


@pytest.mark.asyncio
async def test_keeps_info_without_evidence():
    f = make_finding("Info ok", "RECON", "INFO", "MEDIUM", "d")
    f["fingerprint"] = make_fingerprint("info", "1")
    ctx = _ctx()
    ctx.findings = [f]
    await FindingNormalizerModule(None).run(ctx)
    assert len(ctx.findings) == 1
    assert "false_positive_risk" not in ctx.findings[0]["metadata"]
