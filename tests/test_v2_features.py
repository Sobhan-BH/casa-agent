"""Tests for v0.2.0 features: CVSS engine, WAF detection, SARIF export,
attack mapping, API security middleware, webhook payloads, scheduler, OSV."""
from __future__ import annotations

import json

import pytest


# ------------------------------------------------------------------ CVSS
class TestCVSS31:
    def test_known_vector_score(self):
        from agent.core.cvss import CVSS31

        # Official example: CVE-2022-22965 (SpringShell) base vector
        v = CVSS31.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert v.score == 9.8
        assert v.severity == "CRITICAL"

    def test_scope_changed_math(self):
        from agent.core.cvss import CVSS31

        v = CVSS31.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert v.score == 10.0

    def test_official_severity_bands(self):
        from agent.core.cvss import CVSS31

        # Expectations verified by hand against the FIRST.org spec formulas.
        cases = [
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.7, "LOW"),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L", 5.7, "MEDIUM"),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L", 7.9, "HIGH"),
        ]
        for vector, expected, sev in cases:
            v = CVSS31.parse(vector)
            assert v.score == expected, vector
            assert v.severity == sev

    def test_malformed_vectors_rejected(self):
        from agent.core.cvss import CVSS31, CVSSVectorError

        for bad in ["", "not-a-vector", "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]:
            with pytest.raises(CVSSVectorError):
                CVSS31.parse(bad)

    def test_synthetic_vector_mapping(self):
        from agent.core.cvss import CVSS31, severity_to_synthetic_vector

        # Each synthetic vector must land inside its own severity band.
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            v = CVSS31.parse(severity_to_synthetic_vector(severity))
            assert v.severity == severity, (
                f"{severity} mapped to {v.vector} which scores {v.score} ({v.severity})"
            )
        assert CVSS31.parse(severity_to_synthetic_vector("CRITICAL")).score == 10.0
        assert CVSS31.parse(severity_to_synthetic_vector("INFO")).score == 0.0

    def test_score_to_severity_boundaries(self):
        from agent.core.cvss import score_to_severity

        assert score_to_severity(0.0) == "INFO"
        assert score_to_severity(0.1) == "LOW"
        assert score_to_severity(3.9) == "LOW"
        assert score_to_severity(4.0) == "MEDIUM"
        assert score_to_severity(6.9) == "MEDIUM"
        assert score_to_severity(7.0) == "HIGH"
        assert score_to_severity(8.9) == "HIGH"
        assert score_to_severity(9.0) == "CRITICAL"
        assert score_to_severity(10.0) == "CRITICAL"


# ------------------------------------------------- risk engine CVSS wiring
class TestRiskEngineCVSS:
    def test_every_finding_gets_cvss(self, sample_finding):
        from agent.risk.engine import RiskEngine

        engine = RiskEngine()
        result = engine.score_finding(sample_finding())
        assert result["cvss"] is not None
        assert result["cvss"]["vector"].startswith("CVSS:3.1/")
        assert 0.0 <= result["cvss"]["score"] <= 10.0

    def test_vendor_vector_respected(self, sample_finding):
        from agent.risk.engine import RiskEngine

        f = sample_finding(
            severity="LOW",
            metadata={"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        )
        result = RiskEngine().score_finding(f)
        assert result["cvss"]["score"] == 9.8  # vendor vector wins over severity

    def test_summary_includes_avg_cvss(self, sample_finding):
        from agent.risk.engine import RiskEngine

        summary = RiskEngine().compute([sample_finding(), sample_finding()])
        assert "avg_cvss_base_score" in summary
        assert summary["avg_cvss_base_score"] is not None


# ------------------------------------------------------------ WAF detection
class TestWafDetect:
    def test_cloudflare_header_detected(self):
        from agent.modules.waf_detect import WafDetectModule
        from agent.core.context import AssessmentContext
        from uuid import uuid4

        ctx = AssessmentContext(
            job_id=uuid4(), assessment_id=uuid4(),
            target_url="http://127.0.0.1:8001", base_domain="127.0.0.1",
            scope={},
        )
        ctx.raw_results["http_root"] = {
            "headers": {"server": "cloudflare", "cf-ray": "abc123"},
            "body": "",
            "cookies": [],
        }
        module = WafDetectModule(None)
        import asyncio
        asyncio.run(module.run(ctx))

        assert "Cloudflare" in ctx.raw_results["waf"]["detected"]
        assert any(f["source"] == "waf_detect" for f in ctx.findings)

    def test_no_waf_no_finding(self):
        from agent.modules.waf_detect import WafDetectModule
        from agent.core.context import AssessmentContext
        from uuid import uuid4

        ctx = AssessmentContext(
            job_id=uuid4(), assessment_id=uuid4(),
            target_url="http://127.0.0.1:8001", base_domain="127.0.0.1",
            scope={},
        )
        ctx.raw_results["http_root"] = {
            "headers": {"server": "werkzeug/3.0.0"}, "body": "", "cookies": [],
        }
        import asyncio
        asyncio.run(WafDetectModule(None).run(ctx))
        assert ctx.raw_results["waf"]["detected"] == []
        assert not ctx.findings


# --------------------------------------------------------- attack mapping
class TestAttackMapping:
    def test_secret_file_maps_to_credentials(self):
        from agent.analysis.attack_mapping import AttackMappingModule

        f = {"title": "Dot-env file publicly exposed (.env)", "references": [], "metadata": {}}
        ctx = type("Ctx", (), {"findings": [f], "raw_results": {}})()
        import asyncio
        asyncio.run(AttackMappingModule(None).run(ctx))

        mitre = f["metadata"]["mitre_attack"]
        assert any(t["id"] == "T1552" for t in mitre)
        assert any("attack.mitre.org" in r for r in f["references"])

    def test_unmapped_finding_untouched(self):
        from agent.analysis.attack_mapping import AttackMappingModule

        f = {"title": "Completely unrelated title xyzzy", "references": [], "metadata": {}}
        ctx = type("Ctx", (), {"findings": [f], "raw_results": {}})()
        import asyncio
        asyncio.run(AttackMappingModule(None).run(ctx))
        assert "mitre_attack" not in f["metadata"]


# ------------------------------------------------------------------ SARIF
class TestSarif:
    def test_valid_sarif_structure(self, sample_finding):
        from agent.reports.sarif import build_sarif_report

        f = sample_finding(severity="HIGH")
        report = json.loads(
            json.dumps(build_sarif_report("http://example.com", [f], 42.0))
        )
        assert report["version"] == "2.1.0"
        run = report["runs"][0]
        assert run["tool"]["driver"]["name"] == "CASA"
        assert len(run["tool"]["driver"]["rules"]) == len(run["results"]) == 1
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "7.5"
        assert run["results"][0]["level"] == "error"

    def test_mitre_tags_flow_into_sarif(self, sample_finding):
        from agent.reports.sarif import build_sarif_report

        f = sample_finding(
            title=".env file exposed",
            metadata={"mitre_attack": [{"id": "T1552", "name": "Unsecured Credentials",
                                        "tactic": "Credential Access",
                                        "url": "https://attack.mitre.org/techniques/T1552/"}]},
        )
        report = build_sarif_report("http://x", [f])
        rule = report["runs"][0]["tool"]["driver"]["rules"][0]
        assert "T1552" in rule["properties"]["tags"]


# ------------------------------------------------------------ API security
class TestApiSecurity:
    def test_rate_limiter_window(self):
        from agent.api.security import RateLimiter

        limiter = RateLimiter(3)
        assert limiter.check("ip1") == (True, 0)
        assert limiter.check("ip1") == (True, 0)
        assert limiter.check("ip1") == (True, 0)
        allowed, retry = limiter.check("ip1")
        assert not allowed and retry > 0
        assert limiter.check("ip2") == (True, 0)  # other key unaffected

    def test_middleware_disabled_by_default(self):
        from agent.core.config import settings

        assert settings.api_key == ""
        assert settings.rate_limit_rpm == 0

    def test_middleware_blocks_without_key(self, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from agent.api.security import install_api_security
        from agent.core.config import settings

        monkeypatch.setattr(settings, "api_key", "secret123")
        app = FastAPI()
        install_api_security(app)

        @app.get("/api/v1/ping")
        async def ping():
            return {"ok": True}

        @app.get("/health")
        async def health():
            return {"ok": True}

        c = TestClient(app)
        assert c.get("/api/v1/ping").status_code == 401
        assert c.get("/api/v1/ping", headers={"X-API-Key": "wrong"}).status_code == 401
        assert c.get("/api/v1/ping", headers={"X-API-Key": "secret123"}).status_code == 200
        assert c.get("/health").status_code == 200  # open path

    def test_middleware_rate_limits(self, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from agent.api.security import install_api_security
        from agent.core.config import settings

        monkeypatch.setattr(settings, "rate_limit_rpm", 2)
        app = FastAPI()
        install_api_security(app)

        @app.get("/api/v1/ping")
        async def ping():
            return {"ok": True}

        c = TestClient(app)
        assert c.get("/api/v1/ping").status_code == 200
        assert c.get("/api/v1/ping").status_code == 200
        r = c.get("/api/v1/ping")
        assert r.status_code == 429
        assert int(r.headers["Retry-After"]) >= 1


# ---------------------------------------------------------------- webhook
class TestWebhook:
    def test_payloads_per_format(self, monkeypatch):
        from agent.analysis import notify
        from agent.core.config import settings

        payload = {"target": "http://x", "security_score": 80, "findings": 3,
                   "severity_distribution": {"HIGH": 2, "LOW": 1}}
        monkeypatch.setattr(settings, "webhook_format", "slack")
        p = notify.build_payload("JOB_COMPLETED", payload)
        assert "text" in p and "80/100" in p["text"]

        monkeypatch.setattr(settings, "webhook_format", "discord")
        p = notify.build_payload("JOB_COMPLETED", payload)
        assert "content" in p

        monkeypatch.setattr(settings, "webhook_format", "generic")
        p = notify.build_payload("JOB_COMPLETED", payload)
        assert p["event"] == "JOB_COMPLETED" and p["security_score"] == 80

    async def test_disabled_webhook_is_noop(self, monkeypatch):
        from agent.analysis.notify import send_webhook
        from agent.core.config import settings

        monkeypatch.setattr(settings, "webhook_url", "")
        receipt = await send_webhook("JOB_COMPLETED", {"target": "x"})
        assert receipt == {"sent": False, "reason": "disabled_or_unsubscribed"}


# -------------------------------------------------------------- dashboard
class TestDashboard:
    @pytest.mark.asyncio
    async def test_dashboard_renders(self, client):
        r = await client.get("/dashboard")
        assert r.status_code == 200
        assert "CASA Dashboard" in r.text
        assert "Latest assessments" in r.text

    @pytest.mark.asyncio
    async def test_sarif_endpoint(self, db_session, client):
        from agent.storage import repositories as repo
        from agent.storage.models import Assessment, Job, Target

        target = Target(url="http://127.0.0.1:8099")  # unique across the suite
        db_session.add(target)
        await db_session.commit()
        await db_session.refresh(target)
        job = Job(target_id=target.id, status="COMPLETED", trigger="INITIAL")
        db_session.add(job)
        await db_session.commit()
        await db_session.refresh(job)
        a = Assessment(job_id=job.id, target_id=target.id, target_url=target.url,
                       base_domain="127.0.0.1:8099", status="COMPLETED",
                       security_score=50.0)
        db_session.add(a)
        await db_session.commit()
        await db_session.refresh(a)
        await repo.save_findings(db_session, a.id, [{
            "title": "T", "category": "CONFIGURATION", "severity": "LOW",
            "confidence": "HIGH", "description": "d", "evidence": [],
            "affected_asset": "http://x", "impact": "", "remediation": "",
            "references": [], "source": "test", "fingerprint": "fp123",
        }])

        r = await client.get(f"/api/v1/assessments/{a.id}/sarif")
        assert r.status_code == 200
        body = r.json()
        assert body["version"] == "2.1.0"
        assert body["runs"][0]["results"][0]["partialFingerprints"]["casaFingerprint/v1"] == "fp123"


# ------------------------------------------------------------- OSV parser
class TestOsvParsing:
    def test_version_range_logic(self):
        from agent.modules.osv_enrichment import _in_range, _version_tuple

        assert _version_tuple("3.0.2") == (3, 0, 2)
        assert _version_tuple("2.1.0b2") == (2, 1, 0)
        assert _version_tuple(None) is None
        v = (3, 0, 2)
        assert _in_range(v, {"type": "LT", "value": "3.0.3"})
        assert not _in_range(v, {"type": "LT", "value": "3.0.2"})
        assert _in_range(v, {"type": "EQ", "value": "3.0.2"})

    def test_affected_check_with_fixed(self):
        from agent.modules.osv_enrichment import _version_affected

        affected = {"ranges": [{"events": [{"introduced": "3.0.0"}, {"fixed": "3.0.3"}]}]}
        assert _version_affected("3.0.2", affected) is True
        assert _version_affected("3.0.4", affected) is False
        assert _version_affected(None, affected) is None
