"""Unit + integration tests for the expanded module set (Phases 1-8, 9)."""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------- helpers
def make_ctx(target="http://127.0.0.1:8001", mode="STANDARD"):
    from uuid import uuid4

    from agent.core.context import AssessmentContext

    return AssessmentContext(
        job_id=uuid4(),
        assessment_id=uuid4(),
        target_url=target,
        base_domain="127.0.0.1",
        scope={"allowed_domains": ["127.0.0.1"], "allowed_paths": ["/"]},
        mode=mode,
    )


def lab_headers(resp) -> dict:
    return {k.lower(): v for k, v in resp.headers.items()}


@pytest.fixture
def validator():
    from agent.core.target import ScopeValidator

    return ScopeValidator(allowed_domains=["127.0.0.1"], allowed_paths=["/"])


# ---------------------------------------------------------------- cookies
class TestCookieParsing:
    def test_parse_set_cookie_redacts_values(self):
        from agent.modules.cookies import parse_set_cookie

        cookies = parse_set_cookie(
            "sessionid=supersecret123; Path=/; HttpOnly; Max-Age=999999999"
        )
        assert len(cookies) == 1
        c = cookies[0]
        assert c["name"] == "sessionid"
        assert c["value_length"] == len("supersecret123")
        # The secret VALUE must not survive parsing.
        assert "supersecret123" not in str(c)

    def test_session_cookie_detection(self):
        from agent.modules.cookies import _is_session_cookie

        assert _is_session_cookie("sessionid")
        assert _is_session_cookie("auth_token")
        assert not _is_session_cookie("theme")

    @pytest.mark.asyncio
    async def test_cookie_findings_have_evidence(self, validator):
        from agent.modules.cookies import CookieSecurityModule

        ctx = make_ctx()
        ctx.raw_results["http_root"] = {
            "url": ctx.target_url,
            "status_code": 200,
            "headers": {"set-cookie": "sessionid=abc; Path=/"},
            "body": "",
        }
        await CookieSecurityModule(validator).run(ctx)
        session_findings = [f for f in ctx.findings if "sessionid" in f["title"]]
        assert len(session_findings) >= 2  # Secure + HttpOnly missing at least
        for f in session_findings:
            assert f["evidence"], f"title={f['title']}"
            assert f["evidence"][0]["value_redacted"] is True
            assert f["fingerprint"]


# ---------------------------------------------------------------- headers
class TestHeadersModule:
    @pytest.mark.asyncio
    async def test_missing_headers_detected_with_evidence(self, validator):
        from agent.modules.headers import HeadersModule

        ctx = make_ctx(target="https://127.0.0.1:8001")
        ctx.raw_results["http_root"] = {
            "url": ctx.target_url,
            "status_code": 200,
            "headers": {},
            "body": "",
        }
        await HeadersModule(validator).run(ctx)
        titles = " ".join(f["title"] for f in ctx.findings)
        assert "HSTS" in titles
        assert "Content-Security-Policy" in titles
        for f in ctx.findings:
            assert f["evidence"]
            assert f["evidence"][0]["type"] == "http_headers_observed"

    @pytest.mark.asyncio
    async def test_weak_csp_and_hsts_variants(self, validator):
        from agent.modules.headers import HeadersModule

        ctx = make_ctx(target="https://127.0.0.1:8001")
        ctx.raw_results["http_root"] = {
            "url": ctx.target_url,
            "status_code": 200,
            "headers": {
                "strict-transport-security": "max-age=100",
                "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
            },
            "body": "",
        }
        await HeadersModule(validator).run(ctx)
        titles = " ".join(f["title"] for f in ctx.findings)
        assert "max-age too short" in titles
        assert "unsafe-inline" in titles
        # No duplicates of the "missing" variants.
        assert "HSTS header missing" not in titles
        assert "CSP header missing" not in titles


# ---------------------------------------------------------------- http_config
class TestHttpConfig:
    @pytest.mark.asyncio
    async def test_plain_http_target_flagged(self, validator):
        from agent.modules.http_config import HttpConfigModule

        ctx = make_ctx()
        ctx.raw_results["http_root"] = {
            "url": ctx.target_url, "status_code": 200, "headers": {}, "body": "", "redirects": []
        }
        await HttpConfigModule(validator).run(ctx)
        assert any("plain HTTP (no TLS)" in f["title"] for f in ctx.findings)
        for f in ctx.findings:
            assert f["evidence"]


# ---------------------------------------------------------------- info disclosure
class TestInfoDisclosure:
    @pytest.mark.asyncio
    async def test_soft_404_not_flagged(self, validator, monkeypatch):
        from agent.modules import info_disclosure as idm

        class FakeResp:
            status_code = 200
            headers = {"content-type": "text/html"}
            body = "<html><head><title>404 Not Found</title></head><body>custom page</body></html>"

        class FakeClient:
            def __init__(self, v):
                pass

            async def get(self, url):
                return FakeResp()

        monkeypatch.setattr(idm, "SafeHttpClient", FakeClient)
        ctx = make_ctx()
        ctx.raw_results["http_root"] = {"url": ctx.target_url, "status_code": 200, "headers": {}, "body": ""}
        await idm.InfoDisclosureModule(validator).run(ctx)
        exposure_findings = [f for f in ctx.findings if "publicly exposed" in f["title"]]
        assert exposure_findings == []  # soft-404s must NOT confirm exposures

    @pytest.mark.asyncio
    async def test_real_env_file_confirmed(self, validator, monkeypatch):
        from agent.modules import info_disclosure as idm

        class FakeResp:
            def __init__(self, path):
                self.status_code = 200
                self.headers = {"content-type": "text/plain"}
                self.body = "SECRET_KEY=abc\n" if path.endswith(".env") else "x"
                self.url = "http://127.0.0.1:8001" + path

        class FakeClient:
            def __init__(self, v):
                pass

            async def get(self, url):
                return FakeResp(url)

        monkeypatch.setattr(idm, "SafeHttpClient", FakeClient)
        ctx = make_ctx()
        ctx.raw_results["http_root"] = {"url": ctx.target_url, "status_code": 200, "headers": {}, "body": ""}
        await idm.InfoDisclosureModule(validator).run(ctx)
        assert any("Environment file" in f["title"] for f in ctx.findings)


# ---------------------------------------------------------------- cors
class TestCorsAnalyzer:
    @pytest.mark.asyncio
    async def test_reflected_origin_with_credentials(self, validator, monkeypatch):
        from agent.modules import cors_analyzer as cam

        class FakeResp:
            status_code = 200
            headers = {}

        class FakeClient:
            def __init__(self, v):
                pass

            async def get(self, url):
                return FakeResp()

            async def get_with_origin(self, url, origin):
                r = FakeResp()
                r.headers = {
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true",
                }
                return r

        monkeypatch.setattr(cam, "SafeHttpClient", FakeClient)
        ctx = make_ctx()
        ctx.raw_results["http_root"] = {"url": ctx.target_url, "status_code": 200, "headers": {}}
        await cam.CorsAnalyzerModule(validator).run(ctx)
        reflected = [f for f in ctx.findings if "reflects arbitrary origins" in f["title"]]
        assert len(reflected) == 1
        assert reflected[0]["severity"] == "HIGH"
        assert reflected[0]["evidence"][0]["probe_origin"] == "https://casa-probe-a.example"

    @pytest.mark.asyncio
    async def test_no_cors_no_findings(self, validator, monkeypatch):
        from agent.modules import cors_analyzer as cam

        class FakeResp:
            status_code = 200
            headers = {}

        class FakeClient:
            def __init__(self, v):
                pass

            async def get(self, url):
                return FakeResp()

        monkeypatch.setattr(cam, "SafeHttpClient", FakeClient)
        ctx = make_ctx()
        ctx.raw_results["http_root"] = {"url": ctx.target_url, "status_code": 200, "headers": {}}
        await cam.CorsAnalyzerModule(validator).run(ctx)
        assert ctx.findings == []


# ---------------------------------------------------------------- discovery
class TestDiscovery:
    @pytest.mark.asyncio
    async def test_openapi_doc_detection(self, validator, monkeypatch):
        from agent.modules import discovery as dm

        bodies = {
            "/openapi.json": '{"openapi": "3.0.0", "info": {"title": "X"}}',
            "/docs": "<html><title>Swagger UI</title></html>",
        }

        class FakeResp:
            def __init__(self, path):
                self.status_code = 200
                self.headers = {"content-type": "text/html"}
                self.body = bodies.get(path, "")
                self.url = "http://127.0.0.1:8001" + path

        class FakeClient:
            def __init__(self, v):
                pass

            async def get(self, url):
                path = url.replace("http://127.0.0.1:8001", "", 1)
                return FakeResp(path)

        monkeypatch.setattr(dm, "SafeHttpClient", FakeClient)
        ctx = make_ctx()
        await dm.DiscoveryModule(validator).run(ctx)
        assert any("API documentation is publicly accessible" in f["title"] for f in ctx.findings)
        assert ctx.raw_results["discovery"]["docs_exposed"]

    @pytest.mark.asyncio
    async def test_endpoint_extraction_scope_filtered(self, validator, monkeypatch):
        from agent.modules import discovery as dm

        class FakeResp:
            status_code = 404
            headers = {}
            body = ""

        class FakeClient:
            def __init__(self, v):
                pass

            async def get(self, url):
                return FakeResp()

        monkeypatch.setattr(dm, "SafeHttpClient", FakeClient)
        ctx = make_ctx()
        ctx.raw_results["robots_txt"] = {
            "status_code": 200, "body": "Disallow: /admin\nSitemap: http://evil.test/s.xml"
        }
        ctx.raw_results["http_root"] = {
            "status_code": 200, "url": "http://127.0.0.1:8001/",
            "body": "<a href='/login'>login</a><a href='https://evil.test/x'>x</a>",
        }
        await dm.DiscoveryModule(validator).run(ctx)
        eps = ctx.raw_results["discovery"]["endpoints"]
        urls = eps["urls"]
        assert any("/login" in u for u in urls)
        assert not any("evil.test" in u for u in urls), urls


# ---------------------------------------------------------------- api security
class TestApiSecurity:
    @pytest.mark.asyncio
    async def test_missing_security_schemes(self, validator, monkeypatch):
        from agent.modules import api_security as asm

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "API", "version": "1"},
            "servers": [{"url": "http://localhost:9000"}],
            "paths": {"/a": {"get": {"responses": {}}}},
        }
        import json

        class FakeResp:
            def __init__(self, path):
                self.status_code = 200
                self.headers = {"content-type": "application/json"}
                self.body = json.dumps(spec) if path == "/openapi.json" else ""
                self.url = "http://t" + path

        class FakeClient:
            def __init__(self, v):
                pass

            async def get(self, url):
                return FakeResp(url.replace("http://t", "", 1))

        monkeypatch.setattr(asm, "SafeHttpClient", FakeClient)
        ctx = make_ctx()
        ctx.raw_results["discovery"] = {
            "docs": {"/openapi.json": {"status_code": 200, "url": "http://t/openapi.json",
                                        "body": json.dumps(spec)}},
            "docs_exposed": [{"path": "/openapi.json", "kind": "openapi"}],
            "endpoints": {"urls": []},
        }
        await asm.ApiSecurityModule(validator).run(ctx)
        titles = " ".join(f["title"] for f in ctx.findings)
        assert "no security schemes" in titles
        assert "non-production server URL" in titles


# ---------------------------------------------------------------- dns
class TestDnsSecurity:
    @pytest.mark.asyncio
    async def test_absent_records_flagged(self, validator, monkeypatch):
        from agent.modules import dns_security as dsm
        from agent.modules import dns_queries

        async def fake_resolve(host, rtype, timeout=5.0):
            return []

        monkeypatch.setattr(dns_queries, "_resolve", fake_resolve)
        ctx = make_ctx()
        await dsm.DnsSecurityModule(validator).run(ctx)
        titles = " ".join(f["title"] for f in ctx.findings)
        assert "No SPF" in titles
        assert "No DMARC" in titles
        for f in ctx.findings:
            assert f["evidence"]
            assert f["affected_asset"] == "127.0.0.1" or f["affected_asset"]

    @pytest.mark.asyncio
    async def test_spf_parsing(self):
        from agent.modules.dns_queries import parse_dmarc, parse_spf

        spf = parse_spf(["v=spf1 include:_spf.example.com ~all"])
        assert spf["present"] and spf["all_strict"]
        dmarc = parse_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.com"])
        assert dmarc["present"] and dmarc["policy_enforcing"] and dmarc["rua_configured"]

    @pytest.mark.asyncio
    async def test_ip_targets_skip_dns_module(self, validator):
        from agent.modules.dns_security import DnsSecurityModule, _is_ip_address

        ctx = make_ctx()
        # IP-only targets have no domain/mail posture: the module must skip them.
        assert DnsSecurityModule(validator).applies(ctx) is False
        assert _is_ip_address("example.com") is False
        assert _is_ip_address("1.2.3.4") is True


# ---------------------------------------------------------------- normalizer
class TestNormalizerUpgrades:
    @pytest.mark.asyncio
    async def test_root_cause_grouping(self, validator):
        from agent.analysis.normalizer import FindingNormalizerModule

        ctx = make_ctx()
        ctx.findings = [
            {"title": "HSTS header missing (HTTPS site)", "category": "CONFIGURATION",
             "severity": "MEDIUM", "confidence": "HIGH", "description": "d",
             "evidence": [{"type": "http_headers_observed"}],
             "affected_asset": "http://x", "source": "headers"},
            {"title": "Site is served over plain HTTP without redirect to HTTPS",
             "category": "CONFIGURATION", "severity": "MEDIUM", "confidence": "HIGH",
             "description": "d", "evidence": [{"type": "http_get", "status": 200}],
             "affected_asset": "http://x", "source": "http_config"},
        ]
        await FindingNormalizerModule(validator).run(ctx)
        groups = ctx.raw_results["root_cause_groups"]
        assert any(g["group_id"] == "transport_protection_gap" for g in groups)
        assert all("root_cause_group" in f["metadata"] for f in ctx.findings)

    @pytest.mark.asyncio
    async def test_duplicate_evidence_aggregation(self, validator):
        from agent.analysis.normalizer import FindingNormalizerModule

        ctx = make_ctx()
        base = {
            "title": "Environment file is publicly exposed (/.env)",
            "category": "WEB", "severity": "CRITICAL", "confidence": "HIGH",
            "description": "d", "affected_asset": "http://x/.env", "source": "a",
            "fingerprint": "fp_env_1",
        }
        ctx.findings = [
            {**base, "evidence": [{"type": "http_get", "url": "http://x/.env", "status": 200}]},
            {**base, "source": "b", "evidence": [{"type": "http_probe", "url": "http://x/.env"}]},
        ]
        await FindingNormalizerModule(validator).run(ctx)
        assert len(ctx.findings) == 1
        merged = ctx.findings[0]
        assert len(merged["evidence"]) == 2  # aggregated
        # `source` keeps the primary detector; corroborating ones are listed here.
        assert merged["source"] == "a"
        assert set(merged["metadata"]["also_reported_by"]) == {"b"}

    @pytest.mark.asyncio
    async def test_confidence_never_exceeds_detector_claim_by_more_than_one(self, validator):
        from agent.analysis.normalizer import FindingNormalizerModule

        ctx = make_ctx()
        ctx.findings = [{
            "title": "t", "category": "WEB", "severity": "HIGH", "confidence": "LOW",
            "description": "d", "evidence": [{"type": "http_get", "status": 200},
                                              {"type": "x"}],
            "affected_asset": "http://x", "source": "s",
        }]
        await FindingNormalizerModule(validator).run(ctx)
        # quality 1.0 => calculated HIGH, but detector said LOW -> cap applies
        assert ctx.findings[0]["confidence"] in ("LOW", "MEDIUM")


# ---------------------------------------------------------------- risk engine
class TestRiskEngineExtensions:
    def test_category_scores_present_and_deterministic(self, sample_finding):
        from agent.risk.engine import RiskEngine

        findings = [
            sample_finding(title="HSTS missing", severity="MEDIUM"),
            sample_finding(title="Directory listing enabled", severity="MEDIUM"),
            sample_finding(title="No DMARC record", severity="MEDIUM"),
        ]
        eng = RiskEngine()
        r1 = eng.compute([dict(f) for f in findings])
        r2 = eng.compute([dict(f) for f in findings])
        assert r1 == r2  # deterministic
        assert "category_scores" in r1
        cs = r1["category_scores"]
        expected_categories = {"Web Security", "TLS/HTTPS", "Headers", "Cookies",
                               "Information Disclosure", "API Security",
                               "DNS Security", "Configuration", "Exposure"}
        assert expected_categories == set(cs.keys())
        # All scores within 0..100
        assert all(0 <= c["score"] <= 100 for c in cs.values())

    def test_evidence_factor_affects_score(self, sample_finding):
        from agent.risk.engine import RiskEngine

        f_none = sample_finding()
        f_none["evidence"] = []
        f_two = sample_finding()
        f_two["evidence"] = [{"a": 1}, {"b": 2}]
        s1 = RiskEngine().score_finding(f_none)["risk_score"]
        s2 = RiskEngine().score_finding(f_two)["risk_score"]
        assert s1 < s2


# ---------------------------------------------------------------- profiles
class TestProfiles:
    def test_profile_module_lists(self):
        from agent.workers.orchestrator import PROFILES

        assert set(PROFILES.keys()) == {"QUICK", "STANDARD", "DEEP"}
        assert set(PROFILES["QUICK"]) < set(PROFILES["STANDARD"])
        assert set(PROFILES["STANDARD"]) < set(PROFILES["DEEP"])
        assert "active_safe" in PROFILES["DEEP"]
        assert "active_safe" not in PROFILES["STANDARD"]

    @pytest.mark.asyncio
    async def test_quick_profile_skips_deep_modules(self, db_session, wired_http):
        from agent.connectors.authorization_manager import AuthorizationManager
        from agent.storage import repositories as repo
        from agent.workers.orchestrator import Orchestrator
        import uuid as _uuid

        reg = await AuthorizationManager(db_session).register_authorization(
            {"target": "http://127.0.0.1:8001", "authorized_by": "T",
             "allowed_domains": ["127.0.0.1"]}
        )
        job = await repo.create_job(
            db_session, target_id=reg["target_id"],
            authorization_id=reg["authorization"]["id"], trigger="INITIAL",
            profile="QUICK",
        )
        result = await Orchestrator(db_session).run_job(_uuid.UUID(job.id))
        assert result["status"] == "COMPLETED", result.get("error")
        phases = [p.module for p in []]  # phases live on ctx; verify via findings instead
        # QUICK must not include info_disclosure probes (no 'publicly exposed' findings)
        findings = await repo.list_findings(db_session, result["assessment_id"])
        assert not any("publicly exposed" in f.title for f in findings)
