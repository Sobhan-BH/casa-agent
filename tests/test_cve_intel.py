"""Tests for the CVE intelligence layer (CISA KEV + EPSS) and the
APT-style exploit enrichment threat fusion."""
from __future__ import annotations

import json
from uuid import uuid4

import pytest

from agent.analysis.cve_intel import CveIntelIndex, CveRecord, get_cve_intel


# ------------------------------------------------------------------ records
class TestCveRecord:
    def test_tier_ordering(self):
        assert CveRecord(cve_id="CVE-1", in_kev=True).tier == "P1_KEV"
        assert CveRecord(cve_id="CVE-2", epss_score=0.95).tier == "P2_EPSS_CRITICAL"
        assert CveRecord(cve_id="CVE-3", epss_score=0.6).tier == "P3_EPSS_ELEVATED"
        assert CveRecord(cve_id="CVE-4", epss_score=0.2).tier == "P3_EPSS_ELEVATED"
        assert CveRecord(cve_id="CVE-5", known_ransomware=True).tier == "P3_EPSS_ELEVATED"
        assert CveRecord(cve_id="CVE-6", epss_score=0.05).tier == "P4_INFORMATIONAL"
        assert CveRecord(cve_id="CVE-7").tier == "P4_INFORMATIONAL"

    def test_dict_shape(self):
        d = CveRecord(cve_id="CVE-1", in_kev=True, epss_score=0.99).to_dict()
        assert d["tier"] == "P1_KEV"
        assert d["in_kev"] is True
        assert d["epss"] == 0.99
        assert "tier_label" in d


# ------------------------------------------------------------------- index
def _write_feeds(tmp_path, *, kev_cves=("CVE-2021-42013",), epss_rows=None):
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({
        "vulnerabilities": [
            {"cveID": c, "dueDate": "2022-05-03",
             "knownRansomwareCampaignUse": "Known" if c.endswith("42013") else "Unknown"}
            for c in kev_cves
        ]
    }))
    epss = tmp_path / "epss.csv"
    rows = epss_rows if epss_rows is not None else [
        ("CVE-2021-42013", "0.99964", "0.99976"),
        ("CVE-2024-6387", "0.99506", "0.99945"),
        ("CVE-2099-0001", "0.03351", "0.88305"),
    ]
    epss.write_text(
        "#model_version:vtest,score_date:now\ncve,epss,percentile\n"
        + "".join(f"{c},{s},{p}\n" for c, s, p in rows)
    )
    return kev, epss


class TestCveIntelIndex:
    def test_fused_lookup(self, tmp_path):
        kev, epss = _write_feeds(tmp_path)
        idx = CveIntelIndex.load(kev_path=kev, epss_path=epss)
        r = idx.lookup("cve-2021-42013")  # case-insensitive
        assert r.in_kev and r.known_ransomware
        assert r.epss_score == pytest.approx(0.99964)
        assert r.tier == "P1_KEV"

    def test_missing_cve_is_informational(self, tmp_path):
        kev, epss = _write_feeds(tmp_path)
        idx = CveIntelIndex.load(kev_path=kev, epss_path=epss)
        r = idx.lookup("CVE-1999-0001")
        assert not r.in_kev and r.tier == "P4_INFORMATIONAL"

    def test_empty_feeds_safe(self, tmp_path, monkeypatch):
        # point feed discovery away from the developer-machine real feeds
        monkeypatch.setenv("CASA_KEV_FEED_PATH", str(tmp_path / "no-kev.json"))
        monkeypatch.setenv("CASA_EPSS_FEED_PATH", str(tmp_path / "no-epss.csv"))
        idx = CveIntelIndex.load(kev_path=None, epss_path=None)
        assert not idx.available
        assert idx.lookup("CVE-2021-42013").tier == "P4_INFORMATIONAL"

    def test_worst_priority_and_summary(self, tmp_path):
        kev, epss = _write_feeds(tmp_path)
        idx = CveIntelIndex.load(kev_path=kev, epss_path=epss)
        worst = idx.worst_priority(["CVE-2099-0001", "CVE-2021-42013"])
        assert worst.cve_id == "CVE-2021-42013"
        s = idx.summarize(["CVE-2099-0001", "CVE-2021-42013"])
        assert s["tier"] == "P1_KEV"
        assert s["worst_cve"] == "CVE-2021-42013"
        assert s["in_kev"] == ["CVE-2021-42013"]
        assert s["epss_max"] == pytest.approx(0.99964)
        assert s["known_ransomware"] is True

    def test_epss_only_score(self, tmp_path):
        kev, epss = _write_feeds(tmp_path, kev_cves=())
        idx = CveIntelIndex.load(kev_path=kev, epss_path=epss)
        assert idx.lookup("CVE-2024-6387").tier == "P2_EPSS_CRITICAL"

    def test_process_cache(self, tmp_path, monkeypatch):
        from agent.analysis import cve_intel as ci
        monkeypatch.setenv("CASA_KEV_FEED_PATH", str(tmp_path / "missing.json"))
        monkeypatch.setenv("CASA_EPSS_FEED_PATH", str(tmp_path / "missing.csv"))
        assert ci.get_cve_intel(refresh=True) is ci.get_cve_intel()


# ------------------------------------------------- enrichment threat fusion
def _validator():
    from agent.core.target import ScopeValidator
    return ScopeValidator(allowed_domains=["127.0.0.1"], allowed_paths=["/"])


def _ctx(**kw):
    from agent.core.context import AssessmentContext
    return AssessmentContext(
        job_id=uuid4(), assessment_id=uuid4(),
        target_url="http://127.0.0.1:8001", base_domain="127.0.0.1",
        scope={}, **kw,
    )


def _write_edb_csv(tmp_path):
    csv = tmp_path / "files_exploits.csv"
    csv.write_text(
        "id,file,description,date_published,author,type,platform,codes\n"
        '5,exploits/5.sh,"Apache HTTP Server 2.4.50 - RCE",2021-10-25,e,webapps,multiple,CVE-2021-42013\n'
        '6,exploits/6.txt,"FooBar CMS - XSS",2020-01-01,f,webapps,php,\n'
    )
    return csv


class TestEnrichmentThreatFusion:
    def _run(self, tmp_path, monkeypatch, technologies):
        from agent.modules.exploit_enrichment import ExploitEnrichmentModule
        monkeypatch.setattr(
            "agent.core.config.settings.exploitdb_csv_path", str(_write_edb_csv(tmp_path))
        )
        monkeypatch.setenv("CASA_EXPLOITDB_CSV_PATH", str(tmp_path / "files_exploits.csv"))
        kev, epss = _write_feeds(tmp_path)
        monkeypatch.setenv("CASA_KEV_FEED_PATH", str(kev))
        monkeypatch.setenv("CASA_EPSS_FEED_PATH", str(epss))
        import asyncio
        ctx = _ctx()
        ctx.raw_results["technologies"] = technologies
        asyncio.run(ExploitEnrichmentModule(_validator()).run(ctx))
        return ctx

    def test_versioned_kev_cve_yields_high(self, tmp_path, monkeypatch):
        ctx = self._run(tmp_path, monkeypatch,
                        [{"name": "Apache HTTP Server", "version": "2.4.50"}])
        f = next(f for f in ctx.findings if f["source"] == "exploit_enrichment")
        assert f["severity"] == "HIGH"  # P1_KEV uplift
        assert f["metadata"]["threat_tier"] == "P1_KEV"
        assert "CVE-2021-42013" in f["metadata"]["exploit_cves"]
        assert f["metadata"]["cve_threat"]["in_kev"] == ["CVE-2021-42013"]
        assert any("exploit-db.com/exploits/5" in r for r in f["references"])

    def test_versionless_tech_still_correlated(self, tmp_path, monkeypatch):
        ctx = self._run(tmp_path, monkeypatch, [{"name": "Apache", "version": None}])
        # version-less: the EDB row pins 2.4.50, so no version-precise match;
        # the CVE from the description still fuses to KEV → finding exists,
        # but severity is capped at MEDIUM (version unconfirmed, even for KEV).
        f = next((f for f in ctx.findings if f["source"] == "exploit_enrichment"), None)
        assert f is not None, "version-less tech must still be correlated"
        assert f["severity"] == "MEDIUM"
        assert f["metadata"]["exploit_cves"] == ["CVE-2021-42013"]
        assert ctx.raw_results["exploit_enrichment"]["results"][0]["version_confirmed"] is False

    def test_no_match_records_negative_result(self, tmp_path, monkeypatch):
        ctx = self._run(tmp_path, monkeypatch, [{"name": "gunicorn", "version": "23.0"}])
        assert not [f for f in ctx.findings if f["source"] == "exploit_enrichment"]
        res = ctx.raw_results["exploit_enrichment"]["results"][0]
        assert res["edb_matches"] == [] and res["cves"] == []

    def test_carrier_finding_gets_threat_metadata(self, tmp_path, monkeypatch):
        ctx = self._run(tmp_path, monkeypatch,
                        [{"name": "Apache HTTP Server", "version": "2.4.50"}])
        ctx.findings.clear()
        carrier = {
            "title": "Apache version disclosed (2.4.50)",
            "fingerprint": "car1", "metadata": {}, "references": [],
        }
        ctx.findings.append(carrier)
        import asyncio
        from agent.modules.exploit_enrichment import ExploitEnrichmentModule
        ctx.raw_results["technologies"] = [{"name": "Apache HTTP Server", "version": "2.4.50"}]
        asyncio.run(ExploitEnrichmentModule(_validator()).run(ctx))
        assert carrier["metadata"]["threat_tier"] == "P1_KEV"
        assert "CVE-2021-42013" in carrier["metadata"]["exploit_cves"]
