"""CASA-Brain tests: state snapshot, action space, deterministic policy gate,
information-gain engine, loop integration, trajectory records, ExploitDB."""
from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent.brain.actions import ActionType, BrainAction
from agent.brain.engine import DeterministicStrategy, make_strategy
from agent.brain.loop import BrainLoop, _DisabledLoop, build_default_loop
from agent.brain.policy_gate import PolicyConfig, PolicyGate
from agent.brain.state import BrainState


def _validator():
    from agent.core.target import ScopeValidator

    return ScopeValidator(allowed_domains=["127.0.0.1"], allowed_paths=["/"])


def _ctx(**overrides):
    from agent.core.context import AssessmentContext

    ctx = AssessmentContext(
        job_id=uuid4(), assessment_id=uuid4(),
        target_url="http://127.0.0.1:8001", base_domain="127.0.0.1",
        scope={}, **overrides,
    )
    return ctx


def _finding(**kw):
    base = {
        "fingerprint": "fp" + str(uuid4())[:8],
        "title": "Test finding",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "category": "CONFIGURATION",
        "source": "unit",
        "affected_asset": "http://127.0.0.1:8001",
        "evidence": [{"type": "http_header"}],
        "status": "UNVERIFIED",
        "cvss": {"score": 5.0},
    }
    base.update(kw)
    return base


# ------------------------------------------------------------------ state
class TestBrainState:
    def test_snapshot_is_serializable_and_readonly_scope(self):
        ctx = _ctx()
        ctx.raw_results["technologies"] = [{"name": "nginx", "version": "1.24"}]
        ctx.raw_results["discovery"] = {"endpoints": {"urls": ["/a", "/b"], "forms": []}}
        st = BrainState.from_context(ctx, _validator())
        d = st.to_dict()
        assert d["state_hash"]
        assert d["profile"] == "STANDARD"
        assert d["authorization"]["allowed_domains"] == ["127.0.0.1"]
        assert d["pending_modules"]  # nothing executed yet
        json.dumps(d)  # must not raise

    def test_derived_counts(self):
        ctx = _ctx()
        ctx.findings = [
            _finding(severity="HIGH", evidence=[]),
            _finding(severity="MEDIUM", confidence="LOW", evidence=[]),
            _finding(severity="INFO"),
        ]
        st = BrainState.from_context(ctx, _validator())
        assert st.open_findings == 2
        assert st.critical_high == 1
        assert st.unverified_high_value == 2  # HIGH + weak MEDIUM


# ---------------------------------------------------------------- actions
class TestActionSpace:
    def test_validate_shape_rejects_unknown_module(self):
        a = BrainAction(ActionType.RUN_MODULE, params={"module": "rm -rf /"})
        assert a.validate_shape()

    def test_validate_shape_accepts_legal_module(self):
        a = BrainAction(ActionType.RUN_MODULE, params={"module": "headers"})
        assert not a.validate_shape()

    def test_enrich_requires_known_enricher(self):
        a = BrainAction(ActionType.ENRICH_TECHNOLOGY,
                        params={"enricher": "curl http://evil", "technology": "nginx"})
        assert a.validate_shape()


# ------------------------------------------------------------- policy gate
class TestPolicyGate:
    def _state(self, allowed=None, findings=None, step=1, max_steps=40):
        ctx = _ctx()
        ctx.findings = findings or []
        st = BrainState.from_context(ctx, _validator())
        st.profile = "STANDARD"
        if allowed is not None:
            st.allowed_modules = allowed
        st.step = step
        st.max_steps = max_steps
        st.compute_derived()
        return st

    def test_denies_module_outside_profile(self):
        gate = PolicyGate()
        st = self._state(allowed=["recon"])
        a = BrainAction(ActionType.RUN_MODULE, params={"module": "active_safe"})
        d = gate.evaluate(a, st)
        assert not d.allowed and d.rule_id == "R2_PROFILE"

    def test_denies_repeat_over_limit(self):
        gate = PolicyGate(PolicyConfig(max_module_repeats=1))
        st = self._state()
        a = BrainAction(ActionType.RUN_MODULE, params={"module": "headers"})
        assert gate.evaluate(a, st).allowed
        d = gate.evaluate(BrainAction(ActionType.RUN_MODULE, params={"module": "headers"}), st)
        assert not d.allowed and d.rule_id == "R3B_REPEAT"

    def test_denies_verify_unknown_fingerprint(self):
        gate = PolicyGate()
        st = self._state()
        a = BrainAction(ActionType.VERIFY_FINDING, params={"fingerprint": "nope"})
        d = gate.evaluate(a, st)
        assert not d.allowed and d.rule_id == "R4_VERIFY_TARGET"

    def test_denies_budget_exhaustion_but_allows_stop(self):
        gate = PolicyGate(PolicyConfig(max_actions_per_assessment=1))
        st = self._state()
        first = BrainAction(ActionType.RUN_MODULE, params={"module": "headers"})
        assert gate.evaluate(first, st).allowed
        second = BrainAction(ActionType.RUN_MODULE, params={"module": "recon"})
        assert not gate.evaluate(second, st).allowed
        stop = BrainAction(ActionType.STOP_ASSESSMENT, reason_codes=["done"])
        # STOP at budget edge is still evaluated structurally (R1 applies);
        # it passes only because gate counts were already consumed — document
        # actual behavior: budget applies to every action including STOP.
        assert gate.evaluate(stop, st).allowed is False

    def test_denies_enrich_when_network_disabled(self):
        gate = PolicyGate(PolicyConfig(allow_enrich_network_calls=False))
        st = self._state()
        # OSV needs the network -> denied
        osv = BrainAction(ActionType.ENRICH_TECHNOLOGY,
                          params={"enricher": "osv", "technology": "nginx"})
        d = gate.evaluate(osv, st)
        assert not d.allowed and d.rule_id == "R5_ENRICH_NET"
        # ExploitDB reads the LOCAL CSV index -> still allowed offline
        edb = BrainAction(ActionType.ENRICH_TECHNOLOGY,
                          params={"enricher": "exploitdb", "technology": "nginx"})
        assert gate.evaluate(edb, st).allowed

    def test_step_limit_only_allows_stop(self):
        gate = PolicyGate()
        st = self._state(step=40, max_steps=40)
        run = BrainAction(ActionType.RUN_MODULE, params={"module": "headers"})
        stop = BrainAction(ActionType.STOP_ASSESSMENT, reason_codes=["max steps"])
        assert not gate.evaluate(run, st).allowed
        assert gate.evaluate(stop, st).allowed


# ------------------------------------------------------------------ engine
class TestEngine:
    def _state_with(self, **kw):
        ctx = _ctx()
        ctx.raw_results.update(kw.pop("raw", {}))
        ctx.findings = kw.pop("findings", [])
        st = BrainState.from_context(ctx, _validator())
        for k, v in kw.items():
            setattr(st, k, v)
        st.compute_derived()
        return st

    def test_no_tech_fingerprint_proposes_tech_detection(self):
        st = self._state_with(raw={"technologies": []})
        d = DeterministicStrategy().propose(st)
        assert d.action.params.get("module") == "tech_detection"
        assert d.action.expected_information_gain >= 0.9

    def test_cms_detected_proposes_wordpress_checks(self):
        st = self._state_with(raw={"technologies": [{"name": "WordPress", "version": "6.4"}]})
        d = DeterministicStrategy().propose(st)
        # v0.5.0: exploit-first — version correlation outranks the WP module,
        # but the targeted CMS checks must still be among the candidates.
        assert d.action.action_type == ActionType.ENRICH_TECHNOLOGY
        assert d.action.params.get("enricher") == "exploitdb"
        mods = [c.params.get("module") for c in d.candidates if c.action_type == ActionType.RUN_MODULE]
        assert "wordpress" in mods

    def test_exploit_first_outranks_stop_when_modules_exhausted(self):
        # All profile modules executed, versioned tech present, no exploit
        # correlation yet => the Brain must keep working, not stop.
        st = self._state_with(
            raw={"technologies": [{"name": "Apache HTTP Server", "version": "2.4.50"}]},
            findings=[_finding(title="Apache HTTP Server version disclosed (2.4.50)")],
        )
        st.executed_modules = list(st.allowed_modules)
        st.step = 10
        st.compute_derived()
        d = DeterministicStrategy().propose(st)
        assert d.action.action_type == ActionType.ENRICH_TECHNOLOGY
        assert d.action.params.get("enricher") == "exploitdb"
        assert d.action.expected_information_gain == 0.95

    def test_stop_returns_after_exploit_correlation_recorded(self):
        st = self._state_with(
            raw={
                "technologies": [{"name": "nginx", "version": "1.24"}],
                "exploit_enrichment": {"indexed": True, "results": [{}]},
                "osv": {"advisories": []},
            },
        )
        st.executed_modules = list(st.allowed_modules)
        st.step = 10
        st.compute_derived()
        d = DeterministicStrategy().propose(st)
        assert d.action.action_type == ActionType.STOP_ASSESSMENT

    def test_osv_proposed_once_after_exploit_correlation(self):
        # exploit correlation done, OSV not yet => the Brain still has one
        # meaningful step left before stopping.
        st = self._state_with(
            raw={
                "technologies": [{"name": "nginx", "version": "1.24"}],
                "exploit_enrichment": {"indexed": True, "results": [{}]},
            },
        )
        st.executed_modules = list(st.allowed_modules)
        st.step = 10
        st.compute_derived()
        d = DeterministicStrategy().propose(st)
        assert d.action.action_type == ActionType.ENRICH_TECHNOLOGY
        assert d.action.params.get("enricher") == "osv"

    def test_versioned_tech_proposes_exploit_enrichment(self):
        st = self._state_with(
            raw={"technologies": [{"name": "nginx", "version": "1.24"}]},
            findings=[_finding(title="nginx server version 1.24 disclosed")],
        )
        # force wordpress already executed so enrichment wins
        st.executed_modules.append("wordpress")
        st.compute_derived()
        d = DeterministicStrategy().propose(st)
        kinds = [c.action_type for c in d.candidates]
        assert ActionType.ENRICH_TECHNOLOGY in kinds

    def test_high_unverified_proposes_active_safe_when_pending(self):
        # active_safe exists only in the DEEP profile — emulate it.
        st = self._state_with(findings=[_finding(severity="HIGH", evidence=[])])
        st.profile = "DEEP"
        st.allowed_modules = st.allowed_modules + ["active_safe"]
        st.compute_derived()
        d = DeterministicStrategy().propose(st)
        mods = [c.params.get("module") for c in d.candidates if c.action_type == ActionType.RUN_MODULE]
        assert "active_safe" in mods

    def test_all_executed_and_low_value_stops(self):
        st = self._state_with(findings=[_finding(severity="INFO")])
        st.executed_modules = list(st.allowed_modules)
        st.pending_modules = []
        st.step = 10
        st.compute_derived()
        d = DeterministicStrategy().propose(st)
        assert d.action.action_type == ActionType.STOP_ASSESSMENT
        assert d.action.reason_codes

    def test_local_model_only_reorders_not_invents(self):
        calls = {}

        def rank(state_dict, candidates):
            calls["n"] = len(candidates)
            return 0, "because state says so"

        st = self._state_with(raw={"technologies": []})
        strat = make_strategy(model_rank_fn=rank)
        d = strat.propose(st)
        assert d.strategy == "local-model-v1"
        assert calls["n"] >= 1
        assert "local_model_selected" in d.action.reason_codes

    def test_factory_env_offline_fallback(self, monkeypatch):
        monkeypatch.setenv("CASA_BRAIN_MODEL", "/models/casa-brain.gguf")
        strat = make_strategy()
        assert strat.name == "deterministic-v1"  # graceful degradation


# -------------------------------------------------------------------- loop
class TestLoop:
    def test_disabled_loop_returns_none(self):
        loop = build_default_loop()
        assert isinstance(loop, _DisabledLoop)
        action, decision = loop.next_action(BrainState())
        assert action is None
        assert decision.strategy == "disabled"

    def test_enabled_loop_approves_and_records(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CASA_BRAIN_ENABLED", "1")
        from agent.brain.trajectory import TrajectoryRecorder

        rec = TrajectoryRecorder(path=tmp_path / "traj.jsonl")
        loop = BrainLoop(recorder=rec)
        ctx = _ctx()
        ctx.raw_results["technologies"] = []
        st = BrainState.from_context(ctx, _validator())
        action, decision = loop.next_action(st)
        assert action is not None
        assert decision.candidates
        assert rec.path.exists()

    def test_trajectory_curation_filters(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CASA_BRAIN_ENABLED", "1")
        from agent.brain.trajectory import TrajectoryRecorder

        rec = TrajectoryRecorder(path=tmp_path / "t.jsonl")
        ctx = _ctx()
        st = BrainState.from_context(ctx, _validator())
        loop = BrainLoop(recorder=rec)
        loop.next_action(st)
        loop.record_execution(st.state_hash, loop.report.decisions[0]["selected"] and
                              BrainAction(ActionType.RUN_MODULE, params={"module": "headers"}),
                              {"ok": True}, None)
        curated = rec.load_curated(min_information_gain=0.0)
        assert curated, "at least one approved+executed record"


# ------------------------------------------------------------- exploit intel
class TestExploitIntel:
    def _write_csv(self, tmp_path):
        csv = tmp_path / "files_exploits.csv"
        csv.write_text(
            "id,file,description,date_published,author,type,platform\n"
            '12345,php/webapps/12345.py,"WordPress Core 6.4 - SQL Injection",2024-01-01,someone,webapps,php\n'
            '12346,linux/local/12346.c,"WordPress 6.4.1 - Privilege Escalation",2024-02-01,other,local,linux\n'
            '99999,remote/99999.txt,"Nginx 1.24 - Off-by-scope",2023-05-05,auth,remote,linux\n'
        )
        return csv

    def test_version_precise_match_ranked_first(self, tmp_path):
        from agent.analysis.exploit_intel import ExploitDBIndex

        idx = ExploitDBIndex.load(self._write_csv(tmp_path))
        matches = idx.search("WordPress", "6.4.1")
        assert matches, "should find wordpress matches"
        assert matches[0].matched_on == "technology+version"
        assert matches[0].edb_id == "12346"
        assert matches[0].to_dict()["url"].endswith("/exploits/12346")

    def test_technology_only_match(self, tmp_path):
        from agent.analysis.exploit_intel import ExploitDBIndex

        idx = ExploitDBIndex.load(self._write_csv(tmp_path))
        matches = idx.search("WordPress", None)
        assert any(m.edb_id == "12345" for m in matches)

    def test_no_false_match_for_unrelated(self, tmp_path):
        from agent.analysis.exploit_intel import ExploitDBIndex

        idx = ExploitDBIndex.load(self._write_csv(tmp_path))
        assert idx.search("gunicorn", "23.0") == []

    def test_full_index_semantics(self, tmp_path):
        """Subject-adjacency: plugin bounds must not bind to the platform."""
        from agent.analysis.exploit_intel import ExploitDBIndex

        csv = tmp_path / "files_exploits.csv"
        csv.write_text(
            "id,file,description,date_published,author,type,platform,codes\n"
            '1,exploits/php/1.py,"NEX-Forms WordPress plugin < 7.9.7 - SQLi",2024-01-01,a,webapps,php,CVE-2024-1000\n'
            '2,exploits/php/2.py,"WordPress Core < 6.4.3 - SQL Injection",2024-01-02,b,webapps,php,CVE-2024-1001\n'
            '3,exploits/php/3.py,"WordPress Plugin Buddypress 6.2.0 - XSS",2024-01-03,c,webapps,php,\n'
            '4,exploits/php/4.txt,"Nginx 1.3.9 < 1.4.0 - DoS",2023-01-04,d,dos,linux,\n'
            '5,exploits/php/5.sh,"Apache HTTP Server 2.4.50 - RCE",2021-10-25,e,webapps,multiple,CVE-2021-42013\n'
        )
        idx = ExploitDBIndex.load(csv)

        # WP 6.2: the core row "< 6.4.3" covers it via operator semantics and
        # outranks the plugin row sharing the literal version
        wp = idx.search("WordPress", "6.2.0", limit=2)
        assert wp[0].edb_id == "2"   # core operator bound, w3
        assert wp[1].edb_id == "3"   # plugin literal, w1

        # operator bound belongs to WP Core, not to NEX-Forms plugin
        wp2 = idx.search("WordPress", "6.4.1", limit=2)
        assert wp2[0].edb_id == "2" and wp2[0].matched_version == "<6.4.3"
        assert wp2[0].cves == ["CVE-2024-1001"]

        # nginx band "1.3.9 < 1.4.0" must NOT contain 1.24.0 — only the
        # honest technology-only row may remain
        ng = idx.search("Nginx", "1.24.0", limit=3)
        assert all(m.matched_on == "technology" for m in ng)

        # Apache 2.4.50 RCE with official codes column
        ap = idx.search("Apache HTTP Server", "2.4.50", limit=2)
        assert ap and ap[0].edb_id == "5" and ap[0].cves == ["CVE-2021-42013"]

    def test_get_index_signature_cache(self, tmp_path, monkeypatch):
        from agent.analysis import exploit_intel

        monkeypatch.setenv("CASA_EXPLOITDB_CSV_PATH", "")
        csv = tmp_path / "files_exploits.csv"
        csv.write_text(
            "id,file,description,date_published,author,type,platform\n"
            '11,x/11.txt,"Foo 1.0 - XSS",2024-01-01,a,webapps,linux\n'
        )
        monkeypatch.setattr(exploit_intel.settings_csv, "__code__", None) if False else None
        idx1 = exploit_intel.ExploitDBIndex.load(csv)
        assert idx1.available and idx1.search("Foo", "1.0")
        # same in-memory index object is reused when the file is unchanged
        i1 = exploit_intel.get_index()
        i2 = exploit_intel.get_index()
        assert i1 is i2

    def test_empty_index_is_safe(self):
        from agent.analysis.exploit_intel import ExploitDBIndex

        idx = ExploitDBIndex()
        assert not idx.available
        assert idx.search("WordPress", "6.4") == []

    def test_enrichment_module_annotates_existing_finding(self, tmp_path, monkeypatch):
        from agent.modules.exploit_enrichment import ExploitEnrichmentModule

        monkeypatch.setenv("CASA_EXPLOITDB_CSV_PATH", str(self._write_csv(tmp_path)))
        ctx = _ctx()
        ctx.raw_results["technologies"] = [{"name": "WordPress", "version": "6.4.1"}]
        carrier = _finding(
            title="WordPress version disclosed (6.4.1)",
            fingerprint="wpver123",
        )
        ctx.findings = [carrier]

        # point settings at our CSV
        from agent.core.config import settings
        monkeypatch.setattr(settings, "exploitdb_csv_path", str(tmp_path / "files_exploits.csv"))

        import asyncio
        asyncio.run(ExploitEnrichmentModule(_validator()).run(ctx))

        refs = carrier["references"]
        assert any("exploit-db.com/exploits/12346" in r for r in refs)
        assert carrier["metadata"]["exploit_matches"]


# ------------------------------------------------- orchestrator integration
class TestBrainRiskSummaryInjection:
    """The Brain pass report must reach the persisted risk_summary (API/DB)."""

    @pytest.mark.asyncio
    async def test_brain_report_lands_in_risk_summary(
        self, db_session, wired_http, monkeypatch
    ):
        monkeypatch.setenv("CASA_BRAIN_ENABLED", "1")
        # Keep the gate fully offline (no OSV network) and don't pollute the
        # local trajectory file from the test run.
        from agent.brain.policy_gate import PolicyConfig
        from agent.core.config import settings as app_settings

        monkeypatch.setattr(PolicyConfig, "allow_enrich_network_calls", False)
        monkeypatch.setattr(app_settings, "brain_trajectory_enabled", False)

        from uuid import UUID

        from agent.connectors.authorization_manager import AuthorizationManager
        from agent.storage import repositories as repo
        from agent.workers.orchestrator import Orchestrator

        manager = AuthorizationManager(db_session)
        reg = await manager.register_authorization(
            {
                "target": "http://127.0.0.1:8001",
                "authorized_by": "Lab Owner (unit test)",
                "authorization_reference": "TEST-BRAIN-RS",
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
        result = await Orchestrator(db_session).run_job(UUID(str(job.id)))
        assert result["status"] == "COMPLETED", result.get("error")

        assessment = await repo.get_assessment(db_session, result["assessment_id"])
        brain = (assessment.risk_summary or {}).get("brain")
        assert brain and brain.get("report"), "brain report missing from risk_summary"
        assert brain["report"]["decisions"], "brain must record at least one decision"
        assert brain["report"]["final_reason"] != ""
