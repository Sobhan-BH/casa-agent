"""Tool Integration layer tests.

Covers: registry/availability, command builder safety (no shell, no raw
concatenation), scope enforcement (out-of-scope blocked), parsers for every
tool output format, normalization + provenance, metasploit lab hard-reject,
and orchestrator integration with missing tools (never crashes).
All fixtures are local; no external target is contacted.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------- registry
class TestRegistry:
    def test_registry_health_reports_every_tool(self):
        from agent.tools.registry import tool_registry

        health = tool_registry.health()
        expected = {"nmap", "gobuster", "ffuf", "nikto", "whatweb", "nuclei", "metasploit_lab"}
        assert expected == set(health.keys())
        for name, entry in health.items():
            assert entry["status"] in ("READY", "NOT_INSTALLED", "DISABLED")
            assert entry["available"] == (entry["status"] == "READY")

    def test_missing_tool_never_crashes_health(self):
        from agent.tools.registry import tool_registry

        # health must work regardless of what is installed on this host
        health = tool_registry.health()
        assert isinstance(health, dict)

    def test_profile_mapping(self):
        from agent.tools.registry import PROFILE_TOOLS

        assert set(PROFILE_TOOLS["QUICK"]) == {"whatweb"}
        assert set(PROFILE_TOOLS["STANDARD"]) == {"nmap", "whatweb", "nikto", "nuclei"}
        assert "gobuster" in PROFILE_TOOLS["DEEP"] and "ffuf" in PROFILE_TOOLS["DEEP"]
        assert all("metasploit_lab" not in tools for tools in PROFILE_TOOLS.values())

    def test_select_skips_unavailable_tools(self):
        from agent.core.context import AssessmentContext
        from agent.tools.registry import tool_registry
        from uuid import uuid4

        ctx = AssessmentContext(
            job_id=uuid4(), assessment_id=uuid4(),
            target_url="http://127.0.0.1:8001", base_domain="127.0.0.1", scope={},
            mode="DEEP",
        )
        selected = tool_registry.select(ctx)
        names = {a.name for a in selected}
        # metasploit_lab is NEVER auto-selected; unavailable tools are skipped
        assert "metasploit_lab" not in names
        for adapter in selected:
            assert adapter.is_available()


# ---------------------------------------------------------------- scope
class TestScopeEnforcement:
    def test_out_of_scope_host_blocked(self):
        from agent.core.exceptions import ScopeViolationError
        from agent.tools.nmap import NmapAdapter

        adapter = NmapAdapter()
        with pytest.raises(ScopeViolationError):
            adapter.validate_target("http://evil.example.net:80", {"allowed_domains": ["127.0.0.1"]})

    def test_out_of_policy_port_blocked(self):
        from agent.core.exceptions import ScopeViolationError
        from agent.tools.nmap import NmapAdapter

        adapter = NmapAdapter()
        with pytest.raises(ScopeViolationError):
            adapter.validate_target("http://127.0.0.1:3306", {"allowed_domains": ["127.0.0.1"]})

    def test_excluded_target_blocked(self):
        from agent.core.exceptions import ScopeViolationError
        from agent.tools.whatweb import WhatWebAdapter

        adapter = WhatWebAdapter()
        with pytest.raises(ScopeViolationError):
            adapter.validate_target(
                "http://127.0.0.1:8001",
                {"allowed_domains": ["127.0.0.1"], "excluded_targets": ["127.0.0.1"]},
            )

    def test_userinfo_rejected(self):
        from agent.core.exceptions import ScopeViolationError
        from agent.tools.nikto import NiktoAdapter

        adapter = NiktoAdapter()
        with pytest.raises(ScopeViolationError):
            adapter.validate_target(
                "http://user:pass@127.0.0.1:8001", {"allowed_domains": ["127.0.0.1"]}
            )

    def test_bad_scheme_rejected(self):
        from agent.core.exceptions import ScopeViolationError
        from agent.tools.nuclei import NucleiAdapter

        adapter = NucleiAdapter()
        with pytest.raises(ScopeViolationError):
            adapter.validate_target("ftp://127.0.0.1:8001", {"allowed_domains": ["127.0.0.1"]})

    def test_metasploit_lab_refuses_real_target(self):
        from agent.core.exceptions import ScopeViolationError
        from agent.tools.metasploit_lab import MetasploitLabAdapter

        adapter = MetasploitLabAdapter()
        with pytest.raises(ScopeViolationError):
            adapter.validate_target("https://gulfstore.ir", {"allowed_domains": ["gulfstore.ir"]})
        with pytest.raises(ScopeViolationError):
            adapter.validate_target("http://127.0.0.1:3306", {"allowed_domains": ["127.0.0.1"]})

    def test_metasploit_lab_accepts_lab_target_only(self):
        from agent.tools.metasploit_lab import MetasploitLabAdapter

        adapter = MetasploitLabAdapter()
        # must NOT raise for the local lab
        adapter.validate_target("http://127.0.0.1:8001", {"allowed_domains": ["127.0.0.1"]})


# ---------------------------------------------------------------- commands
class TestCommandBuilder:
    def test_nmap_command_is_argv_list_with_safe_profile(self):
        from agent.tools.nmap import NmapAdapter

        argv = NmapAdapter().build_command({"target": "http://127.0.0.1:8001"})
        assert isinstance(argv, list)
        assert argv[0] == "nmap"
        assert "127.0.0.1" in argv          # target as ONE argv element
        assert "-A" not in argv             # no aggressive profile
        assert "--script" not in argv       # no script execution
        assert "http://127.0.0.1:8001" not in argv  # never raw URL concat

    def test_ffuf_get_only(self):
        from agent.tools.ffuf import FfufAdapter

        argv = FfufAdapter().build_command({"target": "http://127.0.0.1:8001"})
        i = argv.index("-X")
        assert argv[i + 1] == "GET"

    def test_nuclei_policy_flags_applied(self):
        from agent.tools.nuclei import NucleiAdapter

        argv = NucleiAdapter().build_command({"target": "http://127.0.0.1:8001"})
        assert "-exclude-tags" in argv
        assert "http://127.0.0.1:8001" in argv  # target as one argv element

    def test_whatweb_passes_target_as_single_element(self):
        from agent.tools.whatweb import WhatWebAdapter

        argv = WhatWebAdapter().build_command({"target": "http://127.0.0.1:8001/"})
        assert argv[-1] == "http://127.0.0.1:8001/"


# ---------------------------------------------------------------- parsers
NMAP_XML = """<nmaprun><host><hostnames><hostname name="lab.local"/></hostnames>
<ports><port protocol="tcp" portid="8001"><state state="open"/>
<service name="http" product="Python http.server" version="3.14"/></port></ports>
</host></nmaprun>"""

NIKTO_TEXT = """- Nikto v2.5.0
+ Target IP:          127.0.0.1
+ OSVDB-3092: /admin: This might be interesting...
+ GET /debug: Debugging active...
"""


class TestParsers:
    def test_nmap_parser_extracts_services(self):
        from agent.tools.nmap import NmapAdapter

        adapter = NmapAdapter()
        services = adapter._parse_xml(NMAP_XML)
        assert services[0]["port"] == 8001
        assert services[0]["state"] == "open"
        assert services[0]["product"] == "Python http.server"

        raw = {"stdout": NMAP_XML, "target": "http://127.0.0.1:8001"}
        findings = adapter.parse_output(raw)
        assert any(f["severity"] == "INFO" and "8001" in f["title"] for f in findings)
        assert findings[0]["evidence"][0]["type"] == "nmap_service"

    def test_nmap_parser_ignores_garbage(self):
        from agent.tools.nmap import NmapAdapter

        assert NmapAdapter()._parse_xml("not xml at all") == []

    def test_nikto_parser_items_and_references(self):
        from agent.tools.nikto import NiktoAdapter

        adapter = NiktoAdapter()
        raw = {"stdout": NIKTO_TEXT, "target": "http://127.0.0.1:8001"}
        findings = adapter.parse_output(raw)
        assert len(findings) == 2
        assert findings[0]["evidence"][0]["osvdb"] == "OSVDB-3092"
        assert any("vulners.com/osvdb" in r for r in findings[0]["references"])

    def test_whatweb_parser_builds_inventory(self):
        import json

        from agent.tools.whatweb import WhatWebAdapter

        payload = json.dumps(
            [{"plugins": {"Nginx": {"version": ["1.24"], "certainty": [100]},
                          "PHP": {"version": ["8.2"], "certainty": [75]}}}]
        )
        adapter = WhatWebAdapter()
        raw = {"stdout": payload}
        inventory = adapter._parse_json(payload)
        assert inventory[0]["technology"] == "Nginx"
        assert inventory[0]["version"] == "1.24"
        assert inventory[0]["confidence"] == "HIGH"
        assert adapter.parse_output(raw) == []  # inventory, not findings

    def test_nuclei_parser_jsonl_with_provenance(self):
        import json

        from agent.tools.nuclei import NucleiAdapter

        event = {
            "template-id": "cve-2021-44228",
            "matched-at": "http://127.0.0.1:8001/",
            "info": {
                "name": "Log4j RCE", "severity": "critical",
                "reference": ["https://nvd.example/CVE-2021-44228"],
            },
        }
        adapter = NucleiAdapter()
        raw = {"stdout": json.dumps(event), "target": "http://127.0.0.1:8001"}
        findings = adapter.parse_output(raw)
        assert findings[0]["title"].startswith("[cve-2021-44228]")
        assert findings[0]["evidence"][0]["advisory_severity"] == "CRITICAL"
        # advisory severity must NOT set the CASA severity directly
        assert findings[0]["severity"] != "CRITICAL" or findings[0]["evidence"][0]["advisory_severity"] != findings[0]["severity"]

    def test_gobuster_parser_lines(self):
        from agent.tools.gobuster import GobusterAdapter

        adapter = GobusterAdapter()
        entries = adapter._parse_lines_from("200 1234 http://127.0.0.1:8001/admin\n")
        assert entries[0]["path"] == "/admin"
        assert entries[0]["status"] == 200

    def test_ffuf_parser_soft404_filter(self):
        import json

        from agent.tools.ffuf import FfufAdapter

        payload = json.dumps({
            "config": {"url": "http://127.0.0.1:8001/FUZZ"},
            "results": [
                {"url": "http://127.0.0.1:8001/missing-a", "status": 200, "length": 4321},
                {"url": "http://127.0.0.1:8001/missing-b", "status": 200, "length": 4321},
                {"url": "http://127.0.0.1:8001/admin", "status": 200, "length": 812},
            ],
        })
        adapter = FfufAdapter()
        raw = {"stdout": payload, "target": "http://127.0.0.1:8001"}
        findings = adapter.parse_output(raw)
        # the uniform 4321-size soft-404 pair is filtered; /admin survives
        assert len(findings) == 1
        assert "/admin" in findings[0]["affected_asset"]


# ---------------------------------------------------------------- normalize
class TestNormalizationAndProvenance:
    def test_normalize_attaches_provenance(self):
        from agent.tools.nmap import NmapAdapter

        adapter = NmapAdapter()
        raw = {
            "tool": "nmap", "tool_version": "7.94", "target": "http://127.0.0.1:8001",
            "command_profile": "safe_service_discovery",
            "stdout": NMAP_XML,
        }
        findings = adapter.normalize_findings(raw)
        assert findings, "expected at least one normalized finding"
        meta = findings[0]["metadata"]
        assert meta["source_tool"] == "nmap"
        assert meta["tool_version"] == "7.94"
        assert meta["parser_version"].startswith("nmap-parser")
        assert meta["target"] == "http://127.0.0.1:8001"

    def test_secret_redaction(self):
        from agent.tools.base import redact

        text = "Authorization: Bearer abc.def.ghi\nCookie: session=xyz\napi_key=sk-123\n"
        out = redact(text)
        assert "Bearer" not in out and "session=xyz" not in out and "sk-123" not in out
        assert "[REDACTED]" in out


# ---------------------------------------------------------------- integration
@pytest.mark.asyncio
async def test_adapter_full_execution_path_with_stub_binary(tmp_path, monkeypatch):
    """Real subprocess execution end-to-end using a stub nmap binary.

    Proves: scope validation -> argv build -> subprocess (no shell) -> XML
    parse -> normalized finding with provenance. No real nmap required.
    """
    import sys

    from agent.tools.nmap import NmapAdapter

    # Single-quoted XML attributes keep double quotes out of the cmd line.
    NMAP_XML = (
        "<nmaprun><host><hostnames><hostname name='lab.local'/></hostnames>"
        "<ports><port protocol='tcp' portid='8001'><state state='open'/>"
        "<service name='http' product='Python http.server' version='3.14'/>"
        "</port></ports></host></nmaprun>"
    )

    if sys.platform == "win32":
        # Write the XML from a file instead of embedding it in the cmd line:
        # cmd /c argument parsing mangles embedded quotes. The stub script
        # simply cats a sibling payload file.
        payload = tmp_path / "nmap-out.xml"
        payload.write_text(NMAP_XML, encoding="utf-8")
        stub = tmp_path / "nmap-stub.cmd"
        stub.write_text(
            "@echo off\n"
            f"{sys.executable} -c \"import sys;sys.stdout.write(open(r'{payload}',encoding='utf-8').read())\"\n",
            encoding="utf-8",
        )
    else:
        payload = tmp_path / "nmap-out.xml"
        payload.write_text(NMAP_XML, encoding="utf-8")
        stub = tmp_path / "nmap-stub"
        stub.write_text(
            f"#!/bin/sh\n{sys.executable} -c \"import sys;sys.stdout.write(open(r'{payload}',encoding='utf-8').read())\"\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)

    adapter = NmapAdapter()
    monkeypatch.setattr(adapter, "binary", str(stub))
    monkeypatch.setattr(adapter, "_available", True)

    raw = await adapter.execute(
        {
            "target": "http://127.0.0.1:8001",
            "scope": {"allowed_domains": ["127.0.0.1"], "allowed_paths": ["/"]},
        }
    )
    assert raw["status"] == "OK"
    assert raw["returncode"] == 0
    assert raw["services"][0]["port"] == 8001

    findings = adapter.normalize_findings(raw)
    assert findings and findings[0]["metadata"]["source_tool"] == "nmap"
    assert findings[0]["evidence"][0]["type"] == "nmap_service"


@pytest.mark.asyncio
async def test_stub_adapter_blocks_out_of_scope_before_exec(tmp_path, monkeypatch):
    """Even with a working binary, an out-of-scope target never reaches exec."""
    import sys

    from agent.core.exceptions import ScopeViolationError
    from agent.tools.nmap import NmapAdapter

    adapter = NmapAdapter()
    monkeypatch.setattr(adapter, "_available", True)
    executed = False

    original_run = adapter._run

    async def spy_run(argv, **kw):
        nonlocal executed
        executed = True
        return await original_run(argv, **kw)

    monkeypatch.setattr(adapter, "_run", spy_run)
    with pytest.raises(ScopeViolationError):
        await adapter.execute(
            {
                "target": "http://evil.example.net",
                "scope": {"allowed_domains": ["127.0.0.1"], "allowed_paths": ["/"]},
            }
        )
    assert executed is False, "command must never run for out-of-scope targets"


@pytest.mark.asyncio
async def test_unavailable_tool_returns_not_installed(db_session, wired_http):
    from agent.core.context import AssessmentContext
    from agent.modules.tool_runner import ToolRunnerModule
    from agent.core.target import ScopeValidator
    from agent.tools import nmap as nmap_mod
    from uuid import uuid4

    ctx = AssessmentContext(
        job_id=uuid4(), assessment_id=uuid4(),
        target_url="http://127.0.0.1:8001", base_domain="127.0.0.1",
        scope={"allowed_domains": ["127.0.0.1"], "allowed_paths": ["/"]},
        mode="STANDARD",
    )
    ctx.raw_results["http_root"] = {"url": ctx.target_url, "status_code": 200, "headers": {}, "body": ""}

    module = ToolRunnerModule(ScopeValidator(allowed_domains=["127.0.0.1"], allowed_paths=["/"]))
    await module.run(ctx)
    tools = ctx.raw_results["tools"]
    # On this host some tools are absent; the module must record them and live on.
    assert "elapsed_ms" in tools
    for name, entry in tools["run"].items():
        assert entry["status"] in ("OK", "NOT_INSTALLED", "FAILED")


@pytest.mark.asyncio
async def test_pipeline_completes_with_tool_runner(db_session, wired_http):
    """DEEP profile E2E with tool_runner present; tools missing => skipped."""
    from agent.connectors.authorization_manager import AuthorizationManager
    from agent.storage import repositories as repo
    from agent.workers.orchestrator import Orchestrator
    import uuid as _uuid

    reg = await AuthorizationManager(db_session).register_authorization(
        {"target": "http://127.0.0.1:8001", "authorized_by": "ToolE2E",
         "allowed_domains": ["127.0.0.1"], "allowed_paths": ["/"]}
    )
    job = await repo.create_job(
        db_session, target_id=reg["target_id"],
        authorization_id=reg["authorization"]["id"], trigger="INITIAL", profile="DEEP",
    )
    result = await Orchestrator(db_session).run_job(_uuid.UUID(job.id))
    assert result["status"] == "COMPLETED", result.get("error")
    assessment = await repo.get_assessment(db_session, result["assessment_id"])
    surface = assessment.attack_surface or {}
    assert "tools_used" in surface
    assert "tool_provenance" in surface
    # findings still flow through the standard pipeline
    assert assessment.security_score is not None


@pytest.mark.asyncio
async def test_tools_endpoint_reports_health(db_session, client):
    resp = await client.get("/api/v1/tools")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tools_enabled"] is True
    assert "nmap" in body["tools"]
    assert body["tools"]["nmap"]["status"] in ("READY", "NOT_INSTALLED")
    assert "QUICK" in body["profile_map"]
