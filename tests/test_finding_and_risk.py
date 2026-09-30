"""Finding schema + RiskEngine tests."""
import pytest

from agent.core.finding import make_finding, make_fingerprint
from agent.core.exceptions import CasaError
from agent.risk.engine import RiskEngine


def test_make_finding_valid():
    f = make_finding("T", "CONFIGURATION", "HIGH", "HIGH", "d", affected_asset="a")
    assert f["severity"] == "HIGH"
    assert f["status"] == "UNVERIFIED"
    assert f["evidence"] == []


def test_make_finding_invalid_category():
    with pytest.raises(ValueError):
        make_finding("T", "NOT_A_CATEGORY", "HIGH", "HIGH", "d")


def test_make_finding_coerces_case():
    f = make_finding("T", "tls", "high", "HIGH", "d")
    assert f["category"] == "TLS"
    assert f["severity"] == "HIGH"


def test_fingerprint_stable():
    assert make_fingerprint("a", 1) == make_fingerprint("a", 1)
    assert make_fingerprint("a", 1) != make_fingerprint("a", 2)


def test_risk_score_ranks_severities(sample_finding):
    engine = RiskEngine()
    low = engine.score_finding(sample_finding(severity="LOW"))
    crit = engine.score_finding(sample_finding(severity="CRITICAL"))
    assert crit["risk_score"] > low["risk_score"]


def test_risk_info_costs_nothing(sample_finding):
    engine = RiskEngine()
    res = engine.score_finding(sample_finding(severity="INFO"))
    assert res["risk_score"] == 0.0


def test_confidence_scales_risk(sample_finding):
    engine = RiskEngine()
    high = engine.score_finding(sample_finding(confidence="HIGH"))
    lowconf = engine.score_finding(sample_finding(confidence="LOW"))
    assert high["risk_score"] > lowconf["risk_score"]


def test_security_score_bounds_and_order():
    engine = RiskEngine()
    clean = engine.compute([])
    assert clean["security_score"] == 100.0

    findings = [
        make_finding("Exposed env", "WEB", "CRITICAL", "HIGH", "x",
                     affected_asset="http://t/.env")
        for _ in range(6)
    ]
    bad = engine.compute(findings)
    assert bad["security_score"] < clean["security_score"]
    assert 0.0 <= bad["security_score"] <= 100.0
    assert bad["distribution"]["CRITICAL"] == 6


def test_risk_engine_is_deterministic(sample_finding):
    engine = RiskEngine()
    a = engine.compute([sample_finding(), sample_finding(severity="HIGH")])
    b = engine.compute([sample_finding(), sample_finding(severity="HIGH")])
    assert a["security_score"] == b["security_score"]


def test_no_casa_error_import_leak():
    # guards against accidental broad import damage
    import agent.core.finding  # noqa: F401
