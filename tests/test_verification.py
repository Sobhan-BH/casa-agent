"""VerificationEngine tests."""
from agent.verification.engine import VerificationEngine


def test_fixed_and_still_present():
    baseline = [
        {"id": "1", "fingerprint": "fp-hsts", "title": "HSTS missing", "severity": "MEDIUM"},
        {"id": "2", "fingerprint": "fp-git", "title": ".git exposed", "severity": "HIGH"},
    ]
    current = [
        {"id": "10", "fingerprint": "fp-git", "title": ".git exposed", "severity": "HIGH"},
    ]
    res = VerificationEngine().compare(baseline, current)
    by_title = {i["title"]: i["status"] for i in res["items"]}
    assert by_title["HSTS missing"] == "FIXED"
    assert by_title[".git exposed"] == "STILL_PRESENT"
    assert res["counts"]["FIXED"] == 1
    assert res["counts"]["STILL_PRESENT"] == 1


def test_changed_severity():
    baseline = [{"id": "1", "fingerprint": "fp1", "title": "T", "severity": "LOW"}]
    current = [{"id": "9", "fingerprint": "fp1", "title": "T", "severity": "HIGH"}]
    res = VerificationEngine().compare(baseline, current)
    assert res["items"][0]["status"] == "CHANGED"


def test_new_finding_is_open():
    baseline = []
    current = [{"id": "9", "fingerprint": "fpX", "title": "New", "severity": "LOW"}]
    res = VerificationEngine().compare(baseline, current)
    assert res["counts"]["OPEN"] == 1


def test_unverified_when_no_fingerprint():
    baseline = [{"id": "1", "fingerprint": "", "title": "Legacy", "severity": "LOW"}]
    res = VerificationEngine().compare(baseline, [])
    assert res["counts"]["UNVERIFIED"] == 1


def test_full_remediation_flow():
    baseline = [
        {"id": "1", "fingerprint": "fpA", "title": "A", "severity": "HIGH"},
        {"id": "2", "fingerprint": "fpB", "title": "B", "severity": "MEDIUM"},
        {"id": "3", "fingerprint": "fpC", "title": "C", "severity": "LOW"},
    ]
    current = [
        {"id": "11", "fingerprint": "fpB", "title": "B", "severity": "MEDIUM"},  # still present
        {"id": "12", "fingerprint": "fpC", "title": "C", "severity": "MEDIUM"},  # changed
        {"id": "13", "fingerprint": "fpD", "title": "D", "severity": "HIGH"},    # new
    ]
    res = VerificationEngine().compare(baseline, current)
    assert res["counts"] == {
        "OPEN": 1, "FIXED": 1, "STILL_PRESENT": 1, "CHANGED": 1, "UNVERIFIED": 0
    }
