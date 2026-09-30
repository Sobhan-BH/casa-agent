"""End-to-end demo: register authorization, run assessment, print report.

Prerequisites:
    uvicorn agent.api.main:app --port 8000
    python -m lab.vulnerable_app   (only for the default local target)

Usage:
    python scripts/demo_assessment.py                     # local vulnerable lab
    python scripts/demo_assessment.py https://example.com # an authorized target
    python scripts/demo_assessment.py https://example.com --profile DEEP

Only run against targets you own or are explicitly authorized to assess.
"""
from __future__ import annotations

import argparse
import asyncio
import sys

import httpx

API = "http://127.0.0.1:8000"

_parser = argparse.ArgumentParser(description="CASA assessment client")
_parser.add_argument("target", nargs="?", default="http://127.0.0.1:8001")
_parser.add_argument("--profile", default="STANDARD", choices=["QUICK", "STANDARD", "DEEP"])
_args = _parser.parse_args()
TARGET = _args.target
PROFILE = _args.profile


async def main() -> int:
    async with httpx.AsyncClient(base_url=API, timeout=120) as c:
        # 1) health checks
        if (await c.get("/health")).status_code != 200:
            print("API is not running on", API)
            return 1

        # 2) register authorization
        from urllib.parse import urlparse

        host = urlparse(TARGET).hostname or TARGET
        r = await c.post(
            "/api/v1/authorizations",
            json={
                "target": TARGET,
                "authorized_by": "Demo Operator (owner/authorized)",
                "authorization_reference": "DEMO-001",
                "allowed_domains": [host],
                "allowed_paths": ["/"],
            },
        )
        r.raise_for_status()
        target_id = r.json()["target_id"]
        authz_id = r.json()["authorization"]["id"]
        print(f"[1/5] authorization registered: target={target_id} authz={authz_id}")

        # 3) run assessment and wait for completion
        r = await c.post(
            "/api/v1/jobs",
            json={"target_id": target_id, "trigger": "INITIAL", "profile": PROFILE},
        )
        r.raise_for_status()
        job = r.json()
        job_id = job["id"]
        print(f"[2/5] job created: {job_id} (status={job['status']}, profile={PROFILE})")

        import time as _time

        started = _time.monotonic()
        last_shown = None
        while True:
            await asyncio.sleep(2)
            r = await c.get(f"/api/v1/jobs/{job_id}")
            status = r.json()["status"]
            if status in ("COMPLETED", "FAILED", "BLOCKED"):
                break
            elapsed = int(_time.monotonic() - started)
            if elapsed % 10 == 0 and elapsed != last_shown:
                last_shown = elapsed
                print(f"      status: {status} ({elapsed}s elapsed)")
        print(f"[3/5] job finished: {status} in {int(_time.monotonic() - started)}s")
        if status != "COMPLETED":
            print("error:", r.json().get("error"))
            return 2

        # 4) show results
        r = await c.get(f"/api/v1/assessments?target_id={target_id}")
        assessment = r.json()[0]
        aid = assessment["id"]
        print(f"[4/5] assessment {aid}")
        print("      security score:", assessment["security_score"])
        print("      distribution:", assessment["risk_summary"]["distribution"])
        print("      executive summary:", assessment["ai_summary"]["executive_summary"][:200])

        r = await c.get(f"/api/v1/assessments/{aid}/findings")
        print(f"\n      findings ({len(r.json())}):")
        for f in r.json()[:8]:
            print(f"        [{f['severity']:8}] {f['title'][:70]}")

        r = await c.get(f"/api/v1/assessments/{aid}/reports")
        for a in r.json():
            print("      report:", a["fmt"], "->", a["path"])

        # 5) verification pass: re-assess against this baseline and report drift
        r = await c.post(
            "/api/v1/jobs",
            json={
                "target_id": target_id,
                "trigger": "VERIFICATION",
                "previous_assessment_id": aid,
            },
        )
        r.raise_for_status()
        vjob_id = r.json()["id"]
        print(f"[5/5] verification job: {vjob_id}")
        while True:
            await asyncio.sleep(2)
            r = await c.get(f"/api/v1/jobs/{vjob_id}")
            vstatus = r.json()["status"]
            if vstatus in ("COMPLETED", "FAILED", "BLOCKED"):
                break
        r = await c.get(f"/api/v1/assessments?target_id={target_id}")
        v_counts = (r.json()[0].get("verification_summary") or {}).get("counts", {})
        print(f"      verification: {vstatus} — counts: {v_counts}")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
