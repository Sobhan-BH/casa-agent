#!/usr/bin/env python3
"""Fetch the CVE-intel feeds (CISA KEV + EPSS) for offline CASA use.

Downloads (or refreshes) both feeds into ``data/``:

- CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- EPSS:     https://epss.cyentia.com/epss_scores-current.csv.gz

CASA never calls these endpoints at runtime — this script is the only network
step, and everything afterwards works offline from the local snapshot.
"""
from __future__ import annotations

import argparse
import gzip
import json
import shutil
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
KEV_OUT = DATA_DIR / "kev.json"
EPSS_OUT = DATA_DIR / "epss_scores.csv"

KEV_MIN_ENTRIES = 500      # catalog has ~1,300+ entries
EPSS_MIN_ROWS = 100000     # current file carries ~250k+ CVEs


def _fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "casa-agent-cve-intel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    shutil.move(str(tmp), path)


def fetch_kev(timeout: int) -> int:
    print(f"downloading KEV: {KEV_URL}")
    raw = _fetch(KEV_URL, timeout)
    data = json.loads(raw.decode("utf-8", errors="replace"))
    count = len(data.get("vulnerabilities", []))
    if count < KEV_MIN_ENTRIES:
        raise RuntimeError(f"KEV feed too small ({count} entries < {KEV_MIN_ENTRIES})")
    _atomic_write(KEV_OUT, raw)
    print(f"  KEV OK: {count} exploited CVEs -> {KEV_OUT}")
    return count


def fetch_epss(timeout: int) -> int:
    print(f"downloading EPSS: {EPSS_URL}")
    raw = _fetch(EPSS_URL, timeout)
    text = gzip.decompress(raw).decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    rows = max(0, len(lines) - 2)  # header + model-date comment line
    if rows < EPSS_MIN_ROWS:
        raise RuntimeError(f"EPSS feed too small ({rows} rows < {EPSS_MIN_ROWS})")
    _atomic_write(EPSS_OUT, text.encode("utf-8"))
    print(f"  EPSS OK: {rows} scored CVEs -> {EPSS_OUT}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--kev-only", action="store_true")
    parser.add_argument("--epss-only", action="store_true")
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rc = 0
    if not args.epss_only:
        try:
            fetch_kev(args.timeout)
        except Exception as exc:  # noqa: BLE001 — best-effort per feed
            print(f"  KEV FAILED: {exc}", file=sys.stderr)
            rc = 1
    if not args.kev_only:
        try:
            fetch_epss(args.timeout)
        except Exception as exc:  # noqa: BLE001
            print(f"  EPSS FAILED: {exc}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
