"""CVE intelligence — threat-based prioritization beyond "a CVE exists".

An APT does not pick CVEs at random; it picks the ones that are *known to be
worked right now*. This layer fuses two offline feeds with the ExploitDB
correlation:

- **CISA KEV** (Known Exploited Vulnerabilities): the U.S. CISA catalog of
  CVEs with confirmed exploitation in the wild (and a ransomware-use flag).
  Presence in KEV is the strongest "someone is actively exploiting this" signal.
- **EPSS** (Exploit Prediction Scoring System): daily probability (0–1) that
  a CVE will be exploited in the next 30 days, from ciencia/EPSS (cyentia).

Both feeds are downloaded once by ``scripts/fetch_cve_intel.py`` and read
fully offline — CASA still makes **zero** runtime network calls.

Priority model (deterministic, threat-first):

===========================  =============================================
Tier                         Meaning
===========================  =============================================
``P1_KEV``                   CVE is exploited in the wild (KEV member)
``P2_EPSS_CRITICAL``         EPSS >= 0.9 (top exploitation probability)
``P3_EPSS_ELEVATED``         EPSS >= 0.5 or 0.1 with public EDB exploit
``P4_INFORMATIONAL``         CVE known, no active-exploitation signal
===========================  =============================================
"""
from __future__ import annotations

import csv
import json
import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger("casa.cve_intel")

KEV_DEFAULT = "data/kev.json"
EPSS_DEFAULT = "data/epss_scores.csv"

EPSS_CRITICAL = 0.9
EPSS_ELEVATED = 0.5
EPSS_NOTABLE = 0.1

_TIER_ORDER = {
    "P1_KEV": 1,
    "P2_EPSS_CRITICAL": 2,
    "P3_EPSS_ELEVATED": 3,
    "P4_INFORMATIONAL": 4,
}
_TIER_LABEL = {
    "P1_KEV": "Actively exploited in the wild (CISA KEV)",
    "P2_EPSS_CRITICAL": "Very high exploitation probability (EPSS >= 0.9)",
    "P3_EPSS_ELEVATED": "Elevated exploitation probability (EPSS >= 0.5)",
    "P4_INFORMATIONAL": "CVE known; no active-exploitation signal",
}


def _env_path(env_var: str, default: str) -> Path:
    raw = os.environ.get(env_var, "").strip()
    return Path(raw) if raw else Path(default)


def find_kev_feed() -> Path | None:
    from agent.core.config import settings

    raw = (os.environ.get("CASA_KEV_FEED_PATH", "").strip()
           or getattr(settings, "kev_feed_path", "") or "").strip()
    candidates = [Path(raw)] if raw else []
    candidates.append(_env_path("CASA_KEV_FEED_PATH", KEV_DEFAULT))
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def find_epss_feed() -> Path | None:
    from agent.core.config import settings

    raw = (os.environ.get("CASA_EPSS_FEED_PATH", "").strip()
           or getattr(settings, "epss_feed_path", "") or "").strip()
    candidates = [Path(raw)] if raw else []
    candidates.append(_env_path("CASA_EPSS_FEED_PATH", EPSS_DEFAULT))
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


@dataclass(frozen=True)
class CveRecord:
    """Fused threat picture for one CVE."""

    cve_id: str
    in_kev: bool = False
    kev_due_date: str = ""
    known_ransomware: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None

    @property
    def tier(self) -> str:
        if self.in_kev:
            return "P1_KEV"
        if self.epss_score is not None and self.epss_score >= EPSS_CRITICAL:
            return "P2_EPSS_CRITICAL"
        if self.epss_score is not None and self.epss_score >= EPSS_ELEVATED:
            return "P3_EPSS_ELEVATED"
        if (
            self.epss_score is not None and self.epss_score >= EPSS_NOTABLE
        ) or self.known_ransomware:
            return "P3_EPSS_ELEVATED"
        return "P4_INFORMATIONAL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve_id,
            "tier": self.tier,
            "tier_label": _TIER_LABEL[self.tier],
            "in_kev": self.in_kev,
            "kev_due_date": self.kev_due_date,
            "known_ransomware": self.known_ransomware,
            "epss": self.epss_score,
            "epss_percentile": self.epss_percentile,
        }


@dataclass
class CveIntelIndex:
    """Offline KEV + EPSS index with O(1) CVE lookups."""

    kev: dict[str, CveRecord] = field(default_factory=dict)
    epss: dict[str, tuple[float | None, float | None]] = field(default_factory=dict)
    kev_path: str = ""
    epss_path: str = ""

    # ------------------------------------------------------------- loading
    @classmethod
    def load(cls, kev_path: Path | None = None, epss_path: Path | None = None) -> "CveIntelIndex":
        idx = cls()
        kp = kev_path or find_kev_feed()
        if kp:
            try:
                data = json.loads(kp.read_text(encoding="utf-8", errors="replace"))
                for v in data.get("vulnerabilities", []):
                    cve = str(v.get("cveID", "")).strip().upper()
                    if not cve.startswith("CVE-"):
                        continue
                    idx.kev[cve] = CveRecord(
                        cve_id=cve,
                        in_kev=True,
                        kev_due_date=str(v.get("dueDate", "")),
                        known_ransomware=str(
                            v.get("knownRansomwareCampaignUse", "")
                        ).lower() == "known",
                    )
                idx.kev_path = str(kp)
                logger.info("KEV loaded: %d CVEs from %s", len(idx.kev), kp)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("cannot read KEV feed %s: %s", kp, exc)

        sp = epss_path or find_epss_feed()
        if sp:
            try:
                with sp.open("r", encoding="utf-8", errors="replace") as fh:
                    # The EPSS file starts with a '#model_version:...' comment
                    # line; the real header is the first non-comment line.
                    lines = [ln for ln in fh if ln.strip() and not ln.startswith("#")]
                reader = csv.DictReader(lines)
                cols = {c.lower(): c for c in (reader.fieldnames or [])}
                cve_col = cols.get("cve")
                epss_col = cols.get("epss")
                pct_col = cols.get("epss_percentile") or cols.get("percentile")
                if cve_col and epss_col:
                    for row in reader:
                        cve = str(row.get(cve_col, "")).strip().upper()
                        if not cve.startswith("CVE-"):
                            continue
                        try:
                            score = float(row.get(epss_col) or 0.0)
                        except (TypeError, ValueError):
                            score = None
                        pct = None
                        if pct_col:
                            try:
                                pct = float(row.get(pct_col) or 0.0)
                            except (TypeError, ValueError):
                                pct = None
                        idx.epss[cve] = (score, pct)
                idx.epss_path = str(sp)
                logger.info("EPSS loaded: %d CVEs from %s", len(idx.epss), sp)
            except (OSError, csv.Error) as exc:
                logger.warning("cannot read EPSS feed %s: %s", sp, exc)

        # fuse KEV + EPSS into single records
        for cve, rec in idx.kev.items():
            score, pct = idx.epss.get(cve, (None, None))
            idx.kev[cve] = CveRecord(
                cve_id=cve,
                in_kev=True,
                kev_due_date=rec.kev_due_date,
                known_ransomware=rec.known_ransomware,
                epss_score=score,
                epss_percentile=pct,
            )
        return idx

    # ------------------------------------------------------------- lookups
    @property
    def available(self) -> bool:
        return bool(self.kev or self.epss)

    @property
    def kev_count(self) -> int:
        return len(self.kev)

    @property
    def epss_count(self) -> int:
        return len(self.epss)

    def lookup(self, cve_id: str) -> CveRecord:
        """Deterministic fused record — never None (missing feeds → informational)."""
        cve = str(cve_id).strip().upper()
        rec = self.kev.get(cve)
        score, pct = self.epss.get(cve, (None, None))
        if rec is not None:
            return rec
        return CveRecord(cve_id=cve, epss_score=score, epss_percentile=pct)

    def lookup_many(self, cve_ids: list[str]) -> list[CveRecord]:
        seen: dict[str, CveRecord] = {}
        for cve in cve_ids:
            key = str(cve).strip().upper()
            if key not in seen:
                seen[key] = self.lookup(key)
        return list(seen.values())

    def worst_priority(self, cve_ids: list[str]) -> CveRecord | None:
        """The most-dangerous record among the given CVEs (or None if empty)."""
        records = self.lookup_many(cve_ids)
        if not records:
            return None
        return min(records, key=lambda r: _TIER_ORDER[r.tier])

    def summarize(self, cve_ids: list[str]) -> dict[str, Any] | None:
        """APT-style summary block for a set of CVEs (worst-first)."""
        if not cve_ids:
            return None
        records = self.lookup_many(cve_ids)
        worst = min(records, key=lambda r: _TIER_ORDER[r.tier])
        scores = [r.epss_score for r in records if r.epss_score is not None]
        return {
            "tier": worst.tier,
            "tier_label": _TIER_LABEL[worst.tier],
            "worst_cve": worst.cve_id,
            "in_kev": sorted(r.cve_id for r in records if r.in_kev),
            "epss_max": max(scores) if scores else None,
            "known_ransomware": any(r.known_ransomware for r in records),
            "records": [r.to_dict() for r in
                        sorted(records, key=lambda r: _TIER_ORDER[r.tier])[:10]],
            "sources": {
                "kev": self.kev_path or None,
                "epss": self.epss_path or None,
            },
        }


# ----------------------------------------------------------- process cache
def _intel_signature() -> tuple | None:
    sigs: list[tuple[str, int, int]] = []
    for finder in (find_kev_feed, find_epss_feed):
        p = finder()
        if p is None:
            continue
        try:
            st = p.stat()
            sigs.append((str(p), st.st_mtime_ns, st.st_size))
        except OSError:
            continue
    return tuple(sigs) if sigs else None


@lru_cache(maxsize=1)
def _cached_intel(sig: tuple | None) -> CveIntelIndex:
    return CveIntelIndex.load()


def get_cve_intel(refresh: bool = False) -> CveIntelIndex:
    """Shared KEV/EPSS index; transparently reloads when feed files change."""
    if refresh:
        _cached_intel.cache_clear()
    return _cached_intel(_intel_signature())
