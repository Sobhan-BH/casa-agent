"""Verification Engine — post-remediation comparison.

Given baseline findings from a previous assessment and findings from a fresh
assessment of the same target, produces per-finding status:

- OPEN:          present now, no baseline counterpart (new)
- FIXED:         in baseline, absent now
- STILL_PRESENT: in baseline, present now with same severity
- CHANGED:       in baseline, present now with different severity
- UNVERIFIED:    baseline finding has no fingerprint to match against

Baseline FALSE_POSITIVE findings are excluded upstream (orchestrator).
"""
from __future__ import annotations

from typing import Any

from agent.core.enums import FindingStatus


class VerificationEngine:
    name = "verification_engine"

    def compare(
        self, baseline: list[dict[str, Any]], current: list[dict[str, Any]]
    ) -> dict[str, Any]:
        baseline_by_fp = {
            f["fingerprint"]: f for f in baseline if f.get("fingerprint")
        }
        current_by_fp = {f["fingerprint"]: f for f in current if f.get("fingerprint")}

        items: list[dict[str, Any]] = []
        counts = {s.value: 0 for s in FindingStatus if s.value != "FALSE_POSITIVE"}

        # 1) Baseline side: FIXED / STILL_PRESENT / CHANGED / UNVERIFIED
        for fp, prev in baseline_by_fp.items():
            curr = current_by_fp.get(fp)
            if curr is None:
                status = FindingStatus.FIXED.value
            elif prev.get("severity") == curr.get("severity"):
                status = FindingStatus.STILL_PRESENT.value
            else:
                status = FindingStatus.CHANGED.value
            counts[status] += 1
            items.append(
                {
                    "previous_id": prev.get("id"),
                    "current_id": curr.get("id") if curr else None,
                    "fingerprint": fp,
                    "title": prev.get("title"),
                    "previous_severity": prev.get("severity"),
                    "current_severity": curr.get("severity") if curr else None,
                    "status": status,
                }
            )

        # 2) Current side: new findings are OPEN
        for fp, curr in current_by_fp.items():
            if fp in baseline_by_fp:
                continue
            counts[FindingStatus.OPEN.value] += 1
            items.append(
                {
                    "previous_id": None,
                    "current_id": curr.get("id"),
                    "fingerprint": fp,
                    "title": curr.get("title"),
                    "previous_severity": None,
                    "current_severity": curr.get("severity"),
                    "status": FindingStatus.OPEN.value,
                }
            )

        # 3) UNVERIFIED: baseline items without fingerprints never left the list
        unverified = [
            {
                "previous_id": f.get("id"),
                "current_id": None,
                "fingerprint": None,
                "title": f.get("title"),
                "previous_severity": f.get("severity"),
                "current_severity": None,
                "status": FindingStatus.UNVERIFIED.value,
            }
            for f in baseline
            if not f.get("fingerprint")
        ]
        counts[FindingStatus.UNVERIFIED.value] += len(unverified)
        items.extend(unverified)

        summary = (
            f"{counts['FIXED']} fixed, {counts['STILL_PRESENT']} still present, "
            f"{counts['CHANGED']} changed, {counts['OPEN']} new, "
            f"{counts['UNVERIFIED']} unverified"
        )
        return {
            "engine": self.name,
            "summary": summary,
            "counts": counts,
            "items": items,
        }
