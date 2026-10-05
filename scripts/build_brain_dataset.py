#!/usr/bin/env python3
"""Build the CASA-Brain Level-2 training dataset from recorded trajectories.

Reads ``data/brain-trajectories.jsonl`` (written by TrajectoryRecorder),
applies the curation filter (policy-approved AND executed-OK transitions
only, optionally bounded by minimum expected information gain), drops
execution-outcome link records and duplicates, and emits a fine-tuning-ready
JSONL file where each line is::

    {"schema": "casa.brain.dataset/level2/v1",
     "messages": [system, user, assistant],
     "meta": {...}}

- system:    fixed CASA-Brain policy preamble (the action space and the
             safety contract the model must respect)
- user:      compact, deterministic projection of the assessment state
- assistant: the exact action JSON the deterministic Brain selected

Curation-first, never blind: only transitions where the deterministic policy
gate approved and execution succeeded become training pairs, so the dataset
teaches the *legal, working* policy — never denied or failed proposals.

Usage::

    python scripts/build_brain_dataset.py                       # defaults
    python scripts/build_brain_dataset.py --min-gain 0.5
    python scripts/build_brain_dataset.py --in traj.jsonl --out ds.jsonl
    python scripts/build_brain_dataset.py --stats-only
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Make `agent` importable when invoked as `python scripts/build_brain_dataset.py`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if hasattr(sys.stdout, "reconfigure"):  # Windows consoles default to cp1252
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from agent.core.config import settings  # noqa: E402

DATASET_SCHEMA = "casa.brain.dataset/level2/v1"

SYSTEM_PROMPT = (
    "You are CASA-Brain, the decision engine of an authorized-scope-only web "
    "security assessment agent. Given the current assessment state, select the "
    "single best next action from the fixed action space (RUN_MODULE, "
    "REQUEST_MORE_EVIDENCE, CORRELATE_FINDINGS, VERIFY_FINDING, "
    "ENRICH_TECHNOLOGY, REASSESS, STOP_ASSESSMENT). Actions are proposals only: "
    "a deterministic policy gate validates every proposal, and only modules on "
    "the allowlist may run. Optimize expected information gain per action; "
    "choose STOP_ASSESSMENT when further actions add no value. Output exactly "
    "one JSON action object and nothing else."
)

# State fields kept in the user prompt — a compact, deterministic projection of
# BrainState.to_dict() (no raw bodies, no volatile identifiers like job ids).
_STATE_KEYS = (
    "target_url",
    "profile",
    "step",
    "max_steps",
    "allowed_modules",
    "executed_modules",
    "pending_modules",
    "technologies",
    "open_findings",
    "critical_high",
    "unverified_high_value",
    "evidence_counts",
    "uncertainties",
)
_SURFACE_KEYS = ("domains", "subdomains", "endpoints", "forms", "technologies_count", "tools_used")


def state_projection(state: dict[str, Any]) -> dict[str, Any]:
    """Compact deterministic projection of the assessment state for training."""
    surface = state.get("attack_surface") or {}
    proj = {k: state.get(k) for k in _STATE_KEYS if state.get(k) is not None}
    surface_summary = {k: surface.get(k) for k in _SURFACE_KEYS if surface.get(k) is not None}
    if surface_summary:
        proj["attack_surface_summary"] = surface_summary
    return proj


def is_link_record(rec: dict[str, Any]) -> bool:
    """Execution-outcome link records duplicate a decision already captured."""
    return (
        rec.get("decision", {}).get("kind") == "execution-outcome"
        or rec.get("state", {}).get("link") == "execution-outcome"
    )


def read_records(path: Path | str) -> list[dict[str, Any]]:
    """Read all valid JSONL trajectory records (raw, no filtering)."""
    path = Path(path)
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                continue
    return out


def join_execution_outcomes(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach link-record execution outcomes back onto their decisions.

    TrajectoryRecorder writes each decision with execution=None and emits the
    outcome as a *separate* linked record (state_before = {state_hash, link:
    'execution-outcome'}). For training we join them: the decision record is
    the unit, and the matched execution outcome is attached to it.
    """
    outcomes: dict[tuple[str | None, str], dict[str, Any]] = {}
    for rec in records:
        if not is_link_record(rec):
            continue
        key = (
            rec.get("state_hash") or (rec.get("state") or {}).get("state_hash"),
            json.dumps(rec.get("selected") or {}, sort_keys=True, default=str),
        )
        if rec.get("execution") is not None:
            outcomes.setdefault(key, rec["execution"])

    joined: list[dict[str, Any]] = []
    for rec in records:
        if is_link_record(rec):
            continue
        if rec.get("execution") is None:
            key = (
                rec.get("state_hash") or (rec.get("state") or {}).get("state_hash"),
                json.dumps(rec.get("selected") or {}, sort_keys=True, default=str),
            )
            execution = outcomes.get(key)
            if execution is not None:
                rec = {**rec, "execution": execution}
        joined.append(rec)
    return joined


def _curate(
    records: list[dict[str, Any]],
    *,
    min_gain: float,
    require_execution_ok: bool,
) -> list[dict[str, Any]]:
    """Curation filter (mirrors TrajectoryRecorder.load_curated) on joined records."""
    out: list[dict[str, Any]] = []
    for rec in records:
        if require_policy_ok(rec) is False:
            continue
        if require_execution_ok:
            execution = rec.get("execution")
            if execution is None or not execution.get("ok", False):
                continue
        gain = float((rec.get("selected") or {}).get("expected_information_gain", 0.0))
        if gain < min_gain:
            continue
        out.append(rec)
    return out


def require_policy_ok(rec: dict[str, Any]) -> bool:
    return bool((rec.get("policy") or {}).get("allowed"))


def to_training_pair(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one curated trajectory record into a chat-format training pair."""
    state = rec.get("state") or {}
    selected = rec.get("selected") or {}
    if not state or not selected.get("action"):
        return None
    return {
        "schema": DATASET_SCHEMA,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(state_projection(state), sort_keys=True, default=str),
            },
            {
                "role": "assistant",
                "content": json.dumps(selected, sort_keys=True, default=str),
            },
        ],
        "meta": {
            "state_hash": rec.get("state_hash"),
            "strategy": (rec.get("decision") or {}).get("strategy"),
            "policy_rule": (rec.get("policy") or {}).get("rule"),
            "execution": rec.get("execution"),
            "resulting_state_hash": rec.get("resulting_state_hash"),
        },
    }


def build_dataset(
    src: Path | str,
    dst: Path | str,
    *,
    min_gain: float = 0.0,
    require_execution_ok: bool = True,
    max_samples: int = 0,
) -> dict[str, Any]:
    """Curate trajectories into a Level-2 dataset. Returns stats."""
    records = join_execution_outcomes(read_records(src))
    curated = _curate(
        records,
        min_gain=min_gain,
        require_execution_ok=require_execution_ok,
    )

    seen: set[str] = set()
    pairs: list[dict[str, Any]] = []
    duplicates = 0
    for rec in curated:
        if is_link_record(rec):
            continue
        pair = to_training_pair(rec)
        if pair is None:
            continue
        action = pair["messages"][2]["content"]
        key = f"{rec.get('state_hash')}|{action}"
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        pairs.append(pair)
        if max_samples and len(pairs) >= max_samples:
            break

    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w", encoding="utf-8") as fh:
        for pair in pairs:
            fh.write(json.dumps(pair, default=str) + "\n")

    dist = Counter(
        json.loads(p["messages"][2]["content"]).get("action", "?") for p in pairs
    )
    return {
        "source": str(src),
        "output": str(dst),
        "total_lines": _count_lines(Path(src)),
        "curated": len(curated),
        "written": len(pairs),
        "duplicates_dropped": duplicates,
        "action_distribution": dict(sorted(dist.items(), key=lambda kv: -kv[1])),
    }


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return sum(1 for line in fh if line.strip())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the CASA-Brain Level-2 training dataset from trajectories."
    )
    parser.add_argument(
        "--in", dest="inp", default=None,
        help="Input trajectories JSONL (default: data/brain-trajectories.jsonl)",
    )
    parser.add_argument(
        "--out", dest="out", default=None,
        help="Output dataset JSONL (default: data/brain-dataset-level2.jsonl)",
    )
    parser.add_argument(
        "--min-gain", type=float, default=0.0,
        help="Minimum expected_information_gain for a transition to be kept",
    )
    parser.add_argument(
        "--allow-unexecuted", action="store_true",
        help="Keep policy-approved transitions even if execution outcome is missing",
    )
    parser.add_argument("--max-samples", type=int, default=0, help="Cap dataset size")
    parser.add_argument(
        "--stats-only", action="store_true",
        help="Print curation statistics without writing the dataset",
    )
    args = parser.parse_args()

    src = Path(args.inp) if args.inp else settings.data_dir / "brain-trajectories.jsonl"
    dst = Path(args.out) if args.out else settings.data_dir / "brain-dataset-level2.jsonl"

    if args.stats_only:
        records = join_execution_outcomes(read_records(src))
        curated = _curate(
            records,
            min_gain=args.min_gain,
            require_execution_ok=not args.allow_unexecuted,
        )
        stats = {
            "source": str(src),
            "total_lines": _count_lines(src),
            "curated": len(curated),
            "link_records": sum(1 for r in read_records(src) if is_link_record(r)),
        }
    else:
        stats = build_dataset(
            src,
            dst,
            min_gain=args.min_gain,
            require_execution_ok=not args.allow_unexecuted,
            max_samples=args.max_samples,
        )

    print("CASA-Brain Level-2 dataset builder")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
