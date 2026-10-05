"""Tests for scripts/build_brain_dataset.py (Level-2 dataset pipeline)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_brain_dataset.py"
_spec = importlib.util.spec_from_file_location("build_brain_dataset", _SCRIPT)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("build_brain_dataset", _mod)
_spec.loader.exec_module(_mod)


def _state(state_hash: str, *, link: bool = False) -> dict:
    if link:
        return {"state_hash": state_hash, "link": "execution-outcome"}
    return {
        "target_url": "http://target.local",
        "profile": "STANDARD",
        "step": 3,
        "max_steps": 40,
        "technologies": [{"name": "Werkzeug", "version": "3.0.0"}],
        "evidence_counts": {"headers": 1},
        "executed_modules": ["recon"],
        "pending_modules": ["headers"],
        "uncertainties": ["no_endpoint_map"],
        "attack_surface": {"endpoints": 4, "forms": 1, "tools_used": []},
    }


_MISSING = object()


def _record(
    state_hash: str,
    *,
    action: str = "RUN_MODULE",
    params: dict | None = None,
    gain: float = 0.5,
    policy_ok: bool = True,
    execution: dict | None | object = _MISSING,
    link: bool = False,
) -> dict:
    return {
        "schema": "casa.brain.trajectory/v1",
        "state_hash": state_hash,
        "state": _state(state_hash, link=link),
        "candidates": [],
        "selected": {
            "action": action,
            "params": params or {"module": "headers"},
            "reason_codes": ["worth_it"],
            "expected_information_gain": gain,
            "confidence": 0.8,
            "related_findings": [],
            "expected_evidence": "headers",
        },
        "decision": (
            {"kind": "execution-outcome"} if link else {"strategy": "deterministic-v1", "notes": ""}
        ),
        "policy": {"allowed": policy_ok, "reason": "ok", "rule": "R1_SHAPE"},
        "execution": execution if execution is not _MISSING else {"ok": True, "module": "headers"},
        "resulting_state_hash": "abc123",
    }


def _write_traj(tmp_path: Path, records: list[dict]) -> Path:
    src = tmp_path / "trajectories.jsonl"
    with src.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    return src


def test_builds_pairs_and_drops_links_and_duplicates(tmp_path):
    src = _write_traj(
        tmp_path,
        [
            _record("h1"),
            _record("h1"),  # duplicate (same state + same action)
            _record("h2", link=True),  # execution-outcome link record
            _record("h3", action="ENRICH_TECHNOLOGY", params={"technology": "Werkzeug", "enricher": "exploitdb"}, gain=0.95),
        ],
    )
    dst = tmp_path / "dataset.jsonl"
    stats = _mod.build_dataset(src, dst)

    assert stats["written"] == 2
    assert stats["duplicates_dropped"] == 1
    lines = [json.loads(line) for line in dst.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2


def test_pair_shape_system_user_assistant(tmp_path):
    src = _write_traj(tmp_path, [_record("h1")])
    dst = tmp_path / "dataset.jsonl"
    _mod.build_dataset(src, dst)

    pair = json.loads(dst.read_text(encoding="utf-8").splitlines()[0])
    assert pair["schema"] == _mod.DATASET_SCHEMA
    roles = [m["role"] for m in pair["messages"]]
    assert roles == ["system", "user", "assistant"]

    state_in = json.loads(pair["messages"][1]["content"])
    assert state_in["profile"] == "STANDARD"
    assert state_in["technologies"][0]["name"] == "Werkzeug"
    assert "attack_surface_summary" in state_in

    action_out = json.loads(pair["messages"][2]["content"])
    assert action_out["action"] == "RUN_MODULE"
    assert action_out["params"]["module"] == "headers"

    assert pair["meta"]["state_hash"] == "h1"
    assert pair["meta"]["strategy"] == "deterministic-v1"


def test_min_gain_filter(tmp_path):
    src = _write_traj(
        tmp_path,
        [
            _record("h1", gain=0.2),
            _record("h2", gain=0.95),
        ],
    )
    dst = tmp_path / "dataset.jsonl"
    stats = _mod.build_dataset(src, dst, min_gain=0.5)
    assert stats["curated"] == 1 and stats["written"] == 1


def test_unexecuted_excluded_by_default_included_with_flag(tmp_path):
    src = _write_traj(
        tmp_path,
        [
            _record("h1", execution=None),
            _record("h2", execution={"ok": False, "error": "boom"}),
        ],
    )
    dst = tmp_path / "dataset.jsonl"
    stats = _mod.build_dataset(src, dst)
    assert stats["written"] == 0

    stats2 = _mod.build_dataset(src, dst, require_execution_ok=False)
    assert stats2["written"] == 2  # flag relaxes the whole execution check


def test_state_projection_is_compact_and_deterministic():
    proj = _mod.state_projection(_state("h1"))
    assert set(proj) <= set(_mod._STATE_KEYS) | {"attack_surface_summary"}
    assert json.dumps(proj, sort_keys=True) == json.dumps(proj, sort_keys=True)
    assert "job_id" not in proj and "authorization" not in proj
