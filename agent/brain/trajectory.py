"""CASA-Brain — trajectory recording (training-data foundation).

Every Brain decision is appended as a structured transition:

    state_hash, state_snapshot, candidate_actions, selected_action,
    decision_metadata, policy_result, execution_result, evidence_generated,
    resulting_state_hash

Trajectories land in a JSONL file (data/brain-trajectories.jsonl by default).
This is the raw material for the future CASA-specific model — but recording
is curation-friendly, not blind: each record keeps policy + execution
outcomes so that only high-quality trajectories (approved, executed OK,
information gain actually realized) can be filtered for training later.
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from agent.core.config import settings

logger = logging.getLogger("casa.brain.trajectory")

_lock = threading.Lock()


class TrajectoryRecorder:
    """Append-only JSONL writer with graceful degradation (disk full, etc.)."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path or (settings.data_dir / "brain-trajectories.jsonl"))
        self.enabled = settings.brain_trajectory_enabled

    def record_transition(
        self,
        *,
        state_before: dict[str, Any],
        candidate_actions: list[dict[str, Any]],
        selected_action: dict[str, Any],
        decision_metadata: dict[str, Any],
        policy_result: dict[str, Any],
        execution_result: dict[str, Any] | None,
        resulting_state_hash: str | None,
    ) -> bool:
        if not self.enabled:
            return False
        record = {
            "schema": "casa.brain.trajectory/v1",
            "state_hash": state_before.get("state_hash"),
            "state": state_before,
            "candidates": candidate_actions,
            "selected": selected_action,
            "decision": decision_metadata,
            "policy": policy_result,
            "execution": execution_result,
            "resulting_state_hash": resulting_state_hash,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with _lock, self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
            return True
        except OSError as exc:
            logger.warning("trajectory write failed: %s", exc)
            return False

    def load_curated(
        self,
        *,
        require_policy_ok: bool = True,
        require_execution_ok: bool = True,
        min_information_gain: float = 0.0,
    ) -> list[dict[str, Any]]:
        """Curation filter for future training runs — never blind."""
        out: list[dict[str, Any]] = []
        if not self.path.exists():
            return out
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if require_policy_ok and not rec.get("policy", {}).get("allowed"):
                    continue
                if require_execution_ok and rec.get("execution", {}) is None:
                    continue
                if require_execution_ok and not rec["execution"].get("ok", False):
                    continue
                gain = float(
                    rec.get("selected", {}).get("expected_information_gain", 0.0)
                )
                if gain < min_information_gain:
                    continue
                out.append(rec)
        return out
