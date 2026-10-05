"""CASA-Brain — the adaptive loop driver.

Wires state -> decision -> policy gate -> execution hook -> state. The Brain
never executes anything itself: `executor` is a callable provided by the
orchestrator that knows how to run an approved action inside the existing,
fully gated pipeline. The default integration mode is OFF
(CASA_BRAIN_ENABLED=false) so stock CASA behavior is 100% preserved.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Callable

from agent.brain.actions import ActionType, BrainAction
from agent.brain.engine import DeterministicStrategy, Decision, make_strategy
from agent.brain.policy_gate import PolicyConfig, PolicyGate
from agent.brain.state import BrainState
from dataclasses import field

from agent.brain.trajectory import TrajectoryRecorder

logger = logging.getLogger("casa.brain")


def brain_enabled() -> bool:
    return os.environ.get("CASA_BRAIN_ENABLED", "").strip().lower() in (
        "1", "true", "yes", "on"
    )


@dataclass
class BrainReport:
    """Everything the orchestrator (and the report) needs to know."""

    decisions: list[dict[str, Any]] = field(default_factory=list)
    final_reason: str = ""
    approved_count: int = 0
    denied_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "strategy": self.decisions[-1]["strategy"] if self.decisions else "n/a",
            "decisions": self.decisions,
            "approved": self.approved_count,
            "denied": self.denied_count,
            "final_reason": self.final_reason,
        }


class BrainLoop:
    """Runs the observe-decide-validate-execute cycle between modules."""

    def __init__(
        self,
        gate: PolicyGate | None = None,
        recorder: TrajectoryRecorder | None = None,
        strategy=None,
    ) -> None:
        self.gate = gate or PolicyGate(PolicyConfig())
        self.recorder = recorder or TrajectoryRecorder()
        self.strategy = strategy or make_strategy()
        self.report = BrainReport(decisions=[])

    def next_action(self, state: BrainState) -> tuple[BrainAction | None, Decision]:
        """Observe -> decide -> validate. Returns (approved_action|None, decision).

        None means: no legal/valuable action remains (the orchestrator should
        proceed to its normal tail stages).
        """
        decision: Decision = self.strategy.propose(state)
        action = decision.action
        policy = self.gate.evaluate(action, state)

        self.report.decisions.append(
            {
                "strategy": decision.strategy,
                "state_hash": state.state_hash,
                "step": state.step,
                "candidates": [c.to_dict() for c in decision.candidates[:6]],
                "selected": action.to_dict(),
                "policy": {"allowed": policy.allowed, "reason": policy.reason,
                           "rule": policy.rule_id},
                "notes": decision.notes,
            }
        )
        if not policy.allowed:
            self.report.denied_count += 1
            logger.info("brain proposal denied (%s): %s", policy.rule_id, policy.reason)
            # A denied proposal is a hard stop for that branch — try the next
            # best candidate once so a single illegal proposal can't stall the
            # loop, but never fight the gate.
            for alt in decision.candidates[1:4]:
                alt_policy = self.gate.evaluate(alt, state)
                if alt_policy.allowed:
                    self._record(state, decision, alt, alt_policy, None, None)
                    self.report.approved_count += 1
                    return alt, decision
            self._record(state, decision, action, policy, None, None)
            self.report.final_reason = (
                f"no approved action remains ({policy.rule_id}: {policy.reason})"
            )
            return None, decision

        self.report.approved_count += 1
        self._record(state, decision, action, policy, None, None)
        return action, decision

    def record_execution(
        self,
        state_before_hash: str,
        action: BrainAction,
        execution_result: dict[str, Any] | None,
        resulting_state: BrainState | None,
    ) -> None:
        """Attach execution outcome to the last recorded transition."""
        self._append_execution(state_before_hash, action, execution_result,
                               resulting_state.state_hash if resulting_state else None)

    # -------------------------------------------------------------- internal
    def _record(self, state, decision, action, policy, execution, resulting_hash) -> None:
        self.recorder.record_transition(
            state_before=state.to_dict(),
            candidate_actions=[c.to_dict() for c in decision.candidates[:8]],
            selected_action=action.to_dict(),
            decision_metadata={"strategy": decision.strategy, "notes": decision.notes},
            policy_result={"allowed": policy.allowed, "reason": policy.reason,
                           "rule": policy.rule_id},
            execution_result=execution,
            resulting_state_hash=resulting_hash,
        )

    def _append_execution(self, state_hash, action, execution, resulting_hash) -> None:
        # Trajectories are append-only; the execution outcome is written as a
        # linked record rather than mutating history.
        self.recorder.record_transition(
            state_before={"state_hash": state_hash, "link": "execution-outcome"},
            candidate_actions=[],
            selected_action=action.to_dict(),
            decision_metadata={"kind": "execution-outcome"},
            policy_result={"allowed": True, "reason": "already approved", "rule": "LINK"},
            execution_result=execution,
            resulting_state_hash=resulting_hash,
        )


def build_default_loop() -> BrainLoop:
    """Factory used by the orchestrator: reads env, returns disabled-safe loop."""
    if not brain_enabled():
        return _DisabledLoop()  # type: ignore[return-value]
    return BrainLoop()


class _DisabledLoop:  # minimal null-object keeping orchestrator code simple
    def next_action(self, state):  # noqa: ANN001
        return None, Decision(
            BrainAction(ActionType.STOP_ASSESSMENT, reason_codes=["brain_disabled"]),
            [], "disabled", "CASA_BRAIN_ENABLED not set",
        )

    def record_execution(self, *a, **k) -> None:  # noqa: ANN002, ANN003
        return None

    @property
    def report(self):  # noqa: D102
        return BrainReport(decisions=[], final_reason="disabled")
