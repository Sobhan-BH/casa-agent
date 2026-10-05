"""CASA-Brain — deterministic Policy/Safety Gate.

Every Brain proposal passes through here BEFORE execution. The gate is
deliberately dumb and strict: it knows nothing about the Brain's reasoning,
only about rules. This independence is the safety property — a buggy or
poisoned Brain cannot talk an action past a rule.

Decisions are pure functions of (action, BrainState, settings): deterministic,
auditable, and unit-testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent.brain.actions import RUNNABLE_MODULES, ActionType, BrainAction


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    rule_id: str
    modified_action: BrainAction | None = None  # gate may clamp parameters


@dataclass
class PolicyConfig:
    """Operational limits the gate enforces (all deterministic)."""

    max_module_repeats: int = 2          # a module may re-run at most N times
    max_actions_per_assessment: int = 40
    allow_enrich_network_calls: bool = True   # OSV/EDB lookups require this flag
    allow_reassessment: bool = True
    min_actions_remaining: int = 0


class PolicyGate:
    """Validates Brain proposals against the hard boundaries."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()
        self.action_count: int = 0
        self.module_run_counts: dict[str, int] = {}

    # ----------------------------------------------------------------- main
    def evaluate(self, action: BrainAction, state) -> PolicyDecision:
        """Return a PolicyDecision. `state` is a BrainState."""
        # R0: structural sanity (shape errors can never pass)
        shape_errors = action.validate_shape()
        if shape_errors:
            return PolicyDecision(False, "; ".join(shape_errors), "R0_SHAPE")

        # R1: the action budget is finite
        if self.action_count >= self.config.max_actions_per_assessment:
            return PolicyDecision(False, "action budget exhausted", "R1_BUDGET")

        # R2: modules must be profile-legal AND in the runnable allowlist
        if action.action_type in (ActionType.RUN_MODULE, ActionType.REQUEST_MORE_EVIDENCE):
            module = action.params["module"]
            if module not in state.allowed_modules:
                return PolicyDecision(
                    False,
                    f"module {module!r} is not legal for profile {state.profile}",
                    "R2_PROFILE",
                )
            if module not in RUNNABLE_MODULES:
                return PolicyDecision(False, f"module {module!r} not runnable", "R3_ALLOWLIST")

        # R3b: repeat limit — the Brain cannot loop a module forever
        if action.action_type in (ActionType.RUN_MODULE, ActionType.REQUEST_MORE_EVIDENCE):
            module = action.params["module"]
            runs = self.module_run_counts.get(module, 0)
            if runs >= self.config.max_module_repeats:
                return PolicyDecision(
                    False,
                    f"module {module!r} already ran {runs}x (limit "
                    f"{self.config.max_module_repeats})",
                    "R3B_REPEAT",
                )

        # R4: verification targets must exist in state
        if action.action_type == ActionType.VERIFY_FINDING:
            fp = action.params.get("fingerprint")
            known = {f["fingerprint"] for f in state.findings}
            if fp not in known:
                return PolicyDecision(
                    False, f"fingerprint {fp!r} not in current state", "R4_VERIFY_TARGET"
                )

        # R5: only NETWORK-based enrichment is gated. The ExploitDB enricher
        # correlates against the LOCAL CSV index (zero network) so it stays
        # available even in fully offline deployments; OSV.dev needs the flag.
        if action.action_type == ActionType.ENRICH_TECHNOLOGY:
            if (
                action.params.get("enricher") == "osv"
                and not self.config.allow_enrich_network_calls
            ):
                return PolicyDecision(
                    False, "network enrichment disabled by policy", "R5_ENRICH_NET"
                )

        # R6: reassessment requires an assessment to exist and policy opt-in
        if action.action_type == ActionType.REASSESS and not self.config.allow_reassessment:
            return PolicyDecision(False, "reassessment planning disabled", "R6_REASSESS")

        # R7: the Brain can only *stop*, never force-continue past max steps
        if action.action_type != ActionType.STOP_ASSESSMENT:
            if state.max_steps and state.step >= state.max_steps:
                return PolicyDecision(
                    False, "job_max_steps reached; only STOP is legal", "R7_STEP_LIMIT"
                )

        # The gate tracks what it approved (auditable, deterministic).
        self.action_count += 1
        if action.action_type in (ActionType.RUN_MODULE, ActionType.REQUEST_MORE_EVIDENCE):
            mod = action.params["module"]
            self.module_run_counts[mod] = self.module_run_counts.get(mod, 0) + 1

        return PolicyDecision(True, "approved", "OK")

    # ------------------------------------------------------------- utilities
    def reset(self) -> None:
        self.action_count = 0
        self.module_run_counts = {}
