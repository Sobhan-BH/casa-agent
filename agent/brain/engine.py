"""CASA-Brain — deterministic decision engine.

LEVEL 0 intelligence: pure, offline, explainable rules that convert a
BrainState into the single most information-valued next action. Every decision
carries reason codes, expected information gain, confidence and the findings
that motivated it, so a human (or the report) can audit *why*.

The engine is a strategy class. `LocalModelStrategy` (LEVEL 1) implements the
same interface and, when a local model is configured, may re-rank the
deterministic candidates — but it can only *choose among* engine-proposed
actions, never invent new ones. The Policy Gate still validates the result.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agent.brain.actions import (
    EVIDENCE_MODULE_BY_CATEGORY,
    ActionType,
    BrainAction,
)
from agent.brain.state import BrainState

logger = logging.getLogger("casa.brain")


@dataclass
class Decision:
    action: BrainAction
    candidates: list[BrainAction] = field(default_factory=list)
    strategy: str = "deterministic-v1"
    notes: str = ""


class DeterministicStrategy:
    """RULE-BASED next-action selection, ordered by information gain."""

    name = "deterministic-v1"

    def propose(self, state: BrainState) -> Decision:
        candidates = self._candidates(state)
        if not candidates:
            stop = BrainAction(
                ActionType.STOP_ASSESSMENT,
                reason_codes=["no_high_value_actions"],
                expected_information_gain=0.0,
                confidence=1.0,
            )
            return Decision(stop, [stop], self.name, "nothing worth doing")
        candidates.sort(key=lambda a: a.expected_information_gain, reverse=True)
        return Decision(candidates[0], candidates, self.name)

    # ------------------------------------------------------------ candidates
    def _candidates(self, state: BrainState) -> list[BrainAction]:
        out: list[BrainAction] = []

        # 1) STOP dominates when the assessment is mature or exhausted.
        if state.max_steps and state.step >= state.max_steps:
            out.append(self._stop(state, ["max_steps_reached"]))
            return out
        if not state.pending_modules:
            out.append(self._stop(state, ["all_profile_modules_executed"]))
        # Diminishing returns: full profile ran and the last snapshot added
        # nothing high-value that verification could still sharpen.
        if (
            not state.pending_modules
            and state.unverified_high_value == 0
            and state.step >= 4
        ):
            out.append(self._stop(state, ["diminishing_returns", "evidence_sufficient"]))

        # 2) HIGH/CRIT findings without active verification -> active_safe (DEEP)
        weak_sev = [
            f for f in state.findings
            if f["severity"] in ("HIGH", "CRITICAL") and f["evidence_count"] < 2
        ]
        if weak_sev and "active_safe" in state.pending_modules:
            out.append(
                BrainAction(
                    ActionType.RUN_MODULE,
                    params={"module": "active_safe"},
                    reason_codes=["high_severity_unverified", "active_module_available"],
                    expected_information_gain=0.9,
                    confidence=0.9,
                    related_findings=[f["fingerprint"] for f in weak_sev],
                    expected_evidence="active response differentials for high-severity findings",
                )
            )

        # 3) Findings whose category maps to an unrun evidence module.
        by_cat: dict[str, list[dict[str, Any]]] = {}
        for f in state.findings:
            if f["severity"] == "INFO":
                continue
            by_cat.setdefault(f["category"], []).append(f)
        for category, members in sorted(by_cat.items()):
            module = EVIDENCE_MODULE_BY_CATEGORY.get(category)
            if module and module in state.pending_modules and members:
                out.append(
                    BrainAction(
                        ActionType.RUN_MODULE,
                        params={"module": module},
                        reason_codes=[f"category_{category.lower()}_unverified"],
                        expected_information_gain=0.7,
                        confidence=0.8,
                        related_findings=[m["fingerprint"] for m in members[:10]],
                        expected_evidence=f"{module} evidence for {len(members)} {category} findings",
                    )
                )

        # 4) No technology fingerprint yet -> tech_detection is the highest
        #    value single action (it unlocks WP/OSV/exploit branches).
        if not state.technologies and "tech_detection" in state.pending_modules:
            out.append(
                BrainAction(
                    ActionType.RUN_MODULE,
                    params={"module": "tech_detection"},
                    reason_codes=["uncertainty_no_technology_fingerprint"],
                    expected_information_gain=0.95,
                    confidence=0.9,
                    expected_evidence="technology inventory",
                )
            )

        # 5) CMS detected -> targeted wordpress checks (if not yet run).
        cms_names = {"wordpress", "shopify", "woocommerce"}
        has_cms = any(
            t.get("name", "").lower() in cms_names for t in state.technologies
        )
        if has_cms and "wordpress" in state.pending_modules:
            out.append(
                BrainAction(
                    ActionType.RUN_MODULE,
                    params={"module": "wordpress"},
                    reason_codes=["cms_detected", "targeted_checks_available"],
                    expected_information_gain=0.85,
                    confidence=0.85,
                    expected_evidence="CMS-specific exposures (users, xmlrpc, debug.log, version)",
                )
            )

        # 6) Technology with a version -> exploit enrichment has high value.
        versioned = [
            t for t in state.technologies
            if t.get("version") and str(t.get("version")).strip() not in ("", "None")
        ]
        if versioned:
            out.append(
                BrainAction(
                    ActionType.ENRICH_TECHNOLOGY,
                    params={"enricher": "exploitdb", "technology": versioned[0]["name"],
                            "version": versioned[0]["version"]},
                    reason_codes=["versioned_technology_present", "exploit_correlation"],
                    expected_information_gain=0.8,
                    confidence=0.75,
                    related_findings=[
                        f["fingerprint"] for f in state.findings
                        if versioned[0]["name"].lower() in f["title"].lower()
                    ],
                    expected_evidence="matched public exploits for disclosed versions",
                )
            )
            out.append(
                BrainAction(
                    ActionType.ENRICH_TECHNOLOGY,
                    params={"enricher": "osv", "technology": versioned[0]["name"],
                            "version": versioned[0]["version"]},
                    reason_codes=["versioned_technology_present", "advisory_correlation"],
                    expected_information_gain=0.65,
                    confidence=0.7,
                    expected_evidence="OSV advisories for disclosed versions",
                )
            )

        # 7) Endpoints unmapped and discovery still available.
        if not state.attack_surface.get("endpoints") and "discovery" in state.pending_modules:
            out.append(
                BrainAction(
                    ActionType.RUN_MODULE,
                    params={"module": "discovery"},
                    reason_codes=["uncertainty_no_endpoint_map"],
                    expected_information_gain=0.6,
                    confidence=0.75,
                    expected_evidence="endpoint + form inventory",
                )
            )

        # 8) REQUEST_MORE_EVIDENCE: a specific HIGH finding with zero evidence
        #    whose category module already ran once (bounded by gate repeats).
        for f in state.findings:
            if f["severity"] in ("HIGH", "CRITICAL") and f["evidence_count"] == 0:
                module = EVIDENCE_MODULE_BY_CATEGORY.get(f["category"])
                if module and module not in state.pending_modules:
                    out.append(
                        BrainAction(
                            ActionType.REQUEST_MORE_EVIDENCE,
                            params={"module": module},
                            reason_codes=["high_finding_zero_evidence", "strengthen_existing"],
                            expected_information_gain=0.55,
                            confidence=0.7,
                            related_findings=[f["fingerprint"]],
                            expected_evidence=f"fresh {module} evidence",
                        )
                    )

        return out

    @staticmethod
    def _stop(state: BrainState, reasons: list[str]) -> BrainAction:
        return BrainAction(
            ActionType.STOP_ASSESSMENT,
            reason_codes=reasons,
            expected_information_gain=0.0,
            confidence=1.0,
        )


class LocalModelStrategy(DeterministicStrategy):
    """LEVEL 1: optional local-model re-ranking over deterministic candidates.

    Contract with any local model (llama.cpp/ollama/custom ONNX):
      - the model receives ONLY the serialized BrainState and the candidate
        action list (both JSON),
      - it returns a ranking/choice among candidate indices + a rationale,
      - it can NEVER add, modify or remove actions; the Policy Gate still
        evaluates the winner.

    `rank_fn(state_dict, candidates) -> (best_index, rationale)` is injected;
    when absent this strategy behaves exactly like the deterministic one.
    """

    name = "local-model-v1"

    def __init__(self, rank_fn=None) -> None:
        self._rank_fn = rank_fn

    def propose(self, state: BrainState) -> Decision:
        decision = super().propose(state)
        if not self._rank_fn or not decision.candidates:
            return decision
        try:
            idx, rationale = self._rank_fn(
                state.to_dict(), [c.to_dict() for c in decision.candidates]
            )
            idx = int(idx)
            if 0 <= idx < len(decision.candidates):
                chosen = decision.candidates[idx]
                chosen.reason_codes.append("local_model_selected")
                chosen.params = {**chosen.params, "model_rationale": str(rationale)[:300]}
                return Decision(chosen, decision.candidates, self.name,
                                notes=str(rationale)[:300])
        except Exception as exc:  # noqa: BLE001 — model failure must never break CASA
            logger.warning("local model ranking failed (%s); deterministic fallback", exc)
        return Decision(decision.candidates[0], decision.candidates,
                        self.name + "-fallback", notes="model unavailable")


def make_strategy(model_rank_fn=None) -> DeterministicStrategy:
    """Factory honoring CASA_BRAIN_MODEL: none => deterministic engine."""
    import os

    if model_rank_fn is not None:
        return LocalModelStrategy(model_rank_fn)
    if os.environ.get("CASA_BRAIN_MODEL", "").strip():
        # A model path is configured but no runtime is wired in this build;
        # deterministic engine stays authoritative (graceful degradation).
        return DeterministicStrategy()
    return DeterministicStrategy()
