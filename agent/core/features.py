"""Feature flags for modules the MVP intentionally leaves as extension points."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FeatureFlags:
    """Explicit, documented feature toggles.

    Everything marked "extension point" is deliberately NOT implemented in the
    MVP; the hooks exist so later versions can plug in without re-architecting.
    """

    network_port_scanning: bool = False          # extension point: network assessment
    continuous_monitoring: bool = False          # extension point: scheduled reassessments
    attack_path_analysis: bool = False           # extension point: graph-based analysis
    exploit_proofs: bool = False                 # permanently out of scope for this agent
    credential_stuffing_checks: bool = False     # permanently out of scope (auth abuse)
    signed_authorizations_required: bool = False # require signed authz documents
    web_checks_enabled: bool = True
    tls_checks_enabled: bool = True
    ai_analysis_enabled: bool = True
    risk_engine_enabled: bool = True

    def disabled_extension_points(self) -> list[str]:
        return [
            name
            for name in (
                "network_port_scanning",
                "continuous_monitoring",
                "attack_path_analysis",
            )
            if getattr(self, name) is False
        ]
