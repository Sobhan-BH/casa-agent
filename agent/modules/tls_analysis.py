"""TLS/SSL Analysis — certificate metadata + transport findings.

Uses TlsInfoAdapter (a single handshake, no scanning). Skips itself on
plain-HTTP targets via applies().
"""
from __future__ import annotations

from datetime import datetime, timezone

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.connectors.adapters import TlsInfoAdapter

_WEAK_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"}


class TlsAnalysisModule(AssessmentModule):
    name = "tls_analysis"
    phase = "TLS_ANALYSIS"

    def __init__(self, validator) -> None:
        self._validator = validator
        self._adapter = TlsInfoAdapter(validator)

    def applies(self, ctx: AssessmentContext) -> bool:
        return ctx.target_url.startswith("https://")

    async def run(self, ctx: AssessmentContext) -> None:
        raw = await self._adapter.execute({"url": ctx.target_url})
        ctx.raw_results["tls"] = raw
        if raw.get("error"):
            return  # TLS findings for unreachable TLS are noise; recon covers reachability

        asset = ctx.target_url
        not_after = raw.get("not_after")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (expiry - datetime.now(timezone.utc)).days
                ctx.raw_results["tls_days_to_expiry"] = days_left
                if days_left < 0:
                    severity, title = (
                        "CRITICAL",
                        "TLS certificate has expired",
                    )
                elif days_left < 14:
                    severity, title = "HIGH", "TLS certificate expires in less than 14 days"
                elif days_left < 30:
                    severity, title = "MEDIUM", "TLS certificate expires in less than 30 days"
                else:
                    severity, title = None, None
                if severity:
                    f = make_finding(
                        title=title,
                        category="TLS",
                        severity=severity,
                        confidence="HIGH",
                        description=(
                            f"Certificate for {asset} expires on {not_after} "
                            f"({days_left} days)."
                        ),
                        evidence=[{"type": "tls_cert", "not_after": not_after, "days_left": days_left}],
                        affected_asset=asset,
                        impact="Expired certificates cause outages and browser trust warnings.",
                        remediation="Automate certificate renewal (e.g. ACME/Let's Encrypt).",
                        references=["https://letsencrypt.org/docs/automation/"],
                        source=self.name,
                    )
                    f["fingerprint"] = make_fingerprint("tls_expiry", asset)
                    ctx.findings.append(f)
            except ValueError:
                pass

        if raw.get("tls_version") in _WEAK_VERSIONS:
            f = make_finding(
                title=f"Weak TLS protocol negotiated: {raw['tls_version']}",
                category="TLS",
                severity="HIGH",
                confidence="HIGH",
                description=(
                    f"The server negotiated {raw['tls_version']}, which is deprecated and "
                    "vulnerable to known attacks (e.g. POODLE, downgrade)."
                ),
                evidence=[{"type": "tls_handshake", "negotiated": raw["tls_version"]}],
                affected_asset=asset,
                impact="Traffic confidentiality/integrity can be compromised.",
                remediation="Disable TLS < 1.2; serve TLS 1.2+ (prefer 1.3).",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                source=self.name,
            )
            f["fingerprint"] = make_fingerprint("tls_weak_protocol", asset)
            ctx.findings.append(f)

        # Hostname mismatch surfaces as an SSLCertVerificationError in the adapter;
        # handle it here for report clarity.
        if "verification failed" in str(raw.get("error", "")):
            f = make_finding(
                title="TLS certificate hostname verification failed",
                category="TLS",
                severity="HIGH",
                confidence="HIGH",
                description=str(raw["error"]),
                evidence=[{"type": "tls_cert", "error": raw["error"]}],
                affected_asset=asset,
                impact="Clients disable validation or accept MITM.",
                remediation="Deploy a certificate matching the hostname (SAN/CN).",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                source=self.name,
            )
            f["fingerprint"] = make_fingerprint("tls_hostname_mismatch", asset)
            ctx.findings.append(f)

        if raw.get("cipher") and any(
            weak in raw["cipher"].upper() for weak in ("RC4", "DES", "NULL", "EXPORT")
        ):
            f = make_finding(
                title=f"Weak TLS cipher suite negotiated: {raw['cipher']}",
                category="TLS",
                severity="MEDIUM",
                confidence="HIGH",
                description=f"The negotiated cipher {raw['cipher']} is considered weak.",
                evidence=[{"type": "tls_handshake", "cipher": raw["cipher"]}],
                affected_asset=asset,
                impact="Reduced confidentiality of transmitted data.",
                remediation="Configure a modern cipher suite list (TLS 1.3 suites or AEAD ciphers).",
                references=["https://wiki.mozilla.org/Security/Server_Side_TLS"],
                source=self.name,
            )
            f["fingerprint"] = make_fingerprint("tls_weak_cipher", asset)
            ctx.findings.append(f)

        # Keep an informational record that TLS was analyzed.
        info = make_finding(
            title=f"TLS endpoint analyzed ({raw.get('tls_version', 'unknown')})",
            category="TLS",
            severity="INFO",
            confidence="HIGH",
            description="TLS handshake metadata captured for audit purposes.",
            evidence=[{"type": "tls_cert", "subject": raw.get("subject"), "issuer": raw.get("issuer")}],
            affected_asset=asset,
            source=self.name,
        )
        info["fingerprint"] = make_fingerprint("tls_info", asset)
        ctx.findings.append(info)
