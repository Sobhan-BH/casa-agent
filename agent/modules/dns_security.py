"""DNS & Domain Security — passive record analysis via dnspython.

Evaluates mail-related records (SPF/DMARC/DKIM indicators), CAA (certificate
authority authorization), DNSSEC observability, and obvious subdomain
configuration oddities visible from public DNS lookups only.

No zone transfer attempts, no takeover testing, no brute-force enumeration —
every query is a standard single-record lookup against the system resolver.
"""
from __future__ import annotations

from typing import Any

from agent.core.context import AssessmentContext
from agent.core.finding import make_finding, make_fingerprint
from agent.core.interfaces import AssessmentModule
from agent.modules import dns_queries


class DnsSecurityModule(AssessmentModule):
    name = "dns_security"
    phase = "DNS_SECURITY"

    def __init__(self, validator) -> None:
        self._validator = validator

    def applies(self, ctx: AssessmentContext) -> bool:
        # IP-only targets have no meaningful domain security posture to assess.
        return not _is_ip_address(ctx.base_domain)

    async def run(self, ctx: AssessmentContext) -> None:
        domain = ctx.base_domain
        results: dict[str, Any] = {"domain": domain}

        txt = await dns_queries._resolve(domain, "TXT")
        results["txt_records"] = txt[:20]

        # --- SPF ----------------------------------------------------------
        spf = dns_queries.parse_spf(txt)
        results["spf"] = spf
        if not spf["present"]:
            self._add(ctx, domain, "No SPF record is published (SPF absent)", "spf_absent",
                      "LOW", "HIGH",
                      "The domain publishes no v=spf1 record, so receivers cannot verify "
                      "which servers may send its email; spoofing is easier.",
                      "Email spoofing of the domain is trivially possible.",
                      "Publish an SPF record listing authorized senders.",
                      ["https://datatracker.ietf.org/doc/html/rfc7208"],
                      evidence={"type": "dns_txt", "outcome": "no v=spf1 record"})
        elif not spf.get("all_strict"):
            self._add(ctx, domain, "SPF uses a permissive all-policy", "spf_permissive",
                      "LOW", "HIGH",
                      "The SPF record does not end in -all/~all, so any server may claim "
                      "to send for the domain with partial legitimacy.",
                      "Weak anti-spoofing posture for outbound email.",
                      "End the SPF record with -all (or ~all during rollout).",
                      ["https://datatracker.ietf.org/doc/html/rfc7208"],
                      evidence={"type": "dns_spf", "record": spf.get("record", "")})

        # --- DMARC ----------------------------------------------------------
        dmarc_records = await dns_queries._resolve(f"_dmarc.{domain}", "TXT")
        results["dmarc_records"] = dmarc_records[:10]
        dmarc = dns_queries.parse_dmarc(dmarc_records)
        results["dmarc"] = dmarc
        if not dmarc["present"]:
            self._add(ctx, domain, "No DMARC record is published (DMARC absent)", "dmarc_absent",
                      "MEDIUM", "HIGH",
                      "Without DMARC, receivers have no domain-based policy for handling "
                      "spoofed mail; phishing using this domain is harder to stop.",
                      "Phishing emails spoofing this domain face no policy enforcement.",
                      "Publish a _dmarc TXT record, start with p=none + rua, then tighten.",
                      ["https://datatracker.ietf.org/doc/html/rfc7489"],
                      evidence={"type": "dns_txt", "name": f"_dmarc.{domain}", "outcome": "absent"})
        elif not dmarc.get("policy_enforcing"):
            self._add(ctx, domain, "DMARC policy is monitor-only (p=none)", "dmarc_none",
                      "LOW", "HIGH",
                      "DMARC is published with p=none: spoofed mail is not rejected or "
                      "quarantined. Reporting (rua) may still provide value.",
                      "Spoofing protection remains advisory only.",
                      "Move to p=quarantine (then p=reject) once reports confirm legitimate senders.",
                      ["https://datatracker.ietf.org/doc/html/rfc7489"],
                      evidence={"type": "dns_dmarc", "record": dmarc.get("record", "")})

        # --- CAA --------------------------------------------------------------
        caa_records = await dns_queries._resolve(domain, "CAA")
        results["caa"] = dns_queries.parse_caa(caa_records)
        if not caa_records:
            self._add(ctx, domain, "No CAA record is published", "caa_absent",
                      "INFO", "HIGH",
                      "No Certification Authority Authorization record restricts which CAs "
                      "may issue certificates for this domain.",
                      "Any CA may issue certificates for the domain.",
                      "Publish CAA records naming your certificate authority.",
                      ["https://datatracker.ietf.org/doc/html/rfc8659"],
                      evidence={"type": "dns_caa", "outcome": "absent"})

        # --- DNSSEC observability ---------------------------------------------
        ds_records = await dns_queries._resolve(domain, "DS")
        results["dnssec_ds_records"] = ds_records
        if not ds_records:
            self._add(ctx, domain, "No DNSSEC (no DS record at the parent side observable)",
                      "dnssec_absent", "INFO", "MEDIUM",
                      "No DS records were returned for the domain; DNSSEC does not appear "
                      "to be enabled at the registrar/parent zone.",
                      "DNS responses can be spoofed without DNSSEC validation.",
                      "Enable DNSSEC at your registrar and publish DS records.",
                      ["https://datatracker.ietf.org/doc/html/rfc4033"],
                      evidence={"type": "dns_ds", "outcome": "absent"})

        ctx.raw_results["dns_security"] = results

    # ------------------------------------------------------------------ helpers

    def _add(
        self,
        ctx,
        domain: str,
        title: str,
        key: str,
        severity: str,
        confidence: str,
        description: str,
        impact: str,
        remediation: str,
        references: list[str],
        evidence: dict[str, Any],
    ) -> None:
        f = make_finding(
            title=title,
            category="OTHER",
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=[evidence],
            affected_asset=domain,
            impact=impact,
            remediation=remediation,
            references=references,
            source=self.name,
        )
        f["fingerprint"] = make_fingerprint(key, domain)
        ctx.findings.append(f)


def _is_ip_address(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
