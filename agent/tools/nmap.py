"""Nmap adapter — authorized host/port/service discovery.

MVP policy: the default scan profile is a SAFE service-discovery set
(-Pn -sT --top-ports 100 -sV) with version detection and NO aggressive
options (-A, -T4+, script scans) — those stress targets harder than an
authorized web assessment needs. Only the scope-validated host is ever
passed to the binary, as a single argv element.

Output is parsed from Nmap XML (never shown raw to the user) into
CASA assets/services for the Attack Surface Map and low-information
findings for interesting services.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from agent.core.config import settings
from agent.core.exceptions import ScopeViolationError
from agent.tools.base import ToolAdapterBase

# Conservative, low-impact port set for web-focused assessments.
_WEB_PORTS = {80, 443, 8000, 8001, 8080, 8081, 8443, 8888, 3000, 5000, 7001, 9090}


class NmapAdapter(ToolAdapterBase):
    name = "nmap"
    binary = "nmap"
    version = "unknown"
    capabilities = ("port_scan", "service_detection", "version_detection")

    def validate_scope(self, url: str, scope: dict) -> None:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        # Web-tool posture: only scan ports relevant to the authorized web
        # target's origin; full-range scans are out of MVP policy.
        if port not in _WEB_PORTS:
            raise ScopeViolationError(
                f"tool nmap: port {port} is outside the web assessment policy"
            )

    def build_command(self, request: dict) -> list[str]:
        parsed = urlparse(request["target"])
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        # SAFE profile: ping-skip + TCP connect scan + top web ports + service
        # versions. No -A, no scripts, no timing aggression.
        return [
            self.binary,
            "-Pn",
            "-sT",
            "-sV",
            "--top-ports", "100",
            "--open",
            "-oX", "-",          # XML to stdout for parsing
            "-p", str(port),
            host,                # single argv element — never concatenated
        ]

    # ------------------------------------------------------------ parsing
    def parse_output(self, raw: dict) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        services = self._parse_xml(raw.get("stdout", ""))
        raw["services"] = services  # consumed by the attack-surface enricher

        for svc in services:
            port = svc.get("port")
            if port not in _WEB_PORTS:
                continue
            state = svc.get("state")
            if state != "open":
                continue
            service = (svc.get("service") or "").lower()
            product = svc.get("product") or ""
            version = svc.get("version") or ""

            findings.append(
                {
                    "title": f"Open service detected: {service or 'unknown'} on port {port}",
                    "category": "RECON",
                    "severity": "INFO",
                    "confidence": "HIGH" if product else "MEDIUM",
                    "description": (
                        f"Port {port} is open and runs {product or service or 'an unidentified service'}"
                        + (f" version {version}" if version else "")
                        + ". Recorded as an attack-surface asset."
                    ),
                    "evidence": [
                        {
                            "type": "nmap_service",
                            "port": port,
                            "service": service,
                            "product": product,
                            "version": version,
                            "protocol": svc.get("protocol", "tcp"),
                        }
                    ],
                    "affected_asset": f"{svc.get('hostname', '')}:{port}".lstrip(":"),
                    "impact": "Exposed service increases the reachable attack surface.",
                    "remediation": "Close ports that are not required; keep only authorized services.",
                    "references": ["https://nmap.org/book/man.html"],
                    "fingerprint": "",  # set by normalizer asset rules
                }
            )
        return findings

    def _parse_xml(self, xml_text: str) -> list[dict[str, Any]]:
        if not xml_text.strip():
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []
        services: list[dict[str, Any]] = []
        for host_el in root.iter("host"):
            hostname = ""
            for names in host_el.iter("hostnames"):
                name_el = names.find("hostname")
                if name_el is not None:
                    hostname = name_el.get("name", "")
            for port_el in host_el.iter("port"):
                port_id = int(port_el.get("portid", "0") or 0)
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                svc_el = port_el.find("service")
                services.append(
                    {
                        "hostname": hostname,
                        "port": port_id,
                        "protocol": protocol,
                        "state": (state_el.get("state") if state_el is not None else "") or "",
                        "service": (svc_el.get("name") if svc_el is not None else "") or "",
                        "product": (svc_el.get("product") if svc_el is not None else "") or "",
                        "version": (svc_el.get("version") if svc_el is not None else "") or "",
                    }
                )
        return services
