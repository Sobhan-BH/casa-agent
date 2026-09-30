"""SARIF 2.1.0 report format (GitHub Code Scanning compatible).

SARIF is the industry-standard static-analysis exchange format; exporting it
lets CASA results appear in GitHub's Security tab via code-scanning upload
(`github/codeql-action/upload-sarif` accepts any SARIF producer).
"""
from __future__ import annotations

import json
from typing import Any

from agent import __version__

_SEVERITY_RULE_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_GH_SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
    "INFO": "0.0",
}


def build_sarif_report(
    target_url: str,
    findings: list[dict[str, Any]],
    security_score: float | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log dict from normalized CASA findings."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for idx, f in enumerate(findings):
        fingerprint = f.get("fingerprint") or f"CASA-{idx:04d}"
        rule_id = f"CASA/{fingerprint}"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            meta = f.get("metadata") or {}
            taxonomies: list[dict[str, Any]] = []
            mitre = meta.get("mitre_attack") or []
            if mitre:
                taxonomies = [
                    {
                        "id": t.get("id"),
                        "name": t.get("name"),
                        "tactic": t.get("tactic"),
                        "url": t.get("url"),
                    }
                    for t in mitre
                ]
            rules.append(
                {
                    "id": rule_id,
                    "name": (f.get("title") or "CASA finding")[:120],
                    "shortDescription": {"text": (f.get("title") or "")[:300]},
                    "fullDescription": {
                        "text": (f.get("description") or "")[:1000]
                    },
                    "help": {
                        "text": (f.get("remediation") or "")[:1000],
                        "markdown": (f.get("remediation") or "")[:1000],
                    },
                    "properties": {
                        "security-severity": _GH_SECURITY_SEVERITY.get(
                            f.get("severity", "LOW"), "2.5"
                        ),
                        "tags": [f.get("category", "OTHER"), f.get("source", "casa")]
                        + [t.get("id") for t in taxonomies],
                        "casa-category": f.get("category"),
                        "casa-source": f.get("source"),
                        "casa-mitre": taxonomies,
                    },
                }
            )

        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": next(
                    i for i, r in enumerate(rules) if r["id"] == rule_id
                ),
                "level": _SEVERITY_RULE_LEVEL.get(f.get("severity", "LOW"), "note"),
                "message": {
                    "text": f"{f.get('title', '')} — {f.get('description', '')[:300]}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": (f.get("affected_asset") or target_url).replace(
                                    "://", "/"
                                ).lstrip("/"),
                                "uriBaseId": "SRCROOT",
                            },
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {"casaFingerprint/v1": f.get("fingerprint", "")},
                "properties": {
                    "casa-risk-score": f.get("risk_score"),
                    "casa-confidence": f.get("confidence"),
                    "casa-status": f.get("status"),
                },
            }
        )

    driver_properties = {
        "casa-security-score": security_score,
        "casa-target": target_url,
    }

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CASA",
                        "informationUri": "https://github.com/Sobhan-BH/casa-agent",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": rules,
                        "properties": driver_properties,
                    }
                },
                "results": results,
            }
        ],
    }


def sarif_json(target_url: str, findings: list[dict[str, Any]], security_score: float | None = None) -> str:
    """Serialize the SARIF report to a JSON string."""
    return json.dumps(build_sarif_report(target_url, findings, security_score), indent=2, default=str)
