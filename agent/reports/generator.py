"""Report Generator — builds JSON and HTML reports from the assessment context.

Both artifacts are stored in report_artifacts (and optionally on disk under
data/reports). The HTML template renders the full finding set with evidence,
AI summary and verification status.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from agent.core.config import settings
from agent.storage import repositories as repo

logger = logging.getLogger("casa.reports")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CASA Security Assessment Report</title>
<style>
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; background: #f5f6fa; color: #1c1e21; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 24px; }
  h1 { margin: 0 0 4px; }
  .sub { color: #606770; margin-bottom: 24px; }
  .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  .card { background: #fff; border-radius: 10px; padding: 18px 22px; box-shadow: 0 1px 3px rgba(0,0,0,.12); min-width: 160px; }
  .score { font-size: 42px; font-weight: 700; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; color: #fff; }
  .CRITICAL { background: #7a0020; } .HIGH { background: #c62828; }
  .MEDIUM { background: #ef6c00; } .LOW { background: #f9a825; color:#333; }
  .INFO { background: #90a4ae; } .FIXED { background: #2e7d32; }
  .STILL_PRESENT { background: #c62828; } .CHANGED { background: #ef6c00; }
  .OPEN { background: #1565c0; } .UNVERIFIED { background: #757575; }
  section { background: #fff; border-radius: 10px; padding: 20px 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.12); }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { text-align: left; border-bottom: 2px solid #e3e6ea; padding: 8px 6px; }
  td { border-bottom: 1px solid #eceef1; padding: 8px 6px; vertical-align: top; }
  pre { background: #f5f6f7; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
  .muted { color: #606770; font-size: 12px; }
  .phase-ok { color: #2e7d32; } .phase-warn { color: #ef6c00; } .phase-skip { color: #757575; }
</style>
</head>
<body><div class="wrap">
<h1>Security Assessment Report</h1>
<div class="sub">
  Target: <strong>{{ report.target_url }}</strong> &middot;
  Generated: {{ report.generated_at }} &middot;
  Authorization: {{ report.authorization.authorized_by }}
  (ref {{ report.authorization.authorization_reference }})
</div>

<div class="cards">
  <div class="card"><div class="score">{{ report.security_score }}</div>
    <div class="muted">Security Score / 100 ({{ report.risk_summary.grade }}) — {{ report.mode }} mode</div></div>
  <div class="card"><strong>{{ report.findings|length }}</strong><div class="muted">Findings</div></div>
  <div class="card">
    {% for sev, n in report.risk_summary.distribution.items() %}
      <span class="badge {{ sev }}">{{ sev }}: {{ n }}</span>
    {% endfor %}
  </div>
  {% if report.verification %}
  <div class="card"><strong>{{ report.verification.summary }}</strong><div class="muted">Verification vs previous</div></div>
  {% endif %}
</div>

{% if report.category_scores %}
<section>
  <h2>Category Scores</h2>
  <table>
    <tr><th>Category</th><th>Score</th><th>Findings</th></tr>
    {% for name, c in report.category_scores.items() %}
    <tr>
      <td>{{ name }}</td>
      <td><strong>{{ c.score }}</strong>/100</td>
      <td>{{ c.findings }}</td>
    </tr>
    {% endfor %}
  </table>
</section>
{% endif %}

<section>
  <h2>Executive Summary</h2>
  <p>{{ report.ai.executive_summary }}</p>
  <h3>For managers</h3>
  <p>{{ report.ai.manager_summary }}</p>
</section>

<section>
  <h2>Assessment Timeline</h2>
  <table>
    <tr><th>Phase</th><th>Module</th><th>Status</th><th>Duration</th><th>Notes</th></tr>
    {% for p in report.phases %}
    <tr>
      <td>{{ p.phase }}</td><td>{{ p.module }}</td>
      <td class="{% if p.status == 'OK' %}phase-ok{% elif p.status == 'WARNING' %}phase-warn{% else %}phase-skip{% endif %}">{{ p.status }}</td>
      <td>{{ p.duration_ms }} ms</td>
      <td>{{ p.error or p.summary or "" }}</td>
    </tr>
    {% endfor %}
  </table>
</section>

<section>
  <h2>Findings</h2>
  {% for f in report.findings %}
  <div style="margin-bottom:18px; border:1px solid #eceef1; border-radius:8px; padding:14px;">
    <div>
      <span class="badge {{ f.severity }}">{{ f.severity }}</span>
      <span class="badge">{{ f.confidence }}</span>
      <strong>{{ f.title }}</strong>
    </div>
    <div class="muted">Category: {{ f.category }} &middot; Source: {{ f.source }}
      &middot; Asset: {{ f.affected_asset }} &middot; Risk: {{ f.risk_score }}</div>
    <p>{{ f.description }}</p>
    <p><strong>Impact:</strong> {{ f.impact }}</p>
    <p><strong>Remediation:</strong> {{ f.remediation }}</p>
    {% if f.references %}<p class="muted">References: {{ f.references|join(', ') }}</p>{% endif %}
    <details><summary>Evidence ({{ f.evidence|length }})</summary>
      <pre>{{ f.evidence_pretty }}</pre>
    </details>
    {% if f.ai_notes %}<div class="muted">AI notes: {{ f.ai_notes }}</div>{% endif %}
  </div>
  {% endfor %}
</section>

<section>
  <h2>Verification Status</h2>
  {% if report.verification %}
  <table>
    <tr><th>Finding</th><th>Previous</th><th>Current</th><th>Status</th></tr>
    {% for item in report.verification_items %}
    <tr>
      <td>{{ item.title }}</td>
      <td><span class="badge {{ item.previous_severity or 'INFO' }}">{{ item.previous_severity or "-" }}</span></td>
      <td><span class="badge {{ item.current_severity or 'INFO' }}">{{ item.current_severity or "-" }}</span></td>
      <td><span class="badge {{ item.status }}">{{ item.status }}</span></td>
    </tr>
    {% endfor %}
  </table>
  {% else %}<p class="muted">First assessment for this target; no baseline to compare.</p>{% endif %}
</section>

<section>
  <h2>Security Tools</h2>
  {% if report.attack_surface and report.attack_surface.tools_used %}
  <p><strong>Tools used in this assessment:</strong>
    CASA Internal{% for t in report.attack_surface.tools_used %}, {{ t }}{% endfor %}
  </p>
  <table>
    <tr><th>Tool</th><th>Status</th><th>Tool version</th><th>Findings</th><th>Duration</th></tr>
    {% for name, p in report.attack_surface.tool_provenance.items() %}
    <tr>
      <td>{{ name }}</td><td>{{ p.status }}</td><td>{{ p.tool_version }}</td>
      <td>{{ p.findings }}</td><td>{{ p.duration_ms }} ms</td>
    </tr>
    {% endfor %}
  </table>
  {% if report.attack_surface.tools_not_installed %}
  <p class="muted">Not installed (skipped): {{ report.attack_surface.tools_not_installed|join(', ') }}</p>
  {% endif %}
  {% else %}<p class="muted">No external tools ran in this assessment (CASA internal modules only).</p>{% endif %}
</section>

<section>
  <h2>Attack Surface</h2>
  {% if report.attack_surface %}
  <table>
    <tr><th>Asset</th><th>Detail</th></tr>
    <tr><td>Domains</td><td>{{ report.attack_surface.domains.primary }}{% for s in report.attack_surface.domains.in_scope_subdomains %}, {{ s }}{% endfor %}</td></tr>
    <tr><td>Technologies</td><td>{% for t in report.attack_surface.technologies %}{{ t.name }}{% if t.version %} ({{ t.version }}){% endif %}{{ "; " if not loop.last else "" }}{% endfor %}</td></tr>
    <tr><td>APIs exposed</td><td>{{ report.attack_surface.apis|length }}</td></tr>
    <tr><td>Endpoints discovered</td><td>{{ report.attack_surface.endpoints|length }}</td></tr>
    <tr><td>Security controls observed</td><td>{% for c in report.attack_surface.security_controls %}{{ c.control }}{{ "; " if not loop.last else "" }}{% endfor %}</td></tr>
  </table>
  {% else %}<p class="muted">Attack surface map unavailable.</p>{% endif %}
</section>

<section>
  <h2>Technical Details</h2>
  <pre>{{ report.technical_json }}</pre>
</section>

<div class="muted">
  Generated by CASA Agent. Assessment executed under authorization by
  {{ report.authorization.authorized_by }} (ref {{ report.authorization.authorization_reference }}),
  scope: {{ report.authorization.allowed_domains|join(', ') }}.
  Unauthorized scanning is prohibited; this report is provided for the authorized recipient only.
</div>
</div></body></html>
"""


class ReportGenerator:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def generate(self, ctx) -> dict[str, str]:
        findings = ctx.findings
        from agent.analysis.attack_surface import build_attack_surface

        report = {
            "target_url": ctx.target_url,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "security_score": (ctx.risk_summary or {}).get("security_score"),
            "risk_summary": ctx.risk_summary or {},
            "category_scores": (ctx.risk_summary or {}).get("category_scores", {}),
            "mode": ctx.mode,
            "authorization": ctx.scope,
            "ai": ctx.ai_summary or {"executive_summary": "(AI analysis unavailable)"},
            "verification": ctx.verification_summary,
            # Precomputed list: a dict key named "items" would shadow the
            # dict method in Jinja2 and break the for-loop.
            "verification_items": (ctx.verification_summary or {}).get("items", []),
            "attack_surface": build_attack_surface(ctx),
            "phases": [
                {
                    "phase": p.phase,
                    "module": p.module,
                    "status": p.status,
                    "duration_ms": p.duration_ms,
                    "summary": p.summary,
                    "error": p.error,
                }
                for p in ctx.phases
            ],
            "findings": [
                {
                    **f,
                    "evidence_pretty": json.dumps(f.get("evidence", []), indent=2, default=str),
                    "ai_notes": f.get("ai_notes"),
                }
                for f in findings
            ],
            "technical_json": json.dumps(
                {
                    k: v
                    for k, v in ctx.raw_results.items()
                    if k in ("dns", "tls", "technologies", "kb_correlation", "normalization")
                },
                indent=2,
                default=str,
            ),
        }

        json_text = json.dumps(report, indent=2, default=str)
        from jinja2 import Template

        html_text = Template(HTML_TEMPLATE).render(report=report)

        written: dict[str, str] = {}
        for fmt, content in (("json", json_text), ("html", html_text)):
            out_dir = settings.data_dir / "reports"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{ctx.assessment_id}.{fmt}"
            try:
                out_path.write_text(content, encoding="utf-8")
                path_str = str(out_path)
            except OSError:
                path_str = ""
            await repo.save_artifact(
                self._session,
                str(ctx.assessment_id),
                fmt=fmt,
                path=path_str,
                content=content,
            )
            written[fmt] = path_str or "(stored in DB)"
        logger.info("reports generated for assessment %s: %s", ctx.assessment_id, written)
        return written
