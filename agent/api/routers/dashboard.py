"""Internal read-only dashboard at /dashboard.

A single self-contained HTML page (no external CDN, no JS framework) that
summarizes assessments, findings by severity and job history. It reads from
the repositories directly, so it works on both SQLite and Postgres backends.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from agent import __version__
from agent.storage import repositories as repo
from agent.storage.database import get_session

router = APIRouter(tags=["dashboard"])

_CSS = """
:root { color-scheme: dark; }
body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; background:#0d1117; color:#c9d1d9; margin:0; }
.wrap { max-width: 1100px; margin:0 auto; padding:24px; }
h1 { margin:0 0 4px; color:#58a6ff; }
.muted { color:#8b949e; font-size:13px; }
.cards { display:flex; gap:16px; flex-wrap:wrap; margin:24px 0; }
.card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px 22px; min-width:140px; }
.card .num { font-size:34px; font-weight:700; }
.CRITICAL { color:#f85149; } .HIGH { color:#f0883e; } .MEDIUM { color:#d29922; } .LOW { color:#7ee787; } .INFO { color:#8b949e; }
table { width:100%; border-collapse:collapse; margin-top:16px; font-size:14px; }
th { text-align:left; color:#58a6ff; border-bottom:2px solid #30363d; padding:8px 6px; }
td { border-bottom:1px solid #21262d; padding:8px 6px; vertical-align:top; }
.badge { display:inline-block; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600; }
.badge.COMPLETED { background:#1a7f37; } .badge.FAILED, .badge.BLOCKED { background:#b62324; }
.badge.RUNNING, .badge.QUEUED { background:#1f6feb; }
a { color:#58a6ff; text-decoration:none; }
"""

_PAGE_TMPL = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>CASA Dashboard</title>
<style>{css}</style></head>
<body><div class="wrap">
<h1>CASA Dashboard</h1>
<div class="muted">CASA v{version} &middot; {now} &middot; read-only operational view</div>

<div class="cards">
  <div class="card"><div class="num">{n_assessments}</div><div class="muted">Assessments</div></div>
  <div class="card"><div class="num">{n_jobs}</div><div class="muted">Jobs</div></div>
  <div class="card"><div class="num">{n_findings}</div><div class="muted">Findings (latest)</div></div>
  <div class="card"><div class="num {score_class}">{score}</div><div class="muted">Latest security score</div></div>
</div>

<h2>Latest assessments</h2>
<table>
<tr><th>Target</th><th>Status</th><th>Score</th><th>Findings</th><th>Finished</th></tr>
{assessment_rows}
</table>

<h2>Recent jobs</h2>
<table>
<tr><th>Job</th><th>Target</th><th>Profile</th><th>Status</th><th>Queued</th><th>Error</th></tr>
{job_rows}
</table>

<div class="muted" style="margin-top:24px">
  API docs at <a href="/docs">/docs</a> &middot; All assessments run under explicit authorization only.
</div>
</div></body></html>"""


def _fmt_dt(dt: datetime | None) -> str:
    if not dt:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


async def _latest_findings_count(session: AsyncSession, target_id: str) -> int:
    latest = await repo.get_latest_assessment_for_target(session, target_id)
    if not latest:
        return 0
    rows = await repo.list_findings(session, latest.id)
    return len(rows)


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    assessments = await repo.list_assessments(session, limit=10)
    jobs = await repo.list_jobs(session, limit=10)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total_findings = 0
    score = None
    score_class = ""
    if assessments:
        latest = assessments[0]
        score = latest.security_score
        score_class = "LOW" if (score or 0) > 70 else "MEDIUM" if (score or 0) > 40 else "CRITICAL"
        for f in await repo.list_findings(session, latest.id):
            total_findings += 1
            sev = (f.severity or "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

    # Build rows with explicit loops: awaiting inside a generator expression
    # would produce an async generator, which str.join cannot consume.
    assessment_row_parts: list[str] = []
    for a in assessments:
        n_find = await _latest_findings_count(session, a.target_id)
        assessment_row_parts.append(
            f"<tr><td>{html.escape(a.target_url)}</td>"
            f"<td><span class='badge {a.status}'>{a.status}</span></td>"
            f"<td>{a.security_score if a.security_score is not None else '—'}</td>"
            f"<td>{n_find}</td>"
            f"<td>{_fmt_dt(a.finished_at)}</td></tr>"
        )
    assessment_rows = "".join(assessment_row_parts) or (
        "<tr><td colspan=5 class=muted>No assessments yet — run one via /docs or the launcher.</td></tr>"
    )

    job_row_parts: list[str] = []
    for j in jobs:
        job_row_parts.append(
            f"<tr><td>{j.id[:8]}…</td>"
            f"<td>{html.escape(getattr(j, 'target_url', '') or '')}</td>"
            f"<td>{j.profile}</td>"
            f"<td><span class='badge {j.status}'>{j.status}</span></td>"
            f"<td>{_fmt_dt(j.queued_at)}</td>"
            f"<td>{html.escape((j.error or '')[:80])}</td></tr>"
        )
    job_rows = "".join(job_row_parts) or "<tr><td colspan=6 class=muted>No jobs yet.</td></tr>"

    body = _PAGE_TMPL.format(
        css=_CSS,
        version=__version__,
        now=_fmt_dt(datetime.now(timezone.utc)),
        n_assessments=len(assessments),
        n_jobs=len(jobs),
        n_findings=total_findings,
        score=score if score is not None else "—",
        score_class=score_class,
        assessment_rows=assessment_rows,
        job_rows=job_rows,
    )
    return HTMLResponse(body)
