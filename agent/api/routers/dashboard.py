"""CASA Web Console — /dashboard.

A modern, self-contained single-page console (no external CDN, no framework)
for running and reviewing assessments against authorized targets:

- Target form: enter an IP/domain/URL, authorization context, profile; the
  console registers the authorization and starts the job via the REST API.
- Live progress: polls job status (QUEUED → RUNNING → ANALYZING → VERIFYING
  → COMPLETED) with an animated stepper.
- Findings explorer: severity cards, filters, expandable finding cards with
  the full explanation layer (what / attack scenario / business impact /
  exploitability / remediation plan / verification / CVSS rationale).
- History: recent assessments and jobs.

All markup is generated client-side from API JSON; escaping is applied to
every interpolated value.
"""
from __future__ import annotations

import json

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from agent import __version__

router = APIRouter(tags=["dashboard"])

_CSS = """
:root {
  --bg0:#07090f; --bg1:#0d1117; --bg2:#161b22; --bg3:#1c2129; --line:#30363d;
  --txt:#e6edf3; --mut:#8b949e; --acc:#58a6ff; --acc2:#79c0ff;
  --ok:#3fb950; --warn:#d29922; --hi:#f0883e; --crit:#f85149; --info:#8b949e; --low:#7ee787;
  --grad:linear-gradient(135deg,#0d1117 0%,#12192a 60%,#0d1117 100%);
}
* { box-sizing:border-box; }
body { font-family:-apple-system,'Segoe UI',Roboto,'Vazirmatn',sans-serif; background:var(--bg0); color:var(--txt); margin:0; }
a { color:var(--acc); text-decoration:none; }
a:hover { text-decoration:underline; }
.wrap { max-width:1200px; margin:0 auto; padding:28px 24px 60px; }
header.hero { background:var(--grad); border-bottom:1px solid var(--line); padding:22px 24px; }
.hero .inner { max-width:1200px; margin:0 auto; display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
.logo { width:40px; height:40px; border-radius:10px; background:linear-gradient(135deg,#1f6feb,#a371f7); display:flex; align-items:center; justify-content:center; font-size:20px; }
h1 { font-size:20px; margin:0; }
.sub { color:var(--mut); font-size:13px; }
.badge-v { border:1px solid var(--line); color:var(--acc2); border-radius:20px; padding:2px 10px; font-size:12px; }
.grid { display:grid; grid-template-columns:340px 1fr; gap:20px; align-items:start; }
@media (max-width: 950px){ .grid { grid-template-columns:1fr; } }
.card { background:var(--bg2); border:1px solid var(--line); border-radius:12px; padding:18px; }
.card h2 { margin:0 0 12px; font-size:15px; color:var(--acc2); letter-spacing:.3px; }
label { display:block; font-size:12px; color:var(--mut); margin:10px 0 4px; }
input,select { width:100%; background:var(--bg1); color:var(--txt); border:1px solid var(--line); border-radius:8px; padding:9px 11px; font-size:14px; outline:none; }
input:focus,select:focus { border-color:var(--acc); box-shadow:0 0 0 3px rgba(88,166,255,.15); }
.hint { font-size:11px; color:var(--mut); margin-top:4px; }
button.primary { width:100%; margin-top:14px; background:linear-gradient(135deg,#1f6feb,#388bfd); color:#fff; border:none; border-radius:8px; padding:11px; font-size:15px; font-weight:600; cursor:pointer; transition:.15s; }
button.primary:hover { filter:brightness(1.1); }
button.primary:disabled { opacity:.5; cursor:not-allowed; }
.kpi-row { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:16px; }
.kpi { flex:1; min-width:130px; background:var(--bg2); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
.kpi .num { font-size:30px; font-weight:700; }
.kpi .lbl { color:var(--mut); font-size:12px; }
.CRITICAL{color:var(--crit);} .HIGH{color:var(--hi);} .MEDIUM{color:var(--warn);} .LOW{color:var(--low);} .INFO{color:var(--info);}
.score-ring { display:flex; align-items:center; gap:16px; }
.ring { --p:0; width:110px; height:110px; border-radius:50%; background:conic-gradient(var(--sc,#3fb950) calc(var(--p)*1%), var(--bg3) 0); display:flex; align-items:center; justify-content:center; position:relative; }
.ring::before { content:''; position:absolute; width:86px; height:86px; border-radius:50%; background:var(--bg2); }
.ring .val { position:relative; font-size:26px; font-weight:700; }
.steps { display:flex; gap:6px; flex-wrap:wrap; margin:10px 0; }
.step { display:flex; align-items:center; gap:6px; font-size:12px; color:var(--mut); background:var(--bg1); border:1px solid var(--line); border-radius:20px; padding:4px 12px; }
.step.on { color:#fff; border-color:var(--acc); background:rgba(88,166,255,.12); }
.step .dot { width:8px; height:8px; border-radius:50%; background:var(--line); }
.step.on .dot { background:var(--acc); animation:pulse 1.2s infinite; }
.step.done .dot { background:var(--ok); animation:none; }
@keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:.35;} }
.finding { border:1px solid var(--line); border-radius:12px; margin-bottom:12px; background:var(--bg2); overflow:hidden; }
.finding .head { display:flex; gap:10px; align-items:flex-start; padding:14px 16px; cursor:pointer; }
.finding .head:hover { background:var(--bg3); }
.finding .title { font-weight:600; flex:1; }
.finding .meta { color:var(--mut); font-size:12px; margin-top:3px; }
.sev { border-radius:6px; padding:2px 10px; font-size:11px; font-weight:700; letter-spacing:.5px; }
.sev.CRITICAL{background:rgba(248,81,73,.15); border:1px solid var(--crit); color:var(--crit);}
.sev.HIGH{background:rgba(240,136,62,.15); border:1px solid var(--hi); color:var(--hi);}
.sev.MEDIUM{background:rgba(210,153,34,.15); border:1px solid var(--warn); color:var(--warn);}
.sev.LOW{background:rgba(126,231,135,.15); border:1px solid var(--low); color:var(--low);}
.sev.INFO{background:rgba(139,148,158,.15); border:1px solid var(--info); color:var(--info);}
.finding .body { display:none; border-top:1px solid var(--line); padding:16px; }
.finding.open .body { display:block; }
.sect { margin-bottom:14px; }
.sect h4 { margin:0 0 6px; font-size:13px; color:var(--acc2); display:flex; align-items:center; gap:6px; }
.sect p, .sect li { font-size:13.5px; line-height:1.65; color:#c9d1d9; }
.sect ol, .sect ul { margin:4px 0 0; padding-left:22px; }
ol li { margin-bottom:6px; }
.tagrow { display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; }
.tag { font-size:11px; border:1px solid var(--line); color:var(--mut); border-radius:6px; padding:2px 8px; }
.code { background:var(--bg1); border:1px solid var(--line); border-radius:8px; padding:10px 12px; font-family:ui-monospace,Consolas,monospace; font-size:12.5px; overflow-x:auto; }
.filters { display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap; }
.chip { border:1px solid var(--line); background:var(--bg1); color:var(--mut); border-radius:20px; padding:5px 14px; font-size:12.5px; cursor:pointer; }
.chip.on { color:#fff; border-color:var(--acc); background:rgba(88,166,255,.15); }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { text-align:left; color:var(--mut); border-bottom:1px solid var(--line); padding:7px 6px; font-weight:500; }
td { border-bottom:1px solid #21262d; padding:7px 6px; }
.toast { position:fixed; bottom:20px; right:20px; background:var(--bg3); border:1px solid var(--line); border-left:4px solid var(--acc); border-radius:10px; padding:12px 18px; font-size:13.5px; display:none; max-width:420px; z-index:50; }
.toast.err { border-left-color:var(--crit); }
.toast.ok { border-left-color:var(--ok); }
.spin { display:inline-block; width:14px; height:14px; border:2px solid var(--line); border-top-color:var(--acc); border-radius:50%; animation:sp 1s linear infinite; vertical-align:-2px; }
@keyframes sp { to { transform:rotate(360deg); } }
.muted { color:var(--mut); }
.empty { text-align:center; color:var(--mut); padding:30px 10px; font-size:14px; }
.warnbox { background:rgba(210,153,34,.08); border:1px solid rgba(210,153,34,.4); border-radius:10px; padding:10px 14px; font-size:12.5px; color:var(--warn); margin-top:12px; }
"""

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CASA Console</title>
<style>__CSS__</style>
</head>
<body>
<header class="hero"><div class="inner">
  <div class="logo">🛡️</div>
  <div>
    <h1>CASA Security Console</h1>
    <div class="sub">Core Agentic Security Assessment &middot; authorized targets only</div>
  </div>
  <span style="flex:1"></span>
  <span class="badge-v">v__VERSION__</span>
  <a class="badge-v" href="/docs">API Docs</a>
</div></header>

<div class="wrap">
<div class="grid">

  <!-- ============ left: target form ============ -->
  <div>
    <div class="card">
      <h2>🎯 New Assessment</h2>
      <form id="target-form">
        <label>Target (IP / domain / URL) *</label>
        <input id="f-target" placeholder="example.com  |  192.0.2.10  |  http://host  |  https://host" required autocomplete="off">
        <div class="hint">Scheme optional — <b>http://</b> and <b>https://</b> both supported; bare hosts try https first and fall back to http automatically. Only targets you are <b>authorized</b> to test.</div>

        <label>Authorized by *</label>
        <input id="f-by" placeholder="e.g. Security Team — ACME" required value="Dashboard User">

        <label>Authorization reference</label>
        <input id="f-ref" placeholder="ticket / contract / email (optional)">

        <label>Assessment profile</label>
        <select id="f-profile">
          <option value="QUICK">QUICK — fast passive snapshot</option>
          <option value="STANDARD" selected>STANDARD — full web assessment</option>
          <option value="DEEP">DEEP — + API & safe-active checks</option>
        </select>

        <label>Scope paths (comma-separated)</label>
        <input id="f-paths" placeholder="/" value="/">

        <div class="warnbox">⚠️ Only run assessments against systems you own or are contractually authorized to test. Every request is logged and scope-validated.</div>
        <button class="primary" id="btn-run" type="submit">▶ Run Assessment</button>
      </form>
    </div>

    <div class="card" style="margin-top:18px">
      <h2>🕘 Recent Assessments</h2>
      <div id="history" class="muted" style="font-size:13px">Loading…</div>
    </div>
  </div>

  <!-- ============ right: results ============ -->
  <div>
    <div id="progress" class="card" style="display:none">
      <h2>⚙️ Assessment Progress</h2>
      <div id="steps" class="steps"></div>
      <div id="prog-msg" class="muted" style="font-size:13px"></div>
    </div>

    <div id="results" style="display:none">
      <div class="kpi-row" id="kpis"></div>
      <div class="card" id="brain-panel" style="display:none;margin-bottom:18px">
        <h2>🧠 CASA-Brain decisions <span id="brain-stats" class="muted" style="font-weight:400"></span></h2>
        <div id="brain-body"></div>
      </div>
      <div class="card" style="margin-bottom:18px">
        <h2>🚨 Findings <span id="f-count" class="muted" style="font-weight:400"></span></h2>
        <div class="filters" id="filters"></div>
        <div id="findings"></div>
      </div>
    </div>

    <div id="welcome" class="card empty">
      <div style="font-size:40px">🛡️</div>
      <p>Enter an authorized target on the left and press <b>Run Assessment</b>.<br>
      Results appear here live — including full vulnerability explanations,<br>
      CVSS scores, attack scenarios and step-by-step remediation.</p>
    </div>
  </div>

</div>
</div>
<div class="toast" id="toast"></div>

<script>
'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const API = '/api/v1';

let CURRENT = { targetId: null, jobId: null, assessmentId: null, pollTimer: null };
let FINDINGS = [], SEV_FILTER = 'ALL';
const STEPS = ['QUEUED','RUNNING','ANALYZING','VERIFYING','COMPLETED'];

function toast(msg, cls='ok') {
  const t = $('toast'); t.textContent = msg; t.className = 'toast ' + cls; t.style.display = 'block';
  clearTimeout(t._h); t._h = setTimeout(() => t.style.display = 'none', 6000);
}
async function api(path, opts) {
  const r = await fetch(API + path, { headers: {'Content-Type':'application/json'}, ...(opts||{}) });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(body.detail || body.message || r.statusText), {status:r.status, body});
  return body;
}
function normalizeTarget(v) {
  v = v.trim();
  if (!/^https?:\\/\\//i.test(v)) v = 'https://' + v;
  const u = new URL(v);
  return u.origin;
}
async function pickScheme(host) {
  // Scheme auto-detection for http-only sites: a no-cors fetch resolves
  // (opaque) when the TCP/TLS handshake succeeds and rejects on connection
  // or TLS failure — exactly the signal needed, with no CORS involvement.
  for (const scheme of ['https', 'http']) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 3500);
    try {
      await fetch(scheme + '://' + host, { mode: 'no-cors', signal: ctl.signal });
      return scheme;
    } catch { /* unreachable over this scheme — try the next */ }
    finally { clearTimeout(timer); }
  }
  return null; // host unreachable either way — let the assessment report it
}

// ---------------- run form ----------------
$('target-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('btn-run');
  const raw = $('f-target').value.trim();
  let origin;
  try { origin = normalizeTarget(raw); }
  catch { return toast('Invalid target URL', 'err'); }

  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Probing target…';

  // http-only sites: when the user didn't pin a scheme, probe https first and
  // transparently fall back to http BEFORE registering the authorization, so
  // the whole pipeline (probe, modules, scope) runs against the live origin.
  let schemeNote = '';
  if (!/^https?:\\/\\//i.test(raw)) {
    const u = new URL(origin);
    const scheme = await pickScheme(u.host);
    if (scheme === 'http') {
      origin = 'http://' + u.host;
      schemeNote = ' — https unreachable, using http';
    }
  }

  btn.innerHTML = '<span class="spin"></span> Registering…';
  try {
    const reg = await api('/authorizations', { method:'POST', body: JSON.stringify({
      target: origin,
      authorized_by: $('f-by').value.trim(),
      authorization_reference: $('f-ref').value.trim(),
      allowed_domains: [new URL(origin).hostname],
      allowed_paths: $('f-paths').value.split(',').map(s=>s.trim()).filter(Boolean),
    })});
    const job = await api('/jobs', { method:'POST', body: JSON.stringify({
      target_id: reg.target_id, trigger: 'INITIAL', profile: $('f-profile').value,
    })});
    CURRENT = { targetId: reg.target_id, jobId: job.id, assessmentId: null };
    showProgress(); pollJob();
    toast('Assessment started on ' + origin + schemeNote);
  } catch (err) {
    toast('Failed: ' + err.message, 'err');
  } finally {
    btn.disabled = false; btn.textContent = '▶ Run Assessment';
    loadHistory();
  }
});

// ---------------- progress ----------------
function showProgress() {
  $('welcome').style.display = 'none'; $('results').style.display = 'none';
  $('progress').style.display = 'block'; renderSteps('QUEUED', 0);
}
function renderSteps(status, attempts) {
  const idx = STEPS.indexOf(status);
  $('steps').innerHTML = STEPS.map((s,i) =>
    `<div class="step ${i<idx?'done':i===idx?'on':''}"><span class="dot"></span>${s}</div>`).join('')
    + (status==='FAILED'||status==='BLOCKED' ? `<div class="step on" style="border-color:var(--crit)"><span class="dot" style="background:var(--crit)"></span>${status}</div>` : '');
  $('prog-msg').textContent = status==='COMPLETED' ? 'Done — loading findings…'
    : `Live status: ${status}` + (attempts?` (attempt ${attempts})`:'') + ' — polling every 2.5s';
}
async function pollJob() {
  clearTimeout(CURRENT.pollTimer);
  try {
    const job = await api('/jobs/' + CURRENT.jobId);
    renderSteps(job.status, job.attempts);
    if (['COMPLETED','FAILED','BLOCKED'].includes(job.status)) {
      if (job.status === 'COMPLETED') return loadAssessment();
      $('prog-msg').textContent = 'Assessment ' + job.status + (job.error ? ': ' + job.error : '');
      return;
    }
  } catch (e) { $('prog-msg').textContent = 'Poll error: ' + e.message; }
  CURRENT.pollTimer = setTimeout(pollJob, 2500);
}

// ---------------- results ----------------
async function loadAssessment() {
  try {
    const list = await api('/assessments?target_id=' + CURRENT.targetId);
    if (!list.length) { $('prog-msg').textContent = 'No assessment found.'; return; }
    CURRENT.assessmentId = list[0].id;
    const [a, f] = await Promise.all([
      api('/assessments/' + CURRENT.assessmentId),
      api('/assessments/' + CURRENT.assessmentId + '/findings'),
    ]);
    FINDINGS = f; SEV_FILTER = 'ALL';
    $('progress').style.display = 'none';
    $('results').style.display = 'block';
    renderKpis(a); renderFilters(); renderFindings(); renderBrain(a); loadHistory();
  } catch (e) { toast('Load failed: ' + e.message, 'err'); }
}
function renderKpis(a) {
  const d = (a.risk_summary||{}).distribution || {};
  const score = a.security_score ?? 0;
  const color = score >= 80 ? '#3fb950' : score >= 55 ? '#d29922' : '#f85149';
  const total = Object.values(d).reduce((x,y)=>x+y,0);
  $('kpis').innerHTML = `
    <div class="kpi score-ring">
      <div class="ring" style="--p:${score};--sc:${color}"><div class="val" style="color:${color}">${score}</div></div>
      <div><div class="lbl">Security Score / 100</div>
      <div class="num" style="font-size:18px;color:${color}">Grade ${(a.risk_summary||{}).grade||'?'}</div>
      <div class="lbl">avg CVSS ${(a.risk_summary||{}).avg_cvss_base_score ?? '—'}</div></div>
    </div>
    <div class="kpi"><div class="num">${total}</div><div class="lbl">Total findings</div></div>
    ${['CRITICAL','HIGH','MEDIUM','LOW'].map(s=>`
      <div class="kpi"><div class="num ${s}">${d[s]||0}</div><div class="lbl">${s}</div></div>`).join('')}`;
}
function renderFilters() {
  const sevs = ['ALL','CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  $('filters').innerHTML = sevs.map(s =>
    `<div class="chip ${s===SEV_FILTER?'on':''}" onclick="setFilter('${s}')">${s==='ALL'?'All':s}
     ${s!=='ALL'?`(${FINDINGS.filter(f=>f.severity===s).length})`:''}</div>`).join('');
}
window.setFilter = s => { SEV_FILTER = s; renderFilters(); renderFindings(); };
function renderFindings() {
  const list = FINDINGS.filter(f => SEV_FILTER==='ALL' || f.severity===SEV_FILTER)
    .sort((a,b)=>({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[a.severity]-{CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[b.severity]));
  $('f-count').textContent = `(${list.length} shown)`;
  if (!list.length) { $('findings').innerHTML = '<div class="empty">No findings in this view 🎉</div>'; return; }
  $('findings').innerHTML = list.map((f,i) => findingCard(f,i)).join('');
  document.querySelectorAll('.finding .head').forEach(h =>
    h.addEventListener('click', () => h.parentElement.classList.toggle('open')));
}
function threatBadge(md) {
  const t = (md||{}).threat_tier;
  if (!t) return '';
  if (t === 'P1_KEV') return '<span class="tag" style="color:var(--crit);border-color:var(--crit);font-weight:700" title="CVE is exploited in the wild (CISA KEV)">🔥 KEV · exploited in the wild</span>';
  if (t === 'P2_EPSS_CRITICAL') return '<span class="tag" style="color:var(--hi);border-color:var(--hi);font-weight:700" title="EPSS ≥ 0.9 — very high exploitation probability">⚡ EPSS critical</span>';
  if (t === 'P3_EPSS_ELEVATED') return '<span class="tag" style="color:var(--warn);border-color:var(--warn)" title="EPSS ≥ 0.5 — elevated exploitation probability">⚠ EPSS elevated</span>';
  return '';
}
function findingCard(f, i) {
  const x = (f.risk_factors && (f.metadata||{}).explanation) || (f.metadata||{}).explanation || {};
  const mitre = (f.metadata||{}).mitre_attack || [];
  const tbadge = threatBadge(f.metadata);
  const cveThreat = (f.metadata||{}).cve_threat;
  const attk = mitre.map(m => `<span class="tag" title="${esc(m.name)}">ATT&CK ${esc(m.id)}</span>`).join('');
  const cveRow = (f.metadata||{}).exploit_cves?.length ? `
    <div class="sect"><h4>🎯 CVE threat intelligence (ExploitDB + CISA KEV + EPSS)</h4>
      ${tbadge}
      ${cveThreat ? `<p style="font-size:12.5px;color:#c9d1d9;margin:6px 0">${esc(cveThreat.tier_label)}${cveThreat.epss_max != null ? ` · max EPSS ${esc(cveThreat.epss_max)}` : ''}${cveThreat.known_ransomware ? ' · used in ransomware campaigns' : ''}</p>` : ''}
      <div class="tagrow">${(f.metadata.exploit_cves||[]).map(c => `<span class="tag" style="font-family:ui-monospace,Consolas,monospace">${esc(c)}</span>`).join('')}</div>
      ${(f.metadata||{}).exploit_matches?.length ? `<div class="code" style="margin-top:8px">${esc((f.metadata.exploit_matches||[]).slice(0,5).map(m => `EDB-${m.edb_id} [${m.matched_on}${m.matched_version?' '+m.matched_version:''}] ${m.description||''}`).join('; ').slice(0,900))}</div>` : ''}
    </div>` : '';
  return `
  <div class="finding" data-sev="${esc(f.severity)}">
    <div class="head">
      <span class="sev ${esc(f.severity)}">${esc(f.severity)}</span>
      <div class="title">
        ${esc(f.title)}
        <div class="meta">${esc(f.category)} · source: ${esc(f.source)} · risk ${f.risk_score ?? '—'}
          ${mitre.length?` · <span class="tag">ATT&CK ${esc(mitre[0].id)}</span>`:''} ${tbadge}</div>
      </div>
      <span class="muted" style="font-size:11px">ID ${String(i+1).padStart(2,'0')}</span>
    </div>
    <div class="body">
      ${cveRow}
      ${x.vulnerability ? `<div class="sect"><h4>🧩 What is this vulnerability?</h4><p>${esc(x.vulnerability)}</p></div>` : `<div class="sect"><h4>🧩 Description</h4><p>${esc(f.description)}</p></div>`}
      ${x.attack_scenario?.length ? `<div class="sect"><h4>⚔️ How an attacker would exploit it</h4><ol>${x.attack_scenario.map(s=>`<li>${esc(s)}</li>`).join('')}</ol></div>` : ''}
      ${x.business_impact ? `<div class="sect"><h4>💥 Business impact</h4><p>${esc(x.business_impact)}</p></div>` : `<div class="sect"><h4>💥 Impact</h4><p>${esc(f.impact)}</p></div>`}
      ${x.exploitability ? `<div class="sect"><h4>🎚️ Exploitability</h4><p>${esc(x.exploitability)}</p></div>` : ''}
      ${x.cvss_rationale ? `<div class="sect"><h4>📊 Why this severity</h4><p>${esc(x.cvss_rationale)}</p></div>` : ''}
      ${x.remediation_plan?.length ? `<div class="sect"><h4>🛠️ Remediation plan (in order)</h4><ol>${x.remediation_plan.map(s=>`<li>${esc(s)}</li>`).join('')}</ol></div>`
        : `<div class="sect"><h4>🛠️ Remediation</h4><p>${esc(f.remediation)}</p></div>`}
      ${x.verification ? `<div class="sect"><h4>✅ How to verify the fix</h4><p>${esc(x.verification)}</p></div>` : ''}
      <div class="sect"><h4>🔎 Evidence</h4><div class="code">${esc(JSON.stringify(f.evidence_refs || f.risk_factors || {}, null, 2).slice(0,1200))}</div>
        <div class="tagrow">
          <span class="tag">asset: ${esc(f.affected_asset)}</span>
          <span class="tag">confidence: ${esc(f.confidence)}</span>
          <span class="tag">status: ${esc(f.status)}</span>
          <span class="tag">fingerprint: ${esc(f.fingerprint)}</span>
          ${attk}
        </div>
      </div>
    </div>
  </div>`;
}

function renderBrain(a) {
  const panel = $('brain-panel');
  const b = (a.risk_summary || {}).brain;
  const rep = b && b.report;
  const decisions = (rep && rep.decisions) || [];
  if (!rep || !decisions.length) { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  $('brain-stats').textContent =
    `approved ${rep.approved ?? 0} · denied ${rep.denied ?? 0}` +
    (b.executed_actions != null ? ` · executed ${b.executed_actions}` : '');
  const rows = decisions.map((d, i) => {
    const sel = d.selected || {};
    const pol = d.policy || {};
    const p = sel.params || {};
    const tgt = p.module || p.technology || p.fingerprint;
    const verdict = pol.allowed
      ? '<span class="tag" style="color:var(--ok);border-color:var(--ok)">APPROVED</span>'
      : '<span class="tag" style="color:var(--crit);border-color:var(--crit)">DENIED</span>';
    return `<tr>
      <td>${i + 1}</td>
      <td><b>${esc(String(sel.action || '?').replace(/_/g, ' '))}</b>
        ${tgt ? `<div class="muted" style="font-size:11px">${esc(tgt)}${p.enricher ? ' (' + esc(p.enricher) + ')' : ''}</div>` : ''}</td>
      <td>${sel.expected_information_gain ?? '—'}</td>
      <td>${verdict} <span class="tag">${esc(pol.rule || '')}</span>
        <div class="muted" style="font-size:11px">${esc(String(pol.reason || '').slice(0, 120))}</div></td>
    </tr>`;
  }).join('');
  const stop = b.final
    ? `<div class="sect" style="margin-top:12px"><h4>🛑 Final decision</h4><p>${esc(String((b.final.reason_codes || []).join(', ') || b.final.action || ''))}</p></div>`
    : '';
  $('brain-body').innerHTML =
    `<table><tr><th>#</th><th>Action</th><th>Gain</th><th>Policy verdict</th></tr>${rows}</table>${stop}`;
}

// ---------------- history ----------------
async function loadHistory() {
  try {
    const jobs = await api('/jobs?limit=8');
    const targets = {};
    for (const j of jobs) {
      if (!targets[j.target_id]) targets[j.target_id] = {id: j.target_id, status: j.status, profile: j.profile, at: j.queued_at, jobId: j.id};
    }
    const rows = Object.values(targets).slice(0, 8);
    $('history').innerHTML = rows.length ? `<table><tr><th>Target ID</th><th>Profile</th><th>Status</th><th></th></tr>` +
      rows.map(t => `<tr><td class="code" style="font-size:11px">${esc(t.id.slice(0,8))}…</td>
        <td>${esc(t.profile)}</td><td>${esc(t.status)}</td>
        <td><a href="#" onclick="viewTarget('${t.id}','${t.jobId}');return false;">view</a></td></tr>`).join('') + '</table>'
      : '<span class="muted">No assessments yet.</span>';
  } catch { $('history').textContent = 'History unavailable.'; }
}
window.viewTarget = async (targetId, jobId) => {
  CURRENT = { targetId, jobId, assessmentId: null };
  showProgress(); pollJob();
};
loadHistory();
</script>
</body>
</html>"""


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html = _PAGE.replace("__CSS__", _CSS).replace("__VERSION__", __version__)
    return HTMLResponse(html)
