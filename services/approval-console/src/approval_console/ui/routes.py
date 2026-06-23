"""GET /agents — extended agent-centric product console page (C5).

This is a SEPARATE route from GET / (the legacy JIT-only console).
The legacy GET / handler in app.py is UNTOUCHED.

The new page surfaces:
  - Agent list with state badges, skill tags, Gitea repo link, webshell + session buttons.
  - Skill picker form for launching a new agent.
  - Session transcript panel (SSE, reusing the proven heartbeat path).
  - JIT request panel scoped to the current agent (filter by sandbox_id).
  - Token receipt panel (persistent, not just a toast).
  - Self-approval guard: JS checks whoami against requester_sub before showing Approve.
  - Revoke panel stub (disabled, "Coming in Phase D").

Security: all API calls in the page go through the same server-side handlers
(same audit, same Keycloak actor resolution, same SoD enforcement).
"""

from __future__ import annotations

import html as _html_mod

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from approval_console.agents import store as agent_store
from approval_console.config import Config
from approval_console.ui import fragments

router = APIRouter(tags=["ui"])

# ---------------------------------------------------------------------------
# GET /api/agents/{agent_id}/jit-history — JIT requests for this agent
# ---------------------------------------------------------------------------

import time
import hashlib
import json
import logging
import datetime
import httpx

logger = logging.getLogger("approval_console.ui.routes")


def _hash(args: object) -> str:
    raw = json.dumps(args, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


@router.get("/api/harnesses")
async def harnesses() -> JSONResponse:
    """Proxy the sandbox-launcher /harnesses catalog for the launch form dropdown.

    Returns {"default": "<image>", "images": [...]}. On any launcher error, returns
    a safe single-entry catalog (empty default) so the form still renders.
    """
    import os as _os

    url = _os.environ.get("SANDBOX_LAUNCHER_URL", "").strip()
    if not url:
        return JSONResponse(content={"default": "", "images": []})
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{url}/harnesses")
        if resp.is_success:
            return JSONResponse(content=resp.json())
    except httpx.RequestError as exc:
        logger.warning("harnesses.proxy_error: %s", exc)
    return JSONResponse(content={"default": "", "images": []})


@router.get("/api/agents/{agent_id}/jit-history")
async def jit_history(agent_id: str, request: Request) -> JSONResponse:
    """Proxy /requests?sandbox=<sandbox_id> to jit-approver, filtered to this agent."""
    from approval_console.app import _actor, _jit_headers  # type: ignore[import]

    actor = _actor(request)
    agent = agent_store.get_agent(agent_id)
    if agent is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found")

    sandbox_id = agent.sandbox_id
    jit_url = Config.jit_approver_url()
    t0 = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{jit_url}/requests",
                params={"sandbox": sandbox_id} if sandbox_id else {},
                headers=_jit_headers(),
            )
    except httpx.RequestError as exc:
        raise

    # Annotate each request with can_approve flag (client-side guard only; server enforces SoD)
    requests_list = resp.json() if resp.is_success else []
    actor_sub = actor
    annotated = [
        {**r, "can_approve": r.get("requester_sub", "") != actor_sub}
        for r in (requests_list if isinstance(requests_list, list) else [])
    ]

    return JSONResponse(content=annotated, status_code=resp.status_code)


# ---------------------------------------------------------------------------
# GET /agents — extended console HTML page
# ---------------------------------------------------------------------------

_AGENTS_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OpenShell Agent Console</title>
<style>
*, *::before, *::after { box-sizing: border-box; }
body { font-family: "Segoe UI", system-ui, sans-serif; background: #0f1117; color: #e0e0e0;
       margin: 0; padding: 1.5rem; }
h1 { color: #76b900; margin: 0 0 0.25rem; font-size: 1.4rem; }
.subtitle { color: #888; font-size: 0.85rem; margin: 0 0 1.5rem; }
.badge { display:inline-block; padding:0.2em 0.6em; border-radius:0.3em;
         font-size:0.75rem; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; }
.badge-pending  { background:#7c3f00; color:#ffb347; }
.badge-approved { background:#1a3a1a; color:#76b900; }
.badge-issued   { background:#1a2a3a; color:#5bc8f5; }
.badge-expired  { background:#2a2a2a; color:#888; }
.badge-denied   { background:#3a1a1a; color:#f55; }
.mono { font-family:"JetBrains Mono","Cascadia Code",monospace; font-size:0.82em; }
.key { color:#888; }
.val { color:#e0e0e0; }
.section-header { font-size:0.85rem; font-weight:700; color:#76b900; margin:1.5rem 0 0.5rem;
                  text-transform:uppercase; letter-spacing:0.07em; }
#identity-bar { font-size:0.8rem; color:#888; margin-bottom:1rem; }
#identity-bar a { color:#5bc8f5; text-decoration:none; margin-left:0.75rem; }
.agent-card { background:#13161f; border:1px solid #2a2d34; border-radius:0.45em;
              padding:1rem 1.25rem; margin-bottom:0.75rem; }
.agent-card-header { display:flex; align-items:center; gap:0.75rem; margin-bottom:0.4rem; }
.agent-name { font-size:1rem; font-weight:700; color:#e0e0e0; }
.agent-card-meta { font-size:0.8rem; margin-bottom:0.6rem; }
.agent-card-actions button { margin-right:0.5rem; padding:0.3em 0.8em; border-radius:0.3em;
  border:1px solid #5bc8f5; background:#1a2a3a; color:#5bc8f5; cursor:pointer;
  font-size:0.82rem; font-weight:600; }
.agent-card-actions button:disabled { border-color:#333; color:#555; background:#1a1d24; cursor:default; }
.agent-card-actions button:hover:not(:disabled) { background:#1e4a5e; }
.launch-panel { background:#13161f; border:1px solid #2a2d34; border-radius:0.45em;
                padding:1rem 1.25rem; margin-bottom:1.5rem; }
.launch-panel h2 { color:#5bc8f5; font-size:1rem; margin:0 0 0.6rem; font-weight:700; }
.form-row { display:flex; gap:0.75rem; align-items:flex-end; flex-wrap:wrap; margin-bottom:0.6rem; }
.form-field { display:flex; flex-direction:column; gap:0.3rem; }
.form-field label { font-size:0.78rem; color:#aaa; }
.form-field input[type="text"] { background:#0d1117; color:#e0e0e0; border:1px solid #2a2d34;
  border-radius:0.3em; padding:0.4em 0.6em; font-size:0.85rem; min-width:220px; }
.skills-picker { display:flex; flex-wrap:wrap; gap:0.5rem; margin:0.5rem 0; }
.skill-cb { display:flex; align-items:center; gap:0.3rem; font-size:0.82rem;
             background:#1a1d24; border-radius:0.3em; padding:0.25em 0.6em; }
button.launch-btn { background:#1a3a4a; color:#5bc8f5; border:1px solid #5bc8f5;
  padding:0.35em 1em; border-radius:0.3em; cursor:pointer; font-weight:600; font-size:0.85rem; }
button.launch-btn:hover { background:#1e4a5e; }
button.launch-btn:disabled { background:#1a1d24; color:#555; border-color:#333; cursor:default; }
#launch-status { font-size:0.8rem; color:#888; margin-top:0.4rem; min-height:1.2em; }
#agents-list { margin-bottom:1.5rem; }
#agents-empty { color:#555; font-size:0.85rem; padding:1rem 0; }
table { width:100%; border-collapse:collapse; font-size:0.88rem; margin-bottom:1rem; }
th { text-align:left; padding:0.5rem 0.75rem; background:#1a1d24; color:#aaa;
     font-weight:600; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.05em;
     border-bottom:1px solid #2a2d34; }
td { padding:0.55rem 0.75rem; border-bottom:1px solid #1a1d24; vertical-align:top; }
tr:hover td { background:#14171e; }
.trunc { max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
button.approve { background:#76b900; color:#000; border:none; padding:0.35em 0.9em;
  border-radius:0.3em; cursor:pointer; font-weight:600; font-size:0.82rem; }
button.approve:hover { background:#8ed600; }
button.approve:disabled { background:#333; color:#666; cursor:default; }
#transcript { margin-top:0.75rem; background:#0d1117; border:1px solid #2a2d34;
  border-radius:0.35em; padding:0.6rem 0.75rem; font-family:"JetBrains Mono","Cascadia Code",monospace;
  font-size:0.78rem; line-height:1.55; color:#cdd9e5; max-height:320px; overflow-y:auto;
  white-space:pre-wrap; word-break:break-word; display:none; }
.token-receipt { background:#1a1d24; border:1px solid #5bc8f5; border-radius:0.4em;
                 padding:0.75rem 1rem; margin-top:0.75rem; }
.session-jwt-box { background:#0d1117; border:1px solid #5bc8f5; border-radius:0.35em;
  padding:0.5rem 0.75rem; margin-top:0.5rem; font-family:monospace; font-size:0.78rem;
  word-break:break-all; color:#5bc8f5; }
</style>
</head>
<body>
<h1>OpenShell Agent Console</h1>
<div id="identity-bar">Loading identity&hellip;</div>
<p class="subtitle">Launch persistent agents, pick skills, webshell in, approve writes.</p>

<!-- Launch panel -->
<div class="launch-panel">
  <h2>Launch New Agent</h2>
  <div class="form-row">
    <div class="form-field">
      <label for="agent-name">Agent name</label>
      <input type="text" id="agent-name" placeholder="e.g. pfsense-auditor-1" maxlength="80">
    </div>
    <div class="form-field">
      <label for="harness-select">Harness image</label>
      <select id="harness-select" style="background:#0d1117;color:#e0e0e0;border:1px solid #2a2d34;border-radius:0.3em;padding:0.4em 0.6em;font-size:0.85rem;min-width:300px;">
        <option value="">Loading harnesses&hellip;</option>
      </select>
    </div>
  </div>
  <div><label style="font-size:0.78rem;color:#aaa;">Skills</label></div>
  <div class="skills-picker" id="skills-picker">
    <span style="color:#555;font-size:0.82rem">Loading skills&hellip;</span>
  </div>
  <button class="launch-btn" id="launch-btn" onclick="launchAgent()">Launch Agent</button>
  <div id="launch-status"></div>
</div>

<!-- Agent list -->
<div class="section-header">My Agents</div>
<div id="agents-list"><div id="agents-empty">Loading&hellip;</div></div>

<!-- Session transcript -->
<div id="session-panel" style="display:none">
  <div class="section-header" id="session-panel-title">Session</div>
  <pre id="transcript"></pre>
</div>

<!-- JIT requests for selected agent -->
<div id="jit-panel" style="display:none">
  <div class="section-header">JIT Requests</div>
  <table>
    <thead><tr>
      <th>ID</th><th>State</th><th>Requester</th><th>Namespace</th><th>Expires</th><th>Action</th>
    </tr></thead>
    <tbody id="jit-body"></tbody>
  </table>
  <div id="token-receipts"></div>
</div>

<script>
let _me = 'anonymous';
let _selectedAgent = null;
let _tsSource = null;

// Identity banner
(async function() {
  const bar = document.getElementById('identity-bar');
  try {
    const r = await fetch('/api/whoami');
    const d = await r.json();
    _me = d.user || 'anonymous';
    bar.innerHTML = 'Signed in as <b>' + _me + '</b>'
      + (_me !== 'anonymous' ? '<a href="/oauth2/sign_out">Sign out</a>' : '');
  } catch(e) { bar.textContent = 'Could not resolve identity.'; }
})();

// The mcp-helper skill is pre-ticked by default (server also enforces it).
const DEFAULT_MCP_SKILL = 'pfsense-firewall';

// Load skills picker. The mcp-helper skill is always present + pre-ticked, even if
// the central skills repo does not list it (it's baked into the harness image).
(async function() {
  const picker = document.getElementById('skills-picker');
  let names = [];
  try {
    const r = await fetch('/api/skills');
    const skills = r.ok ? await r.json() : [];
    names = skills.map(s => s.name);
  } catch(e) { /* fall through to just the mcp helper */ }
  // Guarantee the mcp-helper appears so it can be pre-ticked.
  if (!names.includes(DEFAULT_MCP_SKILL)) names.unshift(DEFAULT_MCP_SKILL);
  if (!names.length) { picker.innerHTML = '<span style="color:#555">No skills available</span>'; return; }
  picker.innerHTML = names.map(n => {
    const checked = (n === DEFAULT_MCP_SKILL) ? ' checked' : '';
    const tag = (n === DEFAULT_MCP_SKILL) ? ' <span style="color:#76b900;font-size:0.7rem">(mcp helper)</span>' : '';
    return `<label class="skill-cb"><input type="checkbox" name="skill" value="${n}"${checked}>${n}${tag}</label>`;
  }).join('');
})();

// Load harness-image dropdown.
(async function() {
  const sel = document.getElementById('harness-select');
  try {
    const r = await fetch('/api/harnesses');
    const d = r.ok ? await r.json() : {images: []};
    const images = d.images || [];
    if (!images.length) {
      sel.innerHTML = '<option value="">launcher default</option>';
      return;
    }
    sel.innerHTML = images.map((img, i) =>
      `<option value="${img}"${i===0?' selected':''}>${img}${i===0?' (default)':''}</option>`
    ).join('');
  } catch(e) {
    sel.innerHTML = '<option value="">launcher default</option>';
  }
})();

// Load agent list
async function loadAgents() {
  const list = document.getElementById('agents-list');
  const r = await fetch('/api/agents');
  if (!r.ok) { list.innerHTML = '<div style="color:#f55">Failed to load agents</div>'; return; }
  const agents = await r.json();
  if (!agents.length) {
    list.innerHTML = '<div id="agents-empty" style="color:#555;font-size:0.85rem;padding:1rem 0">No agents yet. Launch one above.</div>';
    return;
  }
  list.innerHTML = agents.map(a => agentCardHtml(a)).join('');
}

function agentCardHtml(a) {
  const state = a.state || 'UNKNOWN';
  const badges = {READY:'badge-approved',PROVISIONING:'badge-pending',ARCHIVED:'badge-expired',ERROR:'badge-denied'};
  const badgeCls = badges[state] || 'badge-pending';
  const skills = (a.skills||[]).join(', ') || '&mdash;';
  const repo = a.gitea_repo ? `<a href="${a.gitea_repo}" target="_blank" rel="noopener">repo</a>` : '&mdash;';
  const ready = state === 'READY';
  const arch = state === 'ARCHIVED';
  return `<div class="agent-card" data-id="${a.agent_id}">
    <div class="agent-card-header">
      <span class="agent-name mono">${a.display_name || a.agent_id}</span>
      <span class="badge ${badgeCls}">${state}</span>
    </div>
    <div class="agent-card-meta">
      <span class="key">owner:</span> <span class="val mono">${a.owner}</span> &nbsp;|&nbsp;
      <span class="key">skills:</span> <span class="val">${skills}</span> &nbsp;|&nbsp;
      <span class="key">repo:</span> <span class="val">${repo}</span>
    </div>
    <div class="agent-card-actions">
      <button onclick="openWebshell('${a.agent_id}')" ${ready?'':'disabled'}>Webshell</button>
      <button onclick="startSession('${a.agent_id}')" ${ready?'':'disabled'}>New Session</button>
      <button onclick="viewJit('${a.agent_id}')">JIT Requests</button>
      <button onclick="archiveAgent('${a.agent_id}')" ${arch?'disabled':''}>Archive</button>
    </div>
  </div>`;
}

async function launchAgent() {
  const btn = document.getElementById('launch-btn');
  const status = document.getElementById('launch-status');
  const name = document.getElementById('agent-name').value.trim();
  if (!name) { status.textContent = 'Agent name is required.'; return; }
  const skills = Array.from(document.querySelectorAll('input[name="skill"]:checked')).map(i => i.value);
  const harnessImage = (document.getElementById('harness-select') || {}).value || '';
  btn.disabled = true; btn.textContent = 'Launching…';
  status.textContent = '';
  try {
    const r = await fetch('/api/agents', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({display_name: name, skills, harness_image: harnessImage}),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(JSON.stringify(d));
    status.textContent = 'Agent ' + d.agent_id.slice(0,8) + '… provisioning.';
    await loadAgents();
  } catch(e) {
    status.textContent = 'Launch failed: ' + e;
  }
  btn.disabled = false; btn.textContent = 'Launch Agent';
}

function openWebshell(agentId) {
  // Open the SAME-ORIGIN served webshell page (vendored xterm, no CDN, no
  // document.write). The previous popup wrote cross-site parser-blocking CDN
  // <script> tags AND assigned term.onData (which registers no listener), so
  // typing was dead. The served page (GET /api/agents/{id}/webshell/ui) wires
  // input correctly via term.onData(cb) and loads scripts in a deterministic
  // order. window.open(url) inherits the oauth2-proxy session cookie.
  const uiUrl = '/api/agents/' + encodeURIComponent(agentId) + '/webshell/ui';
  const w = window.open(uiUrl, '_blank', 'width=900,height=600');
  if (!w) { alert('Allow popups to open the webshell.'); }
}

let _sessionSource = null;
async function startSession(agentId) {
  const goal = prompt('Session goal:');
  if (!goal) return;
  const r = await fetch('/api/agents/' + agentId + '/sessions', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({goal}),
  });
  const d = await r.json();
  if (!r.ok) { alert('Failed: ' + JSON.stringify(d)); return; }
  const sid = d.session_id;
  const panel = document.getElementById('session-panel');
  const title = document.getElementById('session-panel-title');
  const transcript = document.getElementById('transcript');
  panel.style.display='block';
  title.textContent = 'Session ' + sid.slice(0,8) + '…';
  transcript.style.display='block';
  transcript.textContent='';
  if (_sessionSource) { _sessionSource.close(); }
  _sessionSource = new EventSource('/api/sessions/' + sid + '/stream');
  _sessionSource.onmessage = function(e) {
    transcript.textContent += renderLine(e.data) + '\\n';
    transcript.scrollTop = transcript.scrollHeight;
  };
  _sessionSource.addEventListener('done', function() {
    _sessionSource.close(); _sessionSource = null;
    title.textContent += ' (done)';
  });
}

function renderLine(raw) {
  try {
    const o = JSON.parse(raw);
    const t = o.type || '';
    if (t==='assistant' && o.text) return '[agent] ' + o.text;
    if (t==='tool_use' && o.tool) return '  → tool: ' + o.tool;
    if (t==='tool_result') return '  ⬍ ' + (o.ok?'ok':'ERR') + (o.content?': '+String(o.content).slice(0,200):'');
    if (t==='result' && o.summary) return '✅ ' + o.summary;
    if (t==='error' && o.msg) return '❌ ' + o.msg;
    if (t==='stderr' && o.msg) return '[stderr] ' + o.msg;
  } catch(_) {}
  return raw;
}

async function viewJit(agentId) {
  _selectedAgent = agentId;
  const panel = document.getElementById('jit-panel');
  panel.style.display = 'block';
  await refreshJit();
}

async function refreshJit() {
  if (!_selectedAgent) return;
  const tbody = document.getElementById('jit-body');
  try {
    const r = await fetch('/api/agents/' + _selectedAgent + '/jit-history');
    const items = r.ok ? await r.json() : [];
    if (!items.length) { tbody.innerHTML = '<tr><td colspan="6" style="color:#555;text-align:center">No JIT requests</td></tr>'; return; }
    tbody.innerHTML = items.map(req => {
      const state = req.state || '';
      const badges = {pending:'badge-pending',approved:'badge-approved',issued:'badge-issued',expired:'badge-expired',denied:'badge-denied'};
      const cls = badges[state] || 'badge-pending';
      const canApprove = req.can_approve !== false && (state === 'pending' || state === 'approved');
      return `<tr>
        <td class="mono">${(req.id||'').slice(0,8)}&hellip;</td>
        <td><span class="badge ${cls}">${state}</span></td>
        <td class="mono">${req.requester_sub || ''}</td>
        <td class="mono">${req.namespace || ''}</td>
        <td class="mono">${req.expires_at || '&mdash;'}</td>
        <td><button class="approve" onclick="approve('${req.id}', this)"
          ${canApprove ? '' : 'disabled title="'+(state!=='pending'?state:'Cannot approve your own request')+'"'}>
          ${canApprove ? 'Approve' : state}</button>
          <button style="margin-left:0.5rem;padding:0.3em 0.7em;border-radius:0.3em;border:1px solid #555;background:#1a1d24;color:#555;cursor:not-allowed" disabled title="Coming in Phase D">Revoke</button>
        </td>
      </tr>`;
    }).join('');
  } catch(e) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:#f55">Failed to load JIT history</td></tr>';
  }
}

async function approve(id, btn) {
  btn.disabled = true; btn.textContent = 'Approving…';
  const r = await fetch('/api/approve/' + id, {method:'POST'});
  const body = await r.json();
  if (r.ok && body.session_id) {
    const receipts = document.getElementById('token-receipts');
    receipts.innerHTML += `<div class="token-receipt">
      <div class="section-header">Token Receipt</div>
      <div><span class="key">Session ID:</span> <code class="mono val">${body.session_id}</code></div>
      <div><span class="key">State:</span> <span class="badge badge-issued">${body.session_state||'issued'}</span></div>
      <div><span class="key">Expires:</span> <code class="mono val">${body.expires_at||'unknown'}</code></div>
    </div>`;
  }
  await refreshJit();
}

async function archiveAgent(agentId) {
  if (!confirm('Archive agent ' + agentId.slice(0,8) + '? The Gitea repo will be renamed.')) return;
  const r = await fetch('/api/agents/' + agentId + '/archive', {method:'POST'});
  if (!r.ok) { alert('Archive failed: ' + (await r.text())); return; }
  await loadAgents();
}

loadAgents();
setInterval(loadAgents, 15000);
setInterval(refreshJit, 10000);
</script>
</body>
</html>
"""


@router.get("/agents", response_class=HTMLResponse)
async def agents_console() -> HTMLResponse:
    """Serve the extended agent-centric product console page."""
    return HTMLResponse(content=_AGENTS_PAGE)
