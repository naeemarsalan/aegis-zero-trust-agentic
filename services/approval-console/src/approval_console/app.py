"""approval-console — minimal operator web UI for JIT write-approval requests.

Endpoints:
  GET  /           -> self-contained HTML console (no build step)
  GET  /api/requests -> proxy to jit-approver GET /requests (with optional ?state= filter)
  GET  /api/requests/{id}/detail -> proxy to jit-approver GET /requests/{id}/detail
  GET  /api/requests/{id}/status -> proxy to jit-approver GET /requests/{id}/status
                                    (post-approval: surfaces session_id + expires_at)
  POST /api/approve/{id} -> merge the Gitea PR for this session; returns merge result
  GET  /healthz    -> liveness probe

Security contract (PoC):
  - No auth on the console itself (behind the cluster Route; see README).
  - GITEA_TOKEN stays server-side; browser never touches Gitea directly.
  - Approve is the ONLY mutating operation; everything else is read-only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse

from approval_console.config import Config

logger = logging.getLogger("approval_console.app")

app = FastAPI(
    title="JIT Approval Console",
    description="Operator web console for JIT write-approval requests",
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_args(args: Any) -> str:
    """sha256 of JSON-serialised arguments (audit contract)."""
    raw = json.dumps(args, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def _audit(event: str, actor: str, outcome: str, latency_ms: float, **extra: Any) -> None:
    """Emit structured audit log line per the platform contract."""
    import datetime

    record: dict[str, Any] = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event,
        "actor": actor,
        "namespace": "mcp-gateway",
        "outcome": outcome,
        "latency_ms": round(latency_ms, 2),
    }
    record.update(extra)
    logger.info(json.dumps(record))


def _jit_headers() -> dict[str, str]:
    """No auth token needed for jit-approver read endpoints (cluster-internal)."""
    return {"Accept": "application/json"}


def _gitea_headers() -> dict[str, str]:
    return {
        "Authorization": f"token {Config.gitea_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


# ---------------------------------------------------------------------------
# GET / — self-contained HTML console
# ---------------------------------------------------------------------------

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JIT Approval Console</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body {
    font-family: "Segoe UI", system-ui, sans-serif;
    background: #0f1117;
    color: #e0e0e0;
    margin: 0;
    padding: 1.5rem;
  }
  h1 { color: #76b900; margin: 0 0 0.25rem; font-size: 1.4rem; }
  .subtitle { color: #888; font-size: 0.85rem; margin: 0 0 1.5rem; }
  .badge {
    display: inline-block;
    padding: 0.2em 0.6em;
    border-radius: 0.3em;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .badge-pending  { background: #7c3f00; color: #ffb347; }
  .badge-approved { background: #1a3a1a; color: #76b900; }
  .badge-issued   { background: #1a2a3a; color: #5bc8f5; }
  .badge-expired  { background: #2a2a2a; color: #888; }
  .badge-denied   { background: #3a1a1a; color: #f55; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
    margin-bottom: 1rem;
  }
  th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    background: #1a1d24;
    color: #aaa;
    font-weight: 600;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid #2a2d34;
  }
  td {
    padding: 0.55rem 0.75rem;
    border-bottom: 1px solid #1a1d24;
    vertical-align: top;
    word-break: break-word;
  }
  tr:hover td { background: #14171e; }
  .mono { font-family: "JetBrains Mono", "Cascadia Code", monospace; font-size: 0.82em; }
  .trunc { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  button.approve {
    background: #76b900;
    color: #000;
    border: none;
    padding: 0.35em 0.9em;
    border-radius: 0.3em;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.82rem;
  }
  button.approve:hover { background: #8ed600; }
  button.approve:disabled { background: #333; color: #666; cursor: default; }
  .actions-col { white-space: nowrap; }
  .pill-pr {
    display: inline-block;
    background: #1e2230;
    border-radius: 0.25em;
    padding: 0.1em 0.5em;
    font-size: 0.78rem;
    color: #76b900;
    text-decoration: none;
  }
  .pill-pr:hover { text-decoration: underline; }
  #status-bar {
    font-size: 0.8rem;
    color: #888;
    margin-bottom: 1rem;
    min-height: 1.2em;
  }
  #status-bar.error { color: #f55; }
  .toast {
    position: fixed;
    bottom: 1.5rem;
    right: 1.5rem;
    background: #1a2a3a;
    border: 1px solid #5bc8f5;
    border-radius: 0.4em;
    padding: 0.75rem 1rem;
    max-width: 420px;
    font-size: 0.85rem;
    z-index: 9999;
    display: none;
  }
  .toast.error { border-color: #f55; background: #2a1a1a; }
  .toast .close { float: right; cursor: pointer; margin-left: 0.5rem; color: #888; }
  .session-detail {
    background: #1a1d24;
    border-radius: 0.4em;
    padding: 0.75rem 1rem;
    margin: 0.25rem 0;
    font-size: 0.83rem;
    line-height: 1.6;
  }
  .session-jwt-box {
    background: #0d1117;
    border: 1px solid #5bc8f5;
    border-radius: 0.35em;
    padding: 0.5rem 0.75rem;
    margin-top: 0.5rem;
    font-family: monospace;
    font-size: 0.78rem;
    word-break: break-all;
    color: #5bc8f5;
  }
  .key { color: #888; }
  .val { color: #e0e0e0; }
  .section-header {
    font-size: 0.85rem;
    font-weight: 700;
    color: #76b900;
    margin: 1.5rem 0 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.07em;
  }
  .empty-row td { color: #555; text-align: center; padding: 2rem; }
  #refresh-counter { color: #555; }
</style>
</head>
<body>
<h1>JIT Approval Console</h1>
<p class="subtitle">
  Zero-trust PoC &mdash; approve by merging the Gitea PR. No auth on this console (PoC caveat; behind cluster route).
</p>

<div id="status-bar">Loading&hellip;</div>

<div class="section-header">Pending Requests</div>
<table id="pending-table">
  <thead>
    <tr>
      <th>Session ID</th>
      <th>State</th>
      <th>Requester</th>
      <th>Namespace</th>
      <th>Verbs / Resources</th>
      <th>Duration</th>
      <th>Justification</th>
      <th>PR</th>
      <th class="actions-col">Action</th>
    </tr>
  </thead>
  <tbody id="pending-body">
    <tr class="empty-row"><td colspan="9">Loading&hellip;</td></tr>
  </tbody>
</table>

<div class="section-header">All Requests</div>
<table id="all-table">
  <thead>
    <tr>
      <th>Session ID</th>
      <th>State</th>
      <th>PR</th>
      <th>Expires At</th>
    </tr>
  </thead>
  <tbody id="all-body">
    <tr class="empty-row"><td colspan="4">Loading&hellip;</td></tr>
  </tbody>
</table>

<div class="toast" id="toast">
  <span class="close" onclick="hideToast()">&times;</span>
  <div id="toast-content"></div>
</div>

<script>
const POLL_INTERVAL = __POLL_INTERVAL_MS__;
let _detailCache = {};
let _countdown = POLL_INTERVAL / 1000;
let _countdownTimer = null;

function badgeHtml(state) {
  return `<span class="badge badge-${state}">${state}</span>`;
}

function trunc(s, n) {
  if (!s) return '';
  s = String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function showToast(html, isError) {
  const t = document.getElementById('toast');
  document.getElementById('toast-content').innerHTML = html;
  t.className = 'toast' + (isError ? ' error' : '');
  t.style.display = 'block';
  if (!isError) {
    setTimeout(hideToast, 8000);
  }
}
function hideToast() {
  document.getElementById('toast').style.display = 'none';
}

async function fetchDetail(id) {
  if (_detailCache[id]) return _detailCache[id];
  try {
    const r = await fetch(`/api/requests/${id}/detail`);
    if (!r.ok) return null;
    const d = await r.json();
    _detailCache[id] = d;
    return d;
  } catch { return null; }
}

async function approve(id, btn) {
  btn.disabled = true;
  btn.textContent = 'Approving…';
  try {
    const r = await fetch(`/api/approve/${id}`, { method: 'POST' });
    const body = await r.json();
    if (!r.ok) {
      showToast(`<b>Approval failed</b> (${r.status}): ${JSON.stringify(body)}`, true);
    } else {
      let html = `<b>Approved!</b> PR merged for session <code>${id.slice(0, 8)}&hellip;</code><br>`;
      if (body.merge_result) {
        html += `Gitea: <code>${body.merge_result}</code><br>`;
      }
      if (body.session_state) {
        html += `Session state: ${badgeHtml(body.session_state)}<br>`;
      }
      if (body.expires_at) {
        html += `Expires: <code>${body.expires_at}</code><br>`;
      }
      if (body.session_id) {
        html += `<b>Session ID (for mcp-call):</b> <code class="mono">${body.session_id}</code><br>`;
      }
      showToast(html, false);
      // Invalidate detail cache so re-poll picks up new state
      delete _detailCache[id];
    }
  } catch (e) {
    showToast(`<b>Network error:</b> ${e}`, true);
  }
  await loadRequests();
}

async function loadRequests() {
  const sb = document.getElementById('status-bar');
  try {
    const r = await fetch('/api/requests');
    if (!r.ok) {
      sb.className = 'error';
      sb.textContent = `Error fetching requests: HTTP ${r.status}`;
      return;
    }
    const all = await r.json();
    sb.className = '';
    sb.innerHTML = `${all.length} session(s) total &nbsp; <span id="refresh-counter"></span>`;
    startCountdown();

    const pending = all.filter(s => s.state === 'pending' || s.state === 'approved');

    // --- Pending table with detail ---
    const pb = document.getElementById('pending-body');
    if (pending.length === 0) {
      pb.innerHTML = '<tr class="empty-row"><td colspan="9">No pending requests</td></tr>';
    } else {
      const rows = await Promise.all(pending.map(async s => {
        const d = await fetchDetail(s.id);
        const verbs = d ? (d.verbs || []).join(', ') : '…';
        const resources = d ? (d.resources || []).join(', ') : '…';
        const requester = d ? (d.requester_sub || '') : '';
        const ns = d ? (d.namespace || '') : '';
        const duration = d ? `${d.duration_minutes || '?'}m` : '…';
        const justification = d ? (d.justification || '') : '';
        const prUrl = s.pr_url || '';
        const prLink = prUrl
          ? `<a class="pill-pr" href="${prUrl}" target="_blank" rel="noopener">#PR</a>`
          : '&mdash;';
        const approveBtn = (s.state === 'pending' || s.state === 'approved')
          ? `<button class="approve" onclick="approve('${s.id}', this)">Approve</button>`
          : `<button class="approve" disabled>${s.state}</button>`;
        return `
          <tr>
            <td class="mono trunc" title="${s.id}">${s.id.slice(0, 8)}&hellip;</td>
            <td>${badgeHtml(s.state)}</td>
            <td class="trunc mono" title="${requester}">${trunc(requester, 30)}</td>
            <td class="mono">${ns}</td>
            <td class="mono">${trunc(verbs, 20)}<br><small style="color:#888">${trunc(resources, 20)}</small></td>
            <td class="mono">${duration}</td>
            <td class="trunc" title="${justification}">${trunc(justification, 50)}</td>
            <td>${prLink}</td>
            <td class="actions-col">${approveBtn}</td>
          </tr>`;
      }));
      pb.innerHTML = rows.join('');
    }

    // --- All requests table (summary) ---
    const ab = document.getElementById('all-body');
    if (all.length === 0) {
      ab.innerHTML = '<tr class="empty-row"><td colspan="4">No sessions yet</td></tr>';
    } else {
      ab.innerHTML = all.map(s => {
        const prUrl = s.pr_url || '';
        const prLink = prUrl
          ? `<a class="pill-pr" href="${prUrl}" target="_blank" rel="noopener">PR</a>`
          : '&mdash;';
        return `
          <tr>
            <td class="mono trunc" title="${s.id}">${s.id.slice(0, 8)}&hellip;</td>
            <td>${badgeHtml(s.state)}</td>
            <td>${prLink}</td>
            <td class="mono">${s.expires_at || '&mdash;'}</td>
          </tr>`;
      }).join('');
    }
  } catch (e) {
    sb.className = 'error';
    sb.textContent = `Network error: ${e}`;
  }
}

function startCountdown() {
  if (_countdownTimer) clearInterval(_countdownTimer);
  _countdown = POLL_INTERVAL / 1000;
  const el = document.getElementById('refresh-counter');
  if (!el) return;
  _countdownTimer = setInterval(() => {
    _countdown -= 1;
    if (el) el.textContent = `(refreshing in ${_countdown}s)`;
    if (_countdown <= 0) {
      clearInterval(_countdownTimer);
      _countdownTimer = null;
    }
  }, 1000);
}

// Initial load + polling loop
loadRequests();
setInterval(loadRequests, POLL_INTERVAL);
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """Serve the self-contained operator console page."""
    poll_ms = Config.poll_interval_seconds() * 1000
    html = _HTML.replace("__POLL_INTERVAL_MS__", str(poll_ms))
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# GET /api/requests — proxy to jit-approver
# ---------------------------------------------------------------------------


@app.get("/api/requests")
async def list_requests(state: str | None = None, sandbox: str | None = None) -> JSONResponse:
    """Proxy GET /requests to jit-approver.

    Passes through optional ?state= and ?sandbox= query params.
    Always fails closed: if jit-approver is unreachable, returns 502.
    """
    t0 = time.monotonic()
    jit_url = Config.jit_approver_url()
    params: dict[str, str] = {}
    if state:
        params["state"] = state
    if sandbox:
        params["sandbox"] = sandbox
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{jit_url}/requests",
                params=params,
                headers=_jit_headers(),
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.list_requests", actor="console", outcome="error", latency_ms=latency,
               tool_args_hash=_hash_args(params), error=str(exc))
        raise HTTPException(status_code=502, detail=f"jit-approver unreachable: {exc}") from exc

    latency = (time.monotonic() - t0) * 1000
    _audit("jit.list_requests", actor="console", outcome="allow" if resp.is_success else "error",
           latency_ms=latency, tool_args_hash=_hash_args(params))
    return JSONResponse(content=resp.json(), status_code=resp.status_code)


# ---------------------------------------------------------------------------
# GET /api/requests/{id}/detail — proxy to jit-approver
# ---------------------------------------------------------------------------


@app.get("/api/requests/{session_id}/detail")
async def get_detail(session_id: str) -> JSONResponse:
    """Proxy GET /requests/{id}/detail to jit-approver.

    Returns the full scope: requester_sub, namespace, verbs, resources,
    duration_minutes, justification, sandbox, policy_delta.
    """
    t0 = time.monotonic()
    jit_url = Config.jit_approver_url()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{jit_url}/requests/{session_id}/detail",
                headers=_jit_headers(),
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.get_detail", actor="console", outcome="error", latency_ms=latency,
               tool_args_hash=_hash_args({"session_id": session_id}), error=str(exc))
        raise HTTPException(status_code=502, detail=f"jit-approver unreachable: {exc}") from exc

    latency = (time.monotonic() - t0) * 1000
    _audit("jit.get_detail", actor="console", outcome="allow" if resp.is_success else "error",
           latency_ms=latency, tool_args_hash=_hash_args({"session_id": session_id}))
    return JSONResponse(content=resp.json(), status_code=resp.status_code)


# ---------------------------------------------------------------------------
# GET /api/requests/{id}/status — proxy to jit-approver (post-approval polling)
# ---------------------------------------------------------------------------


@app.get("/api/requests/{session_id}/status")
async def get_status(session_id: str) -> JSONResponse:
    """Proxy GET /requests/{id}/status to jit-approver.

    When state==issued this returns expires_at so the console can display it.
    Note: session_jwt and sa_token are deliberately NOT forwarded by the console
    (they arrive here but we strip them before sending to the browser — the browser
    does not need them and the console is unauthenticated in this PoC).
    """
    t0 = time.monotonic()
    jit_url = Config.jit_approver_url()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{jit_url}/requests/{session_id}/status",
                headers=_jit_headers(),
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.get_status", actor="console", outcome="error", latency_ms=latency,
               tool_args_hash=_hash_args({"session_id": session_id}), error=str(exc))
        raise HTTPException(status_code=502, detail=f"jit-approver unreachable: {exc}") from exc

    latency = (time.monotonic() - t0) * 1000
    outcome = "allow" if resp.is_success else "error"
    _audit("jit.get_status", actor="console", outcome=outcome, latency_ms=latency,
           tool_args_hash=_hash_args({"session_id": session_id}))

    if not resp.is_success:
        return JSONResponse(content=resp.json(), status_code=resp.status_code)

    data = resp.json()
    # Strip credentials — the console page is unauthenticated (PoC caveat); do
    # not forward session_jwt or sa_token to the browser.
    safe = {k: v for k, v in data.items() if k not in {"session_jwt", "sa_token", "sa_token_path"}}
    return JSONResponse(content=safe, status_code=200)


# ---------------------------------------------------------------------------
# POST /api/approve/{id} — merge the Gitea PR
# ---------------------------------------------------------------------------


@app.post("/api/approve/{session_id}")
async def approve(session_id: str) -> JSONResponse:
    """Approve a JIT session by merging its Gitea PR.

    Flow:
      1. Fetch the session list from jit-approver to get pr_url and pr_number.
         (Uses GET /requests — the detail endpoint also carries pr_url.)
      2. Extract the PR number from the pr_url stored in the session.
         jit-approver stores pr_number directly on the session dict (exposed via
         GET /requests/{id}/detail as pr_url; the PR number is parsed from the URL
         in the same way _extract_pr_number does it in api.py).
      3. Call Gitea PUT /repos/{owner}/{repo}/pulls/{n}/merge.
      4. Poll jit-approver GET /requests/{id}/status once to surface
         expires_at (state transitions to 'issued' via the Gitea webhook).

    Returns:
      {
        "session_id": str,
        "merge_result": str,       # "merged" on success
        "session_state": str,      # state after merge (may still be "pending" if webhook slow)
        "expires_at": str | null,
      }
    """
    t0 = time.monotonic()
    args_hash = _hash_args({"session_id": session_id})

    # Step 1: fetch session detail to get pr_url
    jit_url = Config.jit_approver_url()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            detail_resp = await client.get(
                f"{jit_url}/requests/{session_id}/detail",
                headers=_jit_headers(),
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor="console-operator", outcome="error",
               latency_ms=latency, tool_args_hash=args_hash, error=str(exc))
        raise HTTPException(status_code=502, detail=f"jit-approver unreachable: {exc}") from exc

    if not detail_resp.is_success:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor="console-operator", outcome="deny",
               latency_ms=latency, tool_args_hash=args_hash,
               error=f"detail returned {detail_resp.status_code}")
        raise HTTPException(
            status_code=detail_resp.status_code,
            detail=f"Session {session_id} not found in jit-approver",
        )

    detail = detail_resp.json()
    pr_url: str | None = detail.get("pr_url")
    state: str = detail.get("state", "unknown")

    if not pr_url:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor="console-operator", outcome="deny",
               latency_ms=latency, tool_args_hash=args_hash, error="no pr_url on session")
        raise HTTPException(
            status_code=422,
            detail=f"Session {session_id} has no PR URL — cannot approve.",
        )

    if state not in {"pending", "approved"}:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor="console-operator", outcome="deny",
               latency_ms=latency, tool_args_hash=args_hash,
               error=f"session not approvable (state={state})")
        raise HTTPException(
            status_code=409,
            detail=f"Session {session_id} is in state '{state}' and cannot be approved.",
        )

    # Step 2: parse PR number from URL (matches _extract_pr_number in api.py)
    try:
        pr_number = int(pr_url.rstrip("/").rsplit("/", 1)[-1])
    except (ValueError, IndexError) as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor="console-operator", outcome="error",
               latency_ms=latency, tool_args_hash=args_hash,
               error=f"cannot parse PR number from {pr_url!r}")
        raise HTTPException(
            status_code=422,
            detail=f"Cannot parse PR number from pr_url {pr_url!r}: {exc}",
        ) from exc

    owner = Config.gitea_owner()
    repo = Config.gitea_repo()
    gitea_url = Config.gitea_url().rstrip("/")

    # Step 3: merge the PR via Gitea API
    merge_url = f"{gitea_url}/api/v1/repos/{owner}/{repo}/pulls/{pr_number}/merge"
    logger.info(
        "approve.merging_pr",
        extra={"session_id": session_id, "pr_number": pr_number, "owner": owner, "repo": repo},
    )
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            merge_resp = await client.post(
                merge_url,
                headers=_gitea_headers(),
                json={
                    "Do": "merge",
                    "merge_message_field": f"Approve JIT grant for session {session_id}",
                },
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor="console-operator", outcome="error",
               latency_ms=latency, tool_args_hash=args_hash, error=str(exc))
        raise HTTPException(status_code=502, detail=f"Gitea unreachable: {exc}") from exc

    if not merge_resp.is_success:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor="console-operator", outcome="error",
               latency_ms=latency, tool_args_hash=args_hash,
               error=f"Gitea merge returned {merge_resp.status_code}: {merge_resp.text[:200]}")
        raise HTTPException(
            status_code=merge_resp.status_code,
            detail=f"Gitea merge failed: {merge_resp.text[:400]}",
        )

    logger.info("approve.merged", extra={"session_id": session_id, "pr_number": pr_number})

    # Step 4: quick status poll — Gitea fires the webhook asynchronously so the
    # session may still show 'pending' immediately. We return what we have and the
    # browser's polling loop picks up the transition to 'issued'.
    session_state: str = state
    expires_at: str | None = None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            status_resp = await client.get(
                f"{jit_url}/requests/{session_id}/status",
                headers=_jit_headers(),
            )
        if status_resp.is_success:
            status_data = status_resp.json()
            session_state = status_data.get("state", state)
            expires_at = status_data.get("expires_at")
    except Exception:  # noqa: BLE001 — best-effort post-merge poll
        pass

    latency = (time.monotonic() - t0) * 1000
    _audit("jit.approve", actor="console-operator", outcome="allow",
           latency_ms=latency, tool_args_hash=args_hash,
           pr_number=pr_number, session_state=session_state)

    return JSONResponse(
        content={
            "session_id": session_id,
            "pr_number": pr_number,
            "pr_url": pr_url,
            "merge_result": "merged",
            "session_state": session_state,
            "expires_at": expires_at,
        },
        status_code=200,
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "approval-console"}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}',
    )
    uvicorn.run(
        "approval_console.app:app",
        host="0.0.0.0",
        port=8090,
        log_config=None,
    )


if __name__ == "__main__":
    main()
