"""WebSocket endpoint for in-console webshell (C4).

GET /api/agents/{agent_id}/webshell — WebSocket; proxied PTY into the sandbox.

Security contract:
  1. actor is resolved from oauth2-proxy Keycloak headers on the HTTP upgrade request.
  2. actor must be the agent owner (or console-admin).
  3. agent must be in READY state.
  4. Pod name is resolved from the Agent record (server-side); never taken from client.
  5. bridge.open_bridge is called only after all checks pass.

The Kubernetes exec SA permission required (approval-console SA in ns openshell):
  verbs: [get, create]
  resources: [pods/exec]
This is a GATED cluster mutation (Phase C plan, G-C4a).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from approval_console.agents import store as agent_store
from approval_console.agents.models import AgentState
from approval_console.webshell import bridge as ws_bridge

logger = logging.getLogger("approval_console.webshell.routes")

router = APIRouter(tags=["webshell"])


# ---------------------------------------------------------------------------
# GET /api/agents/{agent_id}/webshell/ui — served webshell terminal PAGE
# ---------------------------------------------------------------------------
#
# This replaces the old window.open('')+document.write(CDN <script>) popup that
# was the root cause of the dead-input bug. It is a REAL same-origin HTML
# document with NORMAL <script src="/static/xterm.min.js"> tags (vendored, not
# CDN), so:
#   - the browser never blocks parser-blocking cross-site document.write scripts;
#   - load order is deterministic (xterm is defined before init runs);
#   - input is wired CORRECTLY via term.onData(cb) (a REGISTRATION call, not an
#     assignment — the assignment was why keystrokes never reached the socket).
#
# The {agent_id} is injected into the WebSocket URL the page opens; all RBAC is
# still enforced on the WebSocket upgrade (the page itself carries no secrets).

_WEBSHELL_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OpenShell Webshell</title>
<link rel="stylesheet" href="/static/xterm.min.css">
<style>
  html, body { margin: 0; height: 100%; background: #000; }
  #t { position: absolute; inset: 0; padding: 4px; }
  #banner { position: absolute; top: 0; left: 0; right: 0; z-index: 10;
            font-family: monospace; font-size: 12px; color: #ffb347;
            background: #1a1d24; padding: 4px 8px; display: none; }
</style>
<!-- Same-origin, NON-cross-site, parser-ordered <script> tags (vendored xterm). -->
<script src="/static/xterm.min.js"></script>
<script src="/static/addon-fit.min.js"></script>
</head>
<body>
<div id="banner"></div>
<div id="t"></div>
<script>
(function () {
  "use strict";
  var banner = document.getElementById('banner');
  function showBanner(msg) { banner.textContent = msg; banner.style.display = 'block'; }

  // Defensive: if the vendored xterm bundle somehow failed to load, fail LOUDLY
  // instead of silently throwing before input is wired.
  if (typeof Terminal === 'undefined') {
    document.body.innerHTML =
      '<pre style="color:#f55;font-family:monospace;padding:1rem">' +
      'Failed to load terminal assets (/static/xterm.min.js). ' +
      'Check the approval-console image bundled the static dir.</pre>';
    return;
  }

  var AGENT_ID = "__AGENT_ID__";
  var wsUrl = location.origin.replace(/^http/, 'ws') +
              '/api/agents/' + AGENT_ID + '/webshell';

  var term = new Terminal({ cursorBlink: true, convertEol: false });
  var fit = null;
  try { fit = new FitAddon.FitAddon(); term.loadAddon(fit); } catch (e) { /* optional */ }

  var el = document.getElementById('t');
  term.open(el);
  term.focus();

  var enc = new TextEncoder();
  var ws = new WebSocket(wsUrl);
  ws.binaryType = "arraybuffer";

  // Keystroke queue: buffer anything typed before the socket is OPEN, then flush.
  var outQueue = [];
  function flushQueue() {
    if (ws.readyState !== 1) return;
    while (outQueue.length) { ws.send(outQueue.shift()); }
  }

  // CRITICAL FIX: term.onData is a REGISTRATION METHOD, not an assignable
  // property. Calling it subscribes the callback to xterm's data emitter; the
  // previous code assigned an arrow to that property instead of calling it,
  // which registered ZERO listeners, so keystrokes were never sent over the
  // socket. We register the callback by CALLING term.onData exactly once here.
  term.onData(function (d) {
    var bytes = enc.encode(d);
    if (ws.readyState === 1) {
      ws.send(bytes);
    } else {
      outQueue.push(bytes);  // buffer until ws.onopen
    }
  });

  function sendResize() {
    if (ws.readyState !== 1) return;
    try { ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows })); }
    catch (e) { /* ignore */ }
  }
  function doFit() {
    if (fit) { try { fit.fit(); } catch (e) { /* ignore */ } }
    sendResize();
  }

  ws.onopen = function () { doFit(); flushQueue(); term.focus(); };
  ws.onmessage = function (e) { term.write(new Uint8Array(e.data)); };
  ws.onclose = function () { showBanner('-- session closed --'); };
  ws.onerror = function () { showBanner('-- websocket error --'); };

  // Keep keyboard focus on the hidden xterm helper textarea across interactions.
  el.addEventListener('mousedown', function () { term.focus(); });
  window.addEventListener('focus', function () { term.focus(); });
  window.addEventListener('resize', doFit);
})();
</script>
</body>
</html>
"""


def _actor_from_ws(ws: WebSocket) -> str:
    """Resolve Keycloak identity from WebSocket upgrade request headers."""
    for header in (
        "x-forwarded-preferred-username",
        "x-forwarded-email",
        "x-forwarded-user",
    ):
        value = ws.headers.get(header, "").strip()
        if value:
            return value
    return "anonymous"


def _is_admin_ws(ws: WebSocket) -> bool:
    groups = ws.headers.get("x-forwarded-groups", "")
    return "console-admin" in groups.split(",")


@router.get("/api/agents/{agent_id}/webshell/ui", response_class=HTMLResponse)
async def webshell_ui(agent_id: str) -> HTMLResponse:
    """Serve the same-origin webshell terminal page for ``agent_id``.

    The page references vendored xterm assets from /static (no CDN, no
    document.write) and opens the /api/agents/{id}/webshell WebSocket. RBAC is
    enforced on the WebSocket upgrade, not here — the page carries no secrets and
    cannot reach the PTY without passing the oauth2-proxy + owner/admin check.
    The agent_id is path-validated (alnum/dash/underscore) before injection to
    avoid breaking out of the JS string literal.
    """
    safe_id = "".join(ch for ch in agent_id if ch.isalnum() or ch in "-_")
    page = _WEBSHELL_PAGE.replace("__AGENT_ID__", safe_id)
    return HTMLResponse(content=page)


@router.websocket("/api/agents/{agent_id}/webshell")
async def webshell(agent_id: str, ws: WebSocket) -> None:
    """WebSocket PTY bridge into the agent's OpenShell sandbox.

    On connection:
      - Resolve actor from Keycloak headers.
      - Verify agent exists, is READY, and actor is owner or admin.
      - Resolve pod name from agent's sandbox_name (server-side).
      - Open the asyncio bridge.
    On any error: send a JSON error frame and close.
    """
    await ws.accept()

    actor = _actor_from_ws(ws)
    is_admin = _is_admin_ws(ws)

    agent = agent_store.get_agent(agent_id)
    if agent is None:
        await ws.send_json({"error": f"Agent {agent_id!r} not found"})
        await ws.close(code=1008)
        return

    if actor != agent.owner and not is_admin:
        await ws.send_json({"error": "Access denied"})
        await ws.close(code=1008)
        return

    if agent.state != AgentState.READY:
        await ws.send_json({"error": f"Agent is not READY (state={agent.state.value})"})
        await ws.close(code=1011)
        return

    if not agent.sandbox_name:
        await ws.send_json({"error": "Agent has no associated sandbox (still provisioning?)"})
        await ws.close(code=1011)
        return

    logger.info(
        "webshell.connect agent_id=%s actor=%s sandbox=%s",
        agent_id,
        actor,
        agent.sandbox_name,
    )

    try:
        await ws_bridge.open_bridge(
            ws=ws,
            pod_name=agent.sandbox_name,
            namespace=agent.namespace,
            container="agent",
        )
    except WebSocketDisconnect:
        logger.info("webshell.disconnect agent_id=%s actor=%s", agent_id, actor)
    except Exception as exc:  # noqa: BLE001
        logger.error("webshell.error agent_id=%s error=%s", agent_id, exc)
        try:
            await ws.send_json({"error": str(exc)})
            await ws.close(code=1011)
        except Exception:  # noqa: BLE001
            pass
