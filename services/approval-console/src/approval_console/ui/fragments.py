"""HTML fragment generators for the extended agent console (C5).

All fragments are pure-Python string functions; no JS build required.
Fragment functions return HTML strings safe for insertion into the main page template.

Self-approval guard: fragments include inline JS that checks whoami against requester_sub
from the JIT detail response. This is UX only — the server enforces SoD via jit-approver M5.
"""

from __future__ import annotations


def agent_card_html(agent: dict) -> str:
    """Render a single agent card for the agent list."""
    state = agent.get("state", "UNKNOWN")
    badge_class = {
        "READY": "badge-approved",
        "PROVISIONING": "badge-pending",
        "ARCHIVED": "badge-expired",
        "ERROR": "badge-denied",
    }.get(state, "badge-pending")
    skills = ", ".join(agent.get("skills") or []) or "&mdash;"
    repo = agent.get("gitea_repo", "")
    repo_link = f'<a href="{repo}" target="_blank" rel="noopener">repo</a>' if repo else "&mdash;"
    agent_id = agent.get("agent_id", "")
    return f"""
<div class="agent-card" data-agent-id="{agent_id}">
  <div class="agent-card-header">
    <span class="agent-name mono">{agent.get('display_name', agent_id)}</span>
    <span class="badge {badge_class}">{state}</span>
  </div>
  <div class="agent-card-meta">
    <span class="key">owner:</span> <span class="val mono">{agent.get('owner', '')}</span>
    &nbsp;|&nbsp;
    <span class="key">skills:</span> <span class="val">{skills}</span>
    &nbsp;|&nbsp;
    <span class="key">repo:</span> <span class="val">{repo_link}</span>
    &nbsp;|&nbsp;
    <span class="key">created:</span> <span class="val mono">{agent.get('created_at', '')[:19]}</span>
  </div>
  <div class="agent-card-actions">
    <button onclick="openWebshell('{agent_id}')" {"disabled" if state != "READY" else ""}>
      Webshell
    </button>
    <button onclick="newSession('{agent_id}')" {"disabled" if state != "READY" else ""}>
      New Session
    </button>
    <button onclick="archiveAgent('{agent_id}')" {"disabled" if state == "ARCHIVED" else ""}>
      Archive
    </button>
  </div>
</div>"""


def jit_history_row_html(request: dict, can_approve: bool) -> str:
    """Render a single row in the JIT history table."""
    state = request.get("state", "")
    badge_class = {
        "pending": "badge-pending",
        "approved": "badge-approved",
        "issued": "badge-issued",
        "expired": "badge-expired",
        "denied": "badge-denied",
    }.get(state, "badge-pending")
    req_id = request.get("id", "")
    approve_attrs = "" if can_approve else "disabled title='Cannot approve your own request'"
    return f"""
<tr>
  <td class="mono trunc" title="{req_id}">{req_id[:8]}&hellip;</td>
  <td><span class="badge {badge_class}">{state}</span></td>
  <td class="mono">{request.get('requester_sub', '')[:30]}</td>
  <td class="mono">{request.get('namespace', '')}</td>
  <td class="mono">{request.get('expires_at', '') or '&mdash;'}</td>
  <td>
    <button class="approve" onclick="approve('{req_id}', this)" {approve_attrs}>
      {"Approve" if state == "pending" else state}
    </button>
  </td>
</tr>"""


def token_receipt_panel_html(session_id: str, expires_at: str, session_state: str) -> str:
    """Render the persistent token receipt panel shown after approval."""
    return f"""
<div class="token-receipt" id="receipt-{session_id[:8]}">
  <div class="section-header">Token Receipt</div>
  <div class="session-detail">
    <div><span class="key">Session ID:</span>
      <code class="mono val">{session_id}</code></div>
    <div><span class="key">State:</span>
      <span class="badge badge-issued">{session_state}</span></div>
    <div><span class="key">Expires:</span>
      <code class="mono val">{expires_at or 'unknown'}</code></div>
    <div class="key" style="margin-top:0.5rem;">Use in mcp-call:</div>
    <div class="session-jwt-box">
      mcp-call &lt;tool&gt; '&lt;args&gt;' --session-id {session_id}
    </div>
  </div>
</div>"""
