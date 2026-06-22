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

from approval_console.agents import store as agent_store
from approval_console.agents.models import AgentState
from approval_console.webshell import bridge as ws_bridge

logger = logging.getLogger("approval_console.webshell.routes")

router = APIRouter(tags=["webshell"])


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
