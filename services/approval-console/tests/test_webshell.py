"""Unit tests for the webshell routes and bridge (C4).

Uses FastAPI's TestClient WebSocket support.  The oc-exec subprocess and
open_bridge are monkeypatched so no cluster access is needed.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("JIT_APPROVER_URL", "http://jit-approver-mock:8080")
os.environ.setdefault("GITEA_URL", "https://gitea-mock")
os.environ.setdefault("GITEA_TOKEN", "test-token")
os.environ.setdefault("GITEA_REPO", "anaeem/nvidia-ida")

from fastapi.testclient import TestClient  # noqa: E402
from approval_console.app import app  # noqa: E402
from approval_console.agents import store as agent_store  # noqa: E402
from approval_console.agents.models import Agent, AgentState  # noqa: E402
from approval_console.webshell.routes import router as ws_router  # noqa: E402

app.include_router(ws_router)


def _make_ready_agent(agent_id: str, owner: str) -> Agent:
    a = Agent(
        agent_id=agent_id,
        display_name="test",
        owner=owner,
        sandbox_name=f"sb-{agent_id[:8]}",
        namespace="openshell",
        state=AgentState.READY,
    )
    agent_store.create_agent(a)
    return a


def _make_archived_agent(agent_id: str, owner: str) -> Agent:
    a = Agent(
        agent_id=agent_id,
        display_name="archived",
        owner=owner,
        sandbox_name="",
        namespace="openshell",
        state=AgentState.ARCHIVED,
    )
    agent_store.create_agent(a)
    return a


# ---------------------------------------------------------------------------
# Happy path — owner connects, bridge is opened (bridge monkeypatched)
# ---------------------------------------------------------------------------


def test_webshell_owner_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    """WebSocket connection by the owner calls open_bridge."""
    opened: list[dict] = []

    async def _fake_bridge(ws, pod_name, namespace, container="agent"):
        opened.append({"pod": pod_name, "ns": namespace})
        await ws.send_bytes(b"hello from fake PTY\r\n")
        # Receive one byte then close.
        try:
            await ws.receive_bytes()
        except Exception:
            pass

    import approval_console.webshell.bridge as bridge_mod
    monkeypatch.setattr(bridge_mod, "open_bridge", _fake_bridge)

    agent = _make_ready_agent("ws-test-001", "alice")
    client = TestClient(app)
    with client.websocket_connect(
        f"/api/agents/{agent.agent_id}/webshell",
        headers={"x-forwarded-preferred-username": "alice"},
    ) as ws:
        data = ws.receive_bytes()
        assert b"hello" in data

    assert opened, "open_bridge was never called"
    assert opened[0]["pod"] == agent.sandbox_name
    agent_store.delete_agent(agent.agent_id)


# ---------------------------------------------------------------------------
# Deny path — non-owner is rejected
# ---------------------------------------------------------------------------


def test_webshell_non_owner_rejected() -> None:
    """WebSocket connection by a non-owner receives an error frame and is closed."""
    agent = _make_ready_agent("ws-test-002", "bob")
    client = TestClient(app)
    with client.websocket_connect(
        f"/api/agents/{agent.agent_id}/webshell",
        headers={"x-forwarded-preferred-username": "mallory"},
    ) as ws:
        msg = ws.receive_json()
        assert "error" in msg
        assert "denied" in msg["error"].lower() or "Access" in msg["error"]

    agent_store.delete_agent(agent.agent_id)


# ---------------------------------------------------------------------------
# Deny path — ARCHIVED agent is rejected
# ---------------------------------------------------------------------------


def test_webshell_archived_agent_rejected() -> None:
    """WebSocket connection to an ARCHIVED agent returns an error."""
    agent = _make_archived_agent("ws-test-003", "carol")
    client = TestClient(app)
    with client.websocket_connect(
        f"/api/agents/{agent.agent_id}/webshell",
        headers={"x-forwarded-preferred-username": "carol"},
    ) as ws:
        msg = ws.receive_json()
        assert "error" in msg

    agent_store.delete_agent(agent.agent_id)


# ---------------------------------------------------------------------------
# 404 path — unknown agent
# ---------------------------------------------------------------------------


def test_webshell_unknown_agent() -> None:
    """WebSocket connection to a non-existent agent receives an error frame."""
    client = TestClient(app)
    with client.websocket_connect(
        "/api/agents/no-such-agent/webshell",
        headers={"x-forwarded-preferred-username": "alice"},
    ) as ws:
        msg = ws.receive_json()
        assert "error" in msg
        assert "not found" in msg["error"].lower()
