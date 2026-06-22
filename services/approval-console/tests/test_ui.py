"""Unit tests for the extended agent console UI (C5).

Verifies the /agents route renders HTML with expected sections, and that
/api/agents/{id}/jit-history annotates requests with can_approve correctly.
"""

from __future__ import annotations

import os

import pytest
import respx
from httpx import AsyncClient, ASGITransport, Response

os.environ.setdefault("JIT_APPROVER_URL", "http://jit-approver-mock:8080")
os.environ.setdefault("GITEA_URL", "https://gitea-mock")
os.environ.setdefault("GITEA_TOKEN", "test-token")
os.environ.setdefault("GITEA_REPO", "anaeem/nvidia-ida")
os.environ.setdefault("POLL_INTERVAL_SECONDS", "5")

from approval_console.app import app  # noqa: E402
from approval_console.agents import store as agent_store  # noqa: E402
from approval_console.agents.models import Agent, AgentState  # noqa: E402
from approval_console.agents.routes import router as agents_router  # noqa: E402
from approval_console.ui.routes import router as ui_router  # noqa: E402

app.include_router(agents_router)
app.include_router(ui_router)


def _ac() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


# ---------------------------------------------------------------------------
# GET /agents — extended console page
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agents_page_returns_html() -> None:
    """GET /agents returns 200 with HTML containing key UI sections."""
    async with _ac() as client:
        r = await client.get("/agents")
    assert r.status_code == 200
    body = r.text
    assert "OpenShell Agent Console" in body
    assert "skills-picker" in body
    assert "Launch Agent" in body
    assert "JIT Requests" in body
    # Revoke is stubbed as disabled.
    assert "Coming in Phase D" in body


# ---------------------------------------------------------------------------
# GET /api/agents/{id}/jit-history — self-approval guard annotation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_jit_history_self_approval_guard() -> None:
    """Requests where requester_sub matches the actor are annotated can_approve=False."""
    # Create a READY agent with a sandbox_id for the filter.
    a = Agent(
        agent_id="ui-jit-001",
        display_name="jit test",
        owner="alice",
        sandbox_id="sb-uuid-1234",
        state=AgentState.READY,
    )
    agent_store.create_agent(a)

    # Mock jit-approver /requests?sandbox=sb-uuid-1234 response.
    respx.get("http://jit-approver-mock:8080/requests").mock(
        return_value=Response(
            200,
            json=[
                {
                    "id": "req-aaa",
                    "state": "pending",
                    "requester_sub": "alice",  # same as actor → self-approval
                    "namespace": "openshell",
                    "expires_at": None,
                    "pr_url": None,
                },
                {
                    "id": "req-bbb",
                    "state": "pending",
                    "requester_sub": "bob",   # different → can approve
                    "namespace": "openshell",
                    "expires_at": None,
                    "pr_url": None,
                },
            ],
        )
    )

    async with _ac() as client:
        r = await client.get(
            f"/api/agents/{a.agent_id}/jit-history",
            headers={"x-forwarded-preferred-username": "alice"},
        )
    assert r.status_code == 200, r.text
    items = r.json()

    self_req = next(x for x in items if x["id"] == "req-aaa")
    other_req = next(x for x in items if x["id"] == "req-bbb")

    assert self_req["can_approve"] is False, "self-approval should be flagged False"
    assert other_req["can_approve"] is True, "different requester should be approvable"

    agent_store.delete_agent(a.agent_id)


@pytest.mark.asyncio
async def test_jit_history_unknown_agent() -> None:
    """GET /api/agents/{id}/jit-history for unknown agent returns 404."""
    async with _ac() as client:
        r = await client.get(
            "/api/agents/no-such-agent/jit-history",
            headers={"x-forwarded-preferred-username": "alice"},
        )
    assert r.status_code == 404
