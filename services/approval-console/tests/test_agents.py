"""Unit tests for the persistent-agent store and routes (C1).

Uses pytest-asyncio (asyncio_mode=auto) with httpx.ASGITransport.
All cluster and Gitea calls are monkeypatched — no network, no cluster.
"""

from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("JIT_APPROVER_URL", "http://jit-approver-mock:8080")
os.environ.setdefault("GITEA_URL", "https://gitea-mock")
os.environ.setdefault("GITEA_TOKEN", "test-token-deadbeef")
os.environ.setdefault("GITEA_REPO", "anaeem/nvidia-ida")
os.environ.setdefault("POLL_INTERVAL_SECONDS", "5")
os.environ.setdefault("JIT_APPROVE_VIA_MINT", "true")
os.environ.setdefault("JIT_MINT_CONSOLE_TOKEN_OVERRIDE", "test-console-token")
# Do NOT set SANDBOX_LAUNCHER_URL so create_sandbox falls through to RuntimeError branch.

from httpx import AsyncClient, ASGITransport  # noqa: E402

# Mount the new routers into a test app instance.
from approval_console.app import app  # noqa: E402
from approval_console.agents.routes import router as agents_router  # noqa: E402
from approval_console.agents import store as agent_store  # noqa: E402
from approval_console.agents.models import Agent, AgentState  # noqa: E402

app.include_router(agents_router)

# Also mount skills and ui routes for completeness.
from approval_console.skills.routes import router as skills_router  # noqa: E402
from approval_console.ui.routes import router as ui_router  # noqa: E402

app.include_router(skills_router)
app.include_router(ui_router)


def _ac() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


def _keycloak_headers(username: str = "alice") -> dict[str, str]:
    return {"x-forwarded-preferred-username": username}


# ---------------------------------------------------------------------------
# Store unit tests (no HTTP)
# ---------------------------------------------------------------------------


def test_create_and_get_agent() -> None:
    store = agent_store
    a = Agent(
        agent_id="test-agent-001",
        display_name="test agent",
        owner="bob",
    )
    store.create_agent(a)
    fetched = store.get_agent("test-agent-001")
    assert fetched is not None
    assert fetched.owner == "bob"
    assert fetched.state == AgentState.PROVISIONING
    # cleanup
    store.delete_agent("test-agent-001")


def test_archive_agent() -> None:
    store = agent_store
    a = Agent(agent_id="test-agent-002", display_name="to archive", owner="carol")
    store.create_agent(a)
    store.archive_agent("test-agent-002", archived_at="2026-06-22T00:00:00+00:00")
    updated = store.get_agent("test-agent-002")
    assert updated is not None
    assert updated.state == AgentState.ARCHIVED
    assert updated.archived_at == "2026-06-22T00:00:00+00:00"
    store.delete_agent("test-agent-002")


def test_list_agents_by_owner() -> None:
    store = agent_store
    a1 = Agent(agent_id="test-list-001", display_name="a1", owner="dave")
    a2 = Agent(agent_id="test-list-002", display_name="a2", owner="eve")
    store.create_agent(a1)
    store.create_agent(a2)
    daves = store.list_agents(owner="dave")
    assert any(a.agent_id == "test-list-001" for a in daves)
    assert not any(a.agent_id == "test-list-002" for a in daves)
    store.delete_agent("test-list-001")
    store.delete_agent("test-list-002")


# ---------------------------------------------------------------------------
# HTTP route unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_agent_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """POST /api/agents returns 201 with agent_id.  No cluster/Gitea calls."""

    async def _fake_sandbox(agent_id: str, owner: str, skills: list) -> dict:
        return {"sandbox_name": f"sb-{agent_id[:8]}", "sandbox_id": "uuid-1234"}

    async def _fake_gitea_create(agent_id: str, owner_username: str):  # type: ignore[return]
        from approval_console.gitea.models import GiteaRepo
        return GiteaRepo(html_url=f"https://gitea-mock/agents/{agent_id}", full_name=f"agents/{agent_id}")

    monkeypatch.setattr("approval_console.agents.routes._create_sandbox", _fake_sandbox)

    import approval_console.gitea.client as gc
    monkeypatch.setattr(gc, "create_agent_repo", _fake_gitea_create)

    async with _ac() as client:
        r = await client.post(
            "/api/agents",
            json={"display_name": "happy-agent", "skills": ["pfsense-firewall"]},
            headers=_keycloak_headers("alice"),
        )
    assert r.status_code == 201, r.text
    data = r.json()
    assert "agent_id" in data
    assert data["owner"] == "alice"
    assert data["skills"] == ["pfsense-firewall"]
    # Cleanup
    agent_store.delete_agent(data["agent_id"])


@pytest.mark.asyncio
async def test_list_agents_returns_only_own(monkeypatch: pytest.MonkeyPatch) -> None:
    """GET /api/agents returns only agents owned by the authenticated user."""
    a = Agent(agent_id="route-list-001", display_name="mine", owner="frank")
    agent_store.create_agent(a)

    async with _ac() as client:
        r = await client.get("/api/agents", headers=_keycloak_headers("frank"))
    assert r.status_code == 200
    ids = [x["agent_id"] for x in r.json()]
    assert "route-list-001" in ids

    async with _ac() as client:
        r2 = await client.get("/api/agents", headers=_keycloak_headers("grace"))
    assert r2.status_code == 200
    ids2 = [x["agent_id"] for x in r2.json()]
    assert "route-list-001" not in ids2

    agent_store.delete_agent("route-list-001")


@pytest.mark.asyncio
async def test_archive_by_non_owner_returns_403() -> None:
    """POST /api/agents/{id}/archive by a non-owner returns 403."""
    a = Agent(agent_id="route-arch-001", display_name="owned", owner="henry")
    agent_store.create_agent(a)

    async with _ac() as client:
        r = await client.post(
            f"/api/agents/{a.agent_id}/archive",
            headers=_keycloak_headers("ivan"),  # not the owner
        )
    assert r.status_code == 403, r.text
    agent_store.delete_agent(a.agent_id)


@pytest.mark.asyncio
async def test_session_on_archived_agent_returns_409() -> None:
    """POST /api/agents/{id}/sessions on an ARCHIVED agent returns 409."""
    a = Agent(agent_id="route-sess-001", display_name="archived-agent", owner="judy")
    agent_store.create_agent(a)
    agent_store.archive_agent(a.agent_id, archived_at="2026-06-22T00:00:00+00:00")

    async with _ac() as client:
        r = await client.post(
            f"/api/agents/{a.agent_id}/sessions",
            json={"goal": "do something"},
            headers=_keycloak_headers("judy"),
        )
    assert r.status_code == 409, r.text
    agent_store.delete_agent(a.agent_id)


@pytest.mark.asyncio
async def test_hard_delete_requires_confirmed() -> None:
    """DELETE /api/agents/{id} without confirmed=true returns 400."""
    a = Agent(agent_id="route-del-001", display_name="to delete", owner="ken")
    agent_store.create_agent(a)

    async with _ac() as client:
        r = await client.delete(
            f"/api/agents/{a.agent_id}",
            headers=_keycloak_headers("ken"),
        )
    assert r.status_code == 400, r.text
    agent_store.delete_agent(a.agent_id)


@pytest.mark.asyncio
async def test_get_agent_404() -> None:
    """GET /api/agents/{id} for a non-existent agent returns 404."""
    async with _ac() as client:
        r = await client.get("/api/agents/nonexistent-agent-id", headers=_keycloak_headers("alice"))
    assert r.status_code == 404
