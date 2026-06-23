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


def test_persistence_survives_reload(tmp_path) -> None:  # noqa: ANN001
    """create -> save to file -> reload fresh store -> record still present.

    Proves the PVC-backed JSON store survives a process restart.  We point the
    module's store path at a temp file, re-enable persistence (the default
    /data path is non-writable under test so saves are otherwise no-ops), then
    reload from disk and confirm the agent is still there with its state.
    """
    store = agent_store
    store_file = tmp_path / "agents.json"

    # Repoint persistence at a writable temp file for this test.
    orig_path = store._STORE_PATH
    orig_disabled = store._PERSIST_DISABLED
    store._STORE_PATH = str(store_file)
    store._PERSIST_DISABLED = False
    try:
        a = Agent(
            agent_id="persist-001",
            display_name="durable agent",
            owner="mallory",
            sandbox_name="agent-mallory-deadbe",
            sandbox_id="aaaabbbb-cccc-dddd-eeee-ffff00001111",
            state=AgentState.READY,
        )
        store.create_agent(a)

        # File must exist on disk now.
        assert store_file.exists()

        # Simulate a restart: wipe in-memory state, reload from the file.
        store.reload_from_disk()

        reloaded = store.get_agent("persist-001")
        assert reloaded is not None, "agent vanished across reload"
        assert reloaded.owner == "mallory"
        assert reloaded.state == AgentState.READY
        assert reloaded.sandbox_name == "agent-mallory-deadbe"
        assert reloaded.sandbox_id == "aaaabbbb-cccc-dddd-eeee-ffff00001111"
    finally:
        store.delete_agent("persist-001")
        store._STORE_PATH = orig_path
        store._PERSIST_DISABLED = orig_disabled
        # Reload the (non-writable default) store so module state matches other tests.
        store.reload_from_disk()


def test_corrupt_file_starts_empty(tmp_path) -> None:  # noqa: ANN001
    """A corrupt store file is tolerated: reload starts empty, never raises."""
    store = agent_store
    bad = tmp_path / "agents.json"
    bad.write_text("{not valid json at all")

    orig_path = store._STORE_PATH
    orig_disabled = store._PERSIST_DISABLED
    store._STORE_PATH = str(bad)
    store._PERSIST_DISABLED = False
    try:
        store.reload_from_disk()  # must not raise
        assert store.get_agent("anything") is None
    finally:
        store._STORE_PATH = orig_path
        store._PERSIST_DISABLED = orig_disabled
        store.reload_from_disk()


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
async def test_session_native_agent_uses_native_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    """An agent with a sandbox_name runs its session via the NATIVE exec path."""
    import approval_console.app as app_mod

    calls: dict[str, object] = {}

    def _fake_native(sid, goal, actor, sandbox_name, sandbox_id):  # noqa: ANN001
        calls["native"] = (sandbox_name, sandbox_id, goal, actor)

    def _fake_harness(sid, goal, actor="anonymous"):  # noqa: ANN001
        calls["harness"] = True

    monkeypatch.setattr(app_mod, "_launch_native_agent_thread", _fake_native)
    monkeypatch.setattr(app_mod, "_launch_agent_thread", _fake_harness)

    a = Agent(
        agent_id="route-native-001",
        display_name="native-agent",
        owner="nora",
        sandbox_name="agent-nora-abc123",
        sandbox_id="11112222-3333-4444-5555-666677778888",
        state=AgentState.READY,
    )
    agent_store.create_agent(a)
    try:
        async with _ac() as client:
            r = await client.post(
                f"/api/agents/{a.agent_id}/sessions",
                json={"goal": "list firewall rules"},
                headers=_keycloak_headers("nora"),
            )
        assert r.status_code == 202, r.text
        assert "native" in calls and "harness" not in calls
        assert calls["native"][0] == "agent-nora-abc123"
        assert calls["native"][1] == "11112222-3333-4444-5555-666677778888"
    finally:
        agent_store.delete_agent(a.agent_id)


@pytest.mark.asyncio
async def test_session_legacy_agent_uses_harness_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    """An agent WITHOUT a sandbox_name falls back to the legacy harness exec."""
    import approval_console.app as app_mod

    calls: dict[str, object] = {}
    monkeypatch.setattr(
        app_mod,
        "_launch_native_agent_thread",
        lambda *a, **k: calls.setdefault("native", True),
    )
    monkeypatch.setattr(
        app_mod,
        "_launch_agent_thread",
        lambda *a, **k: calls.setdefault("harness", True),
    )

    a = Agent(
        agent_id="route-legacy-001",
        display_name="legacy-agent",
        owner="leo",
        sandbox_name="",  # no native sandbox
        state=AgentState.READY,
    )
    agent_store.create_agent(a)
    try:
        async with _ac() as client:
            r = await client.post(
                f"/api/agents/{a.agent_id}/sessions",
                json={"goal": "do something"},
                headers=_keycloak_headers("leo"),
            )
        assert r.status_code == 202, r.text
        assert "harness" in calls and "native" not in calls
    finally:
        agent_store.delete_agent(a.agent_id)


def test_native_brain_env_recipe(monkeypatch: pytest.MonkeyPatch) -> None:
    """_native_brain_env carries the ext-proc recipe + forwards inference creds."""
    import approval_console.app as app_mod

    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://litellm:4000")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("AGENT_MODEL", "anthropic/claude-sonnet-4")

    # bare-hex session id must be converted to a hyphenated UUID for the claude CLI
    env = app_mod._native_brain_env("list rules", "arsalan", "28d80d19e99d46ff9f64a77b549a2192")

    assert env["AGENT_GOAL"] == "list rules"
    assert env["AGENT_USER"] == "arsalan"
    assert env["AGENT_SESSION_ID"] == "28d80d19-e99d-46ff-9f64-a77b549a2192"
    # ext-proc real-pfSense recipe (mirrors launcher _brain_env)
    assert env["MCP_SEND_SVID"] == "true"
    assert env["JIT_TARGET_NAMESPACE"] == "agentic-mcp"
    assert env["SVID_REQUIRE_PATH_SUBSTR"] == "/sandbox/"
    assert env["SVID_JWT_PATH"] == "/tmp/svid-out/mcp-gateway-svid.jwt"
    # inference creds forwarded; both names populated from whichever is set
    assert env["ANTHROPIC_BASE_URL"] == "http://litellm:4000"
    assert env["ANTHROPIC_API_KEY"] == "sk-secret"
    assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-secret"
    assert env["AGENT_MODEL"] == "anthropic/claude-sonnet-4"


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
