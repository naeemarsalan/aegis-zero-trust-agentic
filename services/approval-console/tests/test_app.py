"""Unit tests for approval-console handlers.

Uses pytest-asyncio (asyncio_mode=auto) with httpx.ASGITransport to drive
the FastAPI ASGI app directly in the same event loop, avoiding the sync
bridge issues of TestClient. respx.mock patches the httpx transport for all
async httpx clients spawned inside the handlers.
"""

from __future__ import annotations

import json
import os
import time

import httpx
import pytest
import respx
from httpx import AsyncClient, ASGITransport, Response

# ---------------------------------------------------------------------------
# Env setup before app import so Config.* reads correct values
# ---------------------------------------------------------------------------

os.environ.setdefault("JIT_APPROVER_URL", "http://jit-approver-mock:8080")
os.environ.setdefault("GITEA_URL", "https://gitea-mock")
os.environ.setdefault("GITEA_TOKEN", "test-token-deadbeef")
os.environ.setdefault("GITEA_REPO", "anaeem/nvidia-ida")
os.environ.setdefault("POLL_INTERVAL_SECONDS", "5")

from approval_console import app as _app_module  # noqa: E402
from approval_console.app import app  # noqa: E402

JIT_URL = "http://jit-approver-mock:8080"
GITEA_URL = "https://gitea-mock"
SESSION_ID = "aaaabbbb-1111-2222-3333-444455556666"
PR_URL = f"{GITEA_URL}/anaeem/nvidia-ida/pulls/42"

_PENDING_LIST_RESPONSE = [
    {
        "id": SESSION_ID,
        "state": "pending",
        "pr_url": PR_URL,
        "expires_at": None,
    }
]

_DETAIL_RESPONSE = {
    "id": SESSION_ID,
    "state": "pending",
    "expires_at": None,
    "pr_url": PR_URL,
    "requester_sub": "alice@example.com",
    "namespace": "agent-sandbox",
    "verbs": ["get", "list"],
    "resources": ["pods"],
    "duration_minutes": 15,
    "justification": "debugging agent crash loop",
    "sandbox": None,
    "policy_delta": [],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ac() -> AsyncClient:
    """Return an AsyncClient wired to the ASGI app (no real TCP)."""
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    )


# ---------------------------------------------------------------------------
# GET / — HTML console
# ---------------------------------------------------------------------------


async def test_index_returns_html():
    async with _ac() as c:
        resp = await c.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "function approve(" in resp.text
    assert "5000" in resp.text  # POLL_INTERVAL_SECONDS=5 -> 5000 ms


# ---------------------------------------------------------------------------
# GET /api/requests — proxy
# ---------------------------------------------------------------------------


async def test_list_requests_happy_path():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests").mock(
            return_value=Response(200, json=_PENDING_LIST_RESPONSE)
        )
        async with _ac() as c:
            resp = await c.get("/api/requests")

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert data[0]["id"] == SESSION_ID
    assert data[0]["state"] == "pending"


async def test_list_requests_state_filter_forwarded():
    with respx.mock(assert_all_mocked=True) as m:
        route = m.get(f"{JIT_URL}/requests").mock(return_value=Response(200, json=[]))
        async with _ac() as c:
            resp = await c.get("/api/requests?state=pending")
        assert resp.status_code == 200
        assert "state=pending" in str(route.calls[0].request.url)


async def test_list_requests_jit_unreachable_502():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests").mock(side_effect=httpx.ConnectError("refused"))
        async with _ac() as c:
            resp = await c.get("/api/requests")
    assert resp.status_code == 502
    assert "unreachable" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# GET /api/requests/{id}/detail — proxy
# ---------------------------------------------------------------------------


async def test_get_detail_happy_path():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/detail").mock(
            return_value=Response(200, json=_DETAIL_RESPONSE)
        )
        async with _ac() as c:
            resp = await c.get(f"/api/requests/{SESSION_ID}/detail")

    assert resp.status_code == 200
    data = resp.json()
    assert data["requester_sub"] == "alice@example.com"
    assert data["verbs"] == ["get", "list"]


async def test_get_detail_not_found():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/nonexistent/detail").mock(
            return_value=Response(404, json={"detail": "Session nonexistent not found"})
        )
        async with _ac() as c:
            resp = await c.get("/api/requests/nonexistent/detail")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/requests/{id}/status — credential stripping
# ---------------------------------------------------------------------------


async def test_get_status_strips_credentials():
    """session_jwt and sa_token MUST NOT appear in the browser response."""
    jit_status = {
        "id": SESSION_ID,
        "state": "issued",
        "pr_url": PR_URL,
        "expires_at": "2026-06-18T12:00:00Z",
        "session_jwt": "eyJhbGciOiJSUzI1NiJ9.SENSITIVE.payload",
        "sa_token": "k8s-sa-token-SENSITIVE",
        "sa_token_path": "secret/data/jit/abc",
        "tool_scope": ["firewall_write"],
    }
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/status").mock(
            return_value=Response(200, json=jit_status)
        )
        async with _ac() as c:
            resp = await c.get(f"/api/requests/{SESSION_ID}/status")

    assert resp.status_code == 200
    data = resp.json()
    assert "session_jwt" not in data, "session_jwt must be stripped from browser response"
    assert "sa_token" not in data, "sa_token must be stripped from browser response"
    assert "sa_token_path" not in data, "sa_token_path must be stripped"
    assert data["state"] == "issued"
    assert data["expires_at"] == "2026-06-18T12:00:00Z"
    assert data["tool_scope"] == ["firewall_write"]


async def test_get_status_jit_unreachable_502():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/status").mock(
            side_effect=httpx.ConnectError("refused")
        )
        async with _ac() as c:
            resp = await c.get(f"/api/requests/{SESSION_ID}/status")
    assert resp.status_code == 502


# ---------------------------------------------------------------------------
# POST /api/approve/{id} — happy path
# ---------------------------------------------------------------------------


async def test_approve_happy_path():
    """Full flow: detail fetch -> Gitea merge -> status poll."""
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/detail").mock(
            return_value=Response(200, json=_DETAIL_RESPONSE)
        )
        m.post(
            f"{GITEA_URL}/api/v1/repos/anaeem/nvidia-ida/pulls/42/merge"
        ).mock(return_value=Response(200, json={}))
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/status").mock(
            return_value=Response(
                200,
                json={
                    "id": SESSION_ID,
                    "state": "issued",
                    "pr_url": PR_URL,
                    "expires_at": "2026-06-18T12:30:00Z",
                },
            )
        )
        async with _ac() as c:
            resp = await c.post(f"/api/approve/{SESSION_ID}")

    assert resp.status_code == 200
    data = resp.json()
    assert data["merge_result"] == "merged"
    assert data["pr_number"] == 42
    assert data["session_state"] == "issued"
    assert data["expires_at"] == "2026-06-18T12:30:00Z"
    assert data["session_id"] == SESSION_ID


# ---------------------------------------------------------------------------
# POST /api/approve/{id} — deny / error paths
# ---------------------------------------------------------------------------


async def test_approve_session_not_found_404():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/missing-id/detail").mock(
            return_value=Response(404, json={"detail": "not found"})
        )
        async with _ac() as c:
            resp = await c.post("/api/approve/missing-id")
    assert resp.status_code == 404


async def test_approve_session_already_issued_409():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/detail").mock(
            return_value=Response(200, json={**_DETAIL_RESPONSE, "state": "issued"})
        )
        async with _ac() as c:
            resp = await c.post(f"/api/approve/{SESSION_ID}")
    assert resp.status_code == 409
    assert "issued" in resp.json()["detail"]


async def test_approve_session_expired_409():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/detail").mock(
            return_value=Response(200, json={**_DETAIL_RESPONSE, "state": "expired"})
        )
        async with _ac() as c:
            resp = await c.post(f"/api/approve/{SESSION_ID}")
    assert resp.status_code == 409


async def test_approve_no_pr_url_422():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/detail").mock(
            return_value=Response(200, json={**_DETAIL_RESPONSE, "pr_url": None})
        )
        async with _ac() as c:
            resp = await c.post(f"/api/approve/{SESSION_ID}")
    assert resp.status_code == 422


async def test_approve_gitea_merge_failure_propagates():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/detail").mock(
            return_value=Response(200, json=_DETAIL_RESPONSE)
        )
        m.post(
            f"{GITEA_URL}/api/v1/repos/anaeem/nvidia-ida/pulls/42/merge"
        ).mock(return_value=Response(405, text="PR already merged"))
        async with _ac() as c:
            resp = await c.post(f"/api/approve/{SESSION_ID}")
    assert resp.status_code == 405


async def test_approve_gitea_unreachable_502():
    with respx.mock(assert_all_mocked=True) as m:
        m.get(f"{JIT_URL}/requests/{SESSION_ID}/detail").mock(
            return_value=Response(200, json=_DETAIL_RESPONSE)
        )
        m.post(
            f"{GITEA_URL}/api/v1/repos/anaeem/nvidia-ida/pulls/42/merge"
        ).mock(side_effect=httpx.ConnectError("refused"))
        async with _ac() as c:
            resp = await c.post(f"/api/approve/{SESSION_ID}")
    assert resp.status_code == 502
    assert "gitea" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# GET /healthz
# ---------------------------------------------------------------------------


async def test_healthz():
    async with _ac() as c:
        resp = await c.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "approval-console"}


# ---------------------------------------------------------------------------
# GET / — HTML console: troubleshoot panel injected
# ---------------------------------------------------------------------------


async def test_index_contains_troubleshoot_panel():
    async with _ac() as c:
        resp = await c.get("/")
    assert resp.status_code == 200
    assert "Troubleshoot OpenShift" in resp.text
    assert "startSession()" in resp.text
    assert "id=&quot;" not in resp.text  # no double-escape artefacts
    assert "__DEFAULT_GOAL__" not in resp.text  # placeholder must be replaced


# ---------------------------------------------------------------------------
# POST /api/sessions — happy path (monkeypatch _do_k8s_exec)
# ---------------------------------------------------------------------------


def _make_fake_exec(lines: list[str], delay: float = 0.0):
    """Return a _do_k8s_exec replacement that injects synthetic lines."""

    def _fake(sid: str, goal: str) -> None:  # noqa: ANN001
        if delay:
            time.sleep(delay)
        from approval_console.app import _append_line  # local import avoids circular

        for ln in lines:
            _append_line(sid, ln)

    return _fake


async def test_create_session_returns_session_id(monkeypatch):
    """POST /api/sessions must return a 202 with session_id; no real k8s call."""
    fake_lines = [
        json.dumps({"type": "system", "text": "agent starting"}),
        json.dumps({"type": "result", "status": "ok", "summary": "done"}),
    ]
    monkeypatch.setattr(_app_module, "_do_k8s_exec", _make_fake_exec(fake_lines))

    async with _ac() as c:
        resp = await c.post("/api/sessions", json={"goal": "test goal"})

    assert resp.status_code == 202
    data = resp.json()
    assert "session_id" in data
    assert len(data["session_id"]) == 32  # uuid4 hex


async def test_create_session_uses_default_goal_when_goal_omitted(monkeypatch):
    """POST /api/sessions with no body should use Config.default_goal()."""
    captured: list[str] = []

    def _capture(sid: str, goal: str) -> None:  # noqa: ANN001
        captured.append(goal)

    monkeypatch.setattr(_app_module, "_do_k8s_exec", _capture)

    async with _ac() as c:
        resp = await c.post("/api/sessions", json={})

    assert resp.status_code == 202
    from approval_console.config import Config

    assert captured[0] == Config.default_goal()


# ---------------------------------------------------------------------------
# GET /api/sessions/{sid}/stream — SSE lines then done event
# ---------------------------------------------------------------------------


async def test_stream_session_yields_lines_then_done(monkeypatch):
    """The SSE generator must yield all lines then the terminal done event."""
    fake_lines = [
        json.dumps({"type": "assistant", "text": "hello"}),
        json.dumps({"type": "result", "status": "ok", "summary": "all good"}),
    ]
    monkeypatch.setattr(_app_module, "_do_k8s_exec", _make_fake_exec(fake_lines))

    # Create a session; let the thread run (no delay, so it finishes nearly immediately)
    async with _ac() as c:
        post_resp = await c.post("/api/sessions", json={"goal": "test"})
    assert post_resp.status_code == 202
    sid = post_resp.json()["session_id"]

    # Give the background thread a moment to finish populating lines
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        with _app_module._SESSIONS_LOCK:
            done = _app_module._SESSIONS[sid]["done"]
        if done:
            break
        time.sleep(0.05)

    # Now consume the stream (session is already done — generator should drain and exit)
    collected_data: list[str] = []
    got_done = False

    async with _ac() as c:
        async with c.stream("GET", f"/api/sessions/{sid}/stream") as stream_resp:
            assert stream_resp.status_code == 200
            assert "text/event-stream" in stream_resp.headers["content-type"]
            async for line in stream_resp.aiter_lines():
                if line == "event: done":
                    got_done = True
                elif got_done and line == "data: {}":
                    break  # terminal SSE payload; do not count as a transcript line
                elif line.startswith("data: "):
                    collected_data.append(line[len("data: "):])

    assert len(collected_data) == 2
    assert json.loads(collected_data[0])["type"] == "assistant"
    assert json.loads(collected_data[1])["type"] == "result"
    assert got_done, "expected 'event: done' in SSE stream"


async def test_stream_session_not_found_returns_404():
    async with _ac() as c:
        resp = await c.get("/api/sessions/doesnotexist/stream")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# GET /api/sessions — list
# ---------------------------------------------------------------------------


async def test_list_sessions_reflects_created_sessions(monkeypatch):
    """GET /api/sessions must list sessions created via POST."""
    monkeypatch.setattr(_app_module, "_do_k8s_exec", _make_fake_exec([]))

    async with _ac() as c:
        r1 = await c.post("/api/sessions", json={"goal": "goal-alpha"})
        r2 = await c.post("/api/sessions", json={"goal": "goal-beta"})

    sid1 = r1.json()["session_id"]
    sid2 = r2.json()["session_id"]

    async with _ac() as c:
        list_resp = await c.get("/api/sessions")

    assert list_resp.status_code == 200
    items = list_resp.json()
    assert isinstance(items, list)
    sids = {item["session_id"] for item in items}
    assert sid1 in sids
    assert sid2 in sids
    # Verify each item has the required fields
    for item in items:
        assert "session_id" in item
        assert "done" in item
        assert "lines" in item
        assert "goal" in item


# ---------------------------------------------------------------------------
# Error path: _do_k8s_exec raises — session still gets error line + done
# ---------------------------------------------------------------------------


async def test_create_session_exec_error_marks_done(monkeypatch):
    """If _do_k8s_exec raises, the session must be marked done with an error line."""

    def _boom(sid: str, goal: str) -> None:  # noqa: ANN001
        raise RuntimeError("no pod found")

    monkeypatch.setattr(_app_module, "_do_k8s_exec", _boom)

    async with _ac() as c:
        resp = await c.post("/api/sessions", json={"goal": "crash test"})

    assert resp.status_code == 202
    sid = resp.json()["session_id"]

    # Wait for thread to finish
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        with _app_module._SESSIONS_LOCK:
            done = _app_module._SESSIONS[sid]["done"]
        if done:
            break
        time.sleep(0.05)

    with _app_module._SESSIONS_LOCK:
        session = _app_module._SESSIONS[sid]

    assert session["done"] is True
    # Must have at least one error line
    assert len(session["lines"]) >= 1
    err_obj = json.loads(session["lines"][0])
    assert err_obj["type"] == "error"
    assert "no pod found" in err_obj["msg"]
