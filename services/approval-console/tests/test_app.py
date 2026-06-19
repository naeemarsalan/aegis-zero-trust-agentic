"""Unit tests for approval-console handlers.

Uses pytest-asyncio (asyncio_mode=auto) with httpx.ASGITransport to drive
the FastAPI ASGI app directly in the same event loop, avoiding the sync
bridge issues of TestClient. respx.mock patches the httpx transport for all
async httpx clients spawned inside the handlers.
"""

from __future__ import annotations

import os

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
