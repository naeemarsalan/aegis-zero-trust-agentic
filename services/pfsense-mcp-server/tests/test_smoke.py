"""Integration smoke test for the upstream pfsense-mcp-server.

Requires a running instance of the server.  Configure via env vars:
  MCP_SMOKE_URL      Base URL, default http://localhost:3000
  MCP_SMOKE_API_KEY  Bearer token, default "test"

Run:
  MCP_SMOKE_URL=http://localhost:3000 \\
  MCP_SMOKE_API_KEY=your-token \\
  pytest services/pfsense-mcp-server/tests/test_smoke.py -v

These tests are skipped automatically when the server is not reachable, so
they are safe to include in CI (they are not expected to pass in unit-test runs
without a live server).
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error

import pytest

# ── config ────────────────────────────────────────────────────────────────────

BASE_URL = os.environ.get("MCP_SMOKE_URL", "http://localhost:3000").rstrip("/")
API_KEY = os.environ.get("MCP_SMOKE_API_KEY", "test")
TIMEOUT = int(os.environ.get("MCP_SMOKE_TIMEOUT", "5"))


# ── helpers ───────────────────────────────────────────────────────────────────

def _get(path: str) -> tuple[int, bytes]:
    """HTTP GET; returns (status_code, body_bytes)."""
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {API_KEY}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _post_json(path: str, payload: dict) -> tuple[int, dict]:
    """HTTP POST JSON; returns (status_code, parsed_json_body)."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"_raw": body.decode(errors="replace")}


def _server_reachable() -> bool:
    """Return True if the server is listening at BASE_URL."""
    try:
        _get("/mcp")
        return True
    except (urllib.error.URLError, OSError):
        return False


skip_if_no_server = pytest.mark.skipif(
    not _server_reachable(),
    reason=f"pfsense-mcp server not reachable at {BASE_URL} (set MCP_SMOKE_URL)",
)


# ── smoke tests ───────────────────────────────────────────────────────────────

@skip_if_no_server
def test_health_probe():
    """GET /mcp should return 200 or 405 (endpoint alive).

    The upstream server's MCP endpoint responds to GET with either 200 (health
    check page) or 405 (Method Not Allowed, meaning the endpoint exists but only
    accepts POST).  Either is evidence the server is up.
    """
    status, _ = _get("/mcp")
    assert status in (200, 405), (
        f"Expected 200 or 405 from GET /mcp, got {status}. "
        "Server may not be running or MCP_SMOKE_URL is wrong."
    )


@skip_if_no_server
def test_mcp_initialize_handshake():
    """MCP initialize call should return a valid serverInfo response.

    Sends the standard MCP initialize JSON-RPC request and checks that
    the server responds with 'serverInfo.name' — confirming a real MCP
    server is answering, not a proxy or stub.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-05",
            "capabilities": {},
            "clientInfo": {"name": "smoke-test", "version": "0.0.1"},
        },
    }
    status, body = _post_json("/mcp", payload)
    assert status == 200, f"Expected 200 from MCP initialize, got {status}: {body}"
    assert "result" in body, f"MCP initialize response missing 'result': {body}"
    result = body["result"]
    assert "serverInfo" in result, f"MCP initialize result missing 'serverInfo': {result}"
    server_name = result["serverInfo"].get("name", "")
    assert server_name, f"serverInfo.name is empty: {result['serverInfo']}"
