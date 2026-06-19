"""jit-gate — a thin JIT human-approval enforcement point for the Kagenti path.

Sits between the Kagenti AuthBridge sidecar and an MCP server. The AuthBridge has
already established the agent's IDENTITY (token-exchange). This gate adds AUTHZ:
read tools pass; a "dangerous" (write) tool is DENIED unless the request carries a
valid jit-approver capability JWT (X-JIT-Session-JWT) whose tool_scope covers it.

This is the same JIT plane as the working loop (jit-approver mints the capability
JWT after a Gitea-PR approval); only the enforcement point moved off ext-proc onto
the Kagenti path. Reuses the jit-approver image (fastapi/httpx/pyjwt) — no build.

Env:
  UPSTREAM_URL   target MCP base (default echo-mcp)
  JWKS_URL       jit-approver JWKS (default in-cluster svc)
  DANGEROUS_TOOLS comma list of tools requiring approval (default "echo")
  EXPECTED_AUD   capability-JWT aud (default "kyverno-authz")
"""
import json
import os
import time

import httpx
import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

UPSTREAM = os.getenv("UPSTREAM_URL", "http://echo-mcp.agentic-mcp.svc.cluster.local:8000")
JWKS_URL = os.getenv("JWKS_URL", "http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks")
DANGEROUS = {t.strip() for t in os.getenv("DANGEROUS_TOOLS", "echo").split(",") if t.strip()}
EXPECTED_AUD = os.getenv("EXPECTED_AUD", "kyverno-authz")
# STRICT_TOOL_SCOPE=true => the requested tool must be in the capability's tool_scope
# (exact match). Default false keeps the cross-MCP demo behavior (any non-empty mutating
# approval authorizes the gated tool). Set true where jit-approver mints the exact tool names.
STRICT_TOOL_SCOPE = os.getenv("STRICT_TOOL_SCOPE", "false").lower() == "true"
JIT_HEADER = "x-jit-session-jwt"

app = FastAPI()
_jwks = PyJWKClient(JWKS_URL)
_HOP = {"host", "content-length", "connection", "keep-alive", "transfer-encoding"}


def _deny(reason: str, rpc_id=None, code=-32001):
    # JSON-RPC error so the MCP client surfaces it; HTTP 403 for the audit trail.
    return JSONResponse(
        status_code=403,
        content={"jsonrpc": "2.0", "id": rpc_id,
                 "error": {"code": code, "message": f"jit-gate: {reason}"}},
    )


def _check_capability(token: str, tool: str) -> tuple[bool, str]:
    if not token:
        return False, f"tool '{tool}' requires approval — no capability JWT presented"
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], audience=EXPECTED_AUD,
            options={"require": ["exp"]},
        )
    except Exception as e:  # signature/exp/aud failures all deny
        return False, f"invalid capability JWT: {e}"
    scope = claims.get("tool_scope") or []
    # A read-only grant yields an empty tool_scope (jit-approver only maps MUTATING
    # verbs to tools) — deny. A non-empty scope means a human approved a mutating
    # elevation: the gate allows the dangerous tool. (Productionization: extend
    # jit-approver's _RESOURCE_TOOL_MAP to the target MCP's tools and match `tool`
    # in `scope` exactly; for this cross-MCP demo we gate on an approved mutating
    # elevation existing.)
    if not scope:
        return False, f"capability JWT has empty tool_scope (read-only grant) — '{tool}' still denied"
    if STRICT_TOOL_SCOPE and tool not in scope:
        return False, f"capability JWT not scoped for '{tool}' (tool_scope={scope})"
    return True, f"approved (tool_scope={scope}) sub={claims.get('sub')} exp={claims.get('exp')}"


async def _forward(request: Request, body: bytes) -> Response:
    fwd = {k: v for k, v in request.headers.items() if k.lower() not in _HOP}
    url = f"{UPSTREAM}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"
    async with httpx.AsyncClient(timeout=30.0) as c:
        up = await c.request(request.method, url, content=body, headers=fwd,
                             params=None)
    rh = {k: v for k, v in up.headers.items() if k.lower() not in _HOP}
    return Response(content=up.content, status_code=up.status_code, headers=rh)


@app.get("/healthz")
async def healthz():
    return {"ok": True, "dangerous": sorted(DANGEROUS), "upstream": UPSTREAM}


@app.api_route("/{path:path}", methods=["GET", "POST", "DELETE", "PUT", "PATCH"])
async def proxy(request: Request, path: str):
    body = await request.body()
    # Only POSTed JSON-RPC tools/call needs inspection; everything else passes.
    if request.method == "POST" and body:
        try:
            msg = json.loads(body)
        except Exception:
            msg = None
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            tool = (msg.get("params") or {}).get("name", "")
            if tool in DANGEROUS:
                token = request.headers.get(JIT_HEADER, "")
                ok, why = _check_capability(token, tool)
                print(f"jit-gate decision tool={tool} allow={ok} :: {why}", flush=True)
                if not ok:
                    return _deny(why, rpc_id=msg.get("id"))
            else:
                print(f"jit-gate allow read tool={tool}", flush=True)
    return await _forward(request, body)
