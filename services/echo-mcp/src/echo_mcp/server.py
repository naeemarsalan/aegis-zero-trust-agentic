"""echo-mcp — a minimal MCP server that proves credential delegation.

Its only job: report the identity it sees on the inbound request. In UC1 the
agent calls this through the gateway; ext-proc-delegation swaps the agent's
identity for the *user's* federated token, so echo-mcp must report the USER —
not the agent. That assertion is the UC1 golden test.

Transport: StreamableHTTP on :8000 at /mcp. The Authorization bearer is decoded
WITHOUT verification on purpose — the gateway + ext-proc already enforced it;
echo-mcp only logs/echoes it to demonstrate what the downstream actually sees.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
log = logging.getLogger("echo-mcp")

mcp = FastMCP("echo", host="0.0.0.0", port=int(os.environ.get("MCP_PORT", "8000")))


def _decode_identity(authorization: str | None) -> dict[str, Any]:
    """Best-effort, signature-UNVERIFIED decode of a Bearer JWT's claims."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return {"authenticated": False}
    token = authorization.split(" ", 1)[1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"authenticated": False, "reason": "not-a-jwt"}
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:  # noqa: BLE001
        return {"authenticated": False, "reason": "undecodable"}
    return {
        "authenticated": True,
        "sub": claims.get("sub"),
        "preferred_username": claims.get("preferred_username"),
        "email": claims.get("email"),
        "groups": claims.get("groups", []),
        "azp": claims.get("azp"),
        "aud": claims.get("aud"),
        "iss": claims.get("iss"),
    }


def _identity_from_context() -> dict[str, Any]:
    req: Request | None = mcp.get_context().request_context.request
    auth = req.headers.get("authorization") if req is not None else None
    ident = _decode_identity(auth)
    log.info("tool call — downstream sees principal=%s azp=%s",
             ident.get("preferred_username") or ident.get("sub"), ident.get("azp"))
    return ident


@mcp.tool()
def whoami() -> dict[str, Any]:
    """Return the identity echo-mcp sees on this request.

    UC1 golden assertion: preferred_username/sub == the human user (e.g. arsalan),
    and azp (authorized party) == the downstream client the gateway exchanged to —
    NOT the agent's own client. Proves the agent's identity never reached here.
    """
    return _identity_from_context()


@mcp.tool()
def echo(message: str) -> dict[str, Any]:
    """Echo a message back, annotated with the caller identity echo-mcp observed."""
    return {"message": message, "seen_principal": _identity_from_context()}


def main() -> None:
    log.info("echo-mcp starting (StreamableHTTP /mcp on :%s)", os.environ.get("MCP_PORT", "8000"))
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
