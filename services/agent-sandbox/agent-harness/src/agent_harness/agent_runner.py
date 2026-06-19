"""In-sandbox agent harness — claude-agent-sdk async runner.

Design contract (frozen — see FROZEN CONTRACT in the project design brief)
--------------------------------------------------------------------------
- The agent authenticates to the MCP gateway using its OWN SPIFFE JWT-SVID
  (audience="mcp-gateway"), NEVER a user credential.
- The gateway is registered as an "http" MCP server with a STATIC Authorization:
  Bearer <svid> header. On SVID rotation the options are rebuilt and query() is
  re-issued.
- permission_mode = "dontAsk" so the headless agent never blocks on prompts.
- allowed_tools is restricted to the single read-only firewall tool:
    mcp__mcp-gateway__search_firewall_rules
- Skills on disk at .claude/skills/<name>/SKILL.md are loaded via
  ClaudeAgentOptions(skills="all") — no programmatic registration.
- Each SDK message is emitted as a REDACTED JSONL line on stdout (stream 2 of
  the frozen JSONL contract). The MCP server config and Authorization header are
  NEVER serialised. This is a hard security gate: see _redact() and emit_jsonl().

Environment variables
---------------------
MCP_GATEWAY_URL     — Gateway base URL (default https://mcp-gateway.apps.anaeem.na-launch.com)
AGENT_GOAL          — Goal/prompt for the agent (overridden by argv[1] if present)
AGENT_SESSION_ID    — Optional: stable session ID for resuming or grouping logs
SVID_JWT_PATH       — Path to the agent SVID JWT file (see svid_bearer.py)
SPIFFE_ENDPOINT_SOCKET — SPIFFE workload API socket (fallback to file)
CLAUDE_CLI_PATH     — Optional: explicit path to claude CLI binary
AGENT_MAX_TURNS     — Max SDK turns before stopping (default 10)
PYTHONUNBUFFERED    — Set to 1 in the container; ensures JSONL lines flush immediately

Security invariants
-------------------
- SVID is held in memory only; never written to any log line or file.
- _redact() masks any key matching the REDACT_KEYS set before JSON serialisation.
- emit_jsonl() is the ONLY stdout writer; it always calls _redact() first.
- On any tool call the args dict is logged only via tool_args_hash (sha256 of
  canonical JSON), NEVER raw.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("agent_harness.runner")

# Module-level import reference — guarded so py_compile passes without the SDK.
# Tests patch these names on this module to avoid network/socket calls.
try:
    from claude_agent_sdk import query as sdk_query  # type: ignore[import-untyped]
except ImportError:
    sdk_query = None  # type: ignore[assignment]

from agent_harness.svid_bearer import fetch_agent_svid

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# From frozen contract: MCP server name determines tool namespace prefix.
MCP_SERVER_NAME = "mcp-gateway"

# From frozen contract listRulesTool: exact tool name as surfaced by the SDK.
ALLOWED_TOOL = f"mcp__{MCP_SERVER_NAME}__search_firewall_rules"

# From frozen mcpServer contract.
MCP_GATEWAY_URL_ENV = "MCP_GATEWAY_URL"
MCP_GATEWAY_URL_DEFAULT = "https://mcp-gateway.apps.anaeem.na-launch.com"

AGENT_GOAL_ENV = "AGENT_GOAL"
AGENT_SESSION_ID_ENV = "AGENT_SESSION_ID"
AGENT_MAX_TURNS_ENV = "AGENT_MAX_TURNS"
AGENT_MAX_TURNS_DEFAULT = 10

# Inference model id. When routing through OpenRouter's Anthropic-compatible
# endpoint, this MUST be an OpenRouter "anthropic/..." slug (the SDK's native
# default id is not recognised there). The actual inference credential and
# base URL arrive purely via process env (ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN
# / ANTHROPIC_API_KEY) which the spawned system `claude` CLI inherits — they are
# NEVER read or emitted by this module.
AGENT_MODEL_ENV = "AGENT_MODEL"
AGENT_MODEL_DEFAULT = "anthropic/claude-sonnet-4.5"


def _gateway_mcp_url() -> str:
    base = os.environ.get(MCP_GATEWAY_URL_ENV, MCP_GATEWAY_URL_DEFAULT).rstrip("/")
    return f"{base}/mcp"


def _goal() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]
    goal = os.environ.get(AGENT_GOAL_ENV, "").strip()
    if not goal:
        raise SystemExit(
            "AGENT_GOAL environment variable or argv[1] is required.\n"
            "Usage: agent_runner.py '<goal>'\n"
            "       AGENT_GOAL='list firewall rules' agent_runner.py"
        )
    return goal


def _session_id() -> str:
    # Must be a hyphenated UUID string — the claude CLI rejects a bare hex
    # session id ("Invalid session ID. Must be a valid UUID.").
    return os.environ.get(AGENT_SESSION_ID_ENV, "").strip() or str(uuid.uuid4())


def _max_turns() -> int:
    try:
        return int(os.environ.get(AGENT_MAX_TURNS_ENV, str(AGENT_MAX_TURNS_DEFAULT)))
    except ValueError:
        return AGENT_MAX_TURNS_DEFAULT


def _model() -> str:
    return os.environ.get(AGENT_MODEL_ENV, "").strip() or AGENT_MODEL_DEFAULT


# Allowed tools. Default = the single read-only firewall tool (1A behaviour).
# Set AGENT_ALLOWED_TOOLS (comma-separated) to widen — e.g. "Bash,mcp__mcp-gateway__search_firewall_rules"
# lets the agent read natively AND perform writes via the `mcp-call` helper, which
# transparently runs the JIT self-escalation (deny -> file request -> human approves
# in the console -> retry) so the agent never handles a credential.
AGENT_ALLOWED_TOOLS_ENV = "AGENT_ALLOWED_TOOLS"


def _allowed_tools() -> list[str]:
    raw = os.environ.get(AGENT_ALLOWED_TOOLS_ENV, "").strip()
    if raw:
        return [t.strip() for t in raw.split(",") if t.strip()]
    return [ALLOWED_TOOL]


# ---------------------------------------------------------------------------
# JSONL redaction (security gate — reviewer invariant)
# ---------------------------------------------------------------------------

# Keys whose VALUES must never appear in JSONL output. Any dict key matching
# one of these patterns (case-insensitive) is replaced with "<redacted>".
# This is a defence-in-depth measure; the primary guard is never constructing
# a dict that contains these fields in the first place.
_REDACT_KEYS: frozenset[str] = frozenset({
    "authorization",
    "bearer",
    "mcp_servers",
    "server_config",
    "token",
    "headers",
    "access_token",
    "client_secret",
    "svid",
    "private_key",
    "api_key",
    "password",
    "x-vault-token",
    "x_vault_token",
})


def _redact(obj: Any, depth: int = 0) -> Any:
    """Recursively redact sensitive keys from a serialisable object.

    Operates on dicts, lists, and scalars. Stops recursing at depth 20 to
    prevent stack overflow on adversarially deep structures.
    """
    if depth > 20:
        return "<depth-limit>"
    if isinstance(obj, dict):
        return {
            k: ("<redacted>" if k.lower() in _REDACT_KEYS else _redact(v, depth + 1))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact(item, depth + 1) for item in obj]
    return obj


def _args_hash(args: dict[str, Any]) -> str:
    """Return sha256 hex of canonical JSON of the tool args dict."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def emit_jsonl(line: dict[str, Any]) -> None:
    """Emit a single JSONL line to stdout after redaction.

    This is the ONLY stdout writer in this module. All callers MUST go through
    here. The redaction pass is the final safety net against accidental leakage
    of credentials into log lines scraped by Loki.
    """
    safe = _redact(line)
    # Ensure ts is always present.
    if "ts" not in safe:
        safe["ts"] = datetime.now(timezone.utc).isoformat()
    print(json.dumps(safe, ensure_ascii=True, default=str), flush=True)


# ---------------------------------------------------------------------------
# Build SDK options (called before each query() to get fresh SVID)
# ---------------------------------------------------------------------------


def _build_options(svid_token: str, session_id: str) -> Any:
    """Build ClaudeAgentOptions with the agent SVID as the MCP bearer.

    The SVID is placed ONLY in the McpHttpServerConfig headers dict. It is NOT
    logged, NOT hashed for audit here (it is the agent's own identity, not a
    tool arg), and NOT returned from this function in any form that reaches
    emit_jsonl().

    The McpHttpServerConfig is a TypedDict — constructed as a plain dict and
    passed into mcp_servers. The SDK never exposes this dict back to the
    caller's message stream; it is consumed internally to build the HTTP
    Authorization header for MCP calls.
    """
    # Guard: import inside function so py_compile passes without the SDK installed.
    try:
        from claude_agent_sdk import ClaudeAgentOptions  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "claude-agent-sdk is not installed. Install it via: "
            "pip install claude-agent-sdk"
        ) from exc

    mcp_server_cfg: dict[str, Any] = {
        "type": "http",
        "url": _gateway_mcp_url(),
        # SECURITY: the Authorization header value (the SVID) is constructed
        # here in memory only. It is intentionally NOT included in any log
        # call or emit_jsonl() invocation.
        "headers": {"Authorization": f"Bearer {svid_token}"},
    }

    cli_path = os.environ.get("CLAUDE_CLI_PATH", "").strip() or None

    # Only register the gateway as a native MCP server if an mcp__ tool is allowed.
    # When the agent is meant to drive everything through the `mcp-call` helper
    # (allowed_tools=["Bash"]), we DON'T register the MCP server — otherwise the
    # agent sees the native write tools (e.g. create_firewall_rule_advanced), tries
    # one directly, gets hard-denied by dontAsk mode, and gives up instead of using
    # mcp-call (which does the JIT self-escalation). No MCP server => the only path
    # to a tool is `mcp-call`, which is what the pfsense-firewall skill instructs.
    allowed = _allowed_tools()
    use_mcp = any(t.startswith("mcp__") for t in allowed)

    opts = ClaudeAgentOptions(
        mcp_servers=({MCP_SERVER_NAME: mcp_server_cfg} if use_mcp else {}),  # type: ignore[arg-type]
        strict_mcp_config=True,   # Only use the mcp_servers declared here.
        allowed_tools=allowed,
        permission_mode="dontAsk",
        max_turns=_max_turns(),
        # Inference model — OpenRouter "anthropic/..." slug (see AGENT_MODEL_ENV).
        model=_model(),
        # Load on-disk skills from .claude/skills/<name>/SKILL.md.
        # "all" means "all skills found in the cwd .claude/skills directory".
        skills="all",
        session_id=session_id,
        cli_path=cli_path,
    )
    return opts


# ---------------------------------------------------------------------------
# Message handlers — emit JSONL per frozen stream-2 contract
# ---------------------------------------------------------------------------


def _handle_system_message(msg: Any, session_id: str) -> None:
    """Emit a type="system" JSONL line."""
    emit_jsonl({
        "type": "system",
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "subtype": getattr(msg, "subtype", "unknown"),
        "message": str(getattr(msg, "data", "")),
    })


def _handle_assistant_message(msg: Any, session_id: str) -> None:
    """Emit type="assistant" and type="tool_use" lines from an AssistantMessage.

    Tool args are hashed (sha256) — never logged raw. Content is extracted
    from TextBlock and ToolUseBlock members of msg.content.
    """
    for block in getattr(msg, "content", []):
        block_type = type(block).__name__

        if block_type == "TextBlock":
            emit_jsonl({
                "type": "assistant",
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "text": getattr(block, "text", ""),
            })

        elif block_type in ("ToolUseBlock",):
            tool_name: str = getattr(block, "name", "")
            tool_input: dict[str, Any] = getattr(block, "input", {}) or {}
            emit_jsonl({
                "type": "tool_use",
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "tool": tool_name,
                # SECURITY: args are hashed, never serialised raw.
                "args_hash": _args_hash(tool_input),
            })

        elif block_type in ("ToolResultBlock", "ServerToolResultBlock"):
            # Tool result embedded in the assistant turn (some SDK versions).
            content_val = getattr(block, "content", "")
            if isinstance(content_val, list):
                content_str = " ".join(
                    getattr(c, "text", str(c)) for c in content_val
                )
            else:
                content_str = str(content_val)
            # Truncate large outputs before emitting.
            if len(content_str) > 4096:
                content_str = content_str[:4096] + "...<truncated>"
            emit_jsonl({
                "type": "tool_result",
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "tool": getattr(block, "tool_use_id", ""),
                "ok": not getattr(block, "is_error", False),
                "content": content_str,
            })

        # ThinkingBlock, ServerToolUseBlock — emit a typed notice but no sensitive data.
        elif block_type in ("ThinkingBlock", "ServerToolUseBlock"):
            emit_jsonl({
                "type": "system",
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "subtype": block_type.lower(),
                "message": f"block type={block_type}",
            })


def _handle_result_message(msg: Any, session_id: str) -> None:
    """Emit a type="result" JSONL line from a ResultMessage."""
    is_error: bool = getattr(msg, "is_error", False)
    result_text: str = getattr(msg, "result", "") or ""
    errors: list[str] = getattr(msg, "errors", None) or []
    emit_jsonl({
        "type": "result",
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "status": "error" if is_error else "success",
        "summary": result_text or ("; ".join(errors) if errors else ""),
        "stop_reason": getattr(msg, "stop_reason", None),
        "num_turns": getattr(msg, "num_turns", None),
    })


def _handle_user_message(msg: Any, session_id: str) -> None:
    """Tool result messages surfaced as UserMessage in some SDK versions."""
    for block in getattr(msg, "content", []):
        block_type = type(block).__name__
        if block_type == "ToolResultBlock":
            content_val = getattr(block, "content", "")
            if isinstance(content_val, list):
                content_str = " ".join(getattr(c, "text", str(c)) for c in content_val)
            else:
                content_str = str(content_val)
            if len(content_str) > 4096:
                content_str = content_str[:4096] + "...<truncated>"
            emit_jsonl({
                "type": "tool_result",
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "tool": getattr(block, "tool_use_id", ""),
                "ok": not getattr(block, "is_error", False),
                "content": content_str,
            })


# ---------------------------------------------------------------------------
# Main async runner
# ---------------------------------------------------------------------------


async def run_agent(goal: str, session_id: str) -> bool:
    """Run the agent for one goal, returning True on success.

    SVID rotation: if the query() raises an auth-related error (detected
    heuristically from the exception message) the SVID is re-fetched and the
    query is retried ONCE. This handles the case where the SVID expired between
    _build_options() and the first HTTP call to the MCP gateway.

    Returns:
        True  — ResultMessage with is_error=False received.
        False — ResultMessage with is_error=True OR no ResultMessage received.
    """
    # Use module-level references so tests can patch agent_runner.fetch_agent_svid
    # and agent_runner.sdk_query without modifying the guarded import logic.
    import agent_harness.agent_runner as _self
    _fetch_svid = _self.fetch_agent_svid
    _query = _self.sdk_query
    if _query is None:
        raise RuntimeError("claude-agent-sdk not installed")

    emit_jsonl({
        "type": "system",
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "subtype": "init",
        "message": f"agent_runner starting; session_id={session_id}; "
                   f"allowed_tools={_allowed_tools()!r}; gateway={_gateway_mcp_url()!r}",
    })

    try:
        svid_token = _fetch_svid()
    except RuntimeError as svid_exc:
        emit_jsonl({
            "type": "result",
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "status": "error",
            "summary": f"SVID fetch failed: {svid_exc}",
        })
        return False

    opts = _build_options(svid_token, session_id)

    # SECURITY NOTE: svid_token is no longer needed after _build_options().
    # Delete the local reference so it cannot accidentally reach emit_jsonl().
    del svid_token

    success = False
    retry_attempted = False

    while True:
        try:
            async for msg in _query(prompt=goal, options=opts):
                msg_type = type(msg).__name__

                if msg_type == "SystemMessage":
                    _handle_system_message(msg, session_id)
                elif msg_type == "AssistantMessage":
                    _handle_assistant_message(msg, session_id)
                elif msg_type == "ResultMessage":
                    _handle_result_message(msg, session_id)
                    success = not getattr(msg, "is_error", True)
                elif msg_type == "UserMessage":
                    _handle_user_message(msg, session_id)
                elif msg_type == "RateLimitEvent":
                    delay_ms: int = getattr(msg, "delay_ms", 0) or 0
                    emit_jsonl({
                        "type": "system",
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "session_id": session_id,
                        "subtype": "rate_limit",
                        "message": f"rate_limit delay_ms={delay_ms}",
                    })
                # StreamEvent and other unknown types — emit a minimal notice.
                else:
                    emit_jsonl({
                        "type": "system",
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "session_id": session_id,
                        "subtype": "sdk_event",
                        "message": f"event type={msg_type}",
                    })
            break  # Normal completion.

        except Exception as exc:
            err_str = str(exc).lower()
            # Finding 7: narrow retry trigger to explicit auth signals only.
            # The old heuristic matched the bare substring "token" which would
            # fire on any error message containing that word (e.g. "token bucket
            # exhausted" / "tokenizer error"), causing spurious SVID refreshes.
            # Only match HTTP 401, the literal string "unauthorized", or SVID-
            # specific expiry signals.
            is_auth_error = (
                "401" in err_str
                or "unauthorized" in err_str
                or "svid expired" in err_str
            )
            if is_auth_error and not retry_attempted:
                retry_attempted = True
                emit_jsonl({
                    "type": "system",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "session_id": session_id,
                    "subtype": "svid_rotation",
                    "message": "auth error detected; refreshing SVID and retrying once",
                })
                try:
                    fresh_svid = _fetch_svid()
                    opts = _build_options(fresh_svid, session_id)
                    del fresh_svid
                except RuntimeError as svid_exc:
                    emit_jsonl({
                        "type": "result",
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "session_id": session_id,
                        "status": "error",
                        "summary": f"SVID refresh failed: {svid_exc}",
                    })
                    return False
                continue  # Retry the while loop.
            # Non-recoverable.
            emit_jsonl({
                "type": "result",
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "status": "error",
                "summary": f"sdk_query failed: {type(exc).__name__}",
            })
            return False

    return success


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """Configure logging (JSON to stderr) and run the agent."""
    import logging
    import sys

    # JSON structured logs to stderr (separate from the JSONL stdout stream).
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
        )
    )
    logging.basicConfig(handlers=[handler], level=logging.INFO)

    goal = _goal()
    session_id = _session_id()

    success = asyncio.run(run_agent(goal=goal, session_id=session_id))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
