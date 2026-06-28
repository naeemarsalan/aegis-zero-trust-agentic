"""approval-console — minimal operator web UI for JIT write-approval requests.

Endpoints:
  GET  /           -> self-contained HTML console (no build step)
  GET  /api/requests -> proxy to jit-approver GET /requests (with optional ?state= filter)
  GET  /api/requests/{id}/detail -> proxy to jit-approver GET /requests/{id}/detail
  GET  /api/requests/{id}/status -> proxy to jit-approver GET /requests/{id}/status
                                    (post-approval: surfaces session_id + expires_at)
  POST /api/approve/{id} -> mint gate path: POST to jit-approver /requests/{id}/mint
                            carrying approver_sub from Keycloak forwarded headers.
                            When JIT_APPROVE_VIA_MINT=false falls back to Gitea PR merge.
  GET  /healthz    -> liveness probe

Security contract (PoC):
  - No auth on the console itself (behind the cluster Route; see README).
  - GITEA_TOKEN stays server-side; browser never touches Gitea directly.
  - Approve is the ONLY mutating operation; everything else is read-only.
  - L1: approver identity is taken from oauth2-proxy X-Forwarded-Preferred-Username
    (server-trusted), never from a field the browser/agent controls.
  - L1: /mint enforces approver_sub != requester_sub (M5 self-approval denied).
"""

from __future__ import annotations

import hashlib
import json
import logging
import shlex
import threading
import time
import uuid
from typing import Any

import contextlib
from collections.abc import AsyncIterator

import os as _os_mod

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from approval_console.config import Config

logger = logging.getLogger("approval_console.app")


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """App lifespan: start the background agent reaper at startup.

    The reaper (approval_console.agents.reaper) polls sandbox-launcher for each
    PROVISIONING/READY agent's sandbox phase and flips PROVISIONING -> READY (the
    state the webshell button is gated on) once the sandbox is Ready, and -> ERROR
    if the sandbox is gone/failed. start_reaper() spawns a daemon thread and is
    idempotent, so this is safe across reloads. It reads SANDBOX_LAUNCHER_URL from
    the environment (same env the console already carries) lazily on each poll.
    """
    from approval_console.agents.reaper import start_reaper

    start_reaper()
    yield


app = FastAPI(
    title="JIT Approval Console",
    description="Operator web console for JIT write-approval requests",
    version="0.1.0",
    lifespan=_lifespan,
)

# ---------------------------------------------------------------------------
# In-memory agent session store
# ---------------------------------------------------------------------------
# Each entry: {"lines": list[str], "done": bool, "goal": str, "seq": int}
# "seq" is a monotonically increasing counter assigned at creation time so the
# UI can sort sessions by recency without a real timestamp (avoids the UTC
# import dependency in the store itself).
_SESSIONS: dict[str, dict[str, Any]] = {}
_SESSIONS_LOCK = threading.Lock()
_SESSION_COUNTER = 0


def _new_session(goal: str, owner: str = "anonymous") -> str:
    """Allocate a new session entry; return its ID."""
    global _SESSION_COUNTER  # noqa: PLW0603
    sid = uuid.uuid4().hex
    with _SESSIONS_LOCK:
        _SESSION_COUNTER += 1
        _SESSIONS[sid] = {
            "lines": [],
            "done": False,
            "goal": goal,
            "seq": _SESSION_COUNTER,
            "owner": owner,
        }
    return sid


def _append_line(sid: str, line: str) -> None:
    with _SESSIONS_LOCK:
        _SESSIONS[sid]["lines"].append(line)


def _mark_done(sid: str) -> None:
    with _SESSIONS_LOCK:
        _SESSIONS[sid]["done"] = True


def _get_session(sid: str) -> dict[str, Any] | None:
    with _SESSIONS_LOCK:
        return _SESSIONS.get(sid)


def _launch_agent_thread(sid: str, goal: str, actor: str = "anonymous") -> None:
    """Background daemon thread: exec the agent in the harness pod and pump its stdout."""

    def _run() -> None:
        try:
            # Import kubernetes here so unit tests can monkeypatch _do_k8s_exec
            # without needing a real cluster at import time.
            _do_k8s_exec(sid, goal, actor)
        except Exception as exc:  # noqa: BLE001
            logger.error("agent_session.launch_error", extra={"sid": sid, "error": str(exc)})
            _append_line(sid, json.dumps({"type": "error", "msg": str(exc)}))
        finally:
            _mark_done(sid)

    t = threading.Thread(target=_run, daemon=True, name=f"agent-{sid[:8]}")
    t.start()


def _do_k8s_exec(sid: str, goal: str, actor: str = "anonymous") -> None:
    """Perform the actual Kubernetes pod exec and pump lines into the session store.

    Extracted as a standalone function so tests can monkeypatch it without
    touching the full threading machinery.

    ``actor`` is the authenticated human identity resolved by _actor() from the
    oauth2-proxy headers. It is forwarded into the agent's execution environment
    as AGENT_USER so that mcp-call can file the JIT request with the requester's
    real identity rather than the sandbox SVID.
    """
    from kubernetes import client as k8sclient  # type: ignore[import-untyped]
    from kubernetes import config as k8sconfig  # type: ignore[import-untyped]
    from kubernetes.stream import stream  # type: ignore[import-untyped]

    k8sconfig.load_incluster_config()
    core = k8sclient.CoreV1Api()

    pods = core.list_namespaced_pod(
        Config.harness_namespace(),
        label_selector=Config.harness_selector(),
        field_selector="status.phase=Running",
    )
    if not pods.items:
        raise RuntimeError(
            f"No running pod found with selector {Config.harness_selector()!r} "
            f"in namespace {Config.harness_namespace()!r}"
        )
    pod_name = pods.items[-1].metadata.name

    goal_shell = shlex.quote(goal)
    # shlex.quote the actor so a rogue username (containing spaces or shell
    # metacharacters) cannot break the sh -c string.
    actor_shell = shlex.quote(actor)
    cmd = (
        "cd /app && PYTHONPATH=/app/src "
        f"MCP_READ_URL={Config.k8s_mcp_read_url()} "
        f"MCP_WRITE_URL={Config.k8s_mcp_write_url()} "
        f"JIT_TARGET_NAMESPACE={Config.jit_target_namespace()} "
        "MCP_SEND_SVID=false "
        f"AGENT_ALLOWED_TOOLS={Config.agent_allowed_tools()} "
        f"AGENT_MAX_TURNS={Config.agent_max_turns()} "
        f"AGENT_USER={actor_shell} "
        f"AGENT_GOAL={goal_shell} "
        "python3 -m agent_harness.agent_runner"
    )

    resp = stream(
        core.connect_get_namespaced_pod_exec,
        pod_name,
        Config.harness_namespace(),
        container=Config.harness_container(),
        command=["sh", "-c", cmd],
        stderr=True,
        stdout=True,
        stdin=False,
        tty=False,
        _preload_content=False,
    )

    try:
        while resp.is_open():
            resp.update(timeout=1)
            if resp.peek_stdout():
                for ln in resp.read_stdout().splitlines():
                    ln = ln.strip()
                    if ln:
                        _append_line(sid, ln)
            if resp.peek_stderr():
                for ln in resp.read_stderr().splitlines():
                    ln = ln.strip()
                    if ln:
                        # Wrap stderr in a JSON envelope so the UI can render it
                        _append_line(sid, json.dumps({"type": "stderr", "msg": ln}))
    finally:
        resp.close()


# ---------------------------------------------------------------------------
# Native OpenShell sandbox exec path (Phase C)
# ---------------------------------------------------------------------------
#
# A console "session" is a task handed to a LIVING agent that already owns a
# native OpenShell sandbox pod (created at /api/agents launch time). Instead of
# exec-ing the brain into the shared e2e-harness pod (the legacy _do_k8s_exec
# path), we exec the brain runner inside the AGENT'S OWN sandbox pod in the
# `openshell` namespace, so the ext-proc delegation runs against that sandbox's
# SVID + Vault consent grant. This is what makes a console session produce a
# delegated read against the agent's own sandbox_id.
#
# CRITICAL — the native sandbox pod env does NOT carry the LLM inference creds
# (the launcher injects them only at ExecSandbox time). So the exec command MUST
# carry ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / model
# ids — sourced from the console process's OWN env via the `agent-harness-inference`
# secret (envFrom on the console deployment). Secret VALUES are never logged.

# Env keys forwarded from the console process env into the native-sandbox exec
# command. These mirror sandbox_launcher.openshell._brain_env so a console-driven
# session is identical to a launcher-booted brain. SVID_JWT_PATH /
# SVID_REQUIRE_PATH_SUBSTR / MCP_GATEWAY_URL also live here so they can be
# overridden per-deployment but default to the same values the launcher uses.
_NATIVE_BRAIN_FORWARD_ENV: tuple[str, ...] = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "AGENT_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
)


def _maas_svid_mode() -> bool:
    """True (default) when the brain consumes models via its SPIFFE SVID through the
    in-pod maas_brain_proxy -> MaaS gateway, instead of a stored LiteLLM key. Mirrors
    sandbox_launcher.openshell._maas_svid_mode. Opt out (legacy stored-key path) with
    SANDBOX_BRAIN_MAAS_SVID set falsey on the console pod.
    """
    import os as _os

    return _os.environ.get("SANDBOX_BRAIN_MAAS_SVID", "true").strip().lower() not in (
        "false",
        "0",
        "no",
        "off",
    )


def _native_brain_env(goal: str, actor: str, session_id: str) -> dict[str, str]:
    """Build the env dict for the native-sandbox brain exec.

    Mirrors sandbox_launcher.openshell._brain_env: the ext-proc routing plane
    (MCP_GATEWAY_URL, MCP_SEND_SVID=true, JIT_TARGET_NAMESPACE, the UUID-SVID
    selection knobs) PLUS the inference creds forwarded from the console pod env
    (sourced via the agent-harness-inference secret envFrom). All non-secret
    values have sane defaults so a missing literal still yields the correct
    real-pfSense recipe; secret VALUES are read from os.environ and never logged.
    """
    import os as _os

    # AGENT_SESSION_ID must be a HYPHENATED UUID — the claude CLI rejects a bare
    # 32-char hex id ("Invalid session ID. Must be a valid UUID."). _new_session()
    # allocates a bare-hex uuid4().hex, so convert it back to the canonical dashed
    # form here; an already-dashed value (or a non-uuid) is passed through unchanged
    # and falls back to a CLI-generated UUID in agent_runner if invalid.
    cli_session_id = session_id
    try:
        cli_session_id = str(uuid.UUID(hex=session_id))
    except (ValueError, AttributeError, TypeError):
        pass

    env: dict[str, str] = {
        "AGENT_GOAL": goal,
        "AGENT_USER": actor,
        "AGENT_SESSION_ID": cli_session_id,
        "AGENT_ALLOWED_TOOLS": _os.environ.get("AGENT_ALLOWED_TOOLS", "").strip()
        or Config.agent_allowed_tools(),
        "AGENT_MAX_TURNS": Config.agent_max_turns(),
        # ext-proc routing plane (real pfSense via the mcp-gateway ext-proc).
        "MCP_GATEWAY_URL": _os.environ.get("MCP_GATEWAY_URL", "").strip()
        or "https://mcp-gateway.apps.ocp-dev.na-launch.com",
        "MCP_SEND_SVID": _os.environ.get("MCP_SEND_SVID", "").strip() or "true",
        "JIT_TARGET_NAMESPACE": _os.environ.get("JIT_TARGET_NAMESPACE", "").strip()
        or "agentic-mcp",
        # Deterministic ext-proc SVID selection (UUID-shaped over SA-shaped).
        "SVID_REQUIRE_PATH_SUBSTR": _os.environ.get("SVID_REQUIRE_PATH_SUBSTR", "").strip()
        or "/sandbox/",
        "SVID_JWT_PATH": _os.environ.get("SVID_JWT_PATH", "").strip()
        or "/tmp/svid-out/mcp-gateway-svid.jwt",
        "CLAUDE_CLI_PATH": _os.environ.get("CLAUDE_CLI_PATH", "").strip()
        or "/usr/local/bin/claude",
    }
    if _maas_svid_mode():
        # SVID-ONLY model consumption (invariant default): point the claude CLI at the
        # in-pod maas_brain_proxy loopback. NO stored model credential is injected; the
        # proxy strips this throwaway token, fetches a fresh JWT-SVID per call (reusing
        # SVID_JWT_PATH/SVID_REQUIRE_PATH_SUBSTR above), and the MaaS gateway authorizes
        # it. The proxy is started before the runner in _do_native_k8s_exec.
        port = _os.environ.get("MAAS_BRAIN_LISTEN_PORT", "").strip() or "8787"
        env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{port}"
        env["ANTHROPIC_AUTH_TOKEN"] = "svid-injected-by-local-proxy"
        env["MAAS_BRAIN"] = "1"
        env["MAAS_BRAIN_LISTEN_PORT"] = port
        env["MAAS_GATEWAY_URL"] = (
            _os.environ.get("MAAS_GATEWAY_URL", "").strip() or "http://maas-gateway-istio.maas.svc:80"
        )
        env["MAAS_GATEWAY_HOST"] = (
            _os.environ.get("MAAS_GATEWAY_HOST", "").strip() or "maas.apps.ocp-dev.na-launch.com"
        )
        env["MAAS_ROUTE_PREFIX"] = _os.environ.get("MAAS_ROUTE_PREFIX", "").strip() or "/openrouter"
        # Model-id passthrough only — never a credential or a base_url override.
        for var in _NATIVE_BRAIN_FORWARD_ENV:
            if var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
                continue
            val = _os.environ.get(var, "").strip()
            if val:
                env[var] = val
        return env

    # LEGACY stored-key path (opt-in via SANDBOX_BRAIN_MAAS_SVID=false). Injects a STORED
    # model credential. Never logged. Pass EXACTLY ONE of ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY.
    auth_token = _os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()
    api_key = _os.environ.get("ANTHROPIC_API_KEY", "").strip()
    cred = auth_token or api_key
    if cred:
        env["ANTHROPIC_AUTH_TOKEN"] = cred
    for var in _NATIVE_BRAIN_FORWARD_ENV:
        if var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
            continue
        val = _os.environ.get(var, "").strip()
        if val:
            env[var] = val
    return env


def _do_native_k8s_exec(
    sid: str,
    goal: str,
    actor: str,
    sandbox_name: str,
    sandbox_id: str,
) -> None:
    """Exec the agent-harness brain runner inside the agent's OWN OpenShell sandbox.

    Targets namespace `openshell`, pod == sandbox_name, container `agent`
    (Config.native_sandbox_*). Pumps stdout/stderr into the same _SESSIONS store
    as _do_k8s_exec so the UI transcript stream is identical.

    The brain command is the agent_runner module, fed the goal via AGENT_GOAL and
    the full inference + ext-proc env (see _native_brain_env). Inference creds are
    forwarded from the console env; their VALUES are never logged.
    """
    from kubernetes import client as k8sclient  # type: ignore[import-untyped]
    from kubernetes import config as k8sconfig  # type: ignore[import-untyped]
    from kubernetes.stream import stream  # type: ignore[import-untyped]

    k8sconfig.load_incluster_config()
    core = k8sclient.CoreV1Api()

    namespace = Config.native_sandbox_namespace()
    container = Config.native_sandbox_container()

    # Confirm the sandbox pod is Running before exec (fail-closed with a clear msg).
    pod = core.read_namespaced_pod(sandbox_name, namespace)
    phase = getattr(pod.status, "phase", "")
    if phase != "Running":
        raise RuntimeError(
            f"Native sandbox pod {sandbox_name!r} in {namespace!r} is phase {phase!r}, not Running"
        )

    env = _native_brain_env(goal, actor, sid)
    # Build the inline `KEY=value ` prefix; shlex.quote every value so a goal or
    # username with shell metacharacters cannot break the sh -c string.
    env_prefix = " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())
    # SVID-only model path: start the maas_brain_proxy (SVID injector) in the background
    # before the runner so the runner's ANTHROPIC_BASE_URL=127.0.0.1:<port> has a listener.
    # NO stored model key is involved. A short sleep lets the stdlib proxy bind.
    maas_prefix = ""
    if _maas_svid_mode():
        maas_prefix = (
            f"PYTHONPATH=/app/src {env_prefix} python3 -m agent_harness.maas_brain_proxy "
            ">/tmp/brain-proxy.log 2>&1 & sleep 1; "
        )
    cmd = (
        f"cd /app && {maas_prefix}PYTHONPATH=/app/src {env_prefix} "
        "python3 -m agent_harness.agent_runner"
    )

    # Audit (names only — never the secret VALUES).
    logger.info(
        "agent_session.native_exec sid=%s sandbox=%s/%s sandbox_id=%s env_keys=%s",
        sid,
        namespace,
        sandbox_name,
        sandbox_id,
        ",".join(sorted(env.keys())),
    )

    resp = stream(
        core.connect_get_namespaced_pod_exec,
        sandbox_name,
        namespace,
        container=container,
        command=["sh", "-c", cmd],
        stderr=True,
        stdout=True,
        stdin=False,
        tty=False,
        _preload_content=False,
    )

    try:
        while resp.is_open():
            resp.update(timeout=1)
            if resp.peek_stdout():
                for ln in resp.read_stdout().splitlines():
                    ln = ln.strip()
                    if ln:
                        _append_line(sid, ln)
            if resp.peek_stderr():
                for ln in resp.read_stderr().splitlines():
                    ln = ln.strip()
                    if ln:
                        _append_line(sid, json.dumps({"type": "stderr", "msg": ln}))
    finally:
        resp.close()


def _launch_native_agent_thread(
    sid: str,
    goal: str,
    actor: str,
    sandbox_name: str,
    sandbox_id: str,
) -> None:
    """Background daemon thread: exec the brain in the agent's native sandbox."""

    def _run() -> None:
        try:
            _do_native_k8s_exec(sid, goal, actor, sandbox_name, sandbox_id)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "agent_session.native_launch_error",
                extra={"sid": sid, "sandbox": sandbox_name, "error": str(exc)},
            )
            _append_line(sid, json.dumps({"type": "error", "msg": str(exc)}))
        finally:
            _mark_done(sid)

    t = threading.Thread(target=_run, daemon=True, name=f"agent-native-{sid[:8]}")
    t.start()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_args(args: Any) -> str:
    """sha256 of JSON-serialised arguments (audit contract)."""
    raw = json.dumps(args, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def _audit(event: str, actor: str, outcome: str, latency_ms: float, **extra: Any) -> None:
    """Emit structured audit log line per the platform contract."""
    import datetime

    record: dict[str, Any] = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event,
        "actor": actor,
        "namespace": "mcp-gateway",
        "outcome": outcome,
        "latency_ms": round(latency_ms, 2),
    }
    record.update(extra)
    logger.info(json.dumps(record))


def _actor(request: Request) -> str:
    """Resolve the authenticated human's identity from oauth2-proxy injected headers.

    Resolution order (first non-empty wins):
      X-Forwarded-Preferred-Username  — OIDC preferred_username claim
      X-Forwarded-Email               — OIDC email claim
      X-Forwarded-User                — oauth2-proxy fallback (usually same as username)

    FastAPI's Request.headers dict is case-insensitive. When none of the headers
    are present (local development / no proxy) the function returns "anonymous" so
    tests and non-proxied runs continue to work without any authentication sidecar.
    """
    for header in (
        "x-forwarded-preferred-username",
        "x-forwarded-email",
        "x-forwarded-user",
    ):
        value = request.headers.get(header, "").strip()
        if value:
            return value
    return "anonymous"


def _jit_headers() -> dict[str, str]:
    """No auth token needed for jit-approver read endpoints (cluster-internal)."""
    return {"Accept": "application/json"}


def _mint_headers() -> dict[str, str]:
    """Headers for the authenticated POST /mint call to jit-approver.

    In production these carry the console SA bearer token (X-Console-SA-Token)
    so jit-approver can perform a Kubernetes TokenReview and verify the caller
    is the console service, not an agent-sandbox pod.

    The token is read from the projected service-account volume at
    /var/run/secrets/kubernetes.io/serviceaccount/token (in-cluster) or from
    the env var JIT_MINT_CONSOLE_TOKEN_OVERRIDE (tests / dev).
    """
    import os as _os

    override = _os.environ.get("JIT_MINT_CONSOLE_TOKEN_OVERRIDE", "").strip()
    if override:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Console-SA-Token": override,
        }
    # Try the projected SA token file.
    sa_token = ""
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
            sa_token = f.read().strip()
    except FileNotFoundError:
        pass
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if sa_token:
        headers["X-Console-SA-Token"] = sa_token
    return headers


def _approve_via_mint() -> bool:
    """Return True when the console should use the /mint gate (L1 default=on).

    Set JIT_APPROVE_VIA_MINT=false to revert to the legacy Gitea PR-merge path
    (rollback lever per L1 spec).
    """
    import os as _os

    return _os.environ.get("JIT_APPROVE_VIA_MINT", "true").strip().lower() != "false"


def _canonical_scope_hash(detail: dict) -> str:
    """Compute the canonical scope hash over a detail dict from jit-approver.

    Must produce identical output to jit_approver.models.canonical_scope_hash()
    for the same scope — cross-checked in test_mint.py::test_canonical_scope_hash_cross_check.

    Fields used:
      namespace, verbs (sorted), resources (sorted), duration_minutes,
      sandbox, policy_delta (sorted "host:port" strings).
    """
    policy_delta = detail.get("policy_delta") or []
    delta_sorted = sorted(
        f"{pd.get('host', '')}:{pd.get('port', 443)}" for pd in policy_delta
    )
    canonical: dict = {
        "namespace": detail.get("namespace", ""),
        "verbs": sorted(detail.get("verbs") or []),
        "resources": sorted(detail.get("resources") or []),
        "duration_minutes": detail.get("duration_minutes", 0),
        "sandbox": detail.get("sandbox"),
        "policy_delta": delta_sorted,
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _gitea_headers() -> dict[str, str]:
    return {
        "Authorization": f"token {Config.gitea_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


# ---------------------------------------------------------------------------
# GET / — self-contained HTML console
# ---------------------------------------------------------------------------

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JIT Approval Console</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body {
    font-family: "Segoe UI", system-ui, sans-serif;
    background: #0f1117;
    color: #e0e0e0;
    margin: 0;
    padding: 1.5rem;
  }
  h1 { color: #76b900; margin: 0 0 0.25rem; font-size: 1.4rem; }
  .subtitle { color: #888; font-size: 0.85rem; margin: 0 0 1.5rem; }
  .badge {
    display: inline-block;
    padding: 0.2em 0.6em;
    border-radius: 0.3em;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .badge-pending  { background: #7c3f00; color: #ffb347; }
  .badge-approved { background: #1a3a1a; color: #76b900; }
  .badge-issued   { background: #1a2a3a; color: #5bc8f5; }
  .badge-expired  { background: #2a2a2a; color: #888; }
  .badge-denied   { background: #3a1a1a; color: #f55; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
    margin-bottom: 1rem;
  }
  th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    background: #1a1d24;
    color: #aaa;
    font-weight: 600;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid #2a2d34;
  }
  td {
    padding: 0.55rem 0.75rem;
    border-bottom: 1px solid #1a1d24;
    vertical-align: top;
    word-break: break-word;
  }
  tr:hover td { background: #14171e; }
  .mono { font-family: "JetBrains Mono", "Cascadia Code", monospace; font-size: 0.82em; }
  .trunc { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  button.approve {
    background: #76b900;
    color: #000;
    border: none;
    padding: 0.35em 0.9em;
    border-radius: 0.3em;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.82rem;
  }
  button.approve:hover { background: #8ed600; }
  button.approve:disabled { background: #333; color: #666; cursor: default; }
  .actions-col { white-space: nowrap; }
  .pill-pr {
    display: inline-block;
    background: #1e2230;
    border-radius: 0.25em;
    padding: 0.1em 0.5em;
    font-size: 0.78rem;
    color: #76b900;
    text-decoration: none;
  }
  .pill-pr:hover { text-decoration: underline; }
  #status-bar {
    font-size: 0.8rem;
    color: #888;
    margin-bottom: 1rem;
    min-height: 1.2em;
  }
  #status-bar.error { color: #f55; }
  .toast {
    position: fixed;
    bottom: 1.5rem;
    right: 1.5rem;
    background: #1a2a3a;
    border: 1px solid #5bc8f5;
    border-radius: 0.4em;
    padding: 0.75rem 1rem;
    max-width: 420px;
    font-size: 0.85rem;
    z-index: 9999;
    display: none;
  }
  .toast.error { border-color: #f55; background: #2a1a1a; }
  .toast .close { float: right; cursor: pointer; margin-left: 0.5rem; color: #888; }
  .session-detail {
    background: #1a1d24;
    border-radius: 0.4em;
    padding: 0.75rem 1rem;
    margin: 0.25rem 0;
    font-size: 0.83rem;
    line-height: 1.6;
  }
  .session-jwt-box {
    background: #0d1117;
    border: 1px solid #5bc8f5;
    border-radius: 0.35em;
    padding: 0.5rem 0.75rem;
    margin-top: 0.5rem;
    font-family: monospace;
    font-size: 0.78rem;
    word-break: break-all;
    color: #5bc8f5;
  }
  .key { color: #888; }
  .val { color: #e0e0e0; }
  .section-header {
    font-size: 0.85rem;
    font-weight: 700;
    color: #76b900;
    margin: 1.5rem 0 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.07em;
  }
  .empty-row td { color: #555; text-align: center; padding: 2rem; }
  #refresh-counter { color: #555; }
  /* --- Identity banner (oauth2-proxy) --- */
  #identity-bar {
    font-size: 0.8rem;
    color: #888;
    margin-bottom: 1rem;
  }
  #identity-bar a { color: #5bc8f5; text-decoration: none; margin-left: 0.75rem; }
  #identity-bar a:hover { text-decoration: underline; }
  /* --- Troubleshoot panel --- */
  .ts-panel {
    background: #13161f;
    border: 1px solid #2a2d34;
    border-radius: 0.45em;
    padding: 1rem 1.25rem;
    margin-bottom: 1.5rem;
  }
  .ts-panel h2 {
    color: #5bc8f5;
    font-size: 1rem;
    margin: 0 0 0.6rem;
    font-weight: 700;
    letter-spacing: 0.04em;
  }
  .ts-goal {
    width: 100%;
    min-height: 5rem;
    background: #0d1117;
    color: #e0e0e0;
    border: 1px solid #2a2d34;
    border-radius: 0.3em;
    padding: 0.5rem 0.75rem;
    font-family: "JetBrains Mono", "Cascadia Code", monospace;
    font-size: 0.8rem;
    resize: vertical;
    box-sizing: border-box;
  }
  .ts-goal:focus { outline: 1px solid #5bc8f5; }
  button.ts-start {
    margin-top: 0.5rem;
    background: #1a3a4a;
    color: #5bc8f5;
    border: 1px solid #5bc8f5;
    padding: 0.35em 1em;
    border-radius: 0.3em;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.85rem;
  }
  button.ts-start:hover { background: #1e4a5e; }
  button.ts-start:disabled { background: #1a1d24; color: #555; border-color: #333; cursor: default; }
  #ts-status {
    font-size: 0.8rem;
    color: #888;
    margin-top: 0.4rem;
    min-height: 1.2em;
  }
  #transcript {
    margin-top: 0.75rem;
    background: #0d1117;
    border: 1px solid #2a2d34;
    border-radius: 0.35em;
    padding: 0.6rem 0.75rem;
    font-family: "JetBrains Mono", "Cascadia Code", monospace;
    font-size: 0.78rem;
    line-height: 1.55;
    color: #cdd9e5;
    max-height: 420px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-word;
    display: none;
  }
</style>
</head>
<body>
<h1>JIT Approval Console</h1>
<div id="identity-bar">Loading identity&hellip;</div>
<p class="subtitle">
  Zero-trust PoC &mdash; approve by merging the Gitea PR.
</p>

<!-- ===== Troubleshoot panel ===== -->
<div class="ts-panel">
  <h2>Troubleshoot OpenShift</h2>
  <textarea id="goal" class="ts-goal">__DEFAULT_GOAL__</textarea>
  <br>
  <button id="ts-btn" class="ts-start" onclick="startSession()">Start session</button>
  <div id="ts-status"></div>
  <pre id="transcript"></pre>
</div>

<div id="status-bar">Loading&hellip;</div>

<div class="section-header">Pending Requests</div>
<table id="pending-table">
  <thead>
    <tr>
      <th>Session ID</th>
      <th>State</th>
      <th>Requester</th>
      <th>Namespace</th>
      <th>Verbs / Resources</th>
      <th>Duration</th>
      <th>Justification</th>
      <th>PR</th>
      <th class="actions-col">Action</th>
    </tr>
  </thead>
  <tbody id="pending-body">
    <tr class="empty-row"><td colspan="9">Loading&hellip;</td></tr>
  </tbody>
</table>

<div class="section-header">All Requests</div>
<table id="all-table">
  <thead>
    <tr>
      <th>Session ID</th>
      <th>State</th>
      <th>PR</th>
      <th>Expires At</th>
    </tr>
  </thead>
  <tbody id="all-body">
    <tr class="empty-row"><td colspan="4">Loading&hellip;</td></tr>
  </tbody>
</table>

<div class="toast" id="toast">
  <span class="close" onclick="hideToast()">&times;</span>
  <div id="toast-content"></div>
</div>

<script>
// ---- Identity banner ----
(async function() {
  const bar = document.getElementById('identity-bar');
  try {
    const r = await fetch('/api/whoami');
    const d = await r.json();
    const user = d.user || 'anonymous';
    if (user === 'anonymous') {
      bar.innerHTML = 'Signed in as <b>anonymous</b> (no auth proxy detected)';
    } else {
      bar.innerHTML = 'Signed in as <b>' + user + '</b>'
        + '<a href="/oauth2/sign_out">Sign out</a>';
    }
  } catch (e) {
    bar.textContent = 'Could not resolve identity.';
  }
})();

// ---- Troubleshoot session ----
let _tsSource = null;

function _renderLine(raw) {
  try {
    const obj = JSON.parse(raw);
    const t = obj.type || '';
    if (t === 'assistant' && obj.text)      return '🤖 ' + obj.text;
    if (t === 'tool_use' && obj.tool)       return '  → tool: ' + obj.tool;
    if (t === 'tool_result')                return '  ⮭ ' + (obj.ok ? 'ok' : 'ERR') + (obj.content ? ': ' + String(obj.content).slice(0, 200) : '');
    if (t === 'result' && obj.summary)      return '✅ ' + obj.summary;
    if (t === 'error' && obj.msg)           return '❌ ' + obj.msg;
    if (t === 'stderr' && obj.msg)          return '[stderr] ' + obj.msg;
    if (t === 'system')                     return '[sys] ' + (obj.text || JSON.stringify(obj));
  } catch (_) { /* fall through */ }
  return raw;
}

async function startSession() {
  const btn = document.getElementById('ts-btn');
  const statusEl = document.getElementById('ts-status');
  const transcript = document.getElementById('transcript');
  const goal = document.getElementById('goal').value.trim();
  if (!goal) { statusEl.textContent = 'Goal cannot be empty.'; return; }

  // Close any existing SSE stream
  if (_tsSource) { _tsSource.close(); _tsSource = null; }

  btn.disabled = true;
  btn.textContent = 'Launching…';
  transcript.style.display = 'none';
  transcript.textContent = '';
  statusEl.textContent = 'Starting session…';

  let sid;
  try {
    const r = await fetch('/api/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ goal }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(JSON.stringify(data));
    sid = data.session_id;
  } catch (e) {
    statusEl.textContent = 'Launch failed: ' + e;
    btn.disabled = false;
    btn.textContent = 'Start session';
    return;
  }

  statusEl.textContent = 'Session ' + sid.slice(0, 8) + '… streaming';
  transcript.style.display = 'block';
  transcript.textContent = '';
  btn.textContent = 'Running…';

  _tsSource = new EventSource('/api/sessions/' + sid + '/stream');

  _tsSource.onmessage = function(e) {
    transcript.textContent += _renderLine(e.data) + '\\n';
    transcript.scrollTop = transcript.scrollHeight;
  };

  _tsSource.addEventListener('done', function() {
    _tsSource.close();
    _tsSource = null;
    statusEl.textContent = 'Session ' + sid.slice(0, 8) + '… complete.';
    btn.disabled = false;
    btn.textContent = 'Start session';
  });

  _tsSource.onerror = function() {
    _tsSource.close();
    _tsSource = null;
    statusEl.textContent = 'Stream error or session ended.';
    btn.disabled = false;
    btn.textContent = 'Start session';
  };
}

// ---- Requests table ----
const POLL_INTERVAL = __POLL_INTERVAL_MS__;
let _detailCache = {};
let _countdown = POLL_INTERVAL / 1000;
let _countdownTimer = null;

function badgeHtml(state) {
  return `<span class="badge badge-${state}">${state}</span>`;
}

function trunc(s, n) {
  if (!s) return '';
  s = String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function showToast(html, isError) {
  const t = document.getElementById('toast');
  document.getElementById('toast-content').innerHTML = html;
  t.className = 'toast' + (isError ? ' error' : '');
  t.style.display = 'block';
  if (!isError) {
    setTimeout(hideToast, 8000);
  }
}
function hideToast() {
  document.getElementById('toast').style.display = 'none';
}

async function fetchDetail(id) {
  if (_detailCache[id]) return _detailCache[id];
  try {
    const r = await fetch(`/api/requests/${id}/detail`);
    if (!r.ok) return null;
    const d = await r.json();
    _detailCache[id] = d;
    return d;
  } catch { return null; }
}

async function approve(id, btn) {
  btn.disabled = true;
  btn.textContent = 'Approving…';
  try {
    const r = await fetch(`/api/approve/${id}`, { method: 'POST' });
    const body = await r.json();
    if (!r.ok) {
      showToast(`<b>Approval failed</b> (${r.status}): ${JSON.stringify(body)}`, true);
    } else {
      let html = `<b>Approved!</b> PR merged for session <code>${id.slice(0, 8)}&hellip;</code><br>`;
      if (body.merge_result) {
        html += `Gitea: <code>${body.merge_result}</code><br>`;
      }
      if (body.session_state) {
        html += `Session state: ${badgeHtml(body.session_state)}<br>`;
      }
      if (body.expires_at) {
        html += `Expires: <code>${body.expires_at}</code><br>`;
      }
      if (body.session_id) {
        html += `<b>Session ID (for mcp-call):</b> <code class="mono">${body.session_id}</code><br>`;
      }
      showToast(html, false);
      // Invalidate detail cache so re-poll picks up new state
      delete _detailCache[id];
    }
  } catch (e) {
    showToast(`<b>Network error:</b> ${e}`, true);
  }
  await loadRequests();
}

async function loadRequests() {
  const sb = document.getElementById('status-bar');
  try {
    const r = await fetch('/api/requests');
    if (!r.ok) {
      sb.className = 'error';
      sb.textContent = `Error fetching requests: HTTP ${r.status}`;
      return;
    }
    const all = await r.json();
    sb.className = '';
    sb.innerHTML = `${all.length} session(s) total &nbsp; <span id="refresh-counter"></span>`;
    startCountdown();

    const pending = all.filter(s => s.state === 'pending' || s.state === 'approved');

    // --- Pending table with detail ---
    const pb = document.getElementById('pending-body');
    if (pending.length === 0) {
      pb.innerHTML = '<tr class="empty-row"><td colspan="9">No pending requests</td></tr>';
    } else {
      const rows = await Promise.all(pending.map(async s => {
        const d = await fetchDetail(s.id);
        const verbs = d ? (d.verbs || []).join(', ') : '…';
        const resources = d ? (d.resources || []).join(', ') : '…';
        const requester = d ? (d.requester_sub || '') : '';
        const ns = d ? (d.namespace || '') : '';
        const duration = d ? `${d.duration_minutes || '?'}m` : '…';
        const justification = d ? (d.justification || '') : '';
        const prUrl = s.pr_url || '';
        const prLink = prUrl
          ? `<a class="pill-pr" href="${prUrl}" target="_blank" rel="noopener">#PR</a>`
          : '&mdash;';
        const approveBtn = (s.state === 'pending' || s.state === 'approved')
          ? `<button class="approve" onclick="approve('${s.id}', this)">Approve</button>`
          : `<button class="approve" disabled>${s.state}</button>`;
        return `
          <tr>
            <td class="mono trunc" title="${s.id}">${s.id.slice(0, 8)}&hellip;</td>
            <td>${badgeHtml(s.state)}</td>
            <td class="trunc mono" title="${requester}">${trunc(requester, 30)}</td>
            <td class="mono">${ns}</td>
            <td class="mono">${trunc(verbs, 20)}<br><small style="color:#888">${trunc(resources, 20)}</small></td>
            <td class="mono">${duration}</td>
            <td class="trunc" title="${justification}">${trunc(justification, 50)}</td>
            <td>${prLink}</td>
            <td class="actions-col">${approveBtn}</td>
          </tr>`;
      }));
      pb.innerHTML = rows.join('');
    }

    // --- All requests table (summary) ---
    const ab = document.getElementById('all-body');
    if (all.length === 0) {
      ab.innerHTML = '<tr class="empty-row"><td colspan="4">No sessions yet</td></tr>';
    } else {
      ab.innerHTML = all.map(s => {
        const prUrl = s.pr_url || '';
        const prLink = prUrl
          ? `<a class="pill-pr" href="${prUrl}" target="_blank" rel="noopener">PR</a>`
          : '&mdash;';
        return `
          <tr>
            <td class="mono trunc" title="${s.id}">${s.id.slice(0, 8)}&hellip;</td>
            <td>${badgeHtml(s.state)}</td>
            <td>${prLink}</td>
            <td class="mono">${s.expires_at || '&mdash;'}</td>
          </tr>`;
      }).join('');
    }
  } catch (e) {
    sb.className = 'error';
    sb.textContent = `Network error: ${e}`;
  }
}

function startCountdown() {
  if (_countdownTimer) clearInterval(_countdownTimer);
  _countdown = POLL_INTERVAL / 1000;
  const el = document.getElementById('refresh-counter');
  if (!el) return;
  _countdownTimer = setInterval(() => {
    _countdown -= 1;
    if (el) el.textContent = `(refreshing in ${_countdown}s)`;
    if (_countdown <= 0) {
      clearInterval(_countdownTimer);
      _countdownTimer = null;
    }
  }, 1000);
}

// Initial load + polling loop
loadRequests();
setInterval(loadRequests, POLL_INTERVAL);
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """Serve the self-contained operator console page."""
    poll_ms = Config.poll_interval_seconds() * 1000
    # Escape the goal for safe injection into an HTML attribute/textarea value.
    # The goal text is placed inside a <textarea> (not an attribute), so we only
    # need to escape the HTML special characters that would break the tag.
    import html as _html_mod

    default_goal_escaped = _html_mod.escape(Config.default_goal(), quote=False)
    html = (
        _HTML.replace("__POLL_INTERVAL_MS__", str(poll_ms))
        .replace("__DEFAULT_GOAL__", default_goal_escaped)
    )
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# GET /api/requests — proxy to jit-approver
# ---------------------------------------------------------------------------


@app.get("/api/requests")
async def list_requests(state: str | None = None, sandbox: str | None = None) -> JSONResponse:
    """Proxy GET /requests to jit-approver.

    Passes through optional ?state= and ?sandbox= query params.
    Always fails closed: if jit-approver is unreachable, returns 502.
    """
    t0 = time.monotonic()
    jit_url = Config.jit_approver_url()
    params: dict[str, str] = {}
    if state:
        params["state"] = state
    if sandbox:
        params["sandbox"] = sandbox
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{jit_url}/requests",
                params=params,
                headers=_jit_headers(),
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.list_requests", actor="console", outcome="error", latency_ms=latency,
               tool_args_hash=_hash_args(params), error=str(exc))
        raise HTTPException(status_code=502, detail=f"jit-approver unreachable: {exc}") from exc

    latency = (time.monotonic() - t0) * 1000
    _audit("jit.list_requests", actor="console", outcome="allow" if resp.is_success else "error",
           latency_ms=latency, tool_args_hash=_hash_args(params))
    return JSONResponse(content=resp.json(), status_code=resp.status_code)


# ---------------------------------------------------------------------------
# GET /api/requests/{id}/detail — proxy to jit-approver
# ---------------------------------------------------------------------------


@app.get("/api/requests/{session_id}/detail")
async def get_detail(session_id: str) -> JSONResponse:
    """Proxy GET /requests/{id}/detail to jit-approver.

    Returns the full scope: requester_sub, namespace, verbs, resources,
    duration_minutes, justification, sandbox, policy_delta.
    """
    t0 = time.monotonic()
    jit_url = Config.jit_approver_url()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{jit_url}/requests/{session_id}/detail",
                headers=_jit_headers(),
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.get_detail", actor="console", outcome="error", latency_ms=latency,
               tool_args_hash=_hash_args({"session_id": session_id}), error=str(exc))
        raise HTTPException(status_code=502, detail=f"jit-approver unreachable: {exc}") from exc

    latency = (time.monotonic() - t0) * 1000
    _audit("jit.get_detail", actor="console", outcome="allow" if resp.is_success else "error",
           latency_ms=latency, tool_args_hash=_hash_args({"session_id": session_id}))
    return JSONResponse(content=resp.json(), status_code=resp.status_code)


# ---------------------------------------------------------------------------
# GET /api/requests/{id}/status — proxy to jit-approver (post-approval polling)
# ---------------------------------------------------------------------------


@app.get("/api/requests/{session_id}/status")
async def get_status(session_id: str) -> JSONResponse:
    """Proxy GET /requests/{id}/status to jit-approver.

    When state==issued this returns expires_at so the console can display it.
    Note: session_jwt and sa_token are deliberately NOT forwarded by the console
    (they arrive here but we strip them before sending to the browser — the browser
    does not need them and the console is unauthenticated in this PoC).
    """
    t0 = time.monotonic()
    jit_url = Config.jit_approver_url()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{jit_url}/requests/{session_id}/status",
                headers=_jit_headers(),
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.get_status", actor="console", outcome="error", latency_ms=latency,
               tool_args_hash=_hash_args({"session_id": session_id}), error=str(exc))
        raise HTTPException(status_code=502, detail=f"jit-approver unreachable: {exc}") from exc

    latency = (time.monotonic() - t0) * 1000
    outcome = "allow" if resp.is_success else "error"
    _audit("jit.get_status", actor="console", outcome=outcome, latency_ms=latency,
           tool_args_hash=_hash_args({"session_id": session_id}))

    if not resp.is_success:
        return JSONResponse(content=resp.json(), status_code=resp.status_code)

    data = resp.json()
    # Strip credentials — the console page is unauthenticated (PoC caveat); do
    # not forward session_jwt or sa_token to the browser.
    safe = {k: v for k, v in data.items() if k not in {"session_jwt", "sa_token", "sa_token_path"}}
    return JSONResponse(content=safe, status_code=200)


# ---------------------------------------------------------------------------
# POST /api/approve/{id} — merge the Gitea PR
# ---------------------------------------------------------------------------


@app.post("/api/approve/{session_id}")
async def approve(session_id: str, request: Request) -> JSONResponse:
    """Approve a JIT session.

    L1 default (JIT_APPROVE_VIA_MINT=true — the mint gate path):
      1. Fetch session detail from jit-approver.
      2. Validate state is {pending, approved}.
      3. Compute canonical_scope_hash(detail) — binds approver's view to stored scope.
      4. POST {approver_sub, scope_hash} to jit-approver /requests/{id}/mint.
         - approver_sub is taken from oauth2-proxy X-Forwarded-Preferred-Username
           (server-trusted Keycloak identity), NEVER from a user-controlled field.
         - jit-approver enforces approver_sub != requester_sub (M5 SoD) and
           validates scope_hash (anti-TOCTOU) before issuing credentials.
      5. Poll status once for expires_at.
      6. Map mint 403 (self-approval) to 403 with a clear message.
      The console no longer reads GITEA_TOKEN or calls the Gitea merge API.

    Fallback (JIT_APPROVE_VIA_MINT=false — legacy Gitea PR-merge path):
      Merges the PR via the Gitea API (original L0 behaviour).
      The git path is kept live as an audit mirror even when the mint gate
      is active; turning this flag off reverts to PR-merge approval.

    Returns:
      {
        "session_id": str,
        "merge_result": str | null,    # "minted" (mint path) or "merged" (git path)
        "session_state": str,
        "expires_at": str | null,
      }
    """
    t0 = time.monotonic()
    args_hash = _hash_args({"session_id": session_id})
    # Capture who is performing the approval — separation of duties from the requester.
    # _actor() reads server-trusted oauth2-proxy forwarded headers.
    approver = _actor(request)

    # Step 1: fetch session detail to get pr_url and scope.
    jit_url = Config.jit_approver_url()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            detail_resp = await client.get(
                f"{jit_url}/requests/{session_id}/detail",
                headers=_jit_headers(),
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor=approver, outcome="error",
               latency_ms=latency, tool_args_hash=args_hash, error=str(exc))
        raise HTTPException(status_code=502, detail=f"jit-approver unreachable: {exc}") from exc

    if not detail_resp.is_success:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor=approver, outcome="deny",
               latency_ms=latency, tool_args_hash=args_hash,
               error=f"detail returned {detail_resp.status_code}")
        raise HTTPException(
            status_code=detail_resp.status_code,
            detail=f"Session {session_id} not found in jit-approver",
        )

    detail = detail_resp.json()
    pr_url: str | None = detail.get("pr_url")
    state: str = detail.get("state", "unknown")

    if state not in {"pending", "approved"}:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor=approver, outcome="deny",
               latency_ms=latency, tool_args_hash=args_hash,
               error=f"session not approvable (state={state})")
        raise HTTPException(
            status_code=409,
            detail=f"Session {session_id} is in state '{state}' and cannot be approved.",
        )

    # ---------------------------------------------------------------------------
    # Mint gate path (L1 default — JIT_APPROVE_VIA_MINT=true)
    # ---------------------------------------------------------------------------
    if _approve_via_mint():
        # Step 3: compute scope_hash from the detail we fetched.
        scope_hash = _canonical_scope_hash(detail)

        # Step 4: POST to /mint with the Keycloak-resolved approver identity.
        mint_url = f"{jit_url}/requests/{session_id}/mint"
        logger.info(
            "approve.mint_gate",
            extra={"session_id": session_id, "approver": approver},
        )
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                mint_resp = await client.post(
                    mint_url,
                    headers=_mint_headers(),
                    json={
                        "approver_sub": approver,
                        "scope_hash": scope_hash,
                        "reviewed_scope": {
                            "namespace": detail.get("namespace"),
                            "verbs": detail.get("verbs"),
                            "resources": detail.get("resources"),
                            "duration_minutes": detail.get("duration_minutes"),
                        },
                    },
                )
        except httpx.RequestError as exc:
            latency = (time.monotonic() - t0) * 1000
            _audit("jit.approve", actor=approver, outcome="error",
                   latency_ms=latency, tool_args_hash=args_hash, error=str(exc))
            raise HTTPException(status_code=502, detail=f"jit-approver unreachable: {exc}") from exc

        if mint_resp.status_code == 403:
            # Self-approval or SoD violation — surface clearly to browser.
            latency = (time.monotonic() - t0) * 1000
            _audit("jit.approve", actor=approver, outcome="deny",
                   latency_ms=latency, tool_args_hash=args_hash,
                   error="mint gate: self-approval denied (M5)")
            detail_text = ""
            try:
                detail_text = mint_resp.json().get("detail", "")
            except Exception:  # noqa: BLE001
                detail_text = mint_resp.text[:200]
            raise HTTPException(
                status_code=403,
                detail=f"You cannot approve your own request (self-approval denied). {detail_text}",
            )

        if not mint_resp.is_success:
            latency = (time.monotonic() - t0) * 1000
            _audit("jit.approve", actor=approver, outcome="error",
                   latency_ms=latency, tool_args_hash=args_hash,
                   error=f"mint returned {mint_resp.status_code}: {mint_resp.text[:200]}")
            raise HTTPException(
                status_code=mint_resp.status_code,
                detail=f"Mint gate failed: {mint_resp.text[:400]}",
            )

        logger.info("approve.minted", extra={"session_id": session_id, "approver": approver})

        # Step 5: status poll to surface expires_at.
        session_state: str = "issued"
        expires_at: str | None = None
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                status_resp = await client.get(
                    f"{jit_url}/requests/{session_id}/status",
                    headers=_jit_headers(),
                )
            if status_resp.is_success:
                status_data = status_resp.json()
                session_state = status_data.get("state", "issued")
                expires_at = status_data.get("expires_at")
        except Exception:  # noqa: BLE001 — best-effort poll
            pass

        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor=approver, outcome="allow",
               latency_ms=latency, tool_args_hash=args_hash,
               session_state=session_state, via="mint_gate")

        return JSONResponse(
            content={
                "session_id": session_id,
                "pr_number": None,
                "pr_url": pr_url,
                "merge_result": "minted",
                "session_state": session_state,
                "expires_at": expires_at,
            },
            status_code=200,
        )

    # ---------------------------------------------------------------------------
    # Legacy Gitea PR-merge path (JIT_APPROVE_VIA_MINT=false)
    # ---------------------------------------------------------------------------
    if not pr_url:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor=approver, outcome="deny",
               latency_ms=latency, tool_args_hash=args_hash, error="no pr_url on session")
        raise HTTPException(
            status_code=422,
            detail=f"Session {session_id} has no PR URL — cannot approve.",
        )

    # Step 2: parse PR number from URL (matches _extract_pr_number in api.py)
    try:
        pr_number = int(pr_url.rstrip("/").rsplit("/", 1)[-1])
    except (ValueError, IndexError) as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor=approver, outcome="error",
               latency_ms=latency, tool_args_hash=args_hash,
               error=f"cannot parse PR number from {pr_url!r}")
        raise HTTPException(
            status_code=422,
            detail=f"Cannot parse PR number from pr_url {pr_url!r}: {exc}",
        ) from exc

    owner = Config.gitea_owner()
    repo = Config.gitea_repo()
    gitea_url = Config.gitea_url().rstrip("/")

    # Step 3: merge the PR via Gitea API
    merge_url = f"{gitea_url}/api/v1/repos/{owner}/{repo}/pulls/{pr_number}/merge"
    logger.info(
        "approve.merging_pr",
        extra={"session_id": session_id, "pr_number": pr_number, "owner": owner, "repo": repo},
    )
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            merge_resp = await client.post(
                merge_url,
                headers=_gitea_headers(),
                json={
                    "Do": "merge",
                    "merge_message_field": f"Approve JIT grant for session {session_id}",
                },
            )
    except httpx.RequestError as exc:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor=approver, outcome="error",
               latency_ms=latency, tool_args_hash=args_hash, error=str(exc))
        raise HTTPException(status_code=502, detail=f"Gitea unreachable: {exc}") from exc

    if not merge_resp.is_success:
        latency = (time.monotonic() - t0) * 1000
        _audit("jit.approve", actor=approver, outcome="error",
               latency_ms=latency, tool_args_hash=args_hash,
               error=f"Gitea merge returned {merge_resp.status_code}: {merge_resp.text[:200]}")
        raise HTTPException(
            status_code=merge_resp.status_code,
            detail=f"Gitea merge failed: {merge_resp.text[:400]}",
        )

    logger.info("approve.merged", extra={"session_id": session_id, "pr_number": pr_number})

    # Step 4: quick status poll — Gitea fires the webhook asynchronously so the
    # session may still show 'pending' immediately. We return what we have and the
    # browser's polling loop picks up the transition to 'issued'.
    session_state_legacy: str = state
    expires_at_legacy: str | None = None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            status_resp = await client.get(
                f"{jit_url}/requests/{session_id}/status",
                headers=_jit_headers(),
            )
        if status_resp.is_success:
            status_data = status_resp.json()
            session_state_legacy = status_data.get("state", state)
            expires_at_legacy = status_data.get("expires_at")
    except Exception:  # noqa: BLE001 — best-effort post-merge poll
        pass

    latency = (time.monotonic() - t0) * 1000
    _audit("jit.approve", actor=approver, outcome="allow",
           latency_ms=latency, tool_args_hash=args_hash,
           pr_number=pr_number, session_state=session_state_legacy, via="gitea_merge")

    return JSONResponse(
        content={
            "session_id": session_id,
            "pr_number": pr_number,
            "pr_url": pr_url,
            "merge_result": "merged",
            "session_state": session_state_legacy,
            "expires_at": expires_at_legacy,
        },
        status_code=200,
    )


# ---------------------------------------------------------------------------
# POST /api/sessions — launch a troubleshoot agent session
# ---------------------------------------------------------------------------


@app.post("/api/sessions")
async def create_session(request: Request, body: dict[str, Any] | None = None) -> JSONResponse:
    """Launch the Claude agent in the harness pod and return a streaming session ID.

    The agent is exec'd inside the running e2e-harness pod (namespace agent-sandbox,
    container agent).  Its stdout (one JSON object per line) is pumped into an
    in-memory buffer that /api/sessions/{sid}/stream fans out via SSE.

    Body (optional JSON): {"goal": "<natural-language goal>"}
    If goal is omitted the default troubleshoot goal from Config is used.

    The authenticated human identity (from oauth2-proxy headers) is forwarded into
    the agent execution environment as AGENT_USER so mcp-call can file the JIT
    request under the requester's real identity rather than the sandbox SVID.
    """
    goal = ""
    if body and isinstance(body.get("goal"), str):
        goal = body["goal"].strip()
    if not goal:
        goal = Config.default_goal()

    actor = _actor(request)
    sid = _new_session(goal, owner=actor)
    _launch_agent_thread(sid, goal, actor=actor)

    _audit(
        "agent.session_created",
        actor=actor,
        outcome="allow",
        latency_ms=0,
        tool_args_hash=_hash_args({"goal": goal}),
        session_id=sid,
    )
    return JSONResponse(content={"session_id": sid}, status_code=202)


# ---------------------------------------------------------------------------
# GET /api/whoami — return the authenticated user's identity
# ---------------------------------------------------------------------------


@app.get("/api/whoami")
async def whoami(request: Request) -> JSONResponse:
    """Return the authenticated human's identity as resolved from oauth2-proxy headers.

    The response is intentionally minimal — it is consumed by the browser's
    identity banner JS and has no security gate function (that is the proxy's job).

    Returns: {"user": "<username>"}  where username is "anonymous" when no proxy
    headers are present (local development / no sidecar).
    """
    return JSONResponse(content={"user": _actor(request)})


# ---------------------------------------------------------------------------
# GET /api/sessions/{sid}/stream — SSE transcript stream
# ---------------------------------------------------------------------------


@app.get("/api/sessions/{sid}/stream")
async def stream_session(sid: str) -> StreamingResponse:
    """Server-Sent Events stream for a running (or completed) agent session.

    Each agent stdout line is emitted as one SSE event:
        data: <raw JSON line>\\n\\n

    When all lines have been sent and the session is marked done, a final
    termination event is sent:
        event: done\\ndata: {}\\n\\n

    The generator uses time.sleep (0.5 s poll interval); FastAPI/Starlette
    runs sync generators in a thread pool so this does not block the event loop.
    """
    session = _get_session(sid)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {sid!r} not found")

    def _gen():  # type: ignore[no-untyped-def]
        idx = 0
        idle = 0
        while True:
            with _SESSIONS_LOCK:
                lines = _SESSIONS[sid]["lines"]
                done = _SESSIONS[sid]["done"]
                pending = lines[idx:]
                idx_new = len(lines)

            for ln in pending:
                yield f"data: {ln}\n\n"

            if pending:
                idx = idx_new
                idle = 0
            else:
                # No new lines (e.g. the agent is blocked waiting for human approval).
                # Emit an SSE comment heartbeat every ~10s so the OpenShift router /
                # oauth2-proxy don't time out the idle connection and cut the stream.
                idle += 1
                if idle >= 20:
                    yield ": keepalive\n\n"
                    idle = 0

            if done and idx >= idx_new:
                # All lines drained and session finished
                yield "event: done\ndata: {}\n\n"
                return

            time.sleep(0.5)

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# GET /api/sessions — list all in-memory agent sessions
# ---------------------------------------------------------------------------


@app.get("/api/sessions")
async def list_sessions() -> JSONResponse:
    """Return a summary list of all in-memory agent sessions (newest first)."""
    with _SESSIONS_LOCK:
        items = [
            {
                "session_id": sid,
                "done": data["done"],
                "lines": len(data["lines"]),
                "goal": data["goal"],
            }
            for sid, data in sorted(
                _SESSIONS.items(), key=lambda kv: kv[1]["seq"], reverse=True
            )
        ]
    return JSONResponse(content=items)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "approval-console"}


# ---------------------------------------------------------------------------
# Phase C — product console routers (living agents / skills / webshell / UI)
# Wired here (mirrors tests/test_agents.py) so a single console image serves the
# legacy JIT-approval UI AND the agent-platform endpoints.
# ---------------------------------------------------------------------------
from approval_console.agents.routes import router as _agents_router  # noqa: E402
from approval_console.skills.routes import router as _skills_router  # noqa: E402
from approval_console.ui.routes import router as _ui_router  # noqa: E402
from approval_console.webshell.routes import router as _webshell_router  # noqa: E402

app.include_router(_agents_router)
app.include_router(_skills_router)
app.include_router(_ui_router)
app.include_router(_webshell_router)

# ---------------------------------------------------------------------------
# Static assets (vendored xterm.js) — served SAME-ORIGIN at /static.
# This eliminates the parser-blocking, cross-site document.write of CDN <script>
# tags that the browser warned about (and that broke the webshell input wiring).
# The webshell popup page (GET /api/agents/{id}/webshell/ui) references these
# local files with normal <script src="/static/xterm.min.js"> tags.
# ---------------------------------------------------------------------------
_STATIC_DIR = _os_mod.path.join(_os_mod.path.dirname(__file__), "static")
if _os_mod.path.isdir(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}',
    )
    uvicorn.run(
        "approval_console.app:app",
        host="0.0.0.0",
        port=8090,
        log_config=None,
    )


if __name__ == "__main__":
    main()
