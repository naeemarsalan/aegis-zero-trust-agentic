"""FastAPI router for the persistent-agent API (C1).

Mounted at /api/agents.  All cluster-mutating actions (sandbox creation, PVC creation)
are behind a call to the sandbox-launcher service, which is dependency-injected so tests
can monkeypatch it without a live cluster.

Security contract:
  - owner is always resolved from the oauth2-proxy Keycloak header (_actor()), never
    from a user-controlled field in the request body.
  - Archive and delete require the actor to be the owner OR have role 'console-admin'
    (resolved from X-Forwarded-Groups header).
  - Hard delete (DELETE /api/agents/{id}) requires confirmed=true in the query string.
  - Fail-closed: if sandbox-launcher is unreachable, return 502 and do NOT create an Agent.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import time
import uuid
from typing import Any, Callable

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from approval_console.agents import models as agent_models
from approval_console.agents import store as agent_store

logger = logging.getLogger("approval_console.agents.routes")

router = APIRouter(prefix="/api/agents", tags=["agents"])

# ---------------------------------------------------------------------------
# Dependency: actor resolution (mirrors app._actor)
# ---------------------------------------------------------------------------


def _actor(request: Request) -> str:
    for header in (
        "x-forwarded-preferred-username",
        "x-forwarded-email",
        "x-forwarded-user",
    ):
        value = request.headers.get(header, "").strip()
        if value:
            return value
    return "anonymous"


def _is_admin(request: Request) -> bool:
    groups = request.headers.get("x-forwarded-groups", "")
    return "console-admin" in groups.split(",")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_args(args: Any) -> str:
    raw = json.dumps(args, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def _audit(event: str, actor: str, outcome: str, latency_ms: float, **extra: Any) -> None:
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


def _require_owner_or_admin(agent: agent_models.Agent, actor: str, is_admin: bool) -> None:
    """Raise 403 if actor is not the agent's owner and not an admin."""
    if actor != agent.owner and not is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Actor {actor!r} is not the owner of agent {agent.agent_id!r}.",
        )


# ---------------------------------------------------------------------------
# Sandbox-launcher client (injected for testability)
# ---------------------------------------------------------------------------
#
# In production this calls the sandbox-launcher's POST /launch HTTP endpoint.
# In unit tests it is monkeypatched to return a stub sandbox_id without cluster access.
# The URL is read from the SANDBOX_LAUNCHER_URL env var at call time (lazy, like Config).
#

import os as _os

# The MCP-helper skill — the mcp-call helper that drives the zero-trust gateway
# (read returns immediately; write fires the JIT approval). It lives baked into the
# agent-harness image's .claude/skills (services/agent-sandbox/agent-harness) AND can
# be loaded from the central skills repo. Every new agent gets it by default so the
# brain can reach the real tools out of the box. Override the name via
# DEFAULT_MCP_SKILL (e.g. to 'list-firewall-rules' or 'openshift-troubleshoot').
DEFAULT_MCP_SKILL = _os.environ.get("DEFAULT_MCP_SKILL", "pfsense-firewall").strip() or "pfsense-firewall"


def _with_default_skill(skills: list[str]) -> list[str]:
    """Ensure the mcp-helper skill is present; default it in when skills is empty.

    If the caller passes any skills, respect them but still guarantee the mcp-helper
    is included (so the brain can always reach the gateway). If none are passed, the
    result is just [DEFAULT_MCP_SKILL].
    """
    cleaned = [s.strip() for s in (skills or []) if s and s.strip()]
    if DEFAULT_MCP_SKILL not in cleaned:
        cleaned.insert(0, DEFAULT_MCP_SKILL)
    return cleaned


def _sandbox_launcher_url() -> str:
    url = _os.environ.get("SANDBOX_LAUNCHER_URL", "").strip()
    if not url:
        raise RuntimeError(
            "SANDBOX_LAUNCHER_URL is not set. "
            "Set it to http://sandbox-launcher.openshell.svc.cluster.local:8080"
        )
    return url


async def _create_sandbox(
    agent_id: str,
    owner: str,
    skills: list[str],
    harness_image: str = "",
) -> dict[str, str]:
    """Call sandbox-launcher POST /launch and return {sandbox_name, sandbox_id}.

    Fails closed: raises HTTPException(502) if launcher is unreachable.
    This function is extracted so tests can monkeypatch it on the module.

    `skills` is threaded both as `capabilities` (the launcher's required field) and
    as `skills` (the field the launcher turns into the agents.x-k8s.io/skills
    podTemplate annotation, which the skills-loader Kyverno policy reads).
    `harness_image`, when set, selects the brain image.
    """
    url = _sandbox_launcher_url()
    payload: dict[str, Any] = {
        "goal": f"Persistent agent {agent_id} (owner: {owner})",
        "capabilities": skills if skills else ["openshift-troubleshoot"],
        "skills": skills,
        "mode": "project",
        "userRef": owner,
        "confirmed": True,
        "ttlMinutes": 480,
    }
    if harness_image:
        payload["harnessImage"] = harness_image
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{url}/launch", json=payload)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"sandbox-launcher unreachable: {exc}") from exc
    if not resp.is_success:
        raise HTTPException(
            status_code=502,
            detail=f"sandbox-launcher returned {resp.status_code}: {resp.text[:200]}",
        )
    data = resp.json()
    return {
        "sandbox_name": data.get("sandbox_name", ""),
        "sandbox_id": data.get("sandbox_id", ""),
    }


# ---------------------------------------------------------------------------
# POST /api/agents — create a persistent agent
# ---------------------------------------------------------------------------


async def _write_consent_grant(sandbox_id: str, user: str, scope: str) -> bool:
    """Write the per-sandbox Vault consent grant (ext-proc's on-behalf-of source).

    Mirrors hack/run-agent.sh: integer-typed JSON to secret/data/sandbox-grants/<uid>.
    Reads VAULT_ADDR + VAULT_TOKEN from the console env; returns False if unconfigured.
    The user's token is never stored — only this {user, scope} consent record.
    """
    import os as _os
    import secrets as _secrets
    import datetime as _dt

    addr = _os.environ.get("VAULT_ADDR", "").strip().rstrip("/")
    tok = _os.environ.get("VAULT_TOKEN", "").strip()
    if not (addr and tok and sandbox_id):
        return False
    username = user.rsplit("/", 1)[-1]  # 'user:default/arsalan' or 'arsalan' -> 'arsalan'
    payload = {
        "data": {
            "version": 1,
            "sandbox_uid": sandbox_id,
            "user": username,
            "scope": scope,
            "ttl": 3600,
            "nonce": _secrets.token_hex(16),
            "created": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        }
    }
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp = await client.post(
            f"{addr}/v1/secret/data/sandbox-grants/{sandbox_id}",
            headers={"X-Vault-Token": tok},
            json=payload,
        )
    return resp.status_code < 300


@router.post("", status_code=201)
async def create_agent(
    request: Request,
    body: agent_models.CreateAgentRequest,
) -> JSONResponse:
    """Create a persistent Agent.

    Steps (cluster mutations are GATED — see Phase C plan):
      1. Resolve owner from Keycloak headers.
      2. [GATED] Call sandbox-launcher to provision the OpenShell sandbox.
      3. [GATED] Create per-agent Gitea repo (C2).
      4. Write Agent{state=PROVISIONING} to the in-memory store.
      5. Return agent_id immediately; client polls GET /api/agents/{id} for state=READY.

    In tests, sandbox-launcher and Gitea calls are monkeypatched on this module.
    """
    t0 = time.monotonic()
    actor = _actor(request)
    agent_id = uuid.uuid4().hex

    # Default-in the mcp-helper skill: every new agent gets it (pre-ticked in the
    # form, and enforced server-side here even if the client omits it) so the brain
    # can reach the real tools through the gateway out of the box.
    effective_skills = _with_default_skill(body.skills)

    args_hash = _hash_args({"display_name": body.display_name, "skills": effective_skills})

    # Step 2: provision sandbox (GATED — no-op if SANDBOX_LAUNCHER_URL unset in tests)
    sandbox_info: dict[str, str] = {"sandbox_name": "", "sandbox_id": ""}
    try:
        sandbox_info = await _create_sandbox(
            agent_id, actor, effective_skills, body.harness_image
        )
    except HTTPException:
        raise
    except RuntimeError as exc:
        # SANDBOX_LAUNCHER_URL not set — treat as unconfigured (PoC: allow store write)
        logger.warning("agents.create.sandbox_launcher_unset: %s", exc)

    # Step 2b: write the Vault consent grant so the agent can delegate-as-the-user.
    # ext-proc reads secret/data/sandbox-grants/<sandbox_uid> by the SVID's uuid segment
    # and exchanges to sub=<user> (the on-behalf-of leg). Without it the agent boots but its
    # mcp-call cannot delegate (grant_result=invalid). Best-effort; never fails the launch.
    _sid = sandbox_info.get("sandbox_id", "")
    if _sid:
        try:
            _scope = getattr(body, "scope", None)
            _scope_str = str(getattr(_scope, "value", _scope) or "read-only")
            _ok = await _write_consent_grant(_sid, actor, _scope_str)
            logger.info("agents.create.grant_write sandbox_id=%s ok=%s", _sid, _ok)
        except Exception as exc:  # noqa: BLE001 — grant write is best-effort
            logger.warning("agents.create.grant_write_error: %s", exc)

    # Step 3: create Gitea repo (C2) — delegated to gitea.client; monkeypatched in tests.
    gitea_repo_url = ""
    try:
        from approval_console.gitea import client as gitea_client  # type: ignore[import]
        repo = await gitea_client.create_agent_repo(agent_id=agent_id, owner_username=actor)
        gitea_repo_url = repo.html_url
    except Exception as exc:  # noqa: BLE001 — Gitea is best-effort at creation time
        logger.warning("agents.create.gitea_error: %s", exc)

    # Step 4: write to store
    agent = agent_models.Agent(
        agent_id=agent_id,
        display_name=body.display_name,
        owner=actor,
        sandbox_name=sandbox_info.get("sandbox_name", ""),
        sandbox_id=sandbox_info.get("sandbox_id", ""),
        pvc_name=f"{agent_id}-workspace",
        gitea_repo=gitea_repo_url,
        skills=effective_skills,
        state=agent_models.AgentState.PROVISIONING,
    )
    agent_store.create_agent(agent)

    latency = (time.monotonic() - t0) * 1000
    _audit(
        "agent.create",
        actor=actor,
        outcome="allow",
        latency_ms=latency,
        tool_args_hash=args_hash,
        agent_id=agent_id,
    )

    return JSONResponse(
        content=agent.model_dump(mode="json"),
        status_code=201,
    )


# ---------------------------------------------------------------------------
# GET /api/agents — list agents
# ---------------------------------------------------------------------------


@router.get("")
async def list_agents(request: Request, all_agents: bool = Query(False)) -> JSONResponse:
    """List agents.

    By default, returns only agents owned by the authenticated user.
    Set ?all_agents=true to see all agents (admin only).
    """
    actor = _actor(request)
    is_admin_user = _is_admin(request)

    if all_agents and not is_admin_user:
        raise HTTPException(status_code=403, detail="all_agents=true requires console-admin role")

    owner_filter = None if (all_agents and is_admin_user) else actor
    agents = agent_store.list_agents(owner=owner_filter)
    return JSONResponse(content=[a.model_dump(mode="json") for a in agents])


# ---------------------------------------------------------------------------
# GET /api/agents/{agent_id} — get agent detail
# ---------------------------------------------------------------------------


@router.get("/{agent_id}")
async def get_agent(agent_id: str, request: Request) -> JSONResponse:
    actor = _actor(request)
    is_admin_user = _is_admin(request)

    agent = agent_store.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found")

    if actor != agent.owner and not is_admin_user:
        raise HTTPException(status_code=403, detail="Access denied")

    sessions = agent_store.list_agent_sessions(agent_id)
    data = agent.model_dump(mode="json")
    data["sessions"] = [s.model_dump(mode="json") for s in sessions]
    return JSONResponse(content=data)


# ---------------------------------------------------------------------------
# POST /api/agents/{agent_id}/sessions — launch a session under an agent
# ---------------------------------------------------------------------------


@router.post("/{agent_id}/sessions", status_code=202)
async def create_agent_session(
    agent_id: str,
    request: Request,
    body: dict[str, str] | None = None,
) -> JSONResponse:
    """Launch a new task session under a persistent Agent.

    Delegates execution to the proven _do_k8s_exec path in app.py (via the shared
    _SESSIONS map and _launch_agent_thread).  The session_id is returned immediately;
    the caller subscribes to /api/agents/{id}/sessions/{sid}/stream for the transcript.
    """
    actor = _actor(request)
    agent = agent_store.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found")

    if agent.state not in {agent_models.AgentState.READY, agent_models.AgentState.PROVISIONING}:
        raise HTTPException(
            status_code=409,
            detail=f"Agent {agent_id!r} is in state {agent.state.value} and cannot accept sessions.",
        )

    if actor != agent.owner and not _is_admin(request):
        raise HTTPException(status_code=403, detail="Access denied")

    goal = ""
    if body and isinstance(body.get("goal"), str):
        goal = body["goal"].strip()
    if not goal:
        raise HTTPException(status_code=422, detail="goal is required")

    # Reuse the session infrastructure from the main app module.
    from approval_console.app import (  # type: ignore[import]
        _new_session,
        _launch_agent_thread,
        _launch_native_agent_thread,
    )

    sid = _new_session(goal, owner=actor)

    # Phase C: if this agent owns a native OpenShell sandbox, run the session
    # INSIDE that sandbox (so ext-proc delegates against the agent's own SVID +
    # Vault consent grant). Otherwise fall back to the legacy shared e2e-harness
    # exec path (backward compat with pre-Phase-C agents that have no sandbox).
    if agent.sandbox_name:
        _launch_native_agent_thread(
            sid,
            goal,
            actor=actor,
            sandbox_name=agent.sandbox_name,
            sandbox_id=agent.sandbox_id,
        )
    else:
        _launch_agent_thread(sid, goal, actor=actor)

    agent_session = agent_models.AgentSession(
        session_id=sid,
        agent_id=agent_id,
        goal=goal,
    )
    agent_store.create_agent_session(agent_session)

    _audit(
        "agent.session_created",
        actor=actor,
        outcome="allow",
        latency_ms=0,
        tool_args_hash=_hash_args({"goal": goal, "agent_id": agent_id}),
        agent_id=agent_id,
        session_id=sid,
    )

    return JSONResponse(content={"session_id": sid, "agent_id": agent_id}, status_code=202)


# ---------------------------------------------------------------------------
# POST /api/agents/{agent_id}/archive
# ---------------------------------------------------------------------------


@router.post("/{agent_id}/archive")
async def archive_agent(agent_id: str, request: Request) -> JSONResponse:
    """Soft-archive an agent: state → ARCHIVED, Gitea repo renamed."""
    t0 = time.monotonic()
    actor = _actor(request)
    is_admin_user = _is_admin(request)

    agent = agent_store.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found")

    _require_owner_or_admin(agent, actor, is_admin_user)

    if agent.state == agent_models.AgentState.ARCHIVED:
        return JSONResponse(
            content={"agent_id": agent_id, "state": "ARCHIVED", "detail": "already archived"},
        )

    archived_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    updated = agent_store.archive_agent(agent_id, archived_at=archived_at)

    # Rename Gitea repo (best-effort; non-fatal if Gitea is unreachable).
    if agent.gitea_repo:
        try:
            from approval_console.gitea import client as gitea_client  # type: ignore[import]
            date_suffix = archived_at[:10].replace("-", "")
            new_name = f"{agent_id}-archived-{date_suffix}"
            # full_name = org/agent_id
            org = _os.environ.get("GITEA_ORG", "agents")
            await gitea_client.archive_repo(
                repo_full_name=f"{org}/{agent_id}",
                archived_name=new_name,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("agents.archive.gitea_rename_failed: %s", exc)

    latency = (time.monotonic() - t0) * 1000
    _audit(
        "agent.archive",
        actor=actor,
        outcome="allow",
        latency_ms=latency,
        tool_args_hash=_hash_args({"agent_id": agent_id}),
        agent_id=agent_id,
    )

    return JSONResponse(content=updated.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# DELETE /api/agents/{agent_id} — hard-delete (gated, requires confirmed=true)
# ---------------------------------------------------------------------------


@router.delete("/{agent_id}", status_code=200)
async def delete_agent(
    agent_id: str,
    request: Request,
    confirmed: bool = Query(False),
) -> JSONResponse:
    """Hard-delete an agent.  Requires confirmed=true and owner or admin."""
    actor = _actor(request)
    is_admin_user = _is_admin(request)

    if not confirmed:
        raise HTTPException(
            status_code=400,
            detail="confirmed=true is required for hard-delete.",
        )

    agent = agent_store.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found")

    _require_owner_or_admin(agent, actor, is_admin_user)

    # Hard-delete Gitea repo (best-effort).
    if agent.gitea_repo:
        try:
            from approval_console.gitea import client as gitea_client  # type: ignore[import]
            org = _os.environ.get("GITEA_ORG", "agents")
            await gitea_client.delete_repo(repo_full_name=f"{org}/{agent_id}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("agents.delete.gitea_delete_failed: %s", exc)

    agent_store.delete_agent(agent_id)

    _audit(
        "agent.delete",
        actor=actor,
        outcome="allow",
        latency_ms=0,
        tool_args_hash=_hash_args({"agent_id": agent_id}),
        agent_id=agent_id,
    )

    return JSONResponse(content={"agent_id": agent_id, "deleted": True})
