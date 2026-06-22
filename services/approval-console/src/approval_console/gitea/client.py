"""Async Gitea API client stub for per-agent repo management (C2).

All operations:
  - fail closed: any non-2xx Gitea response raises GiteaClientError.
  - emit a structured audit log line (event, actor, outcome, latency_ms, tool_args_hash).
  - never log raw tool arguments — sha256 hash only.
  - read the admin token from Config.gitea_token() (server-side only; never forwarded).

Config (read from env at call time — lazy, like the rest of the console):
  GITEA_URL      — base URL (already required by the console, e.g. https://git.arsalan.io)
  GITEA_TOKEN    — admin token (server-side only)
  GITEA_ORG      — org under which agent repos are created (default: "agents")

The org is created if it does not exist.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import time

import httpx

from approval_console.gitea.models import GiteaDeployKey, GiteaRepo

logger = logging.getLogger("approval_console.gitea.client")


class GiteaClientError(Exception):
    """Raised on any Gitea API error (non-2xx response or network failure)."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _gitea_url() -> str:
    url = os.environ.get("GITEA_URL", "").strip()
    if not url:
        raise RuntimeError("GITEA_URL is not set")
    return url.rstrip("/")


def _gitea_token() -> str:
    # Reuse Config.gitea_token() logic: env var takes priority, then file.
    token = os.environ.get("GITEA_TOKEN", "").strip()
    if token:
        return token
    try:
        with open("/vault/secrets/gitea-token") as fh:
            return fh.read().strip()
    except FileNotFoundError:
        raise RuntimeError("GITEA_TOKEN env var not set and /vault/secrets/gitea-token not found.")


def _gitea_org() -> str:
    return os.environ.get("GITEA_ORG", "agents")


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"token {_gitea_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _hash(args: object) -> str:
    raw = json.dumps(args, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def _audit(event: str, actor: str, outcome: str, latency_ms: float, **extra: object) -> None:
    record: dict[str, object] = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event,
        "actor": actor,
        "namespace": "gitea",
        "outcome": outcome,
        "latency_ms": round(latency_ms, 2),
    }
    record.update(extra)
    logger.info(json.dumps(record))


# ---------------------------------------------------------------------------
# Org bootstrap (idempotent)
# ---------------------------------------------------------------------------


async def _ensure_org(org: str) -> None:
    """Create the Gitea org if it does not exist (idempotent)."""
    base = _gitea_url()
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{base}/api/v1/orgs/{org}", headers=_headers())
    if resp.status_code == 200:
        return
    if resp.status_code != 404:
        raise GiteaClientError(
            f"Unexpected response checking org {org!r}: {resp.status_code} {resp.text[:200]}",
            status_code=resp.status_code,
        )
    # Create org.
    async with httpx.AsyncClient(timeout=10.0) as client:
        cr = await client.post(
            f"{base}/api/v1/orgs",
            headers=_headers(),
            json={"username": org, "visibility": "private"},
        )
    if not cr.is_success:
        raise GiteaClientError(
            f"Failed to create Gitea org {org!r}: {cr.status_code} {cr.text[:200]}",
            status_code=cr.status_code,
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def create_agent_repo(agent_id: str, owner_username: str) -> GiteaRepo:
    """Create a private Gitea repo named <agent_id> under GITEA_ORG.

    Creates the org if absent.  Returns GiteaRepo.
    Fails closed: raises GiteaClientError on any non-2xx response.
    """
    t0 = time.monotonic()
    org = _gitea_org()
    base = _gitea_url()
    args_hash = _hash({"agent_id": agent_id, "org": org})

    try:
        await _ensure_org(org)

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base}/api/v1/orgs/{org}/repos",
                headers=_headers(),
                json={
                    "name": agent_id,
                    "description": f"Agent workspace — owner: {owner_username}",
                    "private": True,
                    "auto_init": True,
                    "default_branch": "main",
                },
            )
        if not resp.is_success:
            raise GiteaClientError(
                f"Failed to create repo {org}/{agent_id}: {resp.status_code} {resp.text[:200]}",
                status_code=resp.status_code,
            )
        repo = GiteaRepo.model_validate(resp.json())
        latency = (time.monotonic() - t0) * 1000
        _audit(
            "gitea.create.repo",
            actor=owner_username,
            outcome="allow",
            latency_ms=latency,
            tool_args_hash=args_hash,
        )
        return repo

    except GiteaClientError:
        latency = (time.monotonic() - t0) * 1000
        _audit(
            "gitea.create.repo",
            actor=owner_username,
            outcome="error",
            latency_ms=latency,
            tool_args_hash=args_hash,
        )
        raise


async def create_deploy_key(
    repo_full_name: str,
    agent_id: str,
    public_key: str,
    read_only: bool = True,
) -> GiteaDeployKey:
    """Add a deploy key to the repo.

    repo_full_name: "org/agent_id"
    public_key: ed25519 public key in OpenSSH authorized_keys format.
    Raises GiteaClientError on failure.
    """
    t0 = time.monotonic()
    base = _gitea_url()
    args_hash = _hash({"repo": repo_full_name, "agent_id": agent_id})

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{base}/api/v1/repos/{repo_full_name}/keys",
            headers=_headers(),
            json={
                "title": f"agent-{agent_id}",
                "key": public_key,
                "read_only": read_only,
            },
        )
    latency = (time.monotonic() - t0) * 1000
    if not resp.is_success:
        _audit(
            "gitea.create.deploy_key",
            actor="console",
            outcome="error",
            latency_ms=latency,
            tool_args_hash=args_hash,
        )
        raise GiteaClientError(
            f"Failed to create deploy key for {repo_full_name}: {resp.status_code} {resp.text[:200]}",
            status_code=resp.status_code,
        )
    _audit(
        "gitea.create.deploy_key",
        actor="console",
        outcome="allow",
        latency_ms=latency,
        tool_args_hash=args_hash,
    )
    return GiteaDeployKey.model_validate(resp.json())


async def archive_repo(repo_full_name: str, archived_name: str) -> None:
    """Rename and archive a repo (soft-delete on agent archive).

    Renames to archived_name and sets archived=true via PATCH /repos/{owner}/{repo}.
    Non-fatal if already archived.
    """
    t0 = time.monotonic()
    base = _gitea_url()
    args_hash = _hash({"repo": repo_full_name, "new_name": archived_name})

    # Parse owner/name from full_name.
    parts = repo_full_name.split("/", 1)
    if len(parts) != 2:
        raise GiteaClientError(f"Invalid repo_full_name: {repo_full_name!r}")
    owner, old_name = parts

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.patch(
            f"{base}/api/v1/repos/{owner}/{old_name}",
            headers=_headers(),
            json={"name": archived_name, "archived": True},
        )
    latency = (time.monotonic() - t0) * 1000
    if not resp.is_success:
        _audit(
            "gitea.archive.repo",
            actor="console",
            outcome="error",
            latency_ms=latency,
            tool_args_hash=args_hash,
        )
        raise GiteaClientError(
            f"Failed to archive repo {repo_full_name}: {resp.status_code} {resp.text[:200]}",
            status_code=resp.status_code,
        )
    _audit(
        "gitea.archive.repo",
        actor="console",
        outcome="allow",
        latency_ms=latency,
        tool_args_hash=args_hash,
    )


async def delete_repo(repo_full_name: str) -> None:
    """Hard-delete a repo.  Only called from the gated DELETE /api/agents/{id} route."""
    t0 = time.monotonic()
    base = _gitea_url()
    args_hash = _hash({"repo": repo_full_name})

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.delete(
            f"{base}/api/v1/repos/{repo_full_name}",
            headers=_headers(),
        )
    latency = (time.monotonic() - t0) * 1000
    outcome = "allow" if resp.is_success else "error"
    _audit(
        "gitea.delete.repo",
        actor="console",
        outcome=outcome,
        latency_ms=latency,
        tool_args_hash=args_hash,
    )
    if not resp.is_success:
        raise GiteaClientError(
            f"Failed to delete repo {repo_full_name}: {resp.status_code} {resp.text[:200]}",
            status_code=resp.status_code,
        )


async def list_repo_contents(repo_full_name: str, path: str = "") -> list[dict]:
    """List the top-level contents of a repo (used by /api/skills to enumerate skills).

    Returns list of {name, type, ...} dicts from the Gitea API.
    """
    t0 = time.monotonic()
    base = _gitea_url()
    url = f"{base}/api/v1/repos/{repo_full_name}/contents/{path}"
    args_hash = _hash({"repo": repo_full_name, "path": path})

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers=_headers())
    latency = (time.monotonic() - t0) * 1000
    if not resp.is_success:
        _audit(
            "gitea.list.contents",
            actor="console",
            outcome="error",
            latency_ms=latency,
            tool_args_hash=args_hash,
        )
        raise GiteaClientError(
            f"Failed to list contents of {repo_full_name}/{path}: {resp.status_code} {resp.text[:200]}",
            status_code=resp.status_code,
        )
    _audit(
        "gitea.list.contents",
        actor="console",
        outcome="allow",
        latency_ms=latency,
        tool_args_hash=args_hash,
    )
    return resp.json()  # type: ignore[return-value]
