"""Ephemeral-Vault-resource reaper (N3).

The H3 fix mints a per-session ephemeral Vault kubernetes role
(``kubernetes/roles/jit-<session>``) plus a KV tracking record
(``secret/data/jit/<session>``). Neither is cleaned up by the K8s-only
ClusterCleanupPolicy, so without this reaper they accumulate forever — a slow
standing-scope leak (the very risk H3 warned about).

This background task, started at app startup, every ~60s:
  * finds sessions whose ``expires_at`` has passed and that are not already
    reaped,
  * DELETEs ``kubernetes/roles/jit-<session>`` and ``secret/data/jit/<session>``
    using the jit-approver Vault creds (the policy already grants delete on
    ``kubernetes/roles/jit-*``; KV metadata delete on ``secret/metadata/jit/*``),
  * marks the session ``expired``.

Fail-safe: deletes are best-effort and idempotent (404 on an already-gone
resource is fine). A delete failure leaves the session un-reaped so the next
sweep retries — it does NOT mark the session expired prematurely.

Testability: ``reap_once`` is a single-shot pure-ish coroutine with an injectable
``now`` clock and ``http`` client, so tests drive one sweep deterministically.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from jit_approver.models import SessionState
from jit_approver.store import session_store, store_lock
from jit_approver.vault import (
    _vault_addr,
    _vault_login,
    delete_ephemeral_role,
    delete_kv_record,
)

logger = logging.getLogger("jit_approver.reaper")

REAP_INTERVAL_SECONDS = 60

# Sessions in these states still hold (or may hold) live Vault resources that the
# reaper is responsible for tearing down once expiry passes. 'expired' is the
# post-reap terminal state; 'denied'/'pending'/'approved' never minted live creds.
_REAPABLE_STATES = frozenset({SessionState.issued.value})


def _parse_expiry(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _expired_session_ids(now: datetime) -> list[str]:
    """Return session ids that are issued AND whose expiry has passed."""
    due: list[str] = []
    for session_id, session in session_store.items():
        if session.get("state") not in _REAPABLE_STATES:
            continue
        expires_at = _parse_expiry(session.get("expires_at"))
        if expires_at is None:
            continue
        if expires_at <= now:
            due.append(session_id)
    return due


async def reap_once(
    *,
    now: datetime | None = None,
    http: httpx.AsyncClient | None = None,
) -> list[str]:
    """Run a single reap sweep. Returns the list of session ids reaped.

    For each expired issued session: delete the ephemeral Vault role and KV
    record, then flip state to ``expired``. Sessions whose expiry has not passed
    are left untouched. Vault-side deletes are idempotent; a delete that errors
    leaves the session un-reaped for the next sweep (it is NOT marked expired).
    """
    now = now or datetime.now(timezone.utc)
    due = _expired_session_ids(now)
    if not due:
        return []

    reaped: list[str] = []

    async def _run(client: httpx.AsyncClient) -> None:
        vault_token: str | None = None
        addr = _vault_addr()
        for session_id in due:
            session = session_store.get(session_id)
            if session is None:
                continue
            role_name = session.get("vault_role") or f"jit-{session_id}"
            try:
                if vault_token is None:
                    vault_token = await _vault_login(client)
                await delete_ephemeral_role(client, addr, vault_token, role_name)
                await delete_kv_record(client, addr, vault_token, session_id)
            except Exception as exc:  # noqa: BLE001 — retry next sweep, don't expire
                logger.error(
                    "reap_failed",
                    extra={"session_id": session_id, "vault_role": role_name, "error": str(exc)},
                )
                continue
            # Revert the OpenShell network widen back to the baseline floor (the
            # policy-side teardown, sibling of the Vault lease revoke). Best-effort
            # and idempotent (tolerates a gone sandbox / already-removed rule); a
            # failure here must NOT block reaping — the Vault creds are already
            # gone, and a lingering rule is re-attempted only if we leave it
            # un-reaped, which we do not.
            osh_sandbox = session.get("openshell_sandbox")
            if osh_sandbox:
                try:
                    from jit_approver import openshell

                    openshell.revert_network(session_id, osh_sandbox)
                except Exception as exc:  # noqa: BLE001 — best-effort
                    logger.error(
                        "reap_policy_revert_failed",
                        extra={"session_id": session_id, "sandbox": osh_sandbox, "error": str(exc)},
                    )
            async with store_lock:
                sess = session_store.get(session_id)
                if sess is not None:
                    sess["state"] = SessionState.expired.value
            reaped.append(session_id)
            logger.info(
                "session_reaped",
                extra={"session_id": session_id, "vault_role": role_name},
            )

    if http is not None:
        await _run(http)
    else:
        async with httpx.AsyncClient(timeout=30.0) as client:
            await _run(client)

    return reaped


async def reaper_loop(
    *,
    interval_seconds: int = REAP_INTERVAL_SECONDS,
    now_fn: Callable[[], datetime] | None = None,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Background loop: call ``reap_once`` every ``interval_seconds``.

    Started at app startup. Each iteration is wrapped so a single failed sweep
    never kills the loop. ``stop_event`` (optional) lets a graceful shutdown or a
    test break out promptly.
    """
    now_fn = now_fn or (lambda: datetime.now(timezone.utc))
    stop_event = stop_event or asyncio.Event()
    logger.info("reaper_started", extra={"interval_seconds": interval_seconds})
    while not stop_event.is_set():
        try:
            await reap_once(now=now_fn())
        except Exception as exc:  # noqa: BLE001 — never let the loop die
            logger.error("reaper_sweep_error", extra={"error": str(exc)})
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            pass
