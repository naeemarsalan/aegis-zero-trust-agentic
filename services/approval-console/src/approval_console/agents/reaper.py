"""Background reaper for persistent agents (C1).

Runs as a daemon thread started at app startup. Every REAPER_INTERVAL_SECONDS (default 60),
it queries sandbox-launcher for each READY/PROVISIONING agent's sandbox phase. If the sandbox
is no longer present or is in a terminal failure state, the agent is transitioned to ERROR.

Security: the reaper only reads sandbox state; it never mutates the cluster.
The SANDBOX_LAUNCHER_URL is read lazily (same pattern as routes.py).
"""

from __future__ import annotations

import logging
import os
import threading
import time

import httpx

from approval_console.agents import store as agent_store
from approval_console.agents.models import AgentState

logger = logging.getLogger("approval_console.agents.reaper")

_REAPER_STARTED = False
_REAPER_LOCK = threading.Lock()

REAPER_INTERVAL_SECONDS = int(os.environ.get("REAPER_INTERVAL_SECONDS", "60"))


def _sandbox_launcher_url() -> str | None:
    return os.environ.get("SANDBOX_LAUNCHER_URL", "").strip() or None


async def _check_sandbox(sandbox_name: str, launcher_url: str) -> str:
    """Query sandbox-launcher for sandbox phase.  Returns 'READY', 'ERROR', or 'UNKNOWN'."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{launcher_url}/sandboxes/{sandbox_name}")
        if resp.status_code == 404:
            return "ERROR"
        if resp.is_success:
            data = resp.json()
            phase = data.get("phase", "UNKNOWN")
            return "READY" if phase == "READY" else ("ERROR" if phase in {"FAILED", "DELETED"} else "UNKNOWN")
    except Exception as exc:  # noqa: BLE001
        logger.warning("reaper.check_sandbox_error sandbox=%s error=%s", sandbox_name, exc)
    return "UNKNOWN"


def _reaper_loop() -> None:
    """Synchronous reaper loop — runs in a daemon thread.

    Uses a new event loop per iteration to drive the async health check calls.
    Each check is isolated; a failure in one agent does not stop the others.
    """
    import asyncio

    while True:
        time.sleep(REAPER_INTERVAL_SECONDS)
        launcher_url = _sandbox_launcher_url()
        if not launcher_url:
            continue  # not configured — skip

        agents = agent_store.list_agents()
        active = [a for a in agents if a.state in {AgentState.READY, AgentState.PROVISIONING}]
        if not active:
            continue

        loop = asyncio.new_event_loop()
        try:
            for agent in active:
                if not agent.sandbox_name:
                    continue
                try:
                    phase = loop.run_until_complete(
                        _check_sandbox(agent.sandbox_name, launcher_url)
                    )
                    if phase == "ERROR":
                        agent_store.update_agent(agent.agent_id, state=AgentState.ERROR)
                        logger.info(
                            "reaper.agent_errored agent_id=%s sandbox=%s",
                            agent.agent_id,
                            agent.sandbox_name,
                        )
                    elif phase == "READY" and agent.state == AgentState.PROVISIONING:
                        agent_store.update_agent(agent.agent_id, state=AgentState.READY)
                        logger.info(
                            "reaper.agent_ready agent_id=%s sandbox=%s",
                            agent.agent_id,
                            agent.sandbox_name,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("reaper.loop_error agent_id=%s error=%s", agent.agent_id, exc)
        finally:
            loop.close()


def start_reaper() -> None:
    """Start the reaper daemon thread (idempotent — safe to call at startup)."""
    global _REAPER_STARTED
    with _REAPER_LOCK:
        if _REAPER_STARTED:
            return
        t = threading.Thread(target=_reaper_loop, daemon=True, name="agent-reaper")
        t.start()
        _REAPER_STARTED = True
        logger.info("agent_reaper.started interval_s=%d", REAPER_INTERVAL_SECONDS)
