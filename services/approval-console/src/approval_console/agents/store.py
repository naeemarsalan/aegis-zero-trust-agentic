"""Persistent Agent + AgentSession store (C1).

Thread-safe, JSON-file backed.  Designed as a drop-in swap target for a
CNPG-backed store in Phase D — callers interact only through the functions
here, never touching _AGENTS directly.

Durability
----------
Records are mirrored to a JSON file at ``AGENT_STORE_PATH`` (default
``/data/agents.json``, a PVC-mounted volume in the cluster).  Every mutation
writes the WHOLE store atomically (temp file + ``os.replace``) under ``_LOCK``,
the same lock all readers/writers share — so the reaper daemon thread's
``update_agent`` writes are safe against the request-thread readers.

The store loads from the file on import.  A missing / empty / corrupt file is
tolerated: the store simply starts empty (logged, never crashes).  If the
target directory is not writable (e.g. unit tests with the default ``/data``
path and no PVC), saves degrade to a no-op so behaviour stays purely
in-memory — preserving the original drop-in semantics for the test suite.

Only the durable Agent / AgentSession RECORDS are persisted here.  Live run
transcripts (``approval_console.app._SESSIONS``) are deliberately NOT persisted
— they are ephemeral process state.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from typing import Any

from approval_console.agents.models import Agent, AgentSession, AgentState, AgentSessionState

logger = logging.getLogger(__name__)

_AGENTS: dict[str, Agent] = {}
_SESSIONS_BY_AGENT: dict[str, list[AgentSession]] = {}
_LOCK = threading.RLock()

# Resolved once at import; AGENT_STORE_PATH lets the cluster point this at the
# PVC mount and lets tests point it at a writable temp dir.
_STORE_PATH = os.environ.get("AGENT_STORE_PATH", "/data/agents.json")

# When the store dir is not writable we flip this so saves become no-ops and we
# don't log the same failure on every mutation.  Logged once at first failure.
_PERSIST_DISABLED = False


# ---------------------------------------------------------------------------
# Persistence (file <-> in-memory).  Callers MUST hold _LOCK.
# ---------------------------------------------------------------------------


def _save_locked() -> None:
    """Write the whole store to ``_STORE_PATH`` atomically.  Caller holds _LOCK.

    Atomic = write a temp file in the same directory, fsync, then ``os.replace``
    (a rename, atomic on POSIX) over the target.  A reader that opens the path
    at any instant sees either the old or the new complete file, never a partial
    write.  Failures (read-only dir, no PVC) degrade to a logged no-op.
    """
    global _PERSIST_DISABLED
    if _PERSIST_DISABLED:
        return

    payload = {
        "version": 1,
        "agents": [a.model_dump(mode="json") for a in _AGENTS.values()],
        "sessions": {
            agent_id: [s.model_dump(mode="json") for s in sessions]
            for agent_id, sessions in _SESSIONS_BY_AGENT.items()
        },
    }

    directory = os.path.dirname(_STORE_PATH) or "."
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".agents-", suffix=".json.tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, _STORE_PATH)
        except Exception:
            # Clean up the temp file on any failure during write/replace.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as exc:
        # Read-only / missing volume (e.g. unit tests with the default /data
        # path).  Disable further attempts and keep operating in-memory.
        _PERSIST_DISABLED = True
        logger.warning(
            "agent store: persistence disabled, running in-memory only "
            "(path=%s, err=%s)",
            _STORE_PATH,
            exc,
        )


def _load_locked() -> None:
    """Replace in-memory state from ``_STORE_PATH``.  Caller holds _LOCK.

    Missing / empty / corrupt file -> start empty (logged, never raises).
    """
    _AGENTS.clear()
    _SESSIONS_BY_AGENT.clear()

    try:
        with open(_STORE_PATH, encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        logger.info("agent store: no file at %s, starting empty", _STORE_PATH)
        return
    except OSError as exc:
        logger.warning("agent store: cannot read %s (%s), starting empty", _STORE_PATH, exc)
        return

    if not raw.strip():
        logger.info("agent store: empty file at %s, starting empty", _STORE_PATH)
        return

    try:
        data = json.loads(raw)
        for rec in data.get("agents", []):
            agent = Agent.model_validate(rec)
            _AGENTS[agent.agent_id] = agent
            _SESSIONS_BY_AGENT.setdefault(agent.agent_id, [])
        for agent_id, sess_list in data.get("sessions", {}).items():
            _SESSIONS_BY_AGENT[agent_id] = [AgentSession.model_validate(s) for s in sess_list]
        logger.info(
            "agent store: loaded %d agent(s) from %s", len(_AGENTS), _STORE_PATH
        )
    except Exception as exc:  # noqa: BLE001 - corrupt file must never crash boot
        # Corrupt / schema-incompatible file: start empty rather than crash the
        # console.  Do NOT overwrite the bad file here (preserve for forensics);
        # the next successful mutation will rewrite it.
        _AGENTS.clear()
        _SESSIONS_BY_AGENT.clear()
        logger.error(
            "agent store: corrupt file at %s (%s), starting empty", _STORE_PATH, exc
        )


def reload_from_disk() -> None:
    """Public: re-read the store file into memory (used by tests / ops)."""
    with _LOCK:
        _load_locked()


# Load persisted state at import time.
with _LOCK:
    _load_locked()


# ---------------------------------------------------------------------------
# Agent CRUD
# ---------------------------------------------------------------------------


def create_agent(agent: Agent) -> Agent:
    """Persist a new Agent.  Fails fast if agent_id already exists."""
    with _LOCK:
        if agent.agent_id in _AGENTS:
            raise ValueError(f"Agent {agent.agent_id!r} already exists")
        _AGENTS[agent.agent_id] = agent
        _SESSIONS_BY_AGENT[agent.agent_id] = []
        _save_locked()
    return agent


def get_agent(agent_id: str) -> Agent | None:
    with _LOCK:
        return _AGENTS.get(agent_id)


def list_agents(owner: str | None = None) -> list[Agent]:
    """Return all agents, optionally filtered by owner, newest-created first."""
    with _LOCK:
        items = list(_AGENTS.values())
    if owner is not None:
        items = [a for a in items if a.owner == owner]
    return sorted(items, key=lambda a: a.created_at, reverse=True)


def update_agent(agent_id: str, **fields: Any) -> Agent:
    """Apply keyword-argument field updates to an Agent and return the updated record.

    Raises KeyError if the agent does not exist.
    Only fields that exist on Agent are accepted; unknown keys are silently ignored
    so callers can pass the full detail dict without pre-filtering.
    """
    with _LOCK:
        agent = _AGENTS.get(agent_id)
        if agent is None:
            raise KeyError(f"Agent {agent_id!r} not found")
        valid = agent.model_fields_set | set(agent.model_fields.keys())
        updates = {k: v for k, v in fields.items() if k in valid}
        updated = agent.model_copy(update=updates)
        _AGENTS[agent_id] = updated
        _save_locked()
    return updated


def archive_agent(agent_id: str, archived_at: str) -> Agent:
    """Transition an agent to ARCHIVED state."""
    return update_agent(agent_id, state=AgentState.ARCHIVED, archived_at=archived_at)


def delete_agent(agent_id: str) -> None:
    """Hard-delete an agent and its session index.

    NOTE: Only called from the gated DELETE /api/agents/{id} route.
    """
    with _LOCK:
        _AGENTS.pop(agent_id, None)
        _SESSIONS_BY_AGENT.pop(agent_id, None)
        _save_locked()


# ---------------------------------------------------------------------------
# AgentSession CRUD
# ---------------------------------------------------------------------------


def create_agent_session(session: AgentSession) -> AgentSession:
    """Record a new AgentSession under its parent Agent."""
    with _LOCK:
        if session.agent_id not in _AGENTS:
            raise KeyError(f"Agent {session.agent_id!r} not found")
        _SESSIONS_BY_AGENT[session.agent_id].append(session)
        _save_locked()
    return session


def list_agent_sessions(agent_id: str) -> list[AgentSession]:
    """Return sessions for an agent, newest first."""
    with _LOCK:
        sessions = list(_SESSIONS_BY_AGENT.get(agent_id, []))
    return sorted(sessions, key=lambda s: s.created_at, reverse=True)


def update_session_state(session_id: str, agent_id: str, state: AgentSessionState) -> None:
    """Update the state of a session within an agent's session list."""
    with _LOCK:
        sessions = _SESSIONS_BY_AGENT.get(agent_id, [])
        for i, s in enumerate(sessions):
            if s.session_id == session_id:
                sessions[i] = s.model_copy(update={"state": state})
                _save_locked()
                break
