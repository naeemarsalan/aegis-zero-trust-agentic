"""In-memory Agent + AgentSession store (C1).

Thread-safe.  Designed as a drop-in swap target for a CNPG-backed store in Phase D
— callers interact only through the functions here, never touching _AGENTS directly.

The store uses the same lock-and-dict pattern as approval_console.app._SESSIONS so
the two share the same concurrency model and are easy to cross-link.
"""

from __future__ import annotations

import threading
from typing import Any

from approval_console.agents.models import Agent, AgentSession, AgentState, AgentSessionState

_AGENTS: dict[str, Agent] = {}
_SESSIONS_BY_AGENT: dict[str, list[AgentSession]] = {}
_LOCK = threading.Lock()


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


# ---------------------------------------------------------------------------
# AgentSession CRUD
# ---------------------------------------------------------------------------


def create_agent_session(session: AgentSession) -> AgentSession:
    """Record a new AgentSession under its parent Agent."""
    with _LOCK:
        if session.agent_id not in _AGENTS:
            raise KeyError(f"Agent {session.agent_id!r} not found")
        _SESSIONS_BY_AGENT[session.agent_id].append(session)
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
                break
