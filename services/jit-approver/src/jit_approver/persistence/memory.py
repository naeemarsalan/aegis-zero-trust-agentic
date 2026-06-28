"""InMemoryStore — the default backend, byte-for-byte semantics as today's dict/set/Lock.

This is the ONLY implementation active when JIT_STORE_BACKEND is unset or 'memory'.
It also provides the module-level compat dict/set/lock names (session_store,
seen_deliveries, store_lock) that api.py, webhook.py, vault.py, and reaper.py import.

Concurrency model: all state transitions hold ``_lock`` so the once-only C4 guard
is identical to the original asyncio.Lock-under-webhook pattern.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from jit_approver.persistence.base import Store


class InMemoryStore(Store):
    """In-memory Store backed by a plain dict, set, and asyncio.Lock."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}
        self._deliveries: set[str] = set()
        self._lock: asyncio.Lock = asyncio.Lock()
        # Ledger head singleton: (seq, head_hash)
        self._ledger_seq: int = 0
        self._ledger_hash: str = ""
        # Ordered list of ledger entries for chain verification.
        self._ledger_entries: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Session CRUD
    # ------------------------------------------------------------------

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self._sessions.get(session_id)

    async def put_session(self, session_id: str, session: dict[str, Any]) -> None:
        self._sessions[session_id] = session

    async def update_state_atomic(
        self,
        session_id: str,
        expected_states: set[str],
        new_state: str,
    ) -> bool:
        """C4 once-only: acquire lock, check state, flip — identical semantics to
        the original webhook.py store_lock pattern."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            if session["state"] not in expected_states:
                return False
            session["state"] = new_state
            return True

    async def update_session_fields(
        self, session_id: str, fields: dict[str, Any]
    ) -> None:
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                session.update(fields)

    async def list_sessions(
        self,
        sandbox: str | None = None,
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        out = []
        for session in self._sessions.values():
            if sandbox is not None:
                req = session.get("request")
                sess_sandbox = getattr(req, "sandbox", None) or session.get("openshell_sandbox")
                if sess_sandbox != sandbox:
                    continue
            if state is not None and session.get("state") != state:
                continue
            out.append(session)
        return out

    async def iter_sessions(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self._sessions.items())

    # ------------------------------------------------------------------
    # Delivery dedupe
    # ------------------------------------------------------------------

    async def add_delivery_if_new(self, delivery_id: str) -> str | None:
        async with self._lock:
            if delivery_id in self._deliveries:
                return None
            self._deliveries.add(delivery_id)
            return delivery_id

    # ------------------------------------------------------------------
    # Ledger head CAS
    # ------------------------------------------------------------------

    async def read_ledger_head(self) -> tuple[int, str]:
        return (self._ledger_seq, self._ledger_hash)

    async def advance_ledger_head_cas(
        self, expected_seq: int, new_seq: int, new_hash: str
    ) -> bool:
        async with self._lock:
            if self._ledger_seq != expected_seq:
                return False
            self._ledger_seq = new_seq
            self._ledger_hash = new_hash
            return True

    async def append_ledger(self, payload: dict[str, Any]) -> int:
        """Append a WORM entry; advance the hash-chain head atomically under _lock."""
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        async with self._lock:
            prev_hash = self._ledger_hash
            entry_hash = hashlib.sha256(
                (prev_hash + payload_json).encode()
            ).hexdigest()
            new_seq = self._ledger_seq + 1
            self._ledger_entries.append(
                {
                    "seq": new_seq,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                    "payload_json": payload_json,
                }
            )
            self._ledger_seq = new_seq
            self._ledger_hash = entry_hash
            return new_seq

    # ------------------------------------------------------------------
    # Startup check (no-op for in-memory)
    # ------------------------------------------------------------------

    async def startup_check(self) -> None:
        """No-op: in-memory store is always ready."""

    # ------------------------------------------------------------------
    # Async lock property
    # ------------------------------------------------------------------

    @property
    def async_lock(self) -> asyncio.Lock:
        return self._lock

    # ------------------------------------------------------------------
    # Compat dict-like interface (used by the store.py compat shim)
    # ------------------------------------------------------------------
    # These proxy directly to the internal dict/set so module-level
    # ``session_store[id]``, ``session_store.get(id)``, ``.items()``,
    # ``.clear()`` all work as expected.

    # --- dict-like (sessions) ---

    def __getitem__(self, key: str) -> dict[str, Any]:
        return self._sessions[key]

    def __setitem__(self, key: str, value: dict[str, Any]) -> None:
        self._sessions[key] = value

    def __delitem__(self, key: str) -> None:
        del self._sessions[key]

    def __contains__(self, key: object) -> bool:
        return key in self._sessions

    def __iter__(self):  # type: ignore[override]
        return iter(self._sessions)

    def get(self, key: str, default: Any = None) -> Any:
        return self._sessions.get(key, default)

    def items(self):  # type: ignore[override]
        return self._sessions.items()

    def values(self):  # type: ignore[override]
        return self._sessions.values()

    def keys(self):  # type: ignore[override]
        return self._sessions.keys()

    def clear(self) -> None:
        self._sessions.clear()
        # Clear deliveries in-place so any external set-reference (seen_deliveries
        # in store.py) sees the change immediately. Using discard-all preserves
        # the object identity that store.py's module-level name points to.
        self._deliveries.clear()

    # --- set-like (deliveries, exposed via seen_deliveries compat name) ---

    @property
    def _delivery_set(self) -> set[str]:
        return self._deliveries
