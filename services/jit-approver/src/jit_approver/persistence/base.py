"""Store ABC — the single interface both InMemoryStore and PostgresStore implement.

Security invariants enforced by this contract:

C4 once-only issuance:
    ``update_state_atomic`` is the SOLE path to flip a session to ``issued``.
    It MUST be atomic: check current state ∈ expected_states AND flip to
    new_state in a single operation (under a lock for in-memory, a single
    UPDATE…RETURNING for Postgres).  Implementations MUST NOT expose any
    non-atomic read-then-write alternative.

C4 replay / X-Gitea-Delivery dedupe:
    ``add_delivery_if_new`` returns the delivery_id on first insert and
    ``None`` on a duplicate.  The Postgres backend uses INSERT…ON CONFLICT
    DO NOTHING RETURNING; the in-memory backend uses a set under the same
    lock as the session store.

Ledger WORM (L2 prerequisite, seeded here):
    The ledger is INSERT-only.  There is NO ``update_ledger`` or
    ``delete_ledger`` method on this ABC, and the Postgres backend enforces
    this at the DB privilege layer via ``REVOKE UPDATE, DELETE ON jit_ledger``.

Multi-replica note:
    In-memory mode is correct for single-replica SNO only.
    Multi-replica deployments MUST use JIT_STORE_BACKEND=postgres where the
    atomic UPDATE…RETURNING replaces the in-process asyncio.Lock as the
    once-only guard.
"""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any


class Store(ABC):
    """Abstract base class for jit-approver session/delivery/ledger persistence."""

    # ------------------------------------------------------------------
    # Session CRUD
    # ------------------------------------------------------------------

    @abstractmethod
    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Return the session dict or ``None`` if absent."""

    @abstractmethod
    async def put_session(self, session_id: str, session: dict[str, Any]) -> None:
        """Upsert the full session dict (create or overwrite)."""

    @abstractmethod
    async def update_state_atomic(
        self,
        session_id: str,
        expected_states: set[str],
        new_state: str,
    ) -> bool:
        """Atomically flip session state from one of ``expected_states`` to ``new_state``.

        Returns ``True`` on success (flip performed), ``False`` if the session was
        absent or its current state was not in ``expected_states`` (already
        terminal, already issued, etc.).

        This is the C4 once-only guard.  Implementation MUST be atomic:
        - InMemoryStore: hold ``async_lock`` across the read-then-write.
        - PostgresStore: single ``UPDATE … WHERE state = ANY($expected) RETURNING id``.
        """

    @abstractmethod
    async def update_session_fields(
        self, session_id: str, fields: dict[str, Any]
    ) -> None:
        """Merge ``fields`` into the stored session dict (partial update)."""

    @abstractmethod
    async def list_sessions(
        self,
        sandbox: str | None = None,
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all session dicts, optionally filtered by sandbox / state."""

    @abstractmethod
    async def iter_sessions(self) -> list[tuple[str, dict[str, Any]]]:
        """Return all (session_id, session) pairs."""

    # ------------------------------------------------------------------
    # Delivery dedupe (C4 replay protection)
    # ------------------------------------------------------------------

    @abstractmethod
    async def add_delivery_if_new(self, delivery_id: str) -> str | None:
        """Record a delivery id; return it on first insert, ``None`` on duplicate."""

    # ------------------------------------------------------------------
    # Ledger head (CAS — prerequisite for L2 hash-chaining)
    # ------------------------------------------------------------------

    @abstractmethod
    async def read_ledger_head(self) -> tuple[int, str]:
        """Return ``(seq, head_hash)`` for the singleton ledger head (seq=0 at init)."""

    @abstractmethod
    async def advance_ledger_head_cas(
        self, expected_seq: int, new_seq: int, new_hash: str
    ) -> bool:
        """Compare-and-swap the ledger head from ``expected_seq`` to ``new_seq``.

        Returns ``True`` on success, ``False`` if the current seq != expected_seq
        (lost a race; caller must re-read and retry).
        """

    # ------------------------------------------------------------------
    # Startup health check
    # ------------------------------------------------------------------

    @abstractmethod
    async def startup_check(self) -> None:
        """Assert that the backend is healthy and schema-complete.

        In-memory: no-op.
        Postgres: open pool, run SELECT 1, verify jit_session + jit_ledger tables exist.
        MUST raise on failure so the pod crashloops (fail closed) rather than
        serving with no durable persistence.
        """

    # ------------------------------------------------------------------
    # Process-wide async lock (serialises in-memory state transitions)
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def async_lock(self) -> asyncio.Lock:
        """A process-wide asyncio.Lock serialising concurrent state transitions.

        In-memory: the same lock that update_state_atomic uses internally.
        Postgres: a lightweight lock (the DB-side UPDATE is the real guard);
                  kept for API compatibility so webhook.py / reaper.py can
                  ``async with store.async_lock: …`` unchanged.
        """

    # ------------------------------------------------------------------
    # Compat dict-like accessors (delegated to InMemoryStore)
    # ------------------------------------------------------------------
    #
    # These are NOT abstract — they have no meaning for PostgresStore (which
    # is async-only) and are provided only so the module-level compat names
    # in store.py (session_store[id], seen_deliveries, store_lock) work as
    # drop-in replacements for the legacy plain-dict/set usage.
    #
    # PostgresStore MUST NOT implement these.
