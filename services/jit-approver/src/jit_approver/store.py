"""Compatibility shim — exposes module-level session_store / seen_deliveries / store_lock.

Every existing import site (api.py, webhook.py, vault.py, reaper.py, tests) uses:

    from jit_approver.store import session_store, seen_deliveries, store_lock

These names are now backed by the process-wide InMemoryStore instance so all
dict/set/lock usage works identically to the original plain dict/set/asyncio.Lock.

To use a different backend (e.g. Postgres), call ``get_store()`` directly:

    from jit_approver.persistence import get_store
    store = get_store()   # selected by JIT_STORE_BACKEND env (default 'memory')

The in-memory default path is byte-for-byte unchanged when JIT_STORE_BACKEND is
unset or 'memory' — existing import sites need ZERO edits.

Concurrency / replay protection (C4):
    - ``store_lock`` is a process-wide asyncio.Lock that guards the once-only
      state transition to ``issued``. The webhook MUST hold this lock while it
      checks-and-flips state so two concurrent (or redelivered) webhook calls
      cannot both mint a credential for the same session.
    - ``seen_deliveries`` records every ``X-Gitea-Delivery`` id we have already
      processed so Gitea redelivery (retry/timeout) is a cheap no-op ACK.

Multi-replica note:
    In single-replica SNO this is correct. For HA, set JIT_STORE_BACKEND=postgres
    where the atomic DB UPDATE replaces the in-process lock as the once-only guard.
"""

from __future__ import annotations

from jit_approver.persistence.memory import InMemoryStore

# Process-wide in-memory store instance (default, JIT_STORE_BACKEND=memory).
_store: InMemoryStore = InMemoryStore()

# ---------------------------------------------------------------------------
# Compat names — drop-in replacements for the former plain dict/set/Lock.
# ---------------------------------------------------------------------------

# session_id -> session dict (dict-like proxy via InMemoryStore.__getitem__ etc.)
session_store: InMemoryStore = _store

# X-Gitea-Delivery ids we have already handled (set-like proxy via _delivery_set).
# This is the SAME set object that InMemoryStore._deliveries is; modifying either
# reference mutates the same object.
seen_deliveries: set[str] = _store._delivery_set

# Process-wide lock guarding the once-only issuance transition (C4).
# Points at the same asyncio.Lock that InMemoryStore.update_state_atomic uses.
store_lock = _store.async_lock
