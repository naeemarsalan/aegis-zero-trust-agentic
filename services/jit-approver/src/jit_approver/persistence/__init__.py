"""Persistence package for jit-approver.

Provides the Store ABC (base.py) and two implementations:
  - InMemoryStore (memory.py)  — default, zero deps, byte-for-byte today's behaviour
  - PostgresStore (postgres.py) — durable, CNPG-backed, enabled by JIT_STORE_BACKEND=postgres

``store.py`` is a thin compat shim that exposes module-level ``session_store``,
``seen_deliveries``, and ``store_lock`` pointing at an InMemoryStore instance so every
existing import site (api.py, webhook.py, vault.py, reaper.py, tests) keeps working
with zero edits.

Factory::

    from jit_approver.persistence import get_store
    store = get_store()   # selects backend from JIT_STORE_BACKEND env

The factory is a module-level singleton: once created, the same instance is
returned on every call until ``reset_store_singleton()`` is called (tests only).
This guarantees that the lifespan startup_check and the ledger writer share
exactly one store instance — essential for the durable Postgres backend (one
connection pool) and consistent for in-memory (no split state).

``reset_store_singleton()`` is a test helper; never call it in production code.
"""
from __future__ import annotations

import os

from jit_approver.persistence.base import Store
from jit_approver.persistence.memory import InMemoryStore

__all__ = ["Store", "InMemoryStore", "get_store", "reset_store_singleton"]

# ---------------------------------------------------------------------------
# Module-level singleton (one instance per process lifetime)
# ---------------------------------------------------------------------------

_store_singleton: "Store | None" = None
_store_singleton_backend: "str | None" = None


def get_store() -> "Store":
    """Return the configured Store implementation (module-level singleton).

    Reads ``JIT_STORE_BACKEND`` env (default ``memory``).  Setting it to
    ``postgres`` returns a ``PostgresStore`` — requires the ``asyncpg``
    optional dep (``pip install '.[durable]'``) and ``DATABASE_URL`` env.
    Any unknown value raises ``ValueError`` to fail closed.

    The SAME instance is returned on every call while the env var is
    unchanged.  If the env var changes (e.g. between tests), a new instance
    is created and cached.  Use ``reset_store_singleton()`` to force a fresh
    instance (tests only).
    """
    global _store_singleton, _store_singleton_backend

    backend = os.environ.get("JIT_STORE_BACKEND", "memory").strip().lower()

    # Return cached singleton when the backend type is unchanged.
    if _store_singleton is not None and _store_singleton_backend == backend:
        return _store_singleton

    # --- create a new instance ---
    if backend == "memory":
        store: Store = InMemoryStore()
    elif backend == "postgres":
        try:
            from jit_approver.persistence.postgres import PostgresStore
        except ImportError as exc:
            raise ImportError(
                "JIT_STORE_BACKEND=postgres requires 'asyncpg'. "
                "Install with: pip install 'jit-approver[durable]'"
            ) from exc
        db_url = os.environ.get("DATABASE_URL", "")
        if not db_url:
            raise RuntimeError(
                "JIT_STORE_BACKEND=postgres requires DATABASE_URL env var "
                "(set via CNPG-generated secretKeyRef jit-approver-db-app key 'uri')."
            )
        store = PostgresStore(db_url=db_url)
    else:
        raise ValueError(
            f"Unknown JIT_STORE_BACKEND={backend!r}. Valid values: memory, postgres."
        )

    _store_singleton = store
    _store_singleton_backend = backend
    return store


def reset_store_singleton() -> None:
    """Clear the module-level store singleton.

    FOR TESTS ONLY.  Causes the next ``get_store()`` call to create a fresh
    instance, ensuring test isolation when env vars change between tests.
    Never call this in production code paths.
    """
    global _store_singleton, _store_singleton_backend
    _store_singleton = None
    _store_singleton_backend = None
