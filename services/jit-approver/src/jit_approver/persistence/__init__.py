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

"""
from __future__ import annotations

import os

from jit_approver.persistence.base import Store
from jit_approver.persistence.memory import InMemoryStore

__all__ = ["Store", "InMemoryStore", "get_store"]


def get_store() -> "Store":
    """Return the configured Store implementation.

    Reads ``JIT_STORE_BACKEND`` env (default ``memory``).  Setting it to
    ``postgres`` returns a ``PostgresStore`` — requires the ``asyncpg``
    optional dep (``pip install '.[durable]'``) and ``DATABASE_URL`` env.
    Any unknown value raises ``ValueError`` to fail closed.
    """
    backend = os.environ.get("JIT_STORE_BACKEND", "memory").strip().lower()
    if backend == "memory":
        return InMemoryStore()
    if backend == "postgres":
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
        return PostgresStore(db_url=db_url)
    raise ValueError(
        f"Unknown JIT_STORE_BACKEND={backend!r}. Valid values: memory, postgres."
    )
