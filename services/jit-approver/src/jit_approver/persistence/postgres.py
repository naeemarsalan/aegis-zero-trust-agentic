"""PostgresStore — durable asyncpg-backed Store implementation.

Enabled by JIT_STORE_BACKEND=postgres.  Requires:
  - ``asyncpg`` (install with ``pip install 'jit-approver[durable]'``)
  - ``DATABASE_URL`` env pointing at the CNPG-generated jit-approver-db-app secret uri.

Security properties enforced here (see also schema.sql):

C4 once-only (multi-replica safe):
    ``update_state_atomic`` issues a single:
      UPDATE jit_session SET state=$new WHERE id=$id AND state = ANY($expected) RETURNING id
    The DB-layer atomicity replaces the in-process asyncio.Lock as the once-only
    guard, making the flip race-free across multiple pod replicas.

Delivery dedupe:
    ``add_delivery_if_new`` uses:
      INSERT INTO jit_delivery(delivery_id) VALUES($1) ON CONFLICT DO NOTHING RETURNING delivery_id
    Dedupe survives pod restart (persisted in the DB, not process memory).

Ledger WORM (via schema.sql REVOKE):
    The app role has INSERT + SELECT on jit_ledger but NOT UPDATE or DELETE.
    The ``advance_ledger_head_cas`` method uses:
      UPDATE jit_ledger_head SET seq=$new, head_hash=$hash WHERE id=1 AND seq=$expected RETURNING seq
    This CAS serialises concurrent ledger advances without an in-process lock
    and is the foundation for L2 hash-chaining.

Fail-closed startup:
    ``startup_check`` verifies the pool opens AND the schema tables exist.
    A missing table -> RuntimeError -> pod crashloops (not-ready) rather than
    serving with no persistence (fail closed, per spec).
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from jit_approver.persistence.base import Store

logger = logging.getLogger("jit_approver.persistence.postgres")

# Lazily imported so the module can be loaded even when asyncpg is absent
# (get_store() raises a clear ImportError before reaching this code in that case).
try:
    import asyncpg
    _ASYNCPG_AVAILABLE = True
except ImportError:
    _ASYNCPG_AVAILABLE = False


class PostgresStore(Store):
    """asyncpg-backed durable Store."""

    def __init__(self, db_url: str) -> None:
        if not _ASYNCPG_AVAILABLE:
            raise ImportError(
                "asyncpg is required for PostgresStore. "
                "Install with: pip install 'jit-approver[durable]'"
            )
        self._db_url = db_url
        self._pool: Any = None  # asyncpg.Pool, typed as Any to avoid import at class level
        self._lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Pool lifecycle
    # ------------------------------------------------------------------

    async def _get_pool(self) -> Any:
        """Return the connection pool, creating it on first call."""
        if self._pool is None:
            self._pool = await asyncpg.create_pool(
                self._db_url,
                min_size=1,
                max_size=5,
                command_timeout=10,
            )
        return self._pool

    # ------------------------------------------------------------------
    # Startup health check (fail-closed)
    # ------------------------------------------------------------------

    async def startup_check(self) -> None:
        """Open pool, run SELECT 1, verify required tables exist.

        Raises RuntimeError on any failure so the pod crashloops (fail closed)
        rather than serving with no durable persistence.
        """
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
            # Verify required tables created by schema.sql
            for table in ("jit_session", "jit_delivery", "jit_ledger", "jit_ledger_head"):
                exists = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema='public' AND table_name=$1)",
                    table,
                )
                if not exists:
                    raise RuntimeError(
                        f"PostgresStore startup_check: required table '{table}' not found. "
                        "Run schema.sql against the DB before starting with JIT_STORE_BACKEND=postgres."
                    )
        logger.info("postgres_store_startup_ok", extra={"db_url_host": _mask_url(self._db_url)})

    # ------------------------------------------------------------------
    # Session CRUD
    # ------------------------------------------------------------------

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM jit_session WHERE id = $1", session_id
            )
        if row is None:
            return None
        return _row_to_session(row)

    async def put_session(self, session_id: str, session: dict[str, Any]) -> None:
        pool = await self._get_pool()
        request_json = _serialize_request(session.get("request"))
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO jit_session
                    (id, state, pr_url, pr_number, expires_at, requester_sub,
                     approver_sub, scope_hash, request_json, extra_json)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (id) DO UPDATE SET
                    state        = EXCLUDED.state,
                    pr_url       = EXCLUDED.pr_url,
                    pr_number    = EXCLUDED.pr_number,
                    expires_at   = EXCLUDED.expires_at,
                    requester_sub = EXCLUDED.requester_sub,
                    approver_sub = EXCLUDED.approver_sub,
                    scope_hash   = EXCLUDED.scope_hash,
                    request_json = EXCLUDED.request_json,
                    extra_json   = EXCLUDED.extra_json
                """,
                session_id,
                session.get("state", "pending"),
                session.get("pr_url"),
                session.get("pr_number"),
                session.get("expires_at"),
                _get_requester_sub(session),
                session.get("approver_sub"),
                session.get("scope_hash"),
                request_json,
                _session_extra_json(session),
            )

    async def update_state_atomic(
        self,
        session_id: str,
        expected_states: set[str],
        new_state: str,
    ) -> bool:
        """DB-atomic once-only state flip (replaces in-process lock for multi-replica)."""
        pool = await self._get_pool()
        expected_list = list(expected_states)
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE jit_session SET state = $1 "
                "WHERE id = $2 AND state = ANY($3) "
                "RETURNING id",
                new_state,
                session_id,
                expected_list,
            )
        return row is not None

    async def update_session_fields(
        self, session_id: str, fields: dict[str, Any]
    ) -> None:
        """Merge scalar fields into the stored session (partial update)."""
        session = await self.get_session(session_id)
        if session is None:
            return
        session.update(fields)
        await self.put_session(session_id, session)

    async def list_sessions(
        self,
        sandbox: str | None = None,
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        pool = await self._get_pool()
        conditions = []
        params: list[Any] = []
        if state is not None:
            params.append(state)
            conditions.append(f"state = ${len(params)}")
        # sandbox filter is applied in Python (it's inside request_json)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        async with pool.acquire() as conn:
            rows = await conn.fetch(f"SELECT * FROM jit_session {where}", *params)
        sessions = [_row_to_session(r) for r in rows]
        if sandbox is not None:
            sessions = [
                s for s in sessions
                if (_sandbox_from_session(s) == sandbox)
            ]
        return sessions

    async def iter_sessions(self) -> list[tuple[str, dict[str, Any]]]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM jit_session")
        return [(_row_to_session(r)["id"], _row_to_session(r)) for r in rows]

    # ------------------------------------------------------------------
    # Delivery dedupe
    # ------------------------------------------------------------------

    async def add_delivery_if_new(self, delivery_id: str) -> str | None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO jit_delivery(delivery_id) VALUES($1) "
                "ON CONFLICT DO NOTHING RETURNING delivery_id",
                delivery_id,
            )
        return row["delivery_id"] if row else None

    # ------------------------------------------------------------------
    # Ledger head CAS
    # ------------------------------------------------------------------

    async def read_ledger_head(self) -> tuple[int, str]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT seq, head_hash FROM jit_ledger_head WHERE id = 1"
            )
        if row is None:
            return (0, "")
        return (row["seq"], row["head_hash"] or "")

    async def advance_ledger_head_cas(
        self, expected_seq: int, new_seq: int, new_hash: str
    ) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "UPDATE jit_ledger_head SET seq = $1, head_hash = $2 "
                "WHERE id = 1 AND seq = $3 RETURNING seq",
                new_seq,
                new_hash,
                expected_seq,
            )
        return row is not None

    # ------------------------------------------------------------------
    # Async lock property (lightweight; DB UPDATE is the real guard)
    # ------------------------------------------------------------------

    @property
    def async_lock(self) -> asyncio.Lock:
        return self._lock


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _mask_url(url: str) -> str:
    """Return the host portion of a postgres:// URL (never log passwords)."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return p.hostname or "<unknown>"
    except Exception:
        return "<unknown>"


def _serialize_request(req: Any) -> str | None:
    """Serialise an EscalationRequest (pydantic model) to JSON string."""
    if req is None:
        return None
    try:
        return req.model_dump_json()
    except AttributeError:
        try:
            return json.dumps(req)
        except Exception:
            return None


def _deserialize_request(json_str: str | None) -> Any:
    """Deserialise an EscalationRequest from its JSON representation."""
    if not json_str:
        return None
    try:
        from jit_approver.models import EscalationRequest
        return EscalationRequest.model_validate_json(json_str)
    except Exception:
        return None


def _get_requester_sub(session: dict[str, Any]) -> str | None:
    req = session.get("request")
    if req is not None:
        return getattr(req, "requester_sub", None)
    return None


def _session_extra_json(session: dict[str, Any]) -> str:
    """Capture volatile fields (vault_role, session_jwt, sa_token, etc.) as JSON."""
    extra_keys = {
        "vault_role", "session_jwt", "sa_token", "sa_token_path",
        "tool_scope", "summary", "openshell_sandbox",
    }
    extra: dict[str, Any] = {}
    for k in extra_keys:
        if k in session:
            v = session[k]
            # SessionSummary is a pydantic model
            if hasattr(v, "model_dump"):
                extra[k] = v.model_dump()
            else:
                extra[k] = v
    return json.dumps(extra)


def _row_to_session(row: Any) -> dict[str, Any]:
    """Convert a DB row (asyncpg Record) back to a session dict."""
    extra: dict[str, Any] = {}
    extra_json = row["extra_json"] if "extra_json" in row.keys() else None
    if extra_json:
        try:
            raw = json.loads(extra_json)
            # Re-hydrate SessionSummary if present
            if "summary" in raw and raw["summary"] is not None:
                try:
                    from jit_approver.models import SessionSummary
                    raw["summary"] = SessionSummary(**raw["summary"])
                except Exception:
                    pass
            extra = raw
        except Exception:
            pass
    request_json = row["request_json"] if "request_json" in row.keys() else None
    session: dict[str, Any] = {
        "id": row["id"],
        "state": row["state"],
        "pr_url": row["pr_url"],
        "pr_number": row["pr_number"],
        "expires_at": str(row["expires_at"]) if row["expires_at"] else None,
        "request": _deserialize_request(request_json),
        **extra,
    }
    return session


def _sandbox_from_session(session: dict[str, Any]) -> str | None:
    req = session.get("request")
    return getattr(req, "sandbox", None) or session.get("openshell_sandbox")
