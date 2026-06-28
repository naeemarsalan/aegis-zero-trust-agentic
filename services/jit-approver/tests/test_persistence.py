"""Persistence layer tests (L0).

Coverage:
  InMemoryStore (no external deps — always runs):
    - session CRUD: put / get / list / iter
    - update_state_atomic: once-only flip (C4)
    - update_state_atomic: second call returns False (once-only)
    - add_delivery_if_new: returns id on first insert, None on duplicate (C4)
    - ledger-head CAS: single advance succeeds
    - ledger-head CAS: concurrent advances — exactly one wins
    - compat dict names (session_store[id], seen_deliveries, store_lock)

  Adversarial (in-memory, no DB required):
    - update_state_atomic: concurrent flips from pending -> issued — exactly one wins
    - update_state_atomic: flip from terminal state returns False
    - add_delivery_if_new: duplicate delivery returns None (dedupe)
    - ledger-head CAS: duplicate advance (same expected_seq) — exactly one wins
    - WORM: no update_ledger or delete_ledger method on the ABC
    - Fail-closed signing key: JIT_REQUIRE_STABLE_KEY=true + missing PEM -> raises
    - Fail-closed signing key: flag false + missing PEM -> ephemeral fallback (PoC default)

  PostgresStore (skip-if-no-DB via pytest.mark.skipif / asyncpg ImportError):
    - startup_check: raises if jit_ledger table absent
    - update_state_atomic: concurrent flips — exactly one wins (DB-atomic)
    - add_delivery_if_new: returns None on duplicate (ON CONFLICT DO NOTHING)
    - advance_ledger_head_cas: concurrent advances — exactly one wins
    - Durability: write session + ledger row, rebuild pool, read back identical
    - WORM privilege: UPDATE/DELETE on jit_ledger denied for the 'app' role

  get_store() factory:
    - unknown JIT_STORE_BACKEND -> ValueError (fail closed)
    - JIT_STORE_BACKEND=postgres without asyncpg -> ImportError (clear message)
    - JIT_STORE_BACKEND=postgres without DATABASE_URL -> RuntimeError
    - JIT_STORE_BACKEND=memory -> InMemoryStore

  /healthz store_backend field:
    - In-memory: healthz returns store_backend='memory', store_ready=True
    - Postgres (mocked): startup_check fail -> 503 not_ready
"""
from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Env setup (before any app import)
# ---------------------------------------------------------------------------
os.environ.setdefault("JIT_ALLOWED_NAMESPACES", "agent-sandbox,agentic-mcp")
os.environ.setdefault("GITEA_TOKEN", "test-token")
os.environ.setdefault("GITEA_WEBHOOK_SECRET", "test-webhook-secret")
os.environ.setdefault("GITEA_REPO", "anaeem/nvidia-ida")
os.environ.setdefault("GITEA_BASE_URL", "https://git.arsalan.io")
os.environ.setdefault("GITEA_DEFAULT_BRANCH", "main")
os.environ.setdefault("VAULT_ADDR", "https://vault.apps.ocp-dev.na-launch.com")
os.environ.setdefault("JIT_DISABLE_REAPER", "1")

# ---------------------------------------------------------------------------
# Postgres availability check
# ---------------------------------------------------------------------------
try:
    import asyncpg  # noqa: F401
    _ASYNCPG_AVAILABLE = True
except ImportError:
    _ASYNCPG_AVAILABLE = False

_PG_URL = os.environ.get("TEST_DATABASE_URL", "")
_HAS_LIVE_DB = bool(_PG_URL and _ASYNCPG_AVAILABLE)

skip_no_db = pytest.mark.skipif(
    not _HAS_LIVE_DB,
    reason="No live Postgres (set TEST_DATABASE_URL and install asyncpg)",
)


# ===========================================================================
# InMemoryStore unit tests
# ===========================================================================


class TestInMemoryStore:
    @pytest.fixture(autouse=True)
    def store(self):
        from jit_approver.persistence.memory import InMemoryStore
        self._store = InMemoryStore()
        return self._store

    async def test_put_and_get_session(self):
        sid = str(uuid.uuid4())
        session = {"id": sid, "state": "pending", "pr_url": None, "request": None}
        await self._store.put_session(sid, session)
        got = await self._store.get_session(sid)
        assert got is not None
        assert got["id"] == sid
        assert got["state"] == "pending"

    async def test_get_missing_session_returns_none(self):
        got = await self._store.get_session("nonexistent")
        assert got is None

    async def test_update_state_atomic_pending_to_issued(self):
        sid = str(uuid.uuid4())
        await self._store.put_session(sid, {"id": sid, "state": "pending"})
        result = await self._store.update_state_atomic(sid, {"pending", "approved"}, "issued")
        assert result is True
        session = await self._store.get_session(sid)
        assert session["state"] == "issued"

    async def test_update_state_atomic_second_call_returns_false(self):
        """C4 once-only: second flip attempt on an already-issued session returns False."""
        sid = str(uuid.uuid4())
        await self._store.put_session(sid, {"id": sid, "state": "pending"})
        r1 = await self._store.update_state_atomic(sid, {"pending", "approved"}, "issued")
        r2 = await self._store.update_state_atomic(sid, {"pending", "approved"}, "issued")
        assert r1 is True
        assert r2 is False  # once-only: already issued, not in expected_states

    async def test_update_state_atomic_terminal_state_returns_false(self):
        """Flip from a terminal state (expired/denied) is blocked."""
        sid = str(uuid.uuid4())
        await self._store.put_session(sid, {"id": sid, "state": "expired"})
        result = await self._store.update_state_atomic(sid, {"pending", "approved"}, "issued")
        assert result is False
        session = await self._store.get_session(sid)
        assert session["state"] == "expired"  # unchanged

    async def test_update_state_atomic_missing_session_returns_false(self):
        result = await self._store.update_state_atomic("ghost", {"pending"}, "issued")
        assert result is False

    async def test_concurrent_state_atomic_exactly_one_wins(self):
        """Two concurrent flips from pending -> issued: exactly one returns True (C4)."""
        sid = str(uuid.uuid4())
        await self._store.put_session(sid, {"id": sid, "state": "pending"})

        results = []

        async def flip():
            r = await self._store.update_state_atomic(sid, {"pending", "approved"}, "issued")
            results.append(r)

        await asyncio.gather(flip(), flip(), flip())
        assert results.count(True) == 1
        assert results.count(False) == 2

    async def test_add_delivery_if_new_first_call_returns_id(self):
        delivery = "delivery-abc-123"
        result = await self._store.add_delivery_if_new(delivery)
        assert result == delivery

    async def test_add_delivery_if_new_duplicate_returns_none(self):
        """C4 replay: duplicate delivery id returns None (dedupe)."""
        delivery = "delivery-xyz-456"
        r1 = await self._store.add_delivery_if_new(delivery)
        r2 = await self._store.add_delivery_if_new(delivery)
        assert r1 == delivery
        assert r2 is None  # duplicate

    async def test_concurrent_delivery_dedupe_exactly_one_wins(self):
        """Two concurrent add_delivery_if_new calls for the same id: one wins, one None."""
        delivery = "delivery-concurrent-789"
        results = await asyncio.gather(
            self._store.add_delivery_if_new(delivery),
            self._store.add_delivery_if_new(delivery),
        )
        assert results.count(delivery) == 1
        assert results.count(None) == 1

    async def test_ledger_head_initial_state(self):
        seq, head_hash = await self._store.read_ledger_head()
        assert seq == 0
        assert head_hash == ""

    async def test_advance_ledger_head_cas_success(self):
        advanced = await self._store.advance_ledger_head_cas(0, 1, "hash-1")
        assert advanced is True
        seq, head_hash = await self._store.read_ledger_head()
        assert seq == 1
        assert head_hash == "hash-1"

    async def test_advance_ledger_head_cas_stale_expected_returns_false(self):
        """CAS with wrong expected_seq returns False (lost a race)."""
        advanced = await self._store.advance_ledger_head_cas(99, 100, "hash-100")
        assert advanced is False
        seq, _ = await self._store.read_ledger_head()
        assert seq == 0  # unchanged

    async def test_concurrent_ledger_head_cas_exactly_one_wins(self):
        """Two concurrent CAS advances with the same expected_seq: exactly one wins."""
        results = await asyncio.gather(
            self._store.advance_ledger_head_cas(0, 1, "hash-a"),
            self._store.advance_ledger_head_cas(0, 1, "hash-b"),
        )
        assert results.count(True) == 1
        assert results.count(False) == 1

    async def test_list_sessions_no_filter(self):
        await self._store.put_session("s1", {"id": "s1", "state": "pending"})
        await self._store.put_session("s2", {"id": "s2", "state": "issued"})
        sessions = await self._store.list_sessions()
        ids = {s["id"] for s in sessions}
        assert {"s1", "s2"} == ids

    async def test_list_sessions_filter_by_state(self):
        await self._store.put_session("s1", {"id": "s1", "state": "pending"})
        await self._store.put_session("s2", {"id": "s2", "state": "issued"})
        sessions = await self._store.list_sessions(state="pending")
        assert len(sessions) == 1
        assert sessions[0]["id"] == "s1"

    async def test_iter_sessions(self):
        await self._store.put_session("s1", {"id": "s1", "state": "pending"})
        pairs = await self._store.iter_sessions()
        assert len(pairs) == 1
        assert pairs[0][0] == "s1"

    async def test_startup_check_noop(self):
        """In-memory startup_check is a no-op (never raises)."""
        await self._store.startup_check()  # must not raise

    async def test_update_session_fields(self):
        sid = "test-fields"
        await self._store.put_session(sid, {"id": sid, "state": "pending", "pr_url": None})
        await self._store.update_session_fields(sid, {"expires_at": "2099-01-01T00:00:00Z"})
        session = await self._store.get_session(sid)
        assert session["expires_at"] == "2099-01-01T00:00:00Z"
        assert session["state"] == "pending"  # untouched



# ===========================================================================
# InMemoryStore.append_ledger — hash-chain integrity
# ===========================================================================


class TestInMemoryAppendLedger:
    """Tamper-evident hash-chain tests for InMemoryStore.append_ledger."""

    @pytest.fixture(autouse=True)
    def store(self):
        from jit_approver.persistence.memory import InMemoryStore
        self._store = InMemoryStore()
        return self._store

    async def test_seq_numbers_1_2_3(self):
        """Three consecutive appends yield seq 1, 2, 3 (1-based, monotone)."""
        s1 = await self._store.append_ledger({"event": "a"})
        s2 = await self._store.append_ledger({"event": "b"})
        s3 = await self._store.append_ledger({"event": "c"})
        assert s1 == 1
        assert s2 == 2
        assert s3 == 3

    async def test_chain_prev_hash_links(self):
        """Entry N's prev_hash equals entry N-1's entry_hash (chain linkage)."""
        await self._store.append_ledger({"event": "first"})
        await self._store.append_ledger({"event": "second"})
        await self._store.append_ledger({"event": "third"})
        entries = self._store._ledger_entries
        assert len(entries) == 3
        # First entry: prev_hash is "" (genesis)
        assert entries[0]["prev_hash"] == ""
        # Each subsequent entry's prev_hash == prior entry's entry_hash.
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
        assert entries[2]["prev_hash"] == entries[1]["entry_hash"]

    async def test_same_payload_yields_different_entry_hash(self):
        """Identical payloads produce different entry_hash values (prev_hash differs).

        This proves that the hash-chain property holds: replaying the same event
        twice cannot produce colliding hashes, because each entry commits to its
        position in the chain via prev_hash.
        """
        payload = {"event": "duplicate", "session_id": "abc"}
        await self._store.append_ledger(payload)
        await self._store.append_ledger(payload)
        entries = self._store._ledger_entries
        assert entries[0]["entry_hash"] != entries[1]["entry_hash"], (
            "Same payload at different positions must produce different entry_hash "
            "because prev_hash is different"
        )

    async def test_head_advances_after_append(self):
        """read_ledger_head() returns the seq and entry_hash of the latest entry."""
        seq_ret = await self._store.append_ledger({"event": "x"})
        seq_head, hash_head = await self._store.read_ledger_head()
        assert seq_head == 1
        assert seq_ret == 1
        assert hash_head == self._store._ledger_entries[0]["entry_hash"]

    async def test_verifiable_chain_recomputation(self):
        """Recomputing entry_hash from (prev_hash + payload_json) matches the stored value.

        This is the tamper-detection property: an auditor can re-derive every
        entry_hash independently and detect any in-place modification.
        """
        import hashlib
        payloads = [
            {"event": "jit_request", "session_id": "s1"},
            {"event": "jit_approved", "session_id": "s1"},
            {"event": "jit_issued", "session_id": "s1"},
        ]
        for p in payloads:
            await self._store.append_ledger(p)

        for entry in self._store._ledger_entries:
            recomputed = hashlib.sha256(
                (entry["prev_hash"] + entry["payload_json"]).encode()
            ).hexdigest()
            assert recomputed == entry["entry_hash"], (
                f"Chain verification failed at seq={entry['seq']}: "
                f"recomputed={recomputed!r} stored={entry['entry_hash']!r}"
            )

    async def test_genesis_entry_prev_hash_is_empty(self):
        """First ledger entry has prev_hash == '' (no predecessor)."""
        await self._store.append_ledger({"event": "genesis"})
        assert self._store._ledger_entries[0]["prev_hash"] == ""

    async def test_concurrent_appends_produce_consistent_chain(self):
        """Concurrent appends under asyncio must still produce a consistent chain
        (no lost updates, seq is contiguous, each prev_hash == prior entry_hash)."""
        payloads = [{"event": "concurrent", "n": i} for i in range(10)]
        await asyncio.gather(*[self._store.append_ledger(p) for p in payloads])

        entries = sorted(self._store._ledger_entries, key=lambda e: e["seq"])
        assert len(entries) == 10
        # seq values are 1..10 (no gaps).
        assert [e["seq"] for e in entries] == list(range(1, 11))
        # Chain linkage holds for every adjacent pair.
        for i in range(1, len(entries)):
            assert entries[i]["prev_hash"] == entries[i - 1]["entry_hash"], (
                f"Chain broken between seq={entries[i-1]['seq']} and seq={entries[i]['seq']}"
            )


# ===========================================================================
# Compat shim tests (store.py module-level names)
# ===========================================================================


class TestCompatShim:
    @pytest.fixture(autouse=True)
    def reset_store(self):
        """Reset the module-level store between tests."""
        from jit_approver.store import session_store, seen_deliveries
        session_store.clear()
        seen_deliveries.clear()
        yield
        session_store.clear()
        seen_deliveries.clear()

    def test_session_store_dict_setitem_getitem(self):
        from jit_approver.store import session_store
        session_store["abc"] = {"id": "abc", "state": "pending"}
        assert session_store["abc"]["state"] == "pending"

    def test_session_store_get_missing_returns_none(self):
        from jit_approver.store import session_store
        assert session_store.get("ghost") is None

    def test_session_store_contains(self):
        from jit_approver.store import session_store
        session_store["x"] = {"id": "x"}
        assert "x" in session_store
        assert "y" not in session_store

    def test_session_store_items(self):
        from jit_approver.store import session_store
        session_store["s1"] = {"id": "s1"}
        session_store["s2"] = {"id": "s2"}
        keys = [k for k, _ in session_store.items()]
        assert set(keys) == {"s1", "s2"}

    def test_seen_deliveries_add_and_check(self):
        from jit_approver.store import seen_deliveries
        seen_deliveries.add("d1")
        assert "d1" in seen_deliveries
        assert "d2" not in seen_deliveries

    def test_store_lock_is_asyncio_lock(self):
        import asyncio
        from jit_approver.store import store_lock
        assert isinstance(store_lock, asyncio.Lock)

    def test_session_store_clear(self):
        from jit_approver.store import session_store, seen_deliveries
        session_store["k"] = {"id": "k"}
        seen_deliveries.add("d")
        session_store.clear()
        assert "k" not in session_store
        # seen_deliveries cleared by InMemoryStore.clear()
        assert "d" not in seen_deliveries


# ===========================================================================
# WORM invariant: Store ABC has no update/delete ledger methods
# ===========================================================================


class TestWORMContract:
    def test_store_abc_has_no_update_ledger(self):
        """The Store ABC MUST NOT expose an update_ledger or delete_ledger method."""
        from jit_approver.persistence.base import Store
        assert not hasattr(Store, "update_ledger")
        assert not hasattr(Store, "delete_ledger")

    def test_memory_store_has_no_update_ledger(self):
        from jit_approver.persistence.memory import InMemoryStore
        store = InMemoryStore()
        assert not hasattr(store, "update_ledger")
        assert not hasattr(store, "delete_ledger")

    def test_schema_has_no_update_on_jit_ledger(self):
        """Schema SQL has no UPDATE or DELETE statements against jit_ledger."""
        from pathlib import Path
        schema = (
            Path(__file__).resolve().parents[1]
            / "src/jit_approver/persistence/schema.sql"
        )
        text = schema.read_text().upper()
        # The schema should contain REVOKE UPDATE ... ON JIT_LEDGER but NEVER
        # an UPDATE jit_ledger SET ... or DELETE FROM jit_ledger.
        lines = text.splitlines()
        for line in lines:
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("--"):
                continue
            if "REVOKE UPDATE" in stripped:
                continue  # this is the WORM enforcement, expected
            assert "UPDATE JIT_LEDGER" not in stripped, f"Unexpected UPDATE on jit_ledger: {line}"
            assert "DELETE FROM JIT_LEDGER" not in stripped, f"Unexpected DELETE on jit_ledger: {line}"


# ===========================================================================
# Adversarial fail-closed signing key tests
# ===========================================================================


class TestFailClosedSigningKey:
    @pytest.fixture(autouse=True)
    def reset_key_cache(self):
        from jit_approver import signing
        signing.reset_keys_for_test()
        yield
        signing.reset_keys_for_test()

    def test_require_stable_key_missing_pem_raises(self, tmp_path):
        """JIT_REQUIRE_STABLE_KEY=true + missing PEM -> RuntimeError (fail closed)."""
        missing = str(tmp_path / "nonexistent.pem")
        with (
            patch.dict(os.environ, {
                "JIT_SIGNING_KEY_PATH": missing,
                "JIT_REQUIRE_STABLE_KEY": "true",
            }),
        ):
            from jit_approver import signing
            signing.reset_keys_for_test()
            with pytest.raises(RuntimeError, match="JIT_REQUIRE_STABLE_KEY=true"):
                signing._load_or_generate_key()

    def test_require_stable_key_false_missing_pem_falls_back_to_ephemeral(self, tmp_path):
        """JIT_REQUIRE_STABLE_KEY=false (default) + missing PEM -> ephemeral fallback (PoC)."""
        missing = str(tmp_path / "nonexistent.pem")
        with (
            patch.dict(os.environ, {
                "JIT_SIGNING_KEY_PATH": missing,
                "JIT_REQUIRE_STABLE_KEY": "false",
            }),
        ):
            from jit_approver import signing
            signing.reset_keys_for_test()
            # Must NOT raise — PoC ephemeral fallback preserved.
            keys = signing._load_or_generate_key()
            assert keys is not None
            assert keys.private_pem  # ephemeral key was generated

    def test_require_stable_key_unset_missing_pem_falls_back_to_ephemeral(self, tmp_path):
        """No JIT_REQUIRE_STABLE_KEY set (default) + missing PEM -> ephemeral fallback."""
        missing = str(tmp_path / "nonexistent.pem")
        env = {
            "JIT_SIGNING_KEY_PATH": missing,
        }
        # Remove JIT_REQUIRE_STABLE_KEY from env if set
        env_clean = {k: v for k, v in os.environ.items() if k != "JIT_REQUIRE_STABLE_KEY"}
        env_clean["JIT_SIGNING_KEY_PATH"] = missing
        with patch.dict(os.environ, env_clean, clear=True):
            from jit_approver import signing
            signing.reset_keys_for_test()
            keys = signing._load_or_generate_key()
            assert keys is not None

    def test_require_stable_key_valid_pem_loads_stable(self, tmp_path):
        """JIT_REQUIRE_STABLE_KEY=true + valid PEM -> loads stable key (no raise)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pem_file = tmp_path / "signing.pem"
        pem_file.write_bytes(pem_bytes)

        with patch.dict(os.environ, {
            "JIT_SIGNING_KEY_PATH": str(pem_file),
            "JIT_REQUIRE_STABLE_KEY": "true",
        }):
            from jit_approver import signing
            signing.reset_keys_for_test()
            keys = signing._load_or_generate_key()
            assert keys is not None


# ===========================================================================
# get_store() factory adversarial tests
# ===========================================================================


class TestGetStoreFactory:
    @pytest.fixture(autouse=True)
    def _reset_singleton(self):
        """Ensure each factory test starts and ends with a clean singleton."""
        from jit_approver.persistence import reset_store_singleton
        reset_store_singleton()
        yield
        reset_store_singleton()

    def test_unknown_backend_raises_value_error(self):
        with patch.dict(os.environ, {"JIT_STORE_BACKEND": "redis"}):
            from jit_approver.persistence import get_store
            with pytest.raises(ValueError, match="Unknown JIT_STORE_BACKEND"):
                get_store()

    def test_memory_backend_returns_in_memory_store(self):
        with patch.dict(os.environ, {"JIT_STORE_BACKEND": "memory"}):
            from jit_approver.persistence import get_store
            from jit_approver.persistence.memory import InMemoryStore
            store = get_store()
            assert isinstance(store, InMemoryStore)

    def test_unset_backend_defaults_to_memory(self):
        env = {k: v for k, v in os.environ.items() if k != "JIT_STORE_BACKEND"}
        with patch.dict(os.environ, env, clear=True):
            from jit_approver.persistence import get_store
            from jit_approver.persistence.memory import InMemoryStore
            store = get_store()
            assert isinstance(store, InMemoryStore)

    def test_postgres_without_database_url_raises(self):
        if not _ASYNCPG_AVAILABLE:
            pytest.skip("asyncpg not installed")
        env = {k: v for k, v in os.environ.items() if k not in ("JIT_STORE_BACKEND", "DATABASE_URL")}
        env["JIT_STORE_BACKEND"] = "postgres"
        with patch.dict(os.environ, env, clear=True):
            from jit_approver.persistence import get_store
            with pytest.raises(RuntimeError, match="DATABASE_URL"):
                get_store()

    def test_postgres_without_asyncpg_raises_import_error(self):
        with (
            patch.dict(os.environ, {
                "JIT_STORE_BACKEND": "postgres",
                "DATABASE_URL": "postgresql://localhost/test",
            }),
            patch.dict("sys.modules", {"asyncpg": None}),
        ):
            # Force re-import of persistence/__init__.py to pick up patched sys.modules
            import importlib
            import jit_approver.persistence as persistence_mod
            # Patch the internal import inside get_store
            original_get_store = persistence_mod.get_store

            def patched_get_store():
                backend = os.environ.get("JIT_STORE_BACKEND", "memory").strip().lower()
                if backend == "postgres":
                    try:
                        import asyncpg  # noqa: F401
                        raise AssertionError("asyncpg should not be importable here")
                    except (ImportError, TypeError):
                        raise ImportError(
                            "JIT_STORE_BACKEND=postgres requires 'asyncpg'. "
                            "Install with: pip install 'jit-approver[durable]'"
                        )

            # Simply verify the error message shape from get_store by testing the
            # postgres.py module import guard (more reliable than patching sys.modules)
            from jit_approver.persistence.postgres import PostgresStore
            with patch("jit_approver.persistence.postgres._ASYNCPG_AVAILABLE", False):
                with pytest.raises(ImportError, match="asyncpg"):
                    PostgresStore(db_url="postgresql://localhost/test")


# ===========================================================================
# /healthz store_backend field tests
# ===========================================================================


class TestHealthzStoreBackend:
    @pytest.fixture(autouse=True)
    def reset_api_state(self):
        import jit_approver.api as api_mod
        original_backend = api_mod._store_backend
        original_ready = api_mod._store_ready
        yield
        api_mod._store_backend = original_backend
        api_mod._store_ready = original_ready

    def test_healthz_reports_memory_backend(self):
        from fastapi.testclient import TestClient
        from jit_approver.api import app
        import jit_approver.api as api_mod
        api_mod._store_backend = "memory"
        api_mod._store_ready = True

        with TestClient(app) as client:
            resp = client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["store_backend"] == "memory"
        assert data["store_ready"] is True

    def test_healthz_not_ready_returns_503(self):
        """When _store_ready is False (durable backend not yet connected), /healthz returns 503.

        We set the global INSIDE the TestClient context (after lifespan) then call the endpoint.
        This simulates a race where the backend becomes not-ready after startup.
        """
        from fastapi.testclient import TestClient
        from jit_approver.api import app
        import jit_approver.api as api_mod

        with TestClient(app) as client:
            # Override AFTER lifespan has run (lifespan sets _store_ready=True for memory).
            api_mod._store_backend = "postgres"
            api_mod._store_ready = False
            resp = client.get("/healthz")

        # 503 when store is not ready
        assert resp.status_code == 503
        data = resp.json()
        assert data["store_backend"] == "postgres"
        assert data["store_ready"] is False


# ===========================================================================
# Fail-closed DB startup tests (Postgres, no live DB required)
# ===========================================================================


class TestFailClosedDBStartup:
    async def test_postgres_startup_check_raises_on_unreachable_db(self):
        """PostgresStore.startup_check raises on a bad DATABASE_URL (fail closed)."""
        if not _ASYNCPG_AVAILABLE:
            pytest.skip("asyncpg not installed")
        from jit_approver.persistence.postgres import PostgresStore

        store = PostgresStore(db_url="postgresql://invalid:invalid@localhost:9999/nonexistent")
        with pytest.raises(Exception):  # noqa: B017 — pool open or SELECT 1 fails
            await store.startup_check()

    async def test_postgres_startup_check_raises_on_missing_table(self):
        """startup_check raises RuntimeError when jit_ledger table is absent."""
        if not _ASYNCPG_AVAILABLE:
            pytest.skip("asyncpg not installed")
        import asyncpg as apg
        from jit_approver.persistence.postgres import PostgresStore

        fake_conn = AsyncMock()
        fake_conn.fetchval = AsyncMock(side_effect=[1, False])  # SELECT 1 ok, EXISTS False

        fake_pool = MagicMock()
        fake_pool.acquire = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=fake_conn),
            __aexit__=AsyncMock(return_value=None),
        ))

        store = PostgresStore(db_url="postgresql://fake/fake")
        store._pool = fake_pool

        with pytest.raises(RuntimeError, match="required table"):
            await store.startup_check()


# ===========================================================================
# Postgres live-DB tests (skip-if-no-DB)
# ===========================================================================


@skip_no_db
class TestPostgresStoreLiveDB:
    @pytest.fixture(autouse=True)
    async def setup_store(self):
        """Create a fresh PostgresStore and apply schema before each test."""
        from jit_approver.persistence.postgres import PostgresStore
        import asyncpg as apg

        self._store = PostgresStore(db_url=_PG_URL)
        # Apply schema (idempotent)
        from pathlib import Path
        schema = (
            Path(__file__).resolve().parents[1]
            / "src/jit_approver/persistence/schema.sql"
        )
        conn = await apg.connect(_PG_URL)
        await conn.execute(schema.read_text())
        await conn.close()
        # Startup check
        await self._store.startup_check()
        yield
        # Teardown: truncate all tables for test isolation
        conn = await apg.connect(_PG_URL)
        await conn.execute(
            "TRUNCATE jit_session, jit_delivery, jit_ledger CASCADE; "
            "UPDATE jit_ledger_head SET seq=0, head_hash='' WHERE id=1;"
        )
        await conn.close()
        if self._store._pool:
            await self._store._pool.close()

    async def test_put_and_get_session(self):
        from jit_approver.models import EscalationRequest
        sid = str(uuid.uuid4())
        req = EscalationRequest(
            agent_spiffe_id="spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/a",
            requester_sub="user@example.com",
            namespace="agent-sandbox",
            verbs=["get"],
            resources=["pods"],
            duration_minutes=10,
            justification="test session for incident INC-1",
        )
        session = {
            "id": sid,
            "state": "pending",
            "pr_url": "https://git.arsalan.io/pulls/1",
            "pr_number": 1,
            "expires_at": None,
            "request": req,
        }
        await self._store.put_session(sid, session)
        got = await self._store.get_session(sid)
        assert got is not None
        assert got["id"] == sid
        assert got["state"] == "pending"

    async def test_update_state_atomic_once_only(self):
        """C4: DB-atomic flip once; second attempt returns False."""
        sid = str(uuid.uuid4())
        await self._store.put_session(sid, {"id": sid, "state": "pending", "pr_url": None,
                                            "pr_number": 1, "expires_at": None, "request": None})
        r1 = await self._store.update_state_atomic(sid, {"pending", "approved"}, "issued")
        r2 = await self._store.update_state_atomic(sid, {"pending", "approved"}, "issued")
        assert r1 is True
        assert r2 is False

    async def test_concurrent_update_state_atomic_exactly_one_wins(self):
        """Two concurrent DB flips for the same session: exactly one wins."""
        sid = str(uuid.uuid4())
        await self._store.put_session(sid, {"id": sid, "state": "pending", "pr_url": None,
                                            "pr_number": 1, "expires_at": None, "request": None})

        import asyncpg as apg
        from jit_approver.persistence.postgres import PostgresStore

        store2 = PostgresStore(db_url=_PG_URL)
        results = await asyncio.gather(
            self._store.update_state_atomic(sid, {"pending", "approved"}, "issued"),
            store2.update_state_atomic(sid, {"pending", "approved"}, "issued"),
        )
        assert results.count(True) == 1
        assert results.count(False) == 1
        if store2._pool:
            await store2._pool.close()

    async def test_add_delivery_if_new_dedupe_survives_pool_restart(self):
        """Dedupe survives simulated pod restart (new pool, re-insert returns None)."""
        from jit_approver.persistence.postgres import PostgresStore

        delivery = f"delivery-{uuid.uuid4()}"
        r1 = await self._store.add_delivery_if_new(delivery)
        assert r1 == delivery

        # Simulate pod restart: new pool
        store2 = PostgresStore(db_url=_PG_URL)
        r2 = await store2.add_delivery_if_new(delivery)
        assert r2 is None  # duplicate detected from DB, not process memory
        if store2._pool:
            await store2._pool.close()

    async def test_durability_session_survives_pool_restart(self):
        """Session state survives a simulated pod restart (new pool)."""
        from jit_approver.persistence.postgres import PostgresStore

        sid = str(uuid.uuid4())
        await self._store.put_session(sid, {
            "id": sid, "state": "pending", "pr_url": "https://git.arsalan.io/pulls/99",
            "pr_number": 99, "expires_at": None, "request": None,
        })
        await self._store.update_state_atomic(sid, {"pending"}, "issued")

        # Simulate pod restart: new pool
        store2 = PostgresStore(db_url=_PG_URL)
        got = await store2.get_session(sid)
        assert got is not None
        assert got["state"] == "issued"
        if store2._pool:
            await store2._pool.close()

    async def test_advance_ledger_head_cas_concurrent_exactly_one_wins(self):
        """Two concurrent CAS advances: exactly one wins."""
        from jit_approver.persistence.postgres import PostgresStore

        store2 = PostgresStore(db_url=_PG_URL)
        results = await asyncio.gather(
            self._store.advance_ledger_head_cas(0, 1, "hash-a"),
            store2.advance_ledger_head_cas(0, 1, "hash-b"),
        )
        assert results.count(True) == 1
        assert results.count(False) == 1
        if store2._pool:
            await store2._pool.close()

    @pytest.mark.skipif(
        not _HAS_LIVE_DB,
        reason="WORM privilege test requires live DB with REVOKE enforced",
    )
    async def test_worm_privilege_update_jit_ledger_denied(self):
        """UPDATE on jit_ledger as the app role fails (REVOKE enforced)."""
        import asyncpg as apg

        # First insert a ledger row (INSERT is allowed)
        pool = await self._store._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO jit_ledger(prev_hash, entry_hash, payload_json) "
                "VALUES('', 'h1', '{}')"
            )
            # Attempt UPDATE (must fail — REVOKE UPDATE on jit_ledger FROM app)
            with pytest.raises(apg.InsufficientPrivilegeError):
                await conn.execute(
                    "UPDATE jit_ledger SET payload_json = '{\"tampered\":true}'"
                )

    @pytest.mark.skipif(
        not _HAS_LIVE_DB,
        reason="WORM privilege test requires live DB with REVOKE enforced",
    )
    async def test_worm_privilege_delete_jit_ledger_denied(self):
        """DELETE on jit_ledger as the app role fails (REVOKE enforced)."""
        import asyncpg as apg

        pool = await self._store._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO jit_ledger(prev_hash, entry_hash, payload_json) "
                "VALUES('', 'h2', '{}')"
            )
            with pytest.raises(apg.InsufficientPrivilegeError):
                await conn.execute("DELETE FROM jit_ledger")
