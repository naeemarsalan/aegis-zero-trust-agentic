"""Tests for the WORM audit ledger module (ledger.py) and store singleton.

Coverage:
  TestInMemoryAppendLedger  — already covered in test_persistence.py; the
    tests here focus on ledger.record() integration via the singleton.

  TestLedgerRecord
    - record() calls store.append_ledger with the supplied event dict
    - record() does NOT raise when append_ledger raises (fail-safe contract)
    - record() logs an ERROR when append_ledger raises

  TestGetStoreSingleton
    - get_store() returns the SAME instance across two calls
    - reset_store_singleton() causes the next call to return a NEW instance

All tests use the in-memory backend; no network or filesystem access.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Any
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Env setup (before any jit_approver import)
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
# Shared fixture: reset the store singleton before and after every test so
# ledger tests cannot bleed state into (or receive state from) other test files.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    from jit_approver.persistence import reset_store_singleton
    reset_store_singleton()
    yield
    reset_store_singleton()


# ===========================================================================
# TestLedgerRecord — ledger.record() behavior
# ===========================================================================


class TestLedgerRecord:
    async def test_record_calls_append_ledger(self):
        """record() delegates to the store's append_ledger with the event dict."""
        from jit_approver.persistence.memory import InMemoryStore
        from jit_approver import ledger

        mock_store = InMemoryStore()
        captured: list[dict[str, Any]] = []
        original_append = mock_store.append_ledger

        async def _capturing_append(payload: dict[str, Any]) -> int:
            captured.append(payload)
            return await original_append(payload)

        mock_store.append_ledger = _capturing_append  # type: ignore[method-assign]

        with patch("jit_approver.ledger.get_store", return_value=mock_store):
            await ledger.record({"event": "jit_test", "session_id": "abc-123"})

        assert len(captured) == 1
        assert captured[0]["event"] == "jit_test"
        assert captured[0]["session_id"] == "abc-123"

    async def test_record_fail_safe_does_not_raise_on_store_error(self):
        """record() must NOT propagate exceptions from append_ledger (fail-safe)."""
        from jit_approver import ledger

        class _FailingStore:
            async def append_ledger(self, payload: dict[str, Any]) -> int:
                raise RuntimeError("simulated DB is down")

        with patch("jit_approver.ledger.get_store", return_value=_FailingStore()):
            # This must complete without raising — fail-safe contract.
            await ledger.record({"event": "jit_test", "session_id": "xyz"})

    async def test_record_logs_error_on_store_failure(self, caplog: pytest.LogCaptureFixture):
        """When append_ledger raises, an ERROR is logged to jit_approver.ledger."""
        from jit_approver import ledger

        class _FailingStore:
            async def append_ledger(self, payload: dict[str, Any]) -> int:
                raise RuntimeError("test DB failure")

        with patch("jit_approver.ledger.get_store", return_value=_FailingStore()):
            with caplog.at_level(logging.ERROR, logger="jit_approver.ledger"):
                await ledger.record({"event": "jit_denied"})

        assert any(
            "ledger_append_failed" in r.getMessage() for r in caplog.records
        ), "Expected ledger_append_failed log entry on store error"

    async def test_record_writes_to_in_memory_store(self):
        """record() appends to the shared singleton InMemoryStore."""
        from jit_approver.persistence import get_store
        from jit_approver.persistence.memory import InMemoryStore
        from jit_approver import ledger

        # Ensure the singleton is an InMemoryStore for this test.
        os.environ.pop("JIT_STORE_BACKEND", None)
        store = get_store()
        assert isinstance(store, InMemoryStore)

        initial_seq, _ = await store.read_ledger_head()
        await ledger.record({"event": "jit_request", "session_id": "s42"})
        new_seq, _ = await store.read_ledger_head()

        assert new_seq == initial_seq + 1, (
            "Ledger head seq must advance by 1 after record()"
        )


# ===========================================================================
# TestGetStoreSingleton — singleton caching + reset
# ===========================================================================


class TestGetStoreSingleton:
    def test_same_instance_across_two_calls(self):
        """get_store() returns the SAME object on repeated calls (singleton)."""
        from jit_approver.persistence import get_store

        s1 = get_store()
        s2 = get_store()
        assert s1 is s2, (
            "get_store() must return the same instance on repeated calls "
            "(module-level singleton)"
        )

    def test_reset_store_singleton_clears_the_cache(self):
        """reset_store_singleton() causes the next call to return a NEW instance."""
        from jit_approver.persistence import get_store, reset_store_singleton

        s1 = get_store()
        reset_store_singleton()
        s2 = get_store()
        assert s1 is not s2, (
            "After reset_store_singleton(), get_store() must return a fresh instance"
        )

    def test_get_store_default_is_in_memory(self):
        """Default backend (no env var) returns an InMemoryStore."""
        from jit_approver.persistence import get_store
        from jit_approver.persistence.memory import InMemoryStore

        os.environ.pop("JIT_STORE_BACKEND", None)
        store = get_store()
        assert isinstance(store, InMemoryStore)

    def test_unknown_backend_raises_value_error_even_with_cached_singleton(self):
        """ValueError on unknown backend is raised regardless of existing singleton.

        The singleton is type-keyed by backend string: if the env changes to an
        unknown value the factory must raise (fail-closed) rather than silently
        returning the cached wrong-backend instance.
        """
        from jit_approver.persistence import get_store

        # Warm the singleton with memory.
        os.environ.pop("JIT_STORE_BACKEND", None)
        get_store()  # caches memory singleton

        # Now change to an unknown backend.
        with patch.dict(os.environ, {"JIT_STORE_BACKEND": "redis"}):
            with pytest.raises(ValueError, match="Unknown JIT_STORE_BACKEND"):
                get_store()


# ===========================================================================
# TestLedgerChainProperties — hash-chain arithmetic via the module API
# ===========================================================================


class TestLedgerChainProperties:
    """Verify the hash-chain arithmetic is correct when accessed via ledger.record()."""

    async def test_three_records_produce_linked_chain(self):
        """Three record() calls produce a 3-entry chain where each entry
        links to the previous via prev_hash == prior entry_hash."""
        from jit_approver.persistence import get_store
        from jit_approver.persistence.memory import InMemoryStore
        from jit_approver import ledger

        os.environ.pop("JIT_STORE_BACKEND", None)
        store = get_store()
        assert isinstance(store, InMemoryStore)

        events = [
            {"event": "jit_request", "session_id": "s1"},
            {"event": "jit_approved", "session_id": "s1"},
            {"event": "jit_issued", "session_id": "s1"},
        ]
        for e in events:
            await ledger.record(e)

        entries = sorted(store._ledger_entries, key=lambda x: x["seq"])
        assert len(entries) == 3

        # Genesis entry has empty prev_hash.
        assert entries[0]["prev_hash"] == ""
        # Chain linkage.
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
        assert entries[2]["prev_hash"] == entries[1]["entry_hash"]

    async def test_entry_hash_is_verifiable(self):
        """entry_hash = sha256(prev_hash + payload_json) — independently verifiable."""
        import json as _json
        from jit_approver.persistence import get_store
        from jit_approver.persistence.memory import InMemoryStore
        from jit_approver import ledger

        os.environ.pop("JIT_STORE_BACKEND", None)
        store = get_store()
        assert isinstance(store, InMemoryStore)

        payload = {"event": "jit_issued", "session_id": "verify-me", "ns": "agent-sandbox"}
        await ledger.record(payload)

        entry = store._ledger_entries[0]
        expected_hash = hashlib.sha256(
            (entry["prev_hash"] + entry["payload_json"]).encode()
        ).hexdigest()
        assert expected_hash == entry["entry_hash"]

        # Also verify the payload_json is canonical (sort_keys, compact separators).
        expected_json = _json.dumps(payload, sort_keys=True, separators=(",", ":"))
        assert entry["payload_json"] == expected_json
