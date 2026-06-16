"""Unit tests for agent_harness.agent_runner.

No network. No SPIFFE socket. claude-agent-sdk query() is mocked.
Tests verify the JSONL redaction contract and the run_agent() logic.
"""

from __future__ import annotations

import asyncio
import json
import sys
from io import StringIO
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture_stdout(func, *args, **kwargs) -> list[dict[str, Any]]:
    """Run a coroutine (or sync callable) and capture JSONL lines from stdout."""
    buf = StringIO()
    with patch("sys.stdout", buf):
        if asyncio.iscoroutinefunction(func):
            asyncio.run(func(*args, **kwargs))
        else:
            func(*args, **kwargs)
    lines = [l for l in buf.getvalue().splitlines() if l.strip()]
    return [json.loads(l) for l in lines]


async def _collect_jsonl(coro) -> list[dict[str, Any]]:
    buf = StringIO()
    with patch("sys.stdout", buf):
        result = await coro
    lines = [l for l in buf.getvalue().splitlines() if l.strip()]
    return [json.loads(l) for l in lines], result


# ---------------------------------------------------------------------------
# _redact
# ---------------------------------------------------------------------------


class TestRedact:
    def test_redacts_authorization_key(self) -> None:
        from agent_harness.agent_runner import _redact

        obj = {"authorization": "Bearer secret-token", "other": "value"}
        result = _redact(obj)
        assert result["authorization"] == "<redacted>"
        assert result["other"] == "value"

    def test_redacts_bearer_key(self) -> None:
        from agent_harness.agent_runner import _redact

        obj = {"bearer": "some-token"}
        assert _redact(obj)["bearer"] == "<redacted>"

    def test_redacts_mcp_servers(self) -> None:
        from agent_harness.agent_runner import _redact

        obj = {"mcp_servers": {"gateway": {"headers": {"Authorization": "Bearer x"}}}}
        result = _redact(obj)
        assert result["mcp_servers"] == "<redacted>"

    def test_redacts_headers_key(self) -> None:
        from agent_harness.agent_runner import _redact

        obj = {"headers": {"Authorization": "Bearer z"}}
        assert _redact(obj)["headers"] == "<redacted>"

    def test_redacts_case_insensitive(self) -> None:
        from agent_harness.agent_runner import _redact

        obj = {"Authorization": "secret", "BEARER": "secret2"}
        result = _redact(obj)
        assert result["Authorization"] == "<redacted>"
        assert result["BEARER"] == "<redacted>"

    def test_allows_safe_keys(self) -> None:
        from agent_harness.agent_runner import _redact

        obj = {"type": "tool_use", "tool": "search_firewall_rules", "args_hash": "abc123"}
        result = _redact(obj)
        assert result == obj

    def test_redacts_nested_dict(self) -> None:
        from agent_harness.agent_runner import _redact

        obj = {"outer": {"inner": {"authorization": "leak"}}}
        result = _redact(obj)
        assert result["outer"]["inner"]["authorization"] == "<redacted>"

    def test_handles_list(self) -> None:
        from agent_harness.agent_runner import _redact

        obj = [{"authorization": "x"}, {"safe": "y"}]
        result = _redact(obj)
        assert result[0]["authorization"] == "<redacted>"
        assert result[1]["safe"] == "y"

    def test_depth_limit(self) -> None:
        from agent_harness.agent_runner import _redact

        # Build a deeply nested dict — should not blow the stack.
        deep: Any = "leaf"
        for _ in range(25):
            deep = {"k": deep}
        result = _redact(deep)
        assert result is not None


# ---------------------------------------------------------------------------
# _args_hash
# ---------------------------------------------------------------------------


class TestArgsHash:
    def test_deterministic(self) -> None:
        from agent_harness.agent_runner import _args_hash

        h1 = _args_hash({"b": 2, "a": 1})
        h2 = _args_hash({"a": 1, "b": 2})
        assert h1 == h2  # sort_keys canonical form

    def test_hex_sha256(self) -> None:
        from agent_harness.agent_runner import _args_hash

        h = _args_hash({})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_empty_args(self) -> None:
        from agent_harness.agent_runner import _args_hash

        # search_firewall_rules with no args — bare call.
        h = _args_hash({})
        assert isinstance(h, str) and len(h) == 64


# ---------------------------------------------------------------------------
# emit_jsonl
# ---------------------------------------------------------------------------


class TestEmitJsonl:
    def test_emits_valid_json(self) -> None:
        from agent_harness.agent_runner import emit_jsonl

        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_jsonl({"type": "system", "msg": "hello"})
        line = buf.getvalue().strip()
        parsed = json.loads(line)
        assert parsed["type"] == "system"

    def test_redacts_before_emit(self) -> None:
        from agent_harness.agent_runner import emit_jsonl

        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_jsonl({"type": "tool_use", "headers": {"Authorization": "Bearer SECRET"}})
        parsed = json.loads(buf.getvalue().strip())
        assert parsed["headers"] == "<redacted>"

    def test_adds_ts_when_absent(self) -> None:
        from agent_harness.agent_runner import emit_jsonl

        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_jsonl({"type": "result"})
        parsed = json.loads(buf.getvalue().strip())
        assert "ts" in parsed

    def test_no_bearer_value_in_output(self) -> None:
        """Security invariant: no raw Bearer token value in any emitted line."""
        from agent_harness.agent_runner import emit_jsonl

        secret = "SUPER_SECRET_TOKEN_VALUE"
        buf = StringIO()
        with patch("sys.stdout", buf):
            emit_jsonl({
                "type": "system",
                "authorization": f"Bearer {secret}",
                "nested": {"bearer": secret},
            })
        output = buf.getvalue()
        assert secret not in output


# ---------------------------------------------------------------------------
# run_agent — happy path
# ---------------------------------------------------------------------------


class TestRunAgentHappyPath:
    @pytest.mark.asyncio
    async def test_success_returns_true(self) -> None:
        """run_agent returns True when ResultMessage.is_error=False."""
        from agent_harness import agent_runner

        # Build fake SDK messages.
        fake_result = MagicMock()
        fake_result.__class__.__name__ = "ResultMessage"
        fake_result.is_error = False
        fake_result.result = "Firewall rules retrieved successfully."
        fake_result.stop_reason = "end_turn"
        fake_result.num_turns = 2
        fake_result.errors = None

        fake_assistant = MagicMock()
        fake_assistant.__class__.__name__ = "AssistantMessage"
        text_block = MagicMock()
        text_block.__class__.__name__ = "TextBlock"
        text_block.text = "Here are the firewall rules."
        fake_assistant.content = [text_block]

        async def _fake_query(*, prompt, options):
            yield fake_assistant
            yield fake_result

        buf = StringIO()
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value="fake.svid"),
                patch.object(agent_runner, "sdk_query", _fake_query),
                patch.object(agent_runner, "_build_options", return_value=MagicMock()),
            ):
                result = await agent_runner.run_agent(
                    goal="list all firewall rules",
                    session_id="test-session-01",
                )

        assert result is True
        lines = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        types = [l["type"] for l in lines]
        assert "result" in types
        result_line = next(l for l in lines if l["type"] == "result")
        assert result_line["status"] == "success"

    @pytest.mark.asyncio
    async def test_tool_use_args_are_hashed(self) -> None:
        """Tool use block emits args_hash, never raw args."""
        from agent_harness import agent_runner

        fake_result = MagicMock()
        fake_result.__class__.__name__ = "ResultMessage"
        fake_result.is_error = False
        fake_result.result = "done"
        fake_result.stop_reason = "end_turn"
        fake_result.num_turns = 1
        fake_result.errors = None

        fake_assistant = MagicMock()
        fake_assistant.__class__.__name__ = "AssistantMessage"
        tool_block = MagicMock()
        tool_block.__class__.__name__ = "ToolUseBlock"
        tool_block.name = "mcp__mcp-gateway__search_firewall_rules"
        tool_block.input = {"page": 1, "page_size": 20}
        fake_assistant.content = [tool_block]

        async def _fake_query(*, prompt, options):
            yield fake_assistant
            yield fake_result

        buf = StringIO()
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value="fake.svid"),
                patch.object(agent_runner, "sdk_query", _fake_query),
                patch.object(agent_runner, "_build_options", return_value=MagicMock()),
            ):
                await agent_runner.run_agent(
                    goal="list firewall rules",
                    session_id="test-session-02",
                )

        output = buf.getvalue()
        # Raw args values must NOT appear in output.
        assert '"page": 1' not in output
        assert "page_size" not in output

        lines = [json.loads(l) for l in output.splitlines() if l.strip()]
        tool_lines = [l for l in lines if l.get("type") == "tool_use"]
        for tl in tool_lines:
            assert "args_hash" in tl
            assert "input" not in tl
            assert "args" not in tl


# ---------------------------------------------------------------------------
# run_agent — error / deny paths
# ---------------------------------------------------------------------------


class TestRunAgentErrorPath:
    @pytest.mark.asyncio
    async def test_returns_false_on_is_error(self) -> None:
        """ResultMessage.is_error=True -> run_agent returns False."""
        from agent_harness import agent_runner

        fake_result = MagicMock()
        fake_result.__class__.__name__ = "ResultMessage"
        fake_result.is_error = True
        fake_result.result = ""
        fake_result.stop_reason = "tool_error"
        fake_result.num_turns = 1
        fake_result.errors = ["403 Forbidden"]

        async def _fake_query(*, prompt, options):
            yield fake_result

        buf = StringIO()
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value="fake.svid"),
                patch.object(agent_runner, "sdk_query", _fake_query),
                patch.object(agent_runner, "_build_options", return_value=MagicMock()),
            ):
                result = await agent_runner.run_agent(
                    goal="list firewall rules",
                    session_id="test-error-01",
                )

        assert result is False
        lines = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        result_line = next((l for l in lines if l["type"] == "result"), None)
        assert result_line is not None
        assert result_line["status"] == "error"

    @pytest.mark.asyncio
    async def test_svid_fetch_failure_returns_false(self) -> None:
        """SVID fetch failure -> run_agent returns False, emits error result."""
        from agent_harness import agent_runner

        buf = StringIO()
        with patch("sys.stdout", buf):
            with patch.object(agent_runner, "fetch_agent_svid", side_effect=RuntimeError("svid fail")):
                result = await agent_runner.run_agent(
                    goal="list rules",
                    session_id="test-svid-fail",
                )

        assert result is False
        lines = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        result_line = next((l for l in lines if l["type"] == "result"), None)
        assert result_line is not None
        assert result_line["status"] == "error"

    @pytest.mark.asyncio
    async def test_no_credential_in_jsonl_on_any_path(self) -> None:
        """Security invariant: no Bearer/token value appears in any emitted line."""
        from agent_harness import agent_runner

        fake_result = MagicMock()
        fake_result.__class__.__name__ = "ResultMessage"
        fake_result.is_error = True
        fake_result.result = ""
        fake_result.stop_reason = "error"
        fake_result.num_turns = 0
        fake_result.errors = ["auth error: 401"]

        async def _fake_query(*, prompt, options):
            yield fake_result

        secret_svid = "FAKE.SECRET.SVID.DO.NOT.LOG"

        buf = StringIO()
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value=secret_svid),
                patch.object(agent_runner, "sdk_query", _fake_query),
                patch.object(agent_runner, "_build_options", return_value=MagicMock()),
            ):
                await agent_runner.run_agent(
                    goal="list rules",
                    session_id="test-cred-check",
                )

        output = buf.getvalue()
        assert secret_svid not in output, "SVID token appeared in JSONL output — security violation"

    @pytest.mark.asyncio
    async def test_sdk_exception_returns_false(self) -> None:
        """Unrecoverable SDK exception -> run_agent returns False."""
        from agent_harness import agent_runner

        async def _bad_query(*, prompt, options):
            raise ConnectionError("network failure")
            yield  # make it an async generator  # pragma: no cover

        buf = StringIO()
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value="fake.svid"),
                patch.object(agent_runner, "sdk_query", _bad_query),
                patch.object(agent_runner, "_build_options", return_value=MagicMock()),
            ):
                result = await agent_runner.run_agent(
                    goal="list rules",
                    session_id="test-net-fail",
                )

        assert result is False
        lines = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        result_line = next((l for l in lines if l["type"] == "result"), None)
        assert result_line is not None
        assert result_line["status"] == "error"


# ---------------------------------------------------------------------------
# Finding 7: narrowed SVID retry heuristic
# ---------------------------------------------------------------------------


class TestSVIDRetryHeuristic:
    """Finding 7: the SVID-refresh retry must only trigger on explicit auth signals
    (HTTP 401 / 'unauthorized' / 'svid expired'), not on any error containing
    the bare substring 'token'."""

    @pytest.mark.asyncio
    async def test_unauthorized_triggers_svid_refresh(self) -> None:
        """HTTP 401 / 'unauthorized' in exception message -> SVID refresh attempted."""
        from agent_harness import agent_runner

        call_count = {"n": 0}

        async def _query_with_auth_error(*, prompt, options):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise Exception("HTTP 401 unauthorized")
            fake_result = MagicMock()
            fake_result.__class__.__name__ = "ResultMessage"
            fake_result.is_error = False
            fake_result.result = "done"
            fake_result.stop_reason = "end_turn"
            fake_result.num_turns = 1
            fake_result.errors = None
            yield fake_result

        svid_fetch_count = {"n": 0}

        def _fake_svid():
            svid_fetch_count["n"] += 1
            return f"svid-{svid_fetch_count['n']}"

        buf = __import__("io").StringIO()
        with __import__("unittest.mock", fromlist=["patch"]).patch("sys.stdout", buf):
            with (
                __import__("unittest.mock", fromlist=["patch"]).patch.object(
                    agent_runner, "fetch_agent_svid", side_effect=_fake_svid
                ),
                __import__("unittest.mock", fromlist=["patch"]).patch.object(
                    agent_runner, "sdk_query", _query_with_auth_error
                ),
                __import__("unittest.mock", fromlist=["patch"]).patch.object(
                    agent_runner, "_build_options", return_value=MagicMock()
                ),
            ):
                result = await agent_runner.run_agent(
                    goal="list rules", session_id="retry-test"
                )

        assert result is True
        # Should have fetched SVID twice: once at start, once on retry.
        assert svid_fetch_count["n"] == 2, (
            f"Expected 2 SVID fetches (initial + retry), got {svid_fetch_count['n']}"
        )

    @pytest.mark.asyncio
    async def test_bare_token_substring_does_not_trigger_svid_refresh(self) -> None:
        """Finding 7: 'token bucket exhausted' must NOT trigger SVID refresh."""
        from agent_harness import agent_runner

        svid_fetch_count = {"n": 0}

        def _fake_svid():
            svid_fetch_count["n"] += 1
            return f"svid-{svid_fetch_count['n']}"

        async def _query_with_token_error(*, prompt, options):
            # This error message contains 'token' but is NOT an auth error.
            raise Exception("rate limiter: token bucket exhausted")
            yield  # pragma: no cover

        buf = __import__("io").StringIO()
        with __import__("unittest.mock", fromlist=["patch"]).patch("sys.stdout", buf):
            with (
                __import__("unittest.mock", fromlist=["patch"]).patch.object(
                    agent_runner, "fetch_agent_svid", side_effect=_fake_svid
                ),
                __import__("unittest.mock", fromlist=["patch"]).patch.object(
                    agent_runner, "sdk_query", _query_with_token_error
                ),
                __import__("unittest.mock", fromlist=["patch"]).patch.object(
                    agent_runner, "_build_options", return_value=MagicMock()
                ),
            ):
                result = await agent_runner.run_agent(
                    goal="list rules", session_id="no-retry-test"
                )

        # Should have returned False without retry.
        assert result is False
        # Only one SVID fetch (initial), no refresh triggered by 'token bucket'.
        assert svid_fetch_count["n"] == 1, (
            f"Finding 7: bare 'token' substring must NOT trigger retry. "
            f"Got {svid_fetch_count['n']} SVID fetches (want 1)."
        )

    @pytest.mark.asyncio
    async def test_svid_expired_triggers_refresh(self) -> None:
        """'svid expired' in exception message -> SVID refresh attempted."""
        from agent_harness import agent_runner

        call_count = {"n": 0}

        async def _query_with_svid_expired(*, prompt, options):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise Exception("gRPC error: svid expired, please refresh")
            fake_result = MagicMock()
            fake_result.__class__.__name__ = "ResultMessage"
            fake_result.is_error = False
            fake_result.result = "done"
            fake_result.stop_reason = "end_turn"
            fake_result.num_turns = 1
            fake_result.errors = None
            yield fake_result

        svid_fetch_count = {"n": 0}

        def _fake_svid():
            svid_fetch_count["n"] += 1
            return f"svid-{svid_fetch_count['n']}"

        buf = __import__("io").StringIO()
        with __import__("unittest.mock", fromlist=["patch"]).patch("sys.stdout", buf):
            with (
                __import__("unittest.mock", fromlist=["patch"]).patch.object(
                    agent_runner, "fetch_agent_svid", side_effect=_fake_svid
                ),
                __import__("unittest.mock", fromlist=["patch"]).patch.object(
                    agent_runner, "sdk_query", _query_with_svid_expired
                ),
                __import__("unittest.mock", fromlist=["patch"]).patch.object(
                    agent_runner, "_build_options", return_value=MagicMock()
                ),
            ):
                result = await agent_runner.run_agent(
                    goal="list rules", session_id="svid-expired-test"
                )

        assert result is True
        assert svid_fetch_count["n"] == 2, (
            f"Expected 2 SVID fetches for 'svid expired', got {svid_fetch_count['n']}"
        )
