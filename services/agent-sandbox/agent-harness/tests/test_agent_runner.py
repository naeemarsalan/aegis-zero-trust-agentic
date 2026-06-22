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


# ---------------------------------------------------------------------------
# Transient LLM-gateway policy_denied (403) retry (round-3 diagnosis)
# ---------------------------------------------------------------------------


def _result_msg(*, is_error: bool, result: str = "", errors=None):
    m = MagicMock()
    m.__class__.__name__ = "ResultMessage"
    m.is_error = is_error
    m.result = result
    m.stop_reason = "error" if is_error else "end_turn"
    m.num_turns = 1
    m.errors = errors
    return m


class TestGatewayPolicyRetry:
    """A one-shot LLM-gateway policy_denied 403 (surfaced as an is_error
    ResultMessage) must be retried ONCE; a genuine downstream authz DENY
    (403 Forbidden / grant_scope_denied) must NOT be retried."""

    @pytest.mark.asyncio
    async def test_policy_denied_result_retries_then_succeeds(
        self, monkeypatch
    ) -> None:
        from agent_harness import agent_runner

        # No real sleep in the test.
        monkeypatch.setenv("AGENT_GATEWAY_RETRY_BACKOFF_S", "0")

        call_count = {"n": 0}

        async def _query(*, prompt, options):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First request after boot: gateway policy_denied 403 (delivered
                # as an is_error ResultMessage that completes the stream).
                yield _result_msg(
                    is_error=True,
                    result=(
                        "POST 172.16.2.251:4000/v1/messages?beta=true not "
                        "permitted by policy"
                    ),
                    errors=["policy_denied"],
                )
            else:
                yield _result_msg(is_error=False, result="done")

        buf = StringIO()
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value="fake.svid"),
                patch.object(agent_runner, "sdk_query", _query),
                patch.object(agent_runner, "_build_options", return_value=MagicMock()),
            ):
                result = await agent_runner.run_agent(
                    goal="list rules", session_id="gw-retry-test"
                )

        assert result is True, "transient policy_denied should be retried and succeed"
        assert call_count["n"] == 2, (
            f"Expected the query to be re-issued once (2 total), got {call_count['n']}"
        )
        lines = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        assert any(
            l.get("subtype") == "gateway_policy_retry" for l in lines
        ), "expected a gateway_policy_retry system line"

    @pytest.mark.asyncio
    async def test_retry_uses_fresh_canonical_uuid_session(self, monkeypatch) -> None:
        """The gateway retry MUST rebuild options with a FRESH, canonical
        hyphenated UUID session id — the claude CLI rejects both a re-used id
        ("already in use") and a hyphen-less .hex id ("Invalid session ID. Must
        be a valid UUID."). Both were observed live."""
        import re
        import uuid as _uuid
        from agent_harness import agent_runner

        monkeypatch.setenv("AGENT_GATEWAY_RETRY_BACKOFF_S", "0")
        captured_sessions: list[str] = []

        def _fake_build_options(svid_token, session_id):
            captured_sessions.append(session_id)
            return MagicMock()

        call_count = {"n": 0}

        async def _query(*, prompt, options):
            call_count["n"] += 1
            if call_count["n"] == 1:
                yield _result_msg(
                    is_error=True,
                    result="not permitted by policy",
                    errors=["policy_denied"],
                )
            else:
                yield _result_msg(is_error=False, result="done")

        buf = StringIO()
        original_session = "11111111-1111-1111-1111-111111111111"
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value="fake.svid"),
                patch.object(agent_runner, "sdk_query", _query),
                patch.object(agent_runner, "_build_options", _fake_build_options),
            ):
                result = await agent_runner.run_agent(
                    goal="list rules", session_id=original_session
                )

        assert result is True
        # _build_options called twice: once at start (original), once on retry (fresh).
        assert len(captured_sessions) == 2, captured_sessions
        retry_session = captured_sessions[1]
        assert retry_session != original_session, "retry must use a NEW session id"
        # Must be a canonical hyphenated UUID — str(uuid4()) round-trips cleanly.
        assert str(_uuid.UUID(retry_session)) == retry_session, (
            f"retry session id must be a canonical hyphenated UUID, got {retry_session!r}"
        )
        assert re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            retry_session,
        ), retry_session

    @pytest.mark.asyncio
    async def test_resultmsg_then_exception_same_iteration_retries(
        self, monkeypatch
    ) -> None:
        """LIVE FAILURE MODE (observed on SNO): the SDK yields an is_error
        ResultMessage carrying the policy_denied body AND THEN raises a bare
        Exception on the same stream iteration. The retry decision must use the
        captured ResultMessage signal (not str(exc), which is empty)."""
        from agent_harness import agent_runner

        monkeypatch.setenv("AGENT_GATEWAY_RETRY_BACKOFF_S", "0")
        call_count = {"n": 0}

        async def _query(*, prompt, options):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # Same iteration: ResultMessage with the gateway body, THEN raise.
                yield _result_msg(
                    is_error=True,
                    result=(
                        "Failed to authenticate. API Error: 403 "
                        '{"detail":"POST 172.16.2.251:4000/v1/messages?beta=true '
                        'not permitted by policy","error":"policy_denied"}'
                    ),
                    errors=None,
                )
                raise Exception()  # bare — str(exc) carries no policy detail
            else:
                yield _result_msg(is_error=False, result="done")

        buf = StringIO()
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value="fake.svid"),
                patch.object(agent_runner, "sdk_query", _query),
                patch.object(agent_runner, "_build_options", return_value=MagicMock()),
            ):
                result = await agent_runner.run_agent(
                    goal="list rules", session_id="gw-retry-resultthenexc"
                )

        assert result is True, (
            "the ResultMessage-then-Exception boot 403 must be retried and succeed"
        )
        assert call_count["n"] == 2, (
            f"Expected the query re-issued once (2 total), got {call_count['n']}"
        )
        lines = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        assert any(
            l.get("subtype") == "gateway_policy_retry" for l in lines
        ), "expected a gateway_policy_retry system line"

    @pytest.mark.asyncio
    async def test_policy_denied_retry_is_bounded(self, monkeypatch) -> None:
        """If the gateway keeps denying, retry is bounded (here pinned to 1)
        then return False — it never loops forever."""
        from agent_harness import agent_runner

        monkeypatch.setenv("AGENT_GATEWAY_RETRY_BACKOFF_S", "0")
        monkeypatch.setenv("AGENT_GATEWAY_RETRY_MAX", "1")
        call_count = {"n": 0}

        async def _always_denied(*, prompt, options):
            call_count["n"] += 1
            yield _result_msg(
                is_error=True,
                result="not permitted by policy",
                errors=["policy_denied"],
            )

        buf = StringIO()
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value="fake.svid"),
                patch.object(agent_runner, "sdk_query", _always_denied),
                patch.object(agent_runner, "_build_options", return_value=MagicMock()),
            ):
                result = await agent_runner.run_agent(
                    goal="list rules", session_id="gw-retry-bounded"
                )

        assert result is False
        assert call_count["n"] == 2, (
            f"With MAX=1 the gateway retry must be 1 re-issue (2 total), got {call_count['n']}"
        )

    @pytest.mark.asyncio
    async def test_genuine_authz_deny_not_retried(self, monkeypatch) -> None:
        """A real downstream DENY (403 Forbidden / grant_scope_denied) is the
        agent's signal to self-escalate via mcp-call — it must NOT be silently
        re-fired by the gateway-retry path."""
        from agent_harness import agent_runner

        monkeypatch.setenv("AGENT_GATEWAY_RETRY_BACKOFF_S", "0")
        call_count = {"n": 0}

        async def _authz_deny(*, prompt, options):
            call_count["n"] += 1
            yield _result_msg(
                is_error=True,
                result="403 Forbidden: grant_scope_denied",
                errors=["403 Forbidden"],
            )

        buf = StringIO()
        with patch("sys.stdout", buf):
            with (
                patch.object(agent_runner, "fetch_agent_svid", return_value="fake.svid"),
                patch.object(agent_runner, "sdk_query", _authz_deny),
                patch.object(agent_runner, "_build_options", return_value=MagicMock()),
            ):
                result = await agent_runner.run_agent(
                    goal="list rules", session_id="authz-deny-test"
                )

        assert result is False
        assert call_count["n"] == 1, (
            f"A genuine authz DENY must NOT trigger the gateway retry; "
            f"expected 1 query, got {call_count['n']}"
        )
