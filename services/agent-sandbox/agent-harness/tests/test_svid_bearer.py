"""Unit tests for agent_harness.svid_bearer.

No network. No SPIFFE socket. All SPIRE interaction is mocked.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_svid_file(tmp_path: Path, content: str, age_s: float = 0) -> Path:
    p = tmp_path / "svid-gateway.jwt"
    p.write_text(content)
    if age_s > 0:
        mtime = time.time() - age_s
        os.utime(p, (mtime, mtime))
    return p


def _make_jwt(sub: str) -> str:
    """Build an UNSIGNED JWT with the given `sub` claim (shape-guard tests only)."""
    def _b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{_b64({'alg': 'RS256'})}.{_b64({'sub': sub})}.sig"


# ---------------------------------------------------------------------------
# _try_read_svid_file
# ---------------------------------------------------------------------------


class TestTryReadSvidFile:
    def test_returns_token_when_file_fresh(self, tmp_path: Path) -> None:
        from agent_harness.svid_bearer import _try_read_svid_file

        p = _make_svid_file(tmp_path, "eyJfake.svid.token")
        result = _try_read_svid_file(str(p))
        assert result == "eyJfake.svid.token"

    def test_returns_none_when_file_missing(self, tmp_path: Path) -> None:
        from agent_harness.svid_bearer import _try_read_svid_file

        result = _try_read_svid_file(str(tmp_path / "nonexistent.jwt"))
        assert result is None

    def test_returns_none_when_file_empty(self, tmp_path: Path) -> None:
        from agent_harness.svid_bearer import _try_read_svid_file

        p = _make_svid_file(tmp_path, "   \n")
        result = _try_read_svid_file(str(p))
        assert result is None

    def test_returns_none_when_file_stale(self, tmp_path: Path) -> None:
        from agent_harness import svid_bearer

        p = _make_svid_file(tmp_path, "old.token", age_s=400)
        # Override max age to a small value so the file is stale.
        original = svid_bearer._SVID_FILE_MAX_AGE_SECONDS
        try:
            svid_bearer._SVID_FILE_MAX_AGE_SECONDS = 100
            result = svid_bearer._try_read_svid_file(str(p))
            assert result is None
        finally:
            svid_bearer._SVID_FILE_MAX_AGE_SECONDS = original

    def test_strips_whitespace(self, tmp_path: Path) -> None:
        from agent_harness.svid_bearer import _try_read_svid_file

        p = _make_svid_file(tmp_path, "  token.value\n  ")
        result = _try_read_svid_file(str(p))
        assert result == "token.value"

    def test_shape_guard_accepts_uuid_shaped_svid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With SVID_REQUIRE_PATH_SUBSTR set, a /sandbox/ (UUID-shaped) token passes."""
        from agent_harness.svid_bearer import _try_read_svid_file

        monkeypatch.setenv("SVID_REQUIRE_PATH_SUBSTR", "/sandbox/")
        tok = _make_jwt("spiffe://anaeem.na-launch.com/ns/openshell/sandbox/abc-123")
        p = _make_svid_file(tmp_path, tok)
        assert _try_read_svid_file(str(p)) == tok

    def test_shape_guard_rejects_sa_shaped_svid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fail closed: a SA-shaped (kagenti) token is REJECTED (would 401 at ext-proc)."""
        from agent_harness.svid_bearer import _try_read_svid_file

        monkeypatch.setenv("SVID_REQUIRE_PATH_SUBSTR", "/sandbox/")
        tok = _make_jwt("spiffe://anaeem.na-launch.com/ns/kagenti-test/sa/test-agent")
        p = _make_svid_file(tmp_path, tok)
        assert _try_read_svid_file(str(p)) is None

    def test_shape_guard_rejects_unparseable_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fail closed: a non-JWT file is rejected when the shape guard is active."""
        from agent_harness.svid_bearer import _try_read_svid_file

        monkeypatch.setenv("SVID_REQUIRE_PATH_SUBSTR", "/sandbox/")
        p = _make_svid_file(tmp_path, "not-a-jwt")
        assert _try_read_svid_file(str(p)) is None

    def test_no_guard_returns_token_verbatim(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without SVID_REQUIRE_PATH_SUBSTR the legacy verbatim behaviour is preserved."""
        from agent_harness.svid_bearer import _try_read_svid_file

        monkeypatch.delenv("SVID_REQUIRE_PATH_SUBSTR", raising=False)
        p = _make_svid_file(tmp_path, "any.legacy.token")
        assert _try_read_svid_file(str(p)) == "any.legacy.token"


# ---------------------------------------------------------------------------
# _try_workload_api
# ---------------------------------------------------------------------------


class TestTryWorkloadApi:
    def test_returns_none_when_spiffe_not_installed(self) -> None:
        """py-spiffe absent -> None, not ImportError."""
        from agent_harness import svid_bearer

        with patch.dict("sys.modules", {"spiffe": None}):
            result = svid_bearer._try_workload_api("unix:///missing.sock")
        assert result is None

    def test_validates_trust_domain(self) -> None:
        """SVID from wrong trust domain -> None (fail-closed)."""
        from agent_harness import svid_bearer

        # Build a fake spiffe module and client.
        fake_svid = MagicMock()
        fake_svid.spiffe_id = "spiffe://evil.attacker.com/ns/agent-sandbox/sa/x"
        fake_svid.token = "bad.token"

        fake_client = MagicMock()
        fake_client.__enter__ = MagicMock(return_value=fake_client)
        fake_client.__exit__ = MagicMock(return_value=False)
        fake_client.fetch_jwt_svid = MagicMock(return_value=fake_svid)

        fake_spiffe_module = MagicMock()
        fake_spiffe_module.WorkloadApiClient = MagicMock(return_value=fake_client)

        with patch.dict("sys.modules", {"spiffe": fake_spiffe_module}):
            result = svid_bearer._try_workload_api("unix:///test.sock")
        assert result is None

    def test_returns_token_for_correct_trust_domain(self) -> None:
        """Happy path: correct trust domain -> returns token string."""
        from agent_harness import svid_bearer

        fake_svid = MagicMock()
        fake_svid.spiffe_id = "spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/openshell-agent"
        fake_svid.token = "valid.jwt.svid"

        fake_client = MagicMock()
        fake_client.__enter__ = MagicMock(return_value=fake_client)
        fake_client.__exit__ = MagicMock(return_value=False)
        fake_client.fetch_jwt_svid = MagicMock(return_value=fake_svid)

        fake_spiffe_module = MagicMock()
        fake_spiffe_module.WorkloadApiClient = MagicMock(return_value=fake_client)

        with patch.dict("sys.modules", {"spiffe": fake_spiffe_module}):
            result = svid_bearer._try_workload_api("unix:///test.sock")
        assert result == "valid.jwt.svid"

    def test_returns_none_on_socket_exception(self) -> None:
        """Socket error -> None, not raised."""
        from agent_harness import svid_bearer

        fake_client = MagicMock()
        fake_client.__enter__ = MagicMock(side_effect=ConnectionError("no socket"))
        fake_client.__exit__ = MagicMock(return_value=False)

        fake_spiffe_module = MagicMock()
        fake_spiffe_module.WorkloadApiClient = MagicMock(return_value=fake_client)

        with patch.dict("sys.modules", {"spiffe": fake_spiffe_module}):
            result = svid_bearer._try_workload_api("unix:///bad.sock")
        assert result is None


# ---------------------------------------------------------------------------
# fetch_agent_svid
# ---------------------------------------------------------------------------


class TestFetchAgentSvid:
    def test_uses_file_when_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """File-based path takes priority."""
        p = _make_svid_file(tmp_path, "file.based.svid")
        monkeypatch.setenv("SVID_JWT_PATH", str(p))

        from agent_harness import svid_bearer

        result = svid_bearer.fetch_agent_svid()
        assert result == "file.based.svid"

    def test_raises_when_no_source_available(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No file, no socket -> RuntimeError (fail-closed)."""
        # Point SVID_JWT_PATH to a non-existent file.
        monkeypatch.setenv("SVID_JWT_PATH", str(tmp_path / "missing.jwt"))
        # Point socket to a path that the fake spiffe module will fail on.
        monkeypatch.setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///none.sock")

        from agent_harness import svid_bearer

        # Patch _try_workload_api to return None (simulates absent socket).
        with patch.object(svid_bearer, "_try_workload_api", return_value=None):
            with pytest.raises(RuntimeError, match="Cannot obtain agent SPIFFE JWT-SVID"):
                svid_bearer.fetch_agent_svid()

    def test_falls_back_to_workload_api(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When file is absent, falls through to workload API."""
        monkeypatch.setenv("SVID_JWT_PATH", str(tmp_path / "absent.jwt"))

        from agent_harness import svid_bearer

        with patch.object(svid_bearer, "_try_workload_api", return_value="workload.svid"):
            result = svid_bearer.fetch_agent_svid()
        assert result == "workload.svid"
