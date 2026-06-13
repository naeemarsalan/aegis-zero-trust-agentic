"""Pytest test suite for sandbox-launcher.

Coverage:
  Happy path:
    - valid request with mocked JWT verification + mocked gRPC -> 202 + LaunchResponse
    - unverified fallback (no Authorization header) -> 202 with advisory identity

  Auth failures (fail-closed):
    - malformed Authorization header -> 401
    - JWT verification raises ValueError -> 401
    - RHDH JWKS not configured (RuntimeError) -> 503
    - entity_ref / body.user mismatch -> 403

  Input validation:
    - confirmed=false -> 400
    - confirmed missing -> 422
    - blank goal -> 422
    - empty capabilities list -> 422
    - blank capability entry -> 422
    - capabilities > 20 entries -> 422
    - invalid mode -> 422
    - ttl_minutes out of range -> 422

  Gateway errors:
    - OpenShell RuntimeError (not configured) -> 503
    - OpenShell generic exception (gateway error) -> 502

  Health check:
    - GET /healthz -> 200 {"status": "ok"}

All tests mock:
  - sandbox_launcher.auth.verify_caller_token (JWT verification)
  - sandbox_launcher.auth.extract_entity_ref  (claim extraction)
  - sandbox_launcher.openshell.create_sandbox (gRPC call)
  - sandbox_launcher.openshell.available      (config check)

No network calls; no filesystem access beyond tmp.
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Set required env vars before importing the app so defaults take effect
os.environ.setdefault("RHDH_JWKS_URL", "https://developer-hub.example.com/api/auth/.backstage/jwks.json")
os.environ.setdefault("RHDH_TOKEN_ISSUER", "https://developer-hub.example.com")
os.environ.setdefault("LAUNCHER_OIDC_TOKEN_URL", "")   # disabled; avoids OIDC fetch in tests
os.environ.setdefault("SANDBOX_NAMESPACE", "openshell")

from fastapi.testclient import TestClient

from sandbox_launcher.api import app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_BODY: dict[str, Any] = {
    "goal": "Inspect network policies for incident INC-1234",
    "capabilities": ["pfsense-mcp"],
    "mode": "task",
    "user": "user:default/arsalan",
    "confirmed": True,
    "ttl_minutes": 30,
}


def _make_mock_sandbox_resp(
    name: str = "agent-arsalan-abc123",
    sandbox_id: str = "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
    phase: int = 1,  # PROVISIONING
) -> MagicMock:
    resp = MagicMock()
    resp.sandbox.metadata.name = name
    resp.sandbox.metadata.id = sandbox_id
    resp.sandbox.status.phase = phase
    resp.sandbox.status.agent_pod = ""
    return resp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def mock_openshell_ok():
    """Mock openshell.create_sandbox to succeed with a standard PROVISIONING response."""
    fake_resp = _make_mock_sandbox_resp()
    with patch("sandbox_launcher.openshell.create_sandbox", return_value=fake_resp) as m:
        yield m


@pytest.fixture
def mock_jwt_ok():
    """Mock JWT verification to succeed, returning arsalan entity ref."""
    claims = {
        "sub": "user:default/arsalan",
        "iss": "https://developer-hub.example.com",
        "exp": 9_999_999_999,
    }
    with patch("sandbox_launcher.auth.verify_caller_token", return_value=claims) as m_verify, \
         patch("sandbox_launcher.auth.extract_entity_ref", return_value="user:default/arsalan") as m_extract:
        yield m_verify, m_extract


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_valid_request_with_jwt_returns_202(
        self, client: TestClient, mock_jwt_ok, mock_openshell_ok
    ):
        """Valid request with verified JWT returns 202 and correct LaunchResponse fields."""
        resp = client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.jwt.token"},
        )
        assert resp.status_code == 202, resp.text
        data = resp.json()
        assert data["sandbox_name"] == "agent-arsalan-abc123"
        assert data["sandbox_id"] == "aaaabbbb-cccc-dddd-eeee-ffffffffffff"
        assert data["namespace"] == "openshell"
        assert data["phase"] == "PROVISIONING"
        assert data["conversation_url"] is None
        assert "oc -n openshell exec" in data["access_hint"]
        assert data["owner"] == "user:default/arsalan"

    def test_valid_request_no_jwt_falls_back_to_body_user(
        self, client: TestClient, mock_openshell_ok
    ):
        """When Authorization header is absent, launcher falls back to body.user (PoC mode)."""
        resp = client.post("/launch", json=_VALID_BODY)
        assert resp.status_code == 202, resp.text
        data = resp.json()
        # Owner is the body.user since no JWT was verified
        assert data["owner"] == "user:default/arsalan"
        assert data["phase"] == "PROVISIONING"

    def test_project_mode_accepted(self, client: TestClient, mock_jwt_ok, mock_openshell_ok):
        """mode=project is a valid enum value."""
        body = dict(_VALID_BODY, mode="project")
        resp = client.post(
            "/launch",
            json=body,
            headers={"Authorization": "Bearer fake.jwt.token"},
        )
        assert resp.status_code == 202, resp.text

    def test_create_sandbox_called_with_correct_owner(
        self, client: TestClient, mock_jwt_ok, mock_openshell_ok
    ):
        """The gRPC create_sandbox receives the verified entity_ref as owner."""
        client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.jwt.token"},
        )
        mock_openshell_ok.assert_called_once()
        call_kwargs = mock_openshell_ok.call_args
        assert call_kwargs.kwargs["owner_entity_ref"] == "user:default/arsalan"


# ---------------------------------------------------------------------------
# Auth failures (fail-closed)
# ---------------------------------------------------------------------------


class TestAuthFailures:
    def test_malformed_authorization_header_returns_401(
        self, client: TestClient, mock_openshell_ok
    ):
        """Authorization header without 'Bearer ' prefix returns 401."""
        resp = client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 401
        assert "Bearer" in resp.json()["detail"]

    def test_expired_jwt_returns_401(self, client: TestClient, mock_openshell_ok):
        """JWT verification raises ValueError (expired token) -> 401."""
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            side_effect=ValueError("caller token has expired"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer expired.jwt.token"},
            )
        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"]

    def test_invalid_signature_jwt_returns_401(self, client: TestClient, mock_openshell_ok):
        """JWT verification raises ValueError (signature) -> 401."""
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            side_effect=ValueError("caller token signature did not verify"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer rogue.jwt.token"},
            )
        assert resp.status_code == 401

    def test_rhdh_jwks_not_configured_returns_503(self, client: TestClient, mock_openshell_ok):
        """RuntimeError from verify_caller_token (JWKS URL not set) -> 503."""
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            side_effect=RuntimeError("RHDH_JWKS_URL is not configured"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer some.jwt"},
            )
        assert resp.status_code == 503

    def test_entity_ref_mismatch_returns_403(self, client: TestClient, mock_openshell_ok):
        """Verified entity_ref does not match body.user -> 403."""
        claims = {
            "sub": "user:default/other-person",
            "iss": "https://developer-hub.example.com",
            "exp": 9_999_999_999,
        }
        with patch("sandbox_launcher.auth.verify_caller_token", return_value=claims), \
             patch(
                 "sandbox_launcher.auth.extract_entity_ref",
                 return_value="user:default/other-person",
             ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,  # body.user = user:default/arsalan
                headers={"Authorization": "Bearer valid.jwt.for.other"},
            )
        assert resp.status_code == 403
        assert "mismatch" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_confirmed_false_returns_400(self, client: TestClient, mock_openshell_ok):
        """confirmed=false returns 400 (server-side guard, not just pydantic)."""
        body = dict(_VALID_BODY, confirmed=False)
        resp = client.post("/launch", json=body)
        assert resp.status_code == 400
        assert "confirmed" in resp.json()["detail"]

    def test_confirmed_missing_returns_422(self, client: TestClient):
        """confirmed field entirely missing returns 422 (pydantic required field)."""
        body = {k: v for k, v in _VALID_BODY.items() if k != "confirmed"}
        resp = client.post("/launch", json=body)
        assert resp.status_code == 422

    def test_blank_goal_returns_422(self, client: TestClient):
        """Empty goal string fails min_length=1 validation."""
        body = dict(_VALID_BODY, goal="")
        resp = client.post("/launch", json=body)
        assert resp.status_code == 422

    def test_goal_too_long_returns_422(self, client: TestClient):
        """Goal exceeding 500 chars returns 422."""
        body = dict(_VALID_BODY, goal="x" * 501)
        resp = client.post("/launch", json=body)
        assert resp.status_code == 422

    def test_empty_capabilities_list_returns_422(self, client: TestClient):
        """Empty capabilities list fails min_length=1 validation."""
        body = dict(_VALID_BODY, capabilities=[])
        resp = client.post("/launch", json=body)
        assert resp.status_code == 422

    def test_blank_capability_entry_returns_422(self, client: TestClient):
        """A blank string in capabilities is rejected by the validator."""
        body = dict(_VALID_BODY, capabilities=["pfsense-mcp", ""])
        resp = client.post("/launch", json=body)
        assert resp.status_code == 422

    def test_too_many_capabilities_returns_422(self, client: TestClient):
        """More than 20 capabilities is rejected."""
        body = dict(_VALID_BODY, capabilities=[f"cap-{i}" for i in range(21)])
        resp = client.post("/launch", json=body)
        assert resp.status_code == 422

    def test_invalid_mode_returns_422(self, client: TestClient):
        """An invalid mode value returns 422."""
        body = dict(_VALID_BODY, mode="batch")
        resp = client.post("/launch", json=body)
        assert resp.status_code == 422

    def test_ttl_too_low_returns_422(self, client: TestClient):
        """ttl_minutes=4 (below floor of 5) returns 422."""
        body = dict(_VALID_BODY, ttl_minutes=4)
        resp = client.post("/launch", json=body)
        assert resp.status_code == 422

    def test_ttl_too_high_returns_422(self, client: TestClient):
        """ttl_minutes=481 (above ceiling of 480) returns 422."""
        body = dict(_VALID_BODY, ttl_minutes=481)
        resp = client.post("/launch", json=body)
        assert resp.status_code == 422

    def test_valid_ttl_boundary_low(self, client: TestClient, mock_jwt_ok, mock_openshell_ok):
        """ttl_minutes=5 (lower boundary) is accepted."""
        body = dict(_VALID_BODY, ttl_minutes=5)
        resp = client.post(
            "/launch",
            json=body,
            headers={"Authorization": "Bearer fake.jwt.token"},
        )
        assert resp.status_code == 202

    def test_valid_ttl_boundary_high(self, client: TestClient, mock_jwt_ok, mock_openshell_ok):
        """ttl_minutes=480 (upper boundary) is accepted."""
        body = dict(_VALID_BODY, ttl_minutes=480)
        resp = client.post(
            "/launch",
            json=body,
            headers={"Authorization": "Bearer fake.jwt.token"},
        )
        assert resp.status_code == 202


# ---------------------------------------------------------------------------
# Gateway errors
# ---------------------------------------------------------------------------


class TestGatewayErrors:
    def test_openshell_not_configured_returns_503(
        self, client: TestClient, mock_jwt_ok
    ):
        """RuntimeError from create_sandbox (client not configured) -> 503."""
        with patch(
            "sandbox_launcher.openshell.create_sandbox",
            side_effect=RuntimeError("OpenShell client not configured"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.jwt.token"},
            )
        assert resp.status_code == 503
        assert "not ready" in resp.json()["detail"].lower()

    def test_openshell_gateway_error_returns_502(
        self, client: TestClient, mock_jwt_ok
    ):
        """Generic exception from create_sandbox (gateway failure) -> 502."""
        with patch(
            "sandbox_launcher.openshell.create_sandbox",
            side_effect=Exception("connection refused"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.jwt.token"},
            )
        assert resp.status_code == 502
        assert "gateway error" in resp.json()["detail"].lower()

    def test_openshell_not_configured_without_jwt(self, client: TestClient):
        """RuntimeError from create_sandbox with advisory identity -> 503."""
        with patch(
            "sandbox_launcher.openshell.create_sandbox",
            side_effect=RuntimeError("OpenShell client not configured"),
        ):
            resp = client.post("/launch", json=_VALID_BODY)
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


def test_healthz(client: TestClient):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "sandbox-launcher"


# ---------------------------------------------------------------------------
# Sandbox name derivation
# ---------------------------------------------------------------------------


class TestSandboxNameDerivation:
    def test_sandbox_name_format(self):
        """_sandbox_name returns 'agent-<username>-<6hex>' format."""
        from sandbox_launcher.api import _sandbox_name

        name = _sandbox_name("user:default/arsalan")
        parts = name.split("-")
        # Expected: ['agent', 'arsalan', '<6hex>']
        assert parts[0] == "agent"
        assert parts[1] == "arsalan"
        assert len(parts[2]) == 6
        assert all(c in "0123456789abcdef" for c in parts[2])

    def test_sandbox_name_sanitises_special_chars(self):
        """Entity refs with special chars are sanitised."""
        from sandbox_launcher.api import _sandbox_name

        name = _sandbox_name("user:default/john.doe@example.com")
        # Should not contain @ or . directly
        username_part = name.split("-")[1]
        assert "." not in username_part
        assert "@" not in username_part

    def test_sandbox_name_long_username_truncated(self):
        """Usernames longer than 20 chars are truncated."""
        from sandbox_launcher.api import _sandbox_name

        name = _sandbox_name("user:default/" + "a" * 50)
        # agent-<truncated>-<hex>: username part should be <= 20 chars
        parts = name.split("-")
        # parts[1] is the username; it may be further split if hyphenated but length overall bounded
        username_part = parts[1]
        assert len(username_part) <= 20

    def test_sandbox_name_unique_per_call(self):
        """Two calls with the same entity ref produce different names."""
        from sandbox_launcher.api import _sandbox_name

        n1 = _sandbox_name("user:default/arsalan")
        n2 = _sandbox_name("user:default/arsalan")
        assert n1 != n2


# ---------------------------------------------------------------------------
# audit helpers
# ---------------------------------------------------------------------------


class TestAuditHelpers:
    def test_args_hash_is_sha256_hex(self):
        """_args_hash returns a 64-char hex string."""
        import hashlib
        import json

        from sandbox_launcher.audit import _args_hash

        args = {"goal_hash": "abc", "capabilities": ["cap1"], "mode": "task"}
        expected = hashlib.sha256(
            json.dumps(args, sort_keys=True, default=str).encode()
        ).hexdigest()
        assert _args_hash(args) == expected
        assert len(_args_hash(args)) == 64

    def test_hash_never_returns_raw_value(self):
        """_hash output does not contain the raw input value."""
        from sandbox_launcher.audit import _hash

        sensitive = "super-secret-bearer-token-value"
        hashed = _hash(sensitive)
        assert sensitive not in hashed
        assert len(hashed) == 64


def test_template_shaped_body_binds():
    """The exact camelCase body the RHDH scaffolder template POSTs must bind:
    userRef->user, ttlMinutes->ttl_minutes, scope present, confirmed honored."""
    from sandbox_launcher.models import LaunchRequest, LaunchScope
    b = LaunchRequest.model_validate({
        "userRef": "user:default/arsalan",
        "goal": "investigate firewall logs",
        "scope": "read-write",
        "mode": "task",
        "capabilities": ["mcp-pfsense"],
        "ttlMinutes": 120,
        "confirmed": True,
    })
    assert b.user == "user:default/arsalan"
    assert b.ttl_minutes == 120
    assert b.scope is LaunchScope.read_write
    assert b.confirmed is True


def test_sanitize_label_value():
    """Backstage entity refs / emails must become valid k8s label values
    (the gateway rejects ':' and '/' with INVALID_ARGUMENT)."""
    from sandbox_launcher.openshell import _sanitize_label_value as s
    assert s("user:default/arsalan") == "user-default-arsalan"
    assert s("a@b.com") == "a-b.com"
    assert s("::weird//") == "weird"
    assert s("") == "unknown"
    assert len(s("x" * 100)) <= 63
