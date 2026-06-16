"""Pytest test suite for sandbox-launcher.

Coverage:
  Happy path:
    - valid request with mocked RHDH JWT -> 202 + LaunchResponse
    - valid request with mocked Keycloak JWT -> 202, entity ref from preferred_username
    - no Authorization header + LAUNCHER_ALLOW_UNVERIFIED=true -> 202 advisory identity

  Auth failures (fail-closed):
    - missing token (default, LAUNCHER_ALLOW_UNVERIFIED unset) -> 401
    - malformed Authorization header -> 401
    - JWT rejected by all configured issuers (issuer mismatch) -> 401
    - expired JWT -> 401
    - invalid signature JWT -> 401
    - no auth issuer configured (RuntimeError) -> 503
    - entity_ref / body.user mismatch -> 403 (full ref, not just trailing segment)
    - token exceeds 8192 bytes -> 401 (DoS guard)

  Keycloak-specific:
    - valid Keycloak token with preferred_username -> correct entity ref (user:default/<name>)
    - valid Keycloak token with verified email fallback when preferred_username absent
    - unverified email fallback raises ValueError -> 401
    - preferred_username with ':' or '/' chars raises ValueError -> 401
    - issuer mismatch (token iss != KEYCLOAK_ISSUER) -> 401

  KID-based key selection (auth module unit tests):
    - token with matching kid tries only the matching JWKS key
    - token with unmatched kid falls back to all keys
    - token without kid tries all keys

  Full entity-ref cross-check:
    - token for "user:default/bob" with body.user "user:admin/bob" -> 403
      (different namespace; old trailing-segment check would wrongly allow this)
    - matching full refs (case-insensitive) -> 202

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

# Set required env vars before importing the app so defaults take effect.
os.environ.setdefault("RHDH_JWKS_URL", "https://developer-hub.example.com/api/auth/.backstage/jwks.json")
os.environ.setdefault("RHDH_TOKEN_ISSUER", "https://developer-hub.example.com")
os.environ.setdefault("LAUNCHER_OIDC_TOKEN_URL", "")   # disabled; avoids OIDC fetch in tests
os.environ.setdefault("SANDBOX_NAMESPACE", "openshell")
# Ensure the escape hatch is OFF by default for tests (fail-closed).
os.environ.setdefault("LAUNCHER_ALLOW_UNVERIFIED", "false")

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
    """Mock RHDH JWT verification.

    verify_caller_token now returns (claims, issuer_kind).  extract_entity_ref
    now accepts (claims, issuer_kind).  Both are mocked to avoid network calls.
    """
    claims = {
        "sub": "user:default/arsalan",
        "iss": "https://developer-hub.example.com",
        "exp": 9_999_999_999,
    }
    # verify_caller_token returns a (claims, issuer_kind) tuple
    with patch(
        "sandbox_launcher.auth.verify_caller_token",
        return_value=(claims, "rhdh"),
    ) as m_verify, patch(
        "sandbox_launcher.auth.extract_entity_ref",
        return_value="user:default/arsalan",
    ) as m_extract:
        yield m_verify, m_extract


@pytest.fixture
def mock_keycloak_jwt_ok():
    """Mock Keycloak JWT verification returning preferred_username-based entity ref."""
    claims = {
        "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",  # UUID — not usable as entity ref
        "iss": "https://keycloak.apps.anaeem.na-launch.com/realms/agentic",
        "exp": 9_999_999_999,
        "preferred_username": "arsalan",
        "email": "arsalan@example.com",
    }
    with patch(
        "sandbox_launcher.auth.verify_caller_token",
        return_value=(claims, "keycloak"),
    ) as m_verify, patch(
        "sandbox_launcher.auth.extract_entity_ref",
        return_value="user:default/arsalan",
    ) as m_extract:
        yield m_verify, m_extract


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_valid_request_with_rhdh_jwt_returns_202(
        self, client: TestClient, mock_jwt_ok, mock_openshell_ok
    ):
        """Valid request with verified RHDH JWT returns 202 and correct LaunchResponse fields."""
        resp = client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
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

    def test_valid_request_with_keycloak_jwt_returns_202(
        self, client: TestClient, mock_keycloak_jwt_ok, mock_openshell_ok
    ):
        """Valid request with verified Keycloak JWT returns 202.

        The entity ref must be derived from preferred_username, NOT the UUID sub.
        """
        resp = client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.keycloak.jwt"},
        )
        assert resp.status_code == 202, resp.text
        data = resp.json()
        assert data["owner"] == "user:default/arsalan"
        assert data["phase"] == "PROVISIONING"

    def test_keycloak_jwt_verify_caller_token_called_once(
        self, client: TestClient, mock_keycloak_jwt_ok, mock_openshell_ok
    ):
        """verify_caller_token is invoked exactly once per request."""
        m_verify, _ = mock_keycloak_jwt_ok
        client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.keycloak.jwt"},
        )
        m_verify.assert_called_once()

    def test_valid_request_no_jwt_falls_back_with_escape_hatch(
        self, client: TestClient, mock_openshell_ok
    ):
        """When LAUNCHER_ALLOW_UNVERIFIED=true, missing auth falls back to body.user."""
        with patch.dict(os.environ, {"LAUNCHER_ALLOW_UNVERIFIED": "true"}):
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
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        assert resp.status_code == 202, resp.text

    def test_create_sandbox_called_with_correct_owner(
        self, client: TestClient, mock_jwt_ok, mock_openshell_ok
    ):
        """The gRPC create_sandbox receives the verified entity_ref as owner."""
        client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        mock_openshell_ok.assert_called_once()
        call_kwargs = mock_openshell_ok.call_args
        assert call_kwargs.kwargs["owner_entity_ref"] == "user:default/arsalan"


# ---------------------------------------------------------------------------
# Auth failures (fail-closed)
# ---------------------------------------------------------------------------


class TestAuthFailures:
    def test_missing_token_returns_401_by_default(
        self, client: TestClient, mock_openshell_ok
    ):
        """No Authorization header -> 401 (fail-closed default)."""
        resp = client.post("/launch", json=_VALID_BODY)
        assert resp.status_code == 401, resp.text
        assert "Authorization" in resp.json()["detail"]

    def test_missing_token_401_when_escape_hatch_explicitly_false(
        self, client: TestClient, mock_openshell_ok
    ):
        """LAUNCHER_ALLOW_UNVERIFIED=false explicitly -> 401."""
        with patch.dict(os.environ, {"LAUNCHER_ALLOW_UNVERIFIED": "false"}):
            resp = client.post("/launch", json=_VALID_BODY)
        assert resp.status_code == 401, resp.text

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
        """JWT verification raises ValueError (expired token) -> 401 (always fail-closed)."""
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

    def test_issuer_mismatch_returns_401(self, client: TestClient, mock_openshell_ok):
        """Token rejected by all configured issuers (issuer mismatch) -> 401."""
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            side_effect=ValueError(
                "caller token was rejected by all configured issuers: "
                "rhdh: token did not verify (issuer mismatch); "
                "keycloak: token did not verify (issuer mismatch)"
            ),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer foreign.issuer.jwt"},
            )
        assert resp.status_code == 401
        detail = resp.json()["detail"].lower()
        assert "verification failed" in detail

    def test_no_issuer_configured_returns_503(self, client: TestClient, mock_openshell_ok):
        """RuntimeError from verify_caller_token (no issuer configured) -> 503."""
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            side_effect=RuntimeError("No auth issuer is configured"),
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
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            return_value=(claims, "rhdh"),
        ), patch(
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

    def test_token_verification_failure_is_always_401(
        self, client: TestClient, mock_openshell_ok
    ):
        """A presented but unverifiable token is always 401 regardless of env settings.

        Previous PoC behavior (fallback to advisory) is removed. A token that cannot
        be verified by any configured issuer must fail closed.
        """
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            side_effect=ValueError("unable to fetch JWKS for token verification"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer cannot.verify.this"},
            )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Keycloak-specific entity-ref extraction (unit tests for auth module)
# ---------------------------------------------------------------------------


class TestKeycloakEntityRef:
    """Unit tests for auth._extract_entity_ref_keycloak (no network)."""

    def test_preferred_username_used_as_entity_ref(self):
        """Keycloak claims with preferred_username produce user:default/<username>."""
        from sandbox_launcher.auth import extract_entity_ref

        claims = {
            "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "preferred_username": "arsalan",
            "email": "arsalan@example.com",
        }
        ref = extract_entity_ref(claims, "keycloak")
        assert ref == "user:default/arsalan"

    def test_email_localpart_fallback_when_preferred_username_absent_and_verified(self):
        """When preferred_username absent, email localpart used ONLY when email_verified=true."""
        from sandbox_launcher.auth import extract_entity_ref

        claims = {
            "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "email": "bob@example.com",
            "email_verified": True,
        }
        ref = extract_entity_ref(claims, "keycloak")
        assert ref == "user:default/bob"

    def test_email_localpart_fallback_rejected_when_email_unverified(self):
        """Fix (4): unverified email must not be used as identity even as fallback."""
        from sandbox_launcher.auth import extract_entity_ref

        claims = {
            "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "email": "bob@example.com",
            "email_verified": False,
        }
        with pytest.raises(ValueError, match="email_verified=false"):
            extract_entity_ref(claims, "keycloak")

    def test_email_fallback_rejected_when_email_verified_missing(self):
        """Fix (4): missing email_verified claim defaults to False (fail-closed)."""
        from sandbox_launcher.auth import extract_entity_ref

        claims = {
            "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "email": "carol@example.com",
            # email_verified claim absent
        }
        with pytest.raises(ValueError, match="email_verified=false"):
            extract_entity_ref(claims, "keycloak")

    def test_keycloak_raises_when_no_usable_identity(self):
        """Keycloak claims with neither preferred_username nor email -> ValueError."""
        from sandbox_launcher.auth import extract_entity_ref

        claims = {"sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"}
        with pytest.raises(ValueError, match="preferred_username"):
            extract_entity_ref(claims, "keycloak")

    def test_preferred_username_with_colon_rejected(self):
        """Fix (4): preferred_username containing ':' raises ValueError (entity-ref corruption)."""
        from sandbox_launcher.auth import extract_entity_ref

        claims = {
            "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "preferred_username": "admin:default",
        }
        with pytest.raises(ValueError, match="unsafe characters"):
            extract_entity_ref(claims, "keycloak")

    def test_preferred_username_with_slash_rejected(self):
        """Fix (4): preferred_username containing '/' raises ValueError (namespace traversal)."""
        from sandbox_launcher.auth import extract_entity_ref

        claims = {
            "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "preferred_username": "default/arsalan",
        }
        with pytest.raises(ValueError, match="unsafe characters"):
            extract_entity_ref(claims, "keycloak")

    def test_rhdh_path_unchanged(self):
        """RHDH claims still return sub directly when it starts with 'user:'."""
        from sandbox_launcher.auth import extract_entity_ref

        claims = {"sub": "user:default/arsalan", "iss": "https://example.com", "exp": 9_999_999_999}
        ref = extract_entity_ref(claims, "rhdh")
        assert ref == "user:default/arsalan"

    def test_default_issuer_kind_is_rhdh(self):
        """extract_entity_ref defaults to RHDH behavior when issuer_kind is omitted."""
        from sandbox_launcher.auth import extract_entity_ref

        claims = {"sub": "user:default/arsalan"}
        ref = extract_entity_ref(claims)
        assert ref == "user:default/arsalan"


# ---------------------------------------------------------------------------
# Multi-issuer configuration unit tests
# ---------------------------------------------------------------------------


class TestConfiguredIssuers:
    """Unit tests for auth._configured_issuers (no network)."""

    def test_only_rhdh_configured(self):
        from sandbox_launcher.auth import _configured_issuers

        env = {
            "RHDH_JWKS_URL": "https://rhdh.example.com/jwks.json",
            "RHDH_TOKEN_ISSUER": "https://rhdh.example.com",
            "KEYCLOAK_ISSUER": "",
        }
        with patch.dict(os.environ, env):
            assert _configured_issuers() == ["rhdh"]

    def test_only_keycloak_configured(self):
        from sandbox_launcher.auth import _configured_issuers

        env = {
            "RHDH_JWKS_URL": "",
            "RHDH_TOKEN_ISSUER": "",
            "KEYCLOAK_ISSUER": "https://keycloak.example.com/realms/agentic",
        }
        with patch.dict(os.environ, env):
            assert _configured_issuers() == ["keycloak"]

    def test_both_issuers_configured_rhdh_first(self):
        from sandbox_launcher.auth import _configured_issuers

        env = {
            "RHDH_JWKS_URL": "https://rhdh.example.com/jwks.json",
            "RHDH_TOKEN_ISSUER": "https://rhdh.example.com",
            "KEYCLOAK_ISSUER": "https://keycloak.example.com/realms/agentic",
        }
        with patch.dict(os.environ, env):
            issuers = _configured_issuers()
        assert issuers == ["rhdh", "keycloak"]
        # RHDH must be first (existing behavior takes priority)
        assert issuers[0] == "rhdh"

    def test_neither_configured_returns_empty(self):
        from sandbox_launcher.auth import _configured_issuers

        env = {"RHDH_JWKS_URL": "", "RHDH_TOKEN_ISSUER": "", "KEYCLOAK_ISSUER": ""}
        with patch.dict(os.environ, env):
            assert _configured_issuers() == []


# ---------------------------------------------------------------------------
# Keycloak JWKS URL defaulting
# ---------------------------------------------------------------------------


class TestKeycloakJwksParams:
    def test_default_jwks_url_appends_openid_path(self):
        """When KEYCLOAK_JWKS_URL is unset, KEYCLOAK_ISSUER + /protocol/openid-connect/certs is used."""
        from sandbox_launcher.auth import _jwks_params

        env = {
            "KEYCLOAK_ISSUER": "https://keycloak.apps.anaeem.na-launch.com/realms/agentic",
            "KEYCLOAK_JWKS_URL": "",
            "KEYCLOAK_JWKS_CA": "",
        }
        with patch.dict(os.environ, env):
            url, _ = _jwks_params("keycloak")
        assert url == (
            "https://keycloak.apps.anaeem.na-launch.com/realms/agentic"
            "/protocol/openid-connect/certs"
        )

    def test_explicit_keycloak_jwks_url_respected(self):
        from sandbox_launcher.auth import _jwks_params

        env = {
            "KEYCLOAK_ISSUER": "https://keycloak.apps.anaeem.na-launch.com/realms/agentic",
            "KEYCLOAK_JWKS_URL": "https://keycloak.apps.anaeem.na-launch.com/custom/certs",
            "KEYCLOAK_JWKS_CA": "",
        }
        with patch.dict(os.environ, env):
            url, _ = _jwks_params("keycloak")
        assert url == "https://keycloak.apps.anaeem.na-launch.com/custom/certs"

    def test_keycloak_ca_path_used_when_file_exists(self, tmp_path):
        from sandbox_launcher.auth import _jwks_params

        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("fake-pem")
        env = {
            "KEYCLOAK_ISSUER": "https://keycloak.example.com/realms/agentic",
            "KEYCLOAK_JWKS_URL": "",
            "KEYCLOAK_JWKS_CA": str(ca_file),
        }
        with patch.dict(os.environ, env):
            _, verify = _jwks_params("keycloak")
        assert verify == str(ca_file)

    def test_keycloak_verify_falls_back_to_system_cas_when_ca_absent(self):
        from sandbox_launcher.auth import _jwks_params

        env = {
            "KEYCLOAK_ISSUER": "https://keycloak.example.com/realms/agentic",
            "KEYCLOAK_JWKS_URL": "",
            "KEYCLOAK_JWKS_CA": "/nonexistent/path/ca.crt",
        }
        with patch.dict(os.environ, env):
            _, verify = _jwks_params("keycloak")
        assert verify is True


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
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        assert resp.status_code == 202

    def test_valid_ttl_boundary_high(self, client: TestClient, mock_jwt_ok, mock_openshell_ok):
        """ttl_minutes=480 (upper boundary) is accepted."""
        body = dict(_VALID_BODY, ttl_minutes=480)
        resp = client.post(
            "/launch",
            json=body,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
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
                headers={"Authorization": "Bearer fake.rhdh.jwt"},
            )
        assert resp.status_code == 503
        assert "not ready" in resp.json()["detail"].lower()

    def test_openshell_gateway_error_returns_502(
        self, client: TestClient, mock_jwt_ok
    ):
        """Generic exception from create_sandbox (gateway failure) -> 502.

        Finding 2: the detail must be generic — no raw exception text exposed.
        """
        with patch(
            "sandbox_launcher.openshell.create_sandbox",
            side_effect=Exception("connection refused"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.rhdh.jwt"},
            )
        assert resp.status_code == 502
        detail = resp.json()["detail"].lower()
        assert "sandbox backend error" in detail
        # Must NOT contain the raw exception string.
        assert "connection refused" not in detail

    def test_openshell_not_configured_without_jwt_returns_401(self, client: TestClient):
        """No token + no escape hatch -> 401 (auth checked before gateway call)."""
        with patch(
            "sandbox_launcher.openshell.create_sandbox",
            side_effect=RuntimeError("OpenShell client not configured"),
        ):
            resp = client.post("/launch", json=_VALID_BODY)
        # Auth is checked first; no token means 401 before we ever reach OpenShell.
        assert resp.status_code == 401

    def test_openshell_not_configured_with_escape_hatch_returns_503(
        self, client: TestClient
    ):
        """Advisory identity path (escape hatch on) + gateway not ready -> 503."""
        with patch.dict(os.environ, {"LAUNCHER_ALLOW_UNVERIFIED": "true"}), patch(
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


# ---------------------------------------------------------------------------
# Fix (1): Full entity-ref cross-check
# ---------------------------------------------------------------------------


class TestFullEntityRefCrossCheck:
    """The body-vs-token check must compare the FULL normalized ref, not just the
    trailing name segment.  The old trailing-segment-only comparison would allow
    'user:admin/bob' in the body when the token says 'user:default/bob' — same
    name but different namespace/kind, which is a distinct catalog identity."""

    def test_different_namespace_same_name_returns_403(
        self, client: TestClient, mock_openshell_ok
    ):
        """Fix (1): token=user:default/arsalan vs body.user=user:admin/arsalan -> 403.

        The old code compared only 'arsalan' == 'arsalan' and would wrongly 202.
        """
        body_with_wrong_namespace = dict(_VALID_BODY, user="user:admin/arsalan")
        # userRef is the alias; pass it as the alias key
        body_raw = {
            k if k != "user" else "userRef": v
            for k, v in body_with_wrong_namespace.items()
        }
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            return_value=({"sub": "user:default/arsalan", "iss": "https://x", "exp": 9_999_999_999}, "rhdh"),
        ), patch(
            "sandbox_launcher.auth.extract_entity_ref",
            return_value="user:default/arsalan",  # token says default
        ):
            resp = client.post(
                "/launch",
                json=body_raw,  # body says admin
                headers={"Authorization": "Bearer fake.jwt"},
            )
        assert resp.status_code == 403, resp.text
        assert "mismatch" in resp.json()["detail"].lower()

    def test_different_kind_same_name_returns_403(
        self, client: TestClient, mock_openshell_ok
    ):
        """Fix (1): token=user:default/arsalan vs body.user=group:default/arsalan -> 403."""
        body_with_group = {"userRef": "group:default/arsalan", **{k: v for k, v in _VALID_BODY.items() if k != "user"}, "goal": _VALID_BODY["goal"], "confirmed": True}
        body_raw = dict(_VALID_BODY)
        body_raw["userRef"] = "group:default/arsalan"
        body_raw.pop("user", None)
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            return_value=({"sub": "user:default/arsalan", "iss": "https://x", "exp": 9_999_999_999}, "rhdh"),
        ), patch(
            "sandbox_launcher.auth.extract_entity_ref",
            return_value="user:default/arsalan",
        ):
            resp = client.post(
                "/launch",
                json={**{k: v for k, v in _VALID_BODY.items() if k != "user"}, "userRef": "group:default/arsalan"},
                headers={"Authorization": "Bearer fake.jwt"},
            )
        assert resp.status_code == 403, resp.text

    def test_case_insensitive_full_ref_accepted(
        self, client: TestClient, mock_openshell_ok
    ):
        """Fix (1): refs differing only in case are normalized and accepted."""
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            return_value=({"sub": "user:default/arsalan", "iss": "https://x", "exp": 9_999_999_999}, "rhdh"),
        ), patch(
            "sandbox_launcher.auth.extract_entity_ref",
            return_value="User:Default/Arsalan",  # mixed-case from token
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,  # body.user = "user:default/arsalan"
                headers={"Authorization": "Bearer fake.jwt"},
            )
        assert resp.status_code == 202, resp.text


# ---------------------------------------------------------------------------
# Fix (2): Token size bound
# ---------------------------------------------------------------------------


class TestTokenSizeBound:
    """Oversized tokens must be rejected before any crypto work (DoS guard)."""

    def test_token_exactly_at_limit_rejected_or_accepted(
        self, client: TestClient, mock_openshell_ok
    ):
        """A token of exactly 8192 bytes passes the size gate (boundary condition)."""
        # We cannot make a real JWT this large; the gate is on raw bytes.
        # Patch verify_caller_token to never be reached for the oversize case.
        token_8192 = "A" * 8192
        # 8192 bytes is at the limit — verify is still called (it's the exact threshold)
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            side_effect=ValueError("fake rejection"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": f"Bearer {token_8192}"},
            )
        # verify_caller_token was reached, so the size gate didn't fire
        assert resp.status_code == 401
        # The 401 message should be from token verification, NOT size rejection
        assert "size" not in resp.json()["detail"].lower()

    def test_token_one_byte_over_limit_rejected_with_401(
        self, client: TestClient, mock_openshell_ok
    ):
        """A token of 8193 bytes is rejected before crypto with 401 and size message."""
        token_8193 = "A" * 8193
        # verify_caller_token must NOT be reached
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            side_effect=AssertionError("verify_caller_token should not be called for oversized tokens"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": f"Bearer {token_8193}"},
            )
        assert resp.status_code == 401, resp.text
        assert "size" in resp.json()["detail"].lower()

    def test_large_oversized_token_rejected(
        self, client: TestClient, mock_openshell_ok
    ):
        """A 64KB token is rejected before any crypto work."""
        big_token = "X" * (64 * 1024)
        with patch(
            "sandbox_launcher.auth.verify_caller_token",
            side_effect=AssertionError("verify_caller_token should not be reached"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": f"Bearer {big_token}"},
            )
        assert resp.status_code == 401
        assert "size" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Fix (3): KID-based key selection (unit tests on verify_caller_token internals)
# ---------------------------------------------------------------------------


class TestKidBasedKeySelection:
    """verify_caller_token must read the JWT header kid and prefer the matching
    JWKS key, falling back to all keys only when no kid is present or no match."""

    def _make_rsa_key_pair(self):
        """Return (private_key, jwk_dict) for a minimal RS256 test key."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        priv = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return priv

    def test_kid_matching_key_succeeds(self):
        """Fix (3): token kid=k1 with JWKS containing k1 + k2 uses only k1."""
        from sandbox_launcher.auth import verify_caller_token
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        # Generate two key pairs
        priv1 = rsa.generate_private_key(65537, 2048, default_backend())
        priv2 = rsa.generate_private_key(65537, 2048, default_backend())

        # Build minimal JWK dicts (auth.py calls pyjwt.PyJWK.from_dict)
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        import base64, struct

        def _int_to_base64url(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        def _rsa_to_jwk(priv, kid: str) -> dict:
            nums = priv.public_key().public_numbers()
            return {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _int_to_base64url(nums.n),
                "e": _int_to_base64url(nums.e),
            }

        jwk1 = _rsa_to_jwk(priv1, "k1")
        jwk2 = _rsa_to_jwk(priv2, "k2")

        # Sign token with priv1, kid=k1
        payload = {"sub": "user:default/arsalan", "iss": "https://rhdh.test", "exp": 9_999_999_999}
        token = pyjwt.encode(payload, priv1, algorithm="RS256", headers={"kid": "k1"})

        jwks = [jwk1, jwk2]

        call_log: list[str] = []
        original_from_dict = pyjwt.PyJWK.from_dict

        def tracking_from_dict(jwk, *args, **kwargs):
            call_log.append(jwk.get("kid", "no-kid"))
            return original_from_dict(jwk, *args, **kwargs)

        env = {
            "RHDH_JWKS_URL": "https://rhdh.test/jwks.json",
            "RHDH_TOKEN_ISSUER": "https://rhdh.test",
            "KEYCLOAK_ISSUER": "",
        }
        with patch.dict(os.environ, env), \
             patch("sandbox_launcher.auth._fetch_jwks_for", return_value=jwks), \
             patch.object(pyjwt.PyJWK, "from_dict", staticmethod(tracking_from_dict)):
            claims, kind = verify_caller_token(token)

        assert kind == "rhdh"
        assert claims["sub"] == "user:default/arsalan"
        # Only k1 should have been attempted (kid matched)
        assert call_log == ["k1"], f"Expected only k1 to be tried, got: {call_log}"

    def test_no_kid_in_token_tries_all_keys(self):
        """Fix (3): token with no kid header tries all JWKS keys."""
        from sandbox_launcher.auth import verify_caller_token
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        priv = rsa.generate_private_key(65537, 2048, default_backend())

        def _int_to_base64url(n: int) -> str:
            import base64
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        nums = priv.public_key().public_numbers()
        jwk_signing = {
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k-signing",
            "n": _int_to_base64url(nums.n), "e": _int_to_base64url(nums.e),
        }
        # A decoy key (different key, different kid)
        priv_decoy = rsa.generate_private_key(65537, 2048, default_backend())
        nums_decoy = priv_decoy.public_key().public_numbers()
        jwk_decoy = {
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k-decoy",
            "n": _int_to_base64url(nums_decoy.n), "e": _int_to_base64url(nums_decoy.e),
        }

        payload = {"sub": "user:default/arsalan", "iss": "https://rhdh.test", "exp": 9_999_999_999}
        # Token has NO kid header
        token = pyjwt.encode(payload, priv, algorithm="RS256")

        call_log: list[str] = []
        original_from_dict = pyjwt.PyJWK.from_dict

        def tracking_from_dict(jwk, *args, **kwargs):
            call_log.append(jwk.get("kid", "no-kid"))
            return original_from_dict(jwk, *args, **kwargs)

        env = {
            "RHDH_JWKS_URL": "https://rhdh.test/jwks.json",
            "RHDH_TOKEN_ISSUER": "https://rhdh.test",
            "KEYCLOAK_ISSUER": "",
        }
        with patch.dict(os.environ, env), \
             patch("sandbox_launcher.auth._fetch_jwks_for", return_value=[jwk_decoy, jwk_signing]), \
             patch.object(pyjwt.PyJWK, "from_dict", staticmethod(tracking_from_dict)):
            claims, kind = verify_caller_token(token)

        assert claims["sub"] == "user:default/arsalan"
        # Both keys must have been tried (decoy first because no kid to filter)
        assert "k-decoy" in call_log
        assert "k-signing" in call_log

    def test_unmatched_kid_falls_back_to_all_keys(self):
        """Fix (3): token kid not in JWKS falls back to trying all keys (stale cache)."""
        from sandbox_launcher.auth import verify_caller_token
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        priv = rsa.generate_private_key(65537, 2048, default_backend())

        def _int_to_base64url(n: int) -> str:
            import base64
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        nums = priv.public_key().public_numbers()
        # JWKS has key with kid="current", but token has kid="new" (cache stale)
        jwk = {
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "current",
            "n": _int_to_base64url(nums.n), "e": _int_to_base64url(nums.e),
        }

        payload = {"sub": "user:default/arsalan", "iss": "https://rhdh.test", "exp": 9_999_999_999}
        # Token claims kid="new" but the signing key IS in the JWKS (just kid label changed)
        token = pyjwt.encode(payload, priv, algorithm="RS256", headers={"kid": "new"})

        call_log: list[str] = []
        original_from_dict = pyjwt.PyJWK.from_dict

        def tracking_from_dict(jwk_dict, *args, **kwargs):
            call_log.append(jwk_dict.get("kid", "no-kid"))
            return original_from_dict(jwk_dict, *args, **kwargs)

        env = {
            "RHDH_JWKS_URL": "https://rhdh.test/jwks.json",
            "RHDH_TOKEN_ISSUER": "https://rhdh.test",
            "KEYCLOAK_ISSUER": "",
        }
        with patch.dict(os.environ, env), \
             patch("sandbox_launcher.auth._fetch_jwks_for", return_value=[jwk]), \
             patch.object(pyjwt.PyJWK, "from_dict", staticmethod(tracking_from_dict)):
            claims, kind = verify_caller_token(token)

        assert claims["sub"] == "user:default/arsalan"
        # Fell back to all keys — "current" was tried
        assert "current" in call_log


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


# ---------------------------------------------------------------------------
# Vault grant writer — vault.py unit tests (no network)
# ---------------------------------------------------------------------------


class TestVaultBuildGrant:
    """Unit tests for vault.build_grant(); no network required."""

    def test_happy_path_returns_required_fields(self):
        """build_grant returns a dict with all required schema fields."""
        from sandbox_launcher.vault import build_grant

        grant = build_grant(
            sandbox_uid="aaa-bbb-ccc",
            user="arsalan",
            scope="read-only",
            ttl_seconds=3600,
        )
        required = {"version", "sandbox_uid", "user", "scope", "ttl", "nonce", "created"}
        assert required <= grant.keys()
        assert grant["version"] == 1
        assert grant["sandbox_uid"] == "aaa-bbb-ccc"
        assert grant["user"] == "arsalan"
        assert grant["scope"] == "read-only"
        assert grant["ttl"] == 3600
        assert len(grant["nonce"]) == 32  # uuid4 hex
        assert grant["created"].endswith("Z")

    def test_nonce_is_unique_per_call(self):
        """Two successive build_grant calls produce different nonces."""
        from sandbox_launcher.vault import build_grant

        g1 = build_grant("uid-1", "arsalan", "read-only", 60)
        g2 = build_grant("uid-1", "arsalan", "read-only", 60)
        assert g1["nonce"] != g2["nonce"]

    def test_default_ttl_from_env(self):
        """When ttl_seconds is None, VAULT_GRANT_TTL_SECONDS env var is used."""
        from sandbox_launcher.vault import build_grant

        with patch.dict(os.environ, {"VAULT_GRANT_TTL_SECONDS": "7200"}):
            grant = build_grant("uid-1", "arsalan", "read-only")
        assert grant["ttl"] == 7200

    def test_invalid_scope_raises(self):
        """build_grant raises ValueError for an unrecognised scope value."""
        from sandbox_launcher.vault import build_grant

        with pytest.raises(ValueError, match="scope"):
            build_grant("uid-1", "arsalan", "superuser", 60)

    def test_negative_ttl_raises(self):
        """build_grant raises ValueError for a non-positive TTL."""
        from sandbox_launcher.vault import build_grant

        with pytest.raises(ValueError, match="ttl"):
            build_grant("uid-1", "arsalan", "read-only", -1)

    def test_zero_ttl_raises(self):
        """build_grant raises ValueError for TTL=0."""
        from sandbox_launcher.vault import build_grant

        with pytest.raises(ValueError, match="ttl"):
            build_grant("uid-1", "arsalan", "read-only", 0)

    def test_all_valid_scopes_accepted(self):
        """All three scope values from LaunchScope are accepted."""
        from sandbox_launcher.vault import build_grant

        for scope in ("read-only", "read-write", "admin"):
            grant = build_grant("uid-1", "arsalan", scope, 60)
            assert grant["scope"] == scope

    def test_empty_sandbox_uid_raises(self):
        """Empty sandbox_uid raises ValueError during validate_grant."""
        from sandbox_launcher.vault import build_grant

        with pytest.raises(ValueError, match="sandbox_uid"):
            build_grant("", "arsalan", "read-only", 60)

    def test_no_prohibited_fields_in_grant(self):
        """The grant document must not contain any prohibited credential fields."""
        from sandbox_launcher.vault import _PROHIBITED_GRANT_FIELDS, build_grant

        grant = build_grant("uid-1", "arsalan", "read-only", 60)
        for field in _PROHIBITED_GRANT_FIELDS:
            assert field not in grant, f"Prohibited field {field!r} found in grant"


class TestVaultValidateGrant:
    """Unit tests for vault._validate_grant()."""

    def test_valid_grant_does_not_raise(self):
        from sandbox_launcher.vault import _validate_grant

        _validate_grant({
            "version": 1,
            "sandbox_uid": "uid-1",
            "user": "arsalan",
            "scope": "read-only",
            "ttl": 3600,
            "nonce": "abc123",
            "created": "2026-06-15T00:00:00.000000Z",
        })  # must not raise

    def test_missing_required_field_raises(self):
        from sandbox_launcher.vault import _validate_grant

        with pytest.raises(ValueError, match="missing required fields"):
            _validate_grant({
                "version": 1,
                "sandbox_uid": "uid-1",
                "user": "arsalan",
                # scope, ttl, nonce, created absent
            })

    def test_prohibited_access_token_field_raises(self):
        from sandbox_launcher.vault import _validate_grant

        with pytest.raises(ValueError, match="prohibited"):
            _validate_grant({
                "version": 1,
                "sandbox_uid": "uid-1",
                "user": "arsalan",
                "scope": "read-only",
                "ttl": 3600,
                "nonce": "abc",
                "created": "2026-06-15T00:00:00Z",
                "access_token": "secret-value",  # prohibited
            })

    def test_prohibited_bearer_field_raises(self):
        from sandbox_launcher.vault import _validate_grant

        with pytest.raises(ValueError, match="prohibited"):
            _validate_grant({
                "version": 1,
                "sandbox_uid": "uid-1",
                "user": "arsalan",
                "scope": "read-only",
                "ttl": 3600,
                "nonce": "abc",
                "created": "2026-06-15T00:00:00Z",
                "bearer": "some-token",  # prohibited
            })

    def test_prohibited_password_field_raises(self):
        from sandbox_launcher.vault import _validate_grant

        with pytest.raises(ValueError, match="prohibited"):
            _validate_grant({
                "version": 1,
                "sandbox_uid": "uid-1",
                "user": "arsalan",
                "scope": "read-only",
                "ttl": 3600,
                "nonce": "abc",
                "created": "2026-06-15T00:00:00Z",
                "password": "hunter2",  # prohibited
            })

    def test_wrong_version_raises(self):
        from sandbox_launcher.vault import _validate_grant

        with pytest.raises(ValueError, match="version"):
            _validate_grant({
                "version": 2,
                "sandbox_uid": "uid-1",
                "user": "arsalan",
                "scope": "read-only",
                "ttl": 3600,
                "nonce": "abc",
                "created": "2026-06-15T00:00:00Z",
            })

    def test_empty_nonce_raises(self):
        from sandbox_launcher.vault import _validate_grant

        with pytest.raises(ValueError, match="nonce"):
            _validate_grant({
                "version": 1,
                "sandbox_uid": "uid-1",
                "user": "arsalan",
                "scope": "read-only",
                "ttl": 3600,
                "nonce": "",
                "created": "2026-06-15T00:00:00Z",
            })


# ---------------------------------------------------------------------------
# Grant write integration with the /launch handler
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_vault_write_ok():
    """Mock vault.write_sandbox_grant to succeed (no Vault network call)."""
    with patch("sandbox_launcher.vault.write_sandbox_grant") as m:
        m.return_value = None
        yield m


@pytest.fixture
def mock_vault_env():
    """Set VAULT_ADDR so _write_grant does not hit the skip-if-disabled branch."""
    with patch.dict(os.environ, {"VAULT_ADDR": "https://vault.apps.anaeem.na-launch.com"}):
        yield


class TestGrantWriteInLaunchHandler:
    """Tests for the grant-write step in POST /launch (Option-D zero-trust flow)."""

    def test_happy_path_grant_is_written(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
        mock_vault_write_ok,
        mock_vault_env,
    ):
        """Happy path: /launch returns 202 and vault.write_sandbox_grant is called once."""
        resp = client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        assert resp.status_code == 202, resp.text
        mock_vault_write_ok.assert_called_once()

    def test_grant_keyed_by_sandbox_uid(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
        mock_vault_write_ok,
        mock_vault_env,
    ):
        """The sandbox_uid passed to write_sandbox_grant matches the mock resp's id."""
        client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        call_args = mock_vault_write_ok.call_args
        # First positional or keyword arg is sandbox_uid
        sandbox_uid = call_args.kwargs.get("sandbox_uid") or call_args.args[0]
        assert sandbox_uid == "aaaabbbb-cccc-dddd-eeee-ffffffffffff"

    def test_grant_scope_matches_request_scope(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
        mock_vault_write_ok,
        mock_vault_env,
    ):
        """The grant written to Vault carries the scope from the request body."""
        body = dict(_VALID_BODY, scope="read-only")
        client.post(
            "/launch",
            json=body,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        call_kwargs = mock_vault_write_ok.call_args.kwargs
        grant = call_kwargs.get("grant") or mock_vault_write_ok.call_args.args[1]
        assert grant["scope"] == "read-only"

    def test_grant_user_is_bare_username(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
        mock_vault_write_ok,
        mock_vault_env,
    ):
        """The grant 'user' field is the bare username (not the full entity ref)."""
        client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        call_kwargs = mock_vault_write_ok.call_args.kwargs
        grant = call_kwargs.get("grant") or mock_vault_write_ok.call_args.args[1]
        # entity_ref is "user:default/arsalan" -> bare user = "arsalan"
        assert grant["user"] == "arsalan"

    def test_grant_ttl_matches_ttl_minutes(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
        mock_vault_write_ok,
        mock_vault_env,
    ):
        """The grant TTL (seconds) equals ttl_minutes * 60 from the request body."""
        body = dict(_VALID_BODY, ttl_minutes=30)
        client.post(
            "/launch",
            json=body,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        call_kwargs = mock_vault_write_ok.call_args.kwargs
        grant = call_kwargs.get("grant") or mock_vault_write_ok.call_args.args[1]
        assert grant["ttl"] == 30 * 60  # 1800 seconds

    def test_grant_nonce_is_present_and_nonblank(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
        mock_vault_write_ok,
        mock_vault_env,
    ):
        """The grant document carries a non-empty nonce (server-generated)."""
        client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        call_kwargs = mock_vault_write_ok.call_args.kwargs
        grant = call_kwargs.get("grant") or mock_vault_write_ok.call_args.args[1]
        assert "nonce" in grant
        assert grant["nonce"]  # non-blank

    def test_grant_contains_no_prohibited_fields(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
        mock_vault_write_ok,
        mock_vault_env,
    ):
        """The grant written to Vault MUST NOT contain any credential field.

        Reviewer gate: access_token, bearer, password, client_secret, svid,
        private_key, api_key are all prohibited.
        """
        from sandbox_launcher.vault import _PROHIBITED_GRANT_FIELDS

        client.post(
            "/launch",
            json=_VALID_BODY,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        call_kwargs = mock_vault_write_ok.call_args.kwargs
        grant = call_kwargs.get("grant") or mock_vault_write_ok.call_args.args[1]
        for field in _PROHIBITED_GRANT_FIELDS:
            assert field not in grant, (
                f"Prohibited credential field {field!r} found in grant written to Vault. "
                "No-credential-passing invariant violated."
            )

    def test_vault_write_failure_returns_502(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
        mock_vault_env,
    ):
        """If Vault write_sandbox_grant raises, the handler returns 502 (fail-closed).

        Finding 2: the detail must be generic — no raw exception text exposed.
        """
        with patch(
            "sandbox_launcher.vault.write_sandbox_grant",
            side_effect=RuntimeError("Vault connection refused"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.rhdh.jwt"},
            )
        assert resp.status_code == 502, resp.text
        detail = resp.json()["detail"]
        # Generic message only — no raw exception text, no internal addresses.
        assert "grant write failed" in detail.lower()
        # Must NOT contain the raw exception string.
        assert "Vault connection refused" not in detail
        assert "RuntimeError" not in detail

    def test_vault_write_failure_after_sandbox_created_is_502(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
        mock_vault_env,
    ):
        """Vault failure does NOT return 202 — fail-closed even though the sandbox was created."""
        with patch(
            "sandbox_launcher.vault.write_sandbox_grant",
            side_effect=Exception("timeout"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.rhdh.jwt"},
            )
        assert resp.status_code == 502

    def test_grant_write_skipped_when_sandbox_uid_empty(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_vault_env,
    ):
        """When the OpenShell response has an empty sandbox_id, the grant write is skipped
        (dev/stub path where the sandbox UID is not assigned yet) and 202 is returned."""
        fake_resp = _make_mock_sandbox_resp(sandbox_id="")  # no UID
        with patch(
            "sandbox_launcher.openshell.create_sandbox",
            return_value=fake_resp,
        ), patch(
            "sandbox_launcher.vault.write_sandbox_grant",
            side_effect=AssertionError("write_sandbox_grant must not be called without a UID"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.rhdh.jwt"},
            )
        # 202 because grant write is skipped for empty UID
        assert resp.status_code == 202, resp.text

    def test_grant_write_skipped_when_vault_disabled(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_openshell_ok,
    ):
        """When VAULT_ADDR=disabled the grant write is skipped and 202 is returned."""
        with patch.dict(os.environ, {"VAULT_ADDR": "disabled"}), patch(
            "sandbox_launcher.vault.write_sandbox_grant",
            side_effect=AssertionError("write_sandbox_grant must not be called when disabled"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.rhdh.jwt"},
            )
        assert resp.status_code == 202, resp.text

    def test_grant_not_written_on_openshell_error(
        self,
        client: TestClient,
        mock_jwt_ok,
        mock_vault_write_ok,
        mock_vault_env,
    ):
        """If OpenShell create_sandbox fails, write_sandbox_grant is NEVER called."""
        with patch(
            "sandbox_launcher.openshell.create_sandbox",
            side_effect=Exception("gateway down"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.rhdh.jwt"},
            )
        assert resp.status_code == 502
        mock_vault_write_ok.assert_not_called()


# ---------------------------------------------------------------------------
# _bare_username helper
# ---------------------------------------------------------------------------


class TestBareUsername:
    """Unit tests for api._bare_username (entity-ref -> bare user extraction)."""

    def test_full_entity_ref(self):
        from sandbox_launcher.api import _bare_username

        assert _bare_username("user:default/arsalan") == "arsalan"

    def test_no_slash_returns_whole_string(self):
        from sandbox_launcher.api import _bare_username

        assert _bare_username("arsalan") == "arsalan"

    def test_nested_slashes_returns_last_segment(self):
        from sandbox_launcher.api import _bare_username

        assert _bare_username("user:default/admin/arsalan") == "arsalan"

    def test_empty_string_returns_empty(self):
        from sandbox_launcher.api import _bare_username

        assert _bare_username("") == ""


# ---------------------------------------------------------------------------
# Audit emit_grant_write
# ---------------------------------------------------------------------------


class TestAuditEmitGrantWrite:
    """Unit tests for audit.emit_grant_write — verifies log record structure and no raw secrets.

    Uses pytest's caplog fixture (which works with pytest's log-capture plugin)
    to capture log records emitted by emit_grant_write.
    """

    def _call_and_capture(self, caplog, **kwargs) -> dict:
        """Call emit_grant_write under caplog and return the extra fields of the last record."""
        import logging

        from sandbox_launcher.audit import emit_grant_write

        with caplog.at_level(logging.INFO, logger="sandbox_launcher.audit"):
            emit_grant_write(**kwargs)

        # Find the grant_write record
        records = [r for r in caplog.records if getattr(r, "event", "") == "sandbox.grant_write"]
        assert records, f"No sandbox.grant_write log record found. All records: {caplog.records}"
        record = records[-1]
        skip = {
            "name", "msg", "args", "created", "filename", "funcName", "levelname",
            "levelno", "lineno", "module", "msecs", "pathname", "process",
            "processName", "relativeCreated", "stack_info", "thread", "threadName",
            "exc_info", "exc_text", "message",
        }
        return {k: v for k, v in record.__dict__.items() if k not in skip}

    def test_emit_grant_write_allow(self, caplog):
        """emit_grant_write with outcome=allow sets correct structured fields."""
        fields = self._call_and_capture(
            caplog,
            actor="user:default/arsalan",
            sandbox_uid="uid-1",
            sandbox_name="agent-arsalan-abc123",
            grant_scope="read-only",
            grant_user="arsalan",
            grant_ttl=3600,
            grant_nonce_present=True,
            outcome="allow",
            latency_ms=42,
        )
        assert fields["event"] == "sandbox.grant_write"
        assert fields["outcome"] == "allow"
        assert fields["grant_scope"] == "read-only"
        assert fields["grant_nonce_present"] is True
        assert fields["latency_ms"] == 42
        # Nonce VALUE must never be a log field; only the bool "present" flag
        assert "nonce" not in fields

    def test_emit_grant_write_error_includes_reason(self, caplog):
        """emit_grant_write with outcome=error includes the reason field."""
        fields = self._call_and_capture(
            caplog,
            actor="user:default/arsalan",
            sandbox_uid="uid-1",
            sandbox_name="agent-arsalan-abc123",
            grant_scope="read-only",
            grant_user="arsalan",
            grant_ttl=3600,
            grant_nonce_present=False,
            outcome="error",
            latency_ms=5,
            reason="vault_write_failed: RuntimeError",
        )
        assert fields["outcome"] == "error"
        assert "reason" in fields
        assert "vault_write_failed" in fields["reason"]

    def test_emit_grant_write_no_credential_in_fields(self, caplog):
        """emit_grant_write must not pass any credential field into the log record."""
        from sandbox_launcher.vault import _PROHIBITED_GRANT_FIELDS

        fields = self._call_and_capture(
            caplog,
            actor="user:default/arsalan",
            sandbox_uid="uid-1",
            sandbox_name="agent-arsalan-abc123",
            grant_scope="read-only",
            grant_user="arsalan",
            grant_ttl=3600,
            grant_nonce_present=True,
            outcome="allow",
            latency_ms=10,
        )
        for forbidden in _PROHIBITED_GRANT_FIELDS:
            assert forbidden not in fields, (
                f"Credential field {forbidden!r} found in audit log record. "
                "No-credential-passing invariant violated."
            )

    def test_emit_grant_write_tool_args_hash_present(self, caplog):
        """emit_grant_write includes a non-empty tool_args_hash (audit contract)."""
        fields = self._call_and_capture(
            caplog,
            actor="user:default/arsalan",
            sandbox_uid="uid-1",
            sandbox_name="agent-arsalan-abc123",
            grant_scope="read-only",
            grant_user="arsalan",
            grant_ttl=3600,
            grant_nonce_present=True,
            outcome="allow",
            latency_ms=10,
        )
        assert "tool_args_hash" in fields
        # sha256 hex = 64 chars
        assert len(fields["tool_args_hash"]) == 64


# ---------------------------------------------------------------------------
# Finding 2: generic detail — no raw exception text to caller
# ---------------------------------------------------------------------------


class TestGenericErrorDetail:
    """Finding 2: raw exception text must never reach the HTTP response body."""

    def test_openshell_error_detail_is_generic(self, client, mock_jwt_ok):
        """create_sandbox exception text is NOT in the 502 response detail."""
        with patch(
            "sandbox_launcher.openshell.create_sandbox",
            side_effect=Exception("X-Vault-Token: hvs.secret and grpc://internal:9000"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.rhdh.jwt"},
            )
        assert resp.status_code == 502
        detail = resp.json()["detail"]
        assert "X-Vault-Token" not in detail
        assert "hvs.secret" not in detail
        assert "grpc://" not in detail
        assert detail == "sandbox backend error"

    def test_vault_write_error_detail_is_generic(self, client, mock_jwt_ok, mock_openshell_ok, mock_vault_env):
        """vault.write_sandbox_grant exception text is NOT in the 502 response detail."""
        with patch(
            "sandbox_launcher.vault.write_sandbox_grant",
            side_effect=RuntimeError("X-Vault-Token: hvs.internal and https://vault:8200"),
        ):
            resp = client.post(
                "/launch",
                json=_VALID_BODY,
                headers={"Authorization": "Bearer fake.rhdh.jwt"},
            )
        assert resp.status_code == 502
        detail = resp.json()["detail"]
        assert "X-Vault-Token" not in detail
        assert "hvs.internal" not in detail
        assert detail == "grant write failed"


# ---------------------------------------------------------------------------
# Finding 3: server-side TTL cap
# ---------------------------------------------------------------------------


class TestGrantTTLCap:
    """Finding 3: grant TTL must be clamped to MAX_GRANT_TTL_SECONDS server-side."""

    def test_ttl_minutes_clamped_to_max_when_large(
        self, client, mock_jwt_ok, mock_openshell_ok, mock_vault_write_ok, mock_vault_env
    ):
        """A ttl_minutes value whose seconds equivalent exceeds MAX_GRANT_TTL_SECONDS
        is clamped to MAX_GRANT_TTL_SECONDS in the written grant."""
        from sandbox_launcher.api import MAX_GRANT_TTL_SECONDS

        # ttl_minutes=480 -> 28800s > MAX_GRANT_TTL_SECONDS (3600s)
        body = dict(_VALID_BODY, ttl_minutes=480)
        resp = client.post(
            "/launch",
            json=body,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        assert resp.status_code == 202, resp.text
        call_kwargs = mock_vault_write_ok.call_args.kwargs
        grant = call_kwargs.get("grant") or mock_vault_write_ok.call_args.args[1]
        assert grant["ttl"] <= MAX_GRANT_TTL_SECONDS, (
            f"grant TTL {grant['ttl']} exceeds platform cap {MAX_GRANT_TTL_SECONDS}"
        )

    def test_ttl_within_cap_is_preserved(
        self, client, mock_jwt_ok, mock_openshell_ok, mock_vault_write_ok, mock_vault_env
    ):
        """A ttl_minutes within the cap is NOT reduced."""
        from sandbox_launcher.api import MAX_GRANT_TTL_SECONDS

        # 30 minutes = 1800s < 3600s cap
        body = dict(_VALID_BODY, ttl_minutes=30)
        resp = client.post(
            "/launch",
            json=body,
            headers={"Authorization": "Bearer fake.rhdh.jwt"},
        )
        assert resp.status_code == 202, resp.text
        call_kwargs = mock_vault_write_ok.call_args.kwargs
        grant = call_kwargs.get("grant") or mock_vault_write_ok.call_args.args[1]
        assert grant["ttl"] == 30 * 60  # 1800s — unchanged
