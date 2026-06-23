"""Tests for the L1 mint gate: mint_core, POST /requests/{id}/mint, and
canonical_scope_hash.

Test classes:
  TestDualControlUnit          — pure unit tests for _enforce_dual_control
  TestScopeHashUnit            — pure unit tests for _verify_scope_hash + canonical_scope_hash
  TestMintGate                 — happy-path and error-path integration tests for /mint
  TestMintSoD                  — adversarial M5 self-approval tests (canonical M5 regression)
  TestMintOnceOnly             — once-only issuance / idempotency / anti-replay
  TestWebhookMirrorM5          — proves the webhook git-mirror path is also M5-safe
  TestMintAuth                 — caller authentication: missing/invalid token -> 401/403
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from typing import Any
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
import respx
import httpx
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Environment setup (must happen before any jit_approver import)
# ---------------------------------------------------------------------------
os.environ.setdefault("JIT_ALLOWED_NAMESPACES", "agent-sandbox,agentic-mcp")
os.environ.setdefault("GITEA_TOKEN", "test-token")
os.environ.setdefault("GITEA_WEBHOOK_SECRET", "test-webhook-secret")
os.environ.setdefault("GITEA_REPO", "anaeem/nvidia-ida")
os.environ.setdefault("GITEA_BASE_URL", "https://git.arsalan.io")
os.environ.setdefault("GITEA_DEFAULT_BRANCH", "main")
os.environ.setdefault("VAULT_ADDR", "https://vault.apps.ocp-dev.na-launch.com")
os.environ.setdefault("JIT_DISABLE_REAPER", "1")
# Use synthetic token override so /mint auth works in unit tests without k8s.
os.environ.setdefault("JIT_MINT_CONSOLE_TOKEN_OVERRIDE", "test-console-token")

from jit_approver.api import app
from jit_approver.mint_core import _enforce_dual_control, _verify_scope_hash
from jit_approver.models import EscalationRequest, MintRequest, canonical_scope_hash
from jit_approver.store import seen_deliveries, session_store

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VAULT_ADDR = "https://vault.apps.ocp-dev.na-launch.com"
GITEA_BASE = "https://git.arsalan.io"
SESSION_ID = "deadbeef-0001-0002-0003-000000000001"
PR_NUMBER = 42
CONSOLE_TOKEN = "test-console-token"


@pytest.fixture(autouse=True)
def clear_store():
    """Clear session + delivery state between tests."""
    session_store.clear()
    seen_deliveries.clear()
    yield
    session_store.clear()
    seen_deliveries.clear()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _base_req(**overrides) -> EscalationRequest:
    data = {
        "agent_spiffe_id": "spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/test-agent",
        "requester_sub": "alice@example.com",
        "namespace": "agent-sandbox",
        "verbs": ["get", "list"],
        "resources": ["pods", "configmaps"],
        "duration_minutes": 15,
        "justification": "Need to inspect pod logs for debugging incident INC-1234",
    }
    data.update(overrides)
    return EscalationRequest(**data)


def _insert_session(
    session_id: str = SESSION_ID,
    pr_number: int = PR_NUMBER,
    req: EscalationRequest | None = None,
    state: str = "pending",
) -> None:
    """Insert a session into the in-memory store."""
    if req is None:
        req = _base_req()
    session_store[session_id] = {
        "id": session_id,
        "state": state,
        "pr_url": f"https://git.arsalan.io/anaeem/nvidia-ida/pulls/{pr_number}",
        "pr_number": pr_number,
        "expires_at": None,
        "request": req,
    }


def _mock_vault_issue(session_id: str = SESSION_ID) -> None:
    """Mock Vault login, ephemeral role create, creds read, and KV store."""
    role = f"jit-{session_id}"
    respx.post(f"{VAULT_ADDR}/v1/auth/jwt/login").mock(
        return_value=httpx.Response(
            200,
            json={
                "auth": {
                    "client_token": "vault-test-token",
                    "lease_duration": 3600,
                    "policies": ["jit-approver"],
                }
            },
        )
    )
    respx.post(f"{VAULT_ADDR}/v1/kubernetes/roles/{role}").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.post(f"{VAULT_ADDR}/v1/kubernetes/creds/{role}").mock(
        return_value=httpx.Response(
            200,
            json={
                "lease_id": f"kubernetes/creds/{role}/abc",
                "data": {
                    "service_account_token": "k8s-token-xyz",
                    "service_account_name": "jit-sa",
                    "service_account_namespace": "agent-sandbox",
                },
            },
        )
    )
    respx.post(f"{VAULT_ADDR}/v1/secret/data/jit/{session_id}").mock(
        return_value=httpx.Response(200, json={"data": {"version": 1}})
    )


def _mint_body(
    approver_sub: str = "bob@example.com",
    scope_hash: str | None = None,
    req: EscalationRequest | None = None,
) -> dict:
    if req is None:
        req = _base_req()
    if scope_hash is None:
        scope_hash = canonical_scope_hash(req)
    return {
        "approver_sub": approver_sub,
        "scope_hash": scope_hash,
        "reviewed_scope": {
            "namespace": req.namespace,
            "verbs": req.verbs,
            "resources": req.resources,
            "duration_minutes": req.duration_minutes,
        },
    }


def _mint_headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Console-SA-Token": CONSOLE_TOKEN,
    }


def _sign_webhook(body: bytes, secret: str = "test-webhook-secret") -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _pr_webhook_payload(
    merged: bool = True,
    pr_number: int = PR_NUMBER,
    merge_commit_sha: str = "deadbeefcafe",
    merged_by: str = "approver-user",
) -> dict[str, Any]:
    return {
        "action": "closed",
        "pull_request": {
            "number": pr_number,
            "merged": merged,
            "merge_commit_sha": merge_commit_sha,
            "base": {"ref": "main"},
            "labels": [{"name": "jit-approval"}],
            "merged_by": {"login": merged_by},
        },
        "repository": {"full_name": "anaeem/nvidia-ida"},
    }


def _post_webhook(client: TestClient, payload: dict, secret: str = "test-webhook-secret") -> Any:
    body = json.dumps(payload).encode()
    sig = _sign_webhook(body, secret)
    return client.post(
        "/webhooks/gitea",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Gitea-Event": "pull_request",
            "X-Gitea-Signature": sig,
            "X-Gitea-Delivery": str(uuid.uuid4()),
        },
    )


# ---------------------------------------------------------------------------
# TestDualControlUnit — pure unit tests, no I/O
# ---------------------------------------------------------------------------


class TestDualControlUnit:
    def test_distinct_subs_pass(self):
        """Different approver and requester must not raise."""
        _enforce_dual_control("bob@example.com", "alice@example.com")  # no exception

    def test_self_approval_raises_403(self):
        """Same approver and requester must raise 403."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _enforce_dual_control("alice@example.com", "alice@example.com")
        assert exc_info.value.status_code == 403
        assert "self-approval" in exc_info.value.detail.lower()

    def test_self_approval_allowed_when_flag_set(self, monkeypatch):
        """JIT_ALLOW_SELF_APPROVAL=true permits approver==requester (LANE A)."""
        monkeypatch.setenv("JIT_ALLOW_SELF_APPROVAL", "true")
        _enforce_dual_control("alice@example.com", "alice@example.com")  # no exception

    def test_self_approval_flag_does_not_relax_empty_approver(self, monkeypatch):
        """The flag must NEVER relax the empty-identity fail-closed checks."""
        from fastapi import HTTPException

        monkeypatch.setenv("JIT_ALLOW_SELF_APPROVAL", "true")
        with pytest.raises(HTTPException) as exc_info:
            _enforce_dual_control("", "")
        assert exc_info.value.status_code == 403

    def test_self_approval_flag_false_still_denies(self, monkeypatch):
        """Flag set to anything other than 'true' keeps the self-approval denial."""
        from fastapi import HTTPException

        monkeypatch.setenv("JIT_ALLOW_SELF_APPROVAL", "false")
        with pytest.raises(HTTPException) as exc_info:
            _enforce_dual_control("alice@example.com", "alice@example.com")
        assert exc_info.value.status_code == 403

    def test_empty_approver_sub_raises_403(self):
        """Empty approver_sub must raise 403 (fail-closed — cannot establish identity)."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _enforce_dual_control("", "alice@example.com")
        assert exc_info.value.status_code == 403

    def test_whitespace_approver_sub_raises_403(self):
        """Whitespace-only approver_sub must raise 403 (same as empty)."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _enforce_dual_control("   ", "alice@example.com")
        assert exc_info.value.status_code == 403

    def test_empty_requester_sub_raises_403(self):
        """Empty requester_sub must raise 403 (session data error -> deny)."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _enforce_dual_control("bob@example.com", "")
        assert exc_info.value.status_code == 403

    def test_none_approver_sub_raises_403(self):
        """None approver_sub (treated as empty) must raise 403."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _enforce_dual_control(None, "alice@example.com")  # type: ignore[arg-type]
        assert exc_info.value.status_code == 403

    def test_case_sensitive_comparison(self):
        """SoD comparison is exact-string (case-sensitive).

        'alice@example.com' vs 'Alice@example.com' must PASS — they are
        different strings. Production identity normalisation happens upstream
        (Keycloak / oauth2-proxy preferred_username is case-normalised there).
        """
        _enforce_dual_control("Alice@example.com", "alice@example.com")  # no exception


# ---------------------------------------------------------------------------
# TestScopeHashUnit — pure unit tests for canonical_scope_hash + _verify_scope_hash
# ---------------------------------------------------------------------------


class TestScopeHashUnit:
    def test_hash_stable_under_verb_reorder(self):
        """Sorting verbs: same hash regardless of input order."""
        req1 = _base_req(verbs=["get", "list"])
        req2 = _base_req(verbs=["list", "get"])
        assert canonical_scope_hash(req1) == canonical_scope_hash(req2)

    def test_hash_stable_under_resource_reorder(self):
        """Sorting resources: same hash regardless of input order."""
        req1 = _base_req(resources=["pods", "configmaps"])
        req2 = _base_req(resources=["configmaps", "pods"])
        assert canonical_scope_hash(req1) == canonical_scope_hash(req2)

    def test_hash_changes_on_duration(self):
        req1 = _base_req(duration_minutes=15)
        req2 = _base_req(duration_minutes=30)
        assert canonical_scope_hash(req1) != canonical_scope_hash(req2)

    def test_hash_changes_on_namespace(self):
        req1 = _base_req(namespace="agent-sandbox")
        req2 = _base_req(namespace="agentic-mcp")
        assert canonical_scope_hash(req1) != canonical_scope_hash(req2)

    def test_hash_changes_on_verbs(self):
        req1 = _base_req(verbs=["get"])
        req2 = _base_req(verbs=["get", "list"])
        assert canonical_scope_hash(req1) != canonical_scope_hash(req2)

    def test_hash_changes_on_resources(self):
        req1 = _base_req(resources=["pods"])
        req2 = _base_req(resources=["pods", "configmaps"])
        assert canonical_scope_hash(req1) != canonical_scope_hash(req2)

    def test_hash_returns_sha256_hex(self):
        req = _base_req()
        h = canonical_scope_hash(req)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_verify_scope_hash_passes_on_match(self):
        req = _base_req()
        expected_hash = canonical_scope_hash(req)
        _verify_scope_hash(req, expected_hash)  # must not raise

    def test_verify_scope_hash_raises_409_on_mismatch(self):
        from fastapi import HTTPException

        req = _base_req()
        with pytest.raises(HTTPException) as exc_info:
            _verify_scope_hash(req, "0" * 64)
        assert exc_info.value.status_code == 409

    def test_verify_scope_hash_raises_409_on_empty_hash(self):
        from fastapi import HTTPException

        req = _base_req()
        with pytest.raises(HTTPException) as exc_info:
            _verify_scope_hash(req, "")
        assert exc_info.value.status_code == 409

    def test_canonical_scope_hash_cross_check(self):
        """The jit-approver canonical_scope_hash and the console's _canonical_scope_hash
        must produce identical hashes for the same scope.

        We replicate the console's hash algorithm inline here (it's pure computation)
        because the console lives in a separate service with its own venv.  The
        approval-console test_app.py has a parallel assertion that the console's
        helper matches what jit-approver expects, completing the cross-check.

        A mismatch would cause spurious 409s on every /mint call.
        """

        def _console_canonical_scope_hash(detail: dict) -> str:
            """Replication of approval_console.app._canonical_scope_hash.

            Must stay byte-for-byte identical to that function.
            """
            policy_delta = detail.get("policy_delta") or []
            delta_sorted = sorted(
                f"{pd.get('host', '')}:{pd.get('port', 443)}" for pd in policy_delta
            )
            canonical: dict = {
                "namespace": detail.get("namespace", ""),
                "verbs": sorted(detail.get("verbs") or []),
                "resources": sorted(detail.get("resources") or []),
                "duration_minutes": detail.get("duration_minutes", 0),
                "sandbox": detail.get("sandbox"),
                "policy_delta": delta_sorted,
            }
            raw = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
            return hashlib.sha256(raw).hexdigest()

        req = _base_req(
            namespace="agent-sandbox",
            verbs=["list", "get"],   # intentionally unordered
            resources=["configmaps", "pods"],  # intentionally unordered
            duration_minutes=20,
        )
        server_hash = canonical_scope_hash(req)

        # Simulate what /detail returns.
        detail = {
            "namespace": req.namespace,
            "verbs": req.verbs,  # already normalised (lower) by pydantic
            "resources": req.resources,
            "duration_minutes": req.duration_minutes,
            "sandbox": req.sandbox,
            "policy_delta": [],
        }
        client_hash = _console_canonical_scope_hash(detail)
        assert server_hash == client_hash, (
            f"Hash mismatch between server ({server_hash!r}) and "
            f"console ({client_hash!r}) — /mint would always 409"
        )


# ---------------------------------------------------------------------------
# TestMintGate — happy-path + error paths for POST /requests/{id}/mint
# ---------------------------------------------------------------------------


class TestMintGate:
    @respx.mock
    def test_happy_path_issues_session(self, client: TestClient):
        """POST /mint with distinct approver_sub + correct scope_hash on a pending
        session -> 200 issued, Vault minted exactly once, state==issued."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)
        _mock_vault_issue(SESSION_ID)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="bob@example.com", req=req),
                headers=_mint_headers(),
            )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "issued"
        assert data["session_id"] == SESSION_ID
        assert session_store[SESSION_ID]["state"] == "issued"

    @respx.mock
    def test_session_not_found_404(self, client: TestClient):
        """Unknown session_id -> 404."""
        resp = client.post(
            "/requests/does-not-exist/mint",
            json=_mint_body(),
            headers=_mint_headers(),
        )
        assert resp.status_code == 404

    @respx.mock
    def test_state_already_issued_idempotent(self, client: TestClient):
        """Already-issued session -> idempotent response (no second Vault call)."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req, state="issued")
        session_store[SESSION_ID]["expires_at"] = "2026-06-19T12:00:00Z"

        creds = respx.post(f"{VAULT_ADDR}/v1/kubernetes/creds/jit-{SESSION_ID}").mock(
            return_value=httpx.Response(200, json={})
        )

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="bob@example.com", req=req),
                headers=_mint_headers(),
            )

        assert resp.status_code == 200
        # State was already 'issued' — must not have called Vault creds again.
        assert not creds.called

    @respx.mock
    def test_state_pending_approved_both_work(self, client: TestClient):
        """Approved state (not just pending) can also be minted."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req, state="approved")
        _mock_vault_issue(SESSION_ID)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="bob@example.com", req=req),
                headers=_mint_headers(),
            )
        assert resp.status_code == 200
        assert session_store[SESSION_ID]["state"] == "issued"

    @respx.mock
    def test_scope_hash_mismatch_409(self, client: TestClient):
        """scope_hash doesn't match stored request -> 409, no Vault call."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)

        creds = respx.post(f"{VAULT_ADDR}/v1/kubernetes/creds/jit-{SESSION_ID}").mock(
            return_value=httpx.Response(200, json={})
        )

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json={"approver_sub": "bob@example.com", "scope_hash": "deadbeef" * 8},
                headers=_mint_headers(),
            )

        assert resp.status_code == 409, resp.text
        assert not creds.called
        # State must stay pending.
        assert session_store[SESSION_ID]["state"] == "pending"

    @respx.mock
    def test_status_invariant_pending_no_creds(self, client: TestClient):
        """GET /status on a pending session must NOT expose credentials."""
        _insert_session(SESSION_ID, PR_NUMBER)
        with TestClient(app) as c:
            resp = c.get(f"/requests/{SESSION_ID}/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "pending"
        assert data.get("session_jwt") is None
        assert data.get("sa_token") is None


# ---------------------------------------------------------------------------
# TestMintSoD — adversarial M5 self-approval tests
# ---------------------------------------------------------------------------


class TestMintSoD:
    @respx.mock
    def test_self_approval_returns_403(self, client: TestClient):
        """CANONICAL M5 REGRESSION TEST.

        POST /mint with approver_sub == requester_sub -> 403,
        state stays pending, ZERO Vault calls, jit_denied audited.
        """
        req = _base_req(requester_sub="alice@example.com")
        _insert_session(SESSION_ID, PR_NUMBER, req)

        # Wire Vault so we can assert it is NEVER called.
        vault_login = respx.post(f"{VAULT_ADDR}/v1/auth/jwt/login").mock(
            return_value=httpx.Response(200, json={"auth": {"client_token": "t"}})
        )
        vault_creds = respx.post(
            f"{VAULT_ADDR}/v1/kubernetes/creds/jit-{SESSION_ID}"
        ).mock(return_value=httpx.Response(200, json={}))

        denied_events: list[dict] = []

        original_emit_denied = __import__(
            "jit_approver.audit", fromlist=["emit_denied"]
        ).emit_denied

        def _capture_denied(session_id, reason):
            denied_events.append({"session_id": session_id, "reason": reason})
            original_emit_denied(session_id, reason)

        with patch("jit_approver.mint_core.audit.emit_denied", side_effect=_capture_denied):
            with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
                resp = client.post(
                    f"/requests/{SESSION_ID}/mint",
                    json=_mint_body(
                        approver_sub="alice@example.com",  # same as requester_sub
                        req=req,
                    ),
                    headers=_mint_headers(),
                )

        # 403 — self-approval denied.
        assert resp.status_code == 403, resp.text
        # State must remain pending (no state change before SoD check).
        assert session_store[SESSION_ID]["state"] == "pending"
        # Zero Vault calls — fail-closed before any Vault interaction.
        assert not vault_login.called, "Vault login must NOT be called on SoD violation"
        assert not vault_creds.called, "Vault creds must NOT be called on SoD violation"
        # jit_denied must have been emitted.
        assert denied_events, "emit_denied must be called on M5 self-approval"

    @respx.mock
    def test_self_approval_issues_when_flag_set(self, client: TestClient, monkeypatch):
        """LANE A: with JIT_ALLOW_SELF_APPROVAL=true, approver==requester -> 200 issued.

        Mirrors the live deployment behaviour (the threat-model decision is
        human-gates-and-logs every elevation, not 4-eyes). The request is still
        filed + approved + minted (full issuance path runs).
        """
        monkeypatch.setenv("JIT_ALLOW_SELF_APPROVAL", "true")
        req = _base_req(requester_sub="alice@example.com")
        _insert_session(SESSION_ID, PR_NUMBER, req)
        _mock_vault_issue(SESSION_ID)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="alice@example.com", req=req),  # self-approval
                headers=_mint_headers(),
            )

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "issued"
        assert session_store[SESSION_ID]["state"] == "issued"

    @respx.mock
    def test_empty_approver_sub_403(self, client: TestClient):
        """Empty approver_sub -> 403, fail-closed (cannot establish identity)."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)

        vault_creds = respx.post(
            f"{VAULT_ADDR}/v1/kubernetes/creds/jit-{SESSION_ID}"
        ).mock(return_value=httpx.Response(200, json={}))

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            # Pydantic min_length=1 will catch this at body parse time -> 422.
            # We patch MintRequest to bypass that and directly test _enforce_dual_control.
            from jit_approver import mint_core

            original_enforce = mint_core._enforce_dual_control

            def _enforce_with_empty(approver_sub, requester_sub):
                original_enforce(approver_sub, requester_sub)

            # Send a body that would fail Pydantic validation: approver_sub=""
            # is caught by min_length=1 -> 422, which is fail-closed.
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json={"approver_sub": "", "scope_hash": canonical_scope_hash(req)},
                headers=_mint_headers(),
            )

        # 422 (Pydantic min_length=1) is fail-closed — no mint.
        assert resp.status_code in {422, 403}, resp.text
        assert not vault_creds.called

    @respx.mock
    def test_self_approval_state_stays_pending(self, client: TestClient):
        """State must NOT change to issued on self-approval attempt."""
        req = _base_req(requester_sub="alice@example.com")
        _insert_session(SESSION_ID, PR_NUMBER, req)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="alice@example.com", req=req),
                headers=_mint_headers(),
            )

        assert resp.status_code == 403
        assert session_store[SESSION_ID]["state"] == "pending", (
            "State must remain pending after a self-approval attempt"
        )

    @respx.mock
    def test_self_approval_no_vault_calls(self, client: TestClient):
        """Zero Vault calls on self-approval (SoD check fires before issuance)."""
        req = _base_req(requester_sub="alice@example.com")
        _insert_session(SESSION_ID, PR_NUMBER, req)

        vault_login = respx.post(f"{VAULT_ADDR}/v1/auth/jwt/login").mock(
            return_value=httpx.Response(200, json={"auth": {"client_token": "t"}})
        )
        vault_creds = respx.post(
            f"{VAULT_ADDR}/v1/kubernetes/creds/jit-{SESSION_ID}"
        ).mock(return_value=httpx.Response(200, json={}))

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="alice@example.com", req=req),
                headers=_mint_headers(),
            )

        assert resp.status_code == 403
        assert not vault_login.called
        assert not vault_creds.called


# ---------------------------------------------------------------------------
# TestMintOnceOnly — once-only issuance / anti-replay / idempotency
# ---------------------------------------------------------------------------


class TestMintOnceOnly:
    @respx.mock
    def test_duplicate_mint_request_mints_exactly_once(self, client: TestClient):
        """Two consecutive POST /mint for the same pending session -> mints once.

        The second call returns the session's current (issued) state without
        calling Vault a second time.
        """
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)

        # Set up Vault mocks and capture the creds route for call counting.
        vault_addr = VAULT_ADDR
        role = f"jit-{SESSION_ID}"
        respx.post(f"{vault_addr}/v1/auth/jwt/login").mock(
            return_value=httpx.Response(
                200,
                json={"auth": {"client_token": "vault-test-token", "lease_duration": 3600, "policies": ["jit-approver"]}},
            )
        )
        respx.post(f"{vault_addr}/v1/kubernetes/roles/{role}").mock(
            return_value=httpx.Response(200, json={})
        )
        vault_creds = respx.post(f"{vault_addr}/v1/kubernetes/creds/{role}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "lease_id": f"kubernetes/creds/{role}/abc",
                    "data": {
                        "service_account_token": "k8s-token-xyz",
                        "service_account_name": "jit-sa",
                        "service_account_namespace": "agent-sandbox",
                    },
                },
            )
        )
        respx.post(f"{vault_addr}/v1/secret/data/jit/{SESSION_ID}").mock(
            return_value=httpx.Response(200, json={"data": {"version": 1}})
        )

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp1 = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="bob@example.com", req=req),
                headers=_mint_headers(),
            )
            resp2 = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="bob@example.com", req=req),
                headers=_mint_headers(),
            )

        assert resp1.status_code == 200, f"First mint failed: {resp1.text}"
        assert resp2.status_code == 200, f"Second mint failed: {resp2.text}"
        # Vault creds must have been called exactly once.
        assert vault_creds.call_count == 1, (
            f"Vault creds must be called exactly once, got {vault_creds.call_count}"
        )

    @respx.mock
    def test_mint_on_denied_session_idempotent(self, client: TestClient):
        """Mint on an already-denied session -> idempotent, no Vault call."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req, state="denied")

        vault_creds = respx.post(
            f"{VAULT_ADDR}/v1/kubernetes/creds/jit-{SESSION_ID}"
        ).mock(return_value=httpx.Response(200, json={}))

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="bob@example.com", req=req),
                headers=_mint_headers(),
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "denied"
        assert not vault_creds.called


# ---------------------------------------------------------------------------
# TestWebhookMirrorM5 — the still-live git path must also be M5-safe
# ---------------------------------------------------------------------------


class TestWebhookMirrorM5:
    @respx.mock
    def test_webhook_self_approval_denied(self, client: TestClient):
        """WEBHOOK M5 TEST: merged_by == requester_sub -> denied, no Vault call.

        This proves the still-live git mirror path also enforces SoD, so the
        two paths cannot diverge on the M5 check.
        """
        req = _base_req(requester_sub="alice@example.com")
        _insert_session(SESSION_ID, PR_NUMBER, req)

        # SoD reads requester_sub from the RE-VALIDATED merged grant, so the
        # grant must be fetchable and carry requesterSub == merged_by to
        # exercise the real self-approval denial (not a fetch failure).
        grant_yaml = f"""apiVersion: jit.anaeem.na-launch.com/v1alpha1
kind: JITGrant
metadata:
  name: jit-{SESSION_ID}
spec:
  sessionId: {SESSION_ID}
  requesterSub: alice@example.com
  agentSpiffeId: spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/test-agent
  justification: Need to inspect pod logs for debugging incident INC-1234
  requestedScope:
    namespace: agent-sandbox
    durationMinutes: 15
    rules:
      - verbs: [get, list]
        resources: [pods, configmaps]
"""
        respx.get(
            f"{GITEA_BASE}/api/v1/repos/anaeem/nvidia-ida/raw/grants/{SESSION_ID}.yaml"
        ).mock(return_value=httpx.Response(200, text=grant_yaml))

        vault_creds = respx.post(
            f"{VAULT_ADDR}/v1/kubernetes/creds/jit-{SESSION_ID}"
        ).mock(return_value=httpx.Response(200, json={}))
        vault_login = respx.post(f"{VAULT_ADDR}/v1/auth/jwt/login").mock(
            return_value=httpx.Response(200, json={"auth": {"client_token": "t"}})
        )

        # merged_by == requester_sub → self-approval
        payload = _pr_webhook_payload(pr_number=PR_NUMBER, merged_by="alice@example.com")

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = _post_webhook(client, payload)

        assert resp.status_code == 200, resp.text
        data = resp.json()
        # The webhook must deny/return an error, not issue.
        assert data.get("status") in {"denied", "error"}, (
            f"Webhook self-approval must be denied, got: {data}"
        )
        assert not vault_creds.called, "Vault must NOT be called on webhook self-approval"
        assert not vault_login.called, "Vault must NOT be called on webhook self-approval"
        # Session must remain pending.
        assert session_store[SESSION_ID]["state"] == "pending", (
            "Session state must remain pending after webhook self-approval attempt"
        )

    @respx.mock
    def test_webhook_distinct_approver_still_issues(self, client: TestClient):
        """Webhook with merged_by != requester_sub issues normally (regression test).

        This verifies that the M5 fix does not break the legitimate webhook path.
        """
        req = _base_req(requester_sub="alice@example.com")
        _insert_session(SESSION_ID, PR_NUMBER, req)

        grant_yaml = f"""apiVersion: jit.anaeem.na-launch.com/v1alpha1
kind: JITGrant
metadata:
  name: jit-{SESSION_ID}
spec:
  sessionId: {SESSION_ID}
  requesterSub: alice@example.com
  agentSpiffeId: spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/test-agent
  justification: Need to inspect pod logs for debugging incident INC-1234
  requestedScope:
    namespace: agent-sandbox
    durationMinutes: 15
    rules:
      - verbs: [get, list]
        resources: [pods, configmaps]
"""
        respx.get(
            f"{GITEA_BASE}/api/v1/repos/anaeem/nvidia-ida/raw/grants/{SESSION_ID}.yaml"
        ).mock(return_value=httpx.Response(200, text=grant_yaml))
        _mock_vault_issue(SESSION_ID)

        # merged_by != requester_sub — different user, SoD satisfied.
        payload = _pr_webhook_payload(pr_number=PR_NUMBER, merged_by="bob@example.com")

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = _post_webhook(client, payload)

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "issued"
        assert session_store[SESSION_ID]["state"] == "issued"


# ---------------------------------------------------------------------------
# TestMintAuth — caller authentication
# ---------------------------------------------------------------------------


class TestMintAuth:
    @respx.mock
    def test_missing_console_token_returns_401(self, client: TestClient):
        """POST /mint with no X-Console-SA-Token and no SPIFFE ID -> 401."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)

        # Clear the override so there's nothing to match against.
        with patch.dict(os.environ, {"JIT_MINT_CONSOLE_TOKEN_OVERRIDE": ""}):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(req=req),
                # No X-Console-SA-Token header.
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 401, resp.text

    @respx.mock
    def test_wrong_console_token_returns_401(self, client: TestClient):
        """POST /mint with wrong token -> 401."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)

        resp = client.post(
            f"/requests/{SESSION_ID}/mint",
            json=_mint_body(req=req),
            headers={"Content-Type": "application/json", "X-Console-SA-Token": "WRONG-TOKEN"},
        )
        assert resp.status_code == 401, resp.text

    @respx.mock
    def test_spiffe_id_path_valid_id_allowed(self, client: TestClient):
        """When JIT_MINT_REQUIRE_MTLS=true, a valid SPIFFE ID in the allowlist passes."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)
        _mock_vault_issue(SESSION_ID)

        console_svid = "spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/approval-console"
        with patch.dict(os.environ, {
            "JIT_MINT_REQUIRE_MTLS": "true",
            "JIT_MINT_ALLOWED_SPIFFE_IDS": console_svid,
        }):
            with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
                resp = client.post(
                    f"/requests/{SESSION_ID}/mint",
                    json=_mint_body(approver_sub="bob@example.com", req=req),
                    headers={
                        "Content-Type": "application/json",
                        "X-Peer-Spiffe-Id": console_svid,
                    },
                )
        assert resp.status_code == 200, resp.text

    @respx.mock
    def test_spiffe_id_path_wrong_id_rejected(self, client: TestClient):
        """When JIT_MINT_REQUIRE_MTLS=true, a SPIFFE ID not in the allowlist -> 403."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)

        console_svid = "spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/approval-console"
        agent_svid = "spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/my-agent"
        with patch.dict(os.environ, {
            "JIT_MINT_REQUIRE_MTLS": "true",
            "JIT_MINT_ALLOWED_SPIFFE_IDS": console_svid,
        }):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="bob@example.com", req=req),
                headers={
                    "Content-Type": "application/json",
                    "X-Peer-Spiffe-Id": agent_svid,  # agent SVID, not console
                },
            )
        assert resp.status_code == 403, resp.text

    @respx.mock
    def test_spiffe_id_path_missing_id_401(self, client: TestClient):
        """When JIT_MINT_REQUIRE_MTLS=true, missing X-Peer-Spiffe-Id -> 401."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)

        with patch.dict(os.environ, {
            "JIT_MINT_REQUIRE_MTLS": "true",
            "JIT_MINT_ALLOWED_SPIFFE_IDS": "spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/approval-console",
        }):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(approver_sub="bob@example.com", req=req),
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 401, resp.text

    @respx.mock
    def test_mint_gate_disabled_returns_503(self, client: TestClient):
        """When JIT_MINT_GATE_ENABLED=false, /mint returns 503."""
        req = _base_req()
        _insert_session(SESSION_ID, PR_NUMBER, req)

        with patch.dict(os.environ, {"JIT_MINT_GATE_ENABLED": "false"}):
            resp = client.post(
                f"/requests/{SESSION_ID}/mint",
                json=_mint_body(req=req),
                headers=_mint_headers(),
            )
        assert resp.status_code == 503, resp.text
