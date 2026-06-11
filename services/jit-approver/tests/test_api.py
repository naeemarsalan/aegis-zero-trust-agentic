"""Pytest test suite for jit-approver.

Coverage:
  Scope ceiling rejections:
    - delete verb rejected
    - secrets resource rejected
    - escalate verb rejected
    - impersonate verb rejected
    - duration > 60 minutes rejected
    - unknown/foreign namespace rejected
    - clusterroles resource rejected
    - rolebindings resource rejected

  Happy path:
    - valid request -> 202 + session id + pr_url (Gitea calls mocked via respx)

  Webhook:
    - bad HMAC signature -> 401
    - non pull_request event -> ignored
    - pull_request action=opened (not closed) -> ignored
    - pull_request closed but not merged -> ignored
    - pull_request closed+merged but wrong repo -> ignored
    - pull_request closed+merged but missing jit-approval label -> ignored
    - pull_request closed+merged, label present, Vault call mocked -> issued

  Status endpoint:
    - unknown session -> 404
    - known session -> 200 with state

  Summary endpoint:
    - post summary for known session -> 200 (Gitea comment mocked)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import respx
import httpx
from fastapi.testclient import TestClient

# Set required env vars before importing the app
os.environ.setdefault("JIT_ALLOWED_NAMESPACES", "agent-sandbox,agentic-mcp")
os.environ.setdefault("GITEA_TOKEN", "test-token")
os.environ.setdefault("GITEA_WEBHOOK_SECRET", "test-webhook-secret")
os.environ.setdefault("GITEA_REPO", "anaeem/nvidia-ida")
os.environ.setdefault("GITEA_BASE_URL", "https://git.arsalan.io")
os.environ.setdefault("GITEA_DEFAULT_BRANCH", "main")
os.environ.setdefault("VAULT_ADDR", "https://vault.apps.anaeem.na-launch.com")
# Drive the reaper via reap_once() in tests; don't start the background loop
# (which would try a real Vault login on TestClient startup).
os.environ.setdefault("JIT_DISABLE_REAPER", "1")

from jit_approver.api import app
from jit_approver.store import session_store

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign(body: bytes, secret: str = "test-webhook-secret") -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _base_request() -> dict[str, Any]:
    return {
        "agent_spiffe_id": "spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/test-agent",
        "requester_sub": "user@example.com",
        "namespace": "agent-sandbox",
        "verbs": ["get", "list"],
        "resources": ["pods", "configmaps"],
        "duration_minutes": 15,
        "justification": "Need to inspect pod logs for debugging incident INC-1234",
    }


def _pr_webhook_payload(
    merged: bool = True,
    labels: list[str] | None = None,
    repo: str = "anaeem/nvidia-ida",
    base_branch: str = "main",
    action: str = "closed",
    pr_number: int = 42,
    merge_commit_sha: str = "deadbeefcafe",
) -> dict[str, Any]:
    if labels is None:
        labels = ["jit-approval"]
    return {
        "action": action,
        "pull_request": {
            "number": pr_number,
            "merged": merged,
            "merge_commit_sha": merge_commit_sha,
            "base": {"ref": base_branch},
            "labels": [{"name": lbl} for lbl in labels],
            "merged_by": {"login": "approver-user"},
        },
        "repository": {"full_name": repo},
    }


def _grant_yaml(
    session_id: str,
    namespace: str = "agent-sandbox",
    verbs: list[str] | None = None,
    resources: list[str] | None = None,
    duration_minutes: int = 15,
    requester_sub: str = "user@example.com",
    agent_spiffe_id: str = "spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/test-agent",
    justification: str = "Need to inspect pod logs for debugging incident INC-1234",
) -> str:
    """Render a reviewed grants/<session>.yaml exactly as gitea._render_scope_yaml does."""
    import yaml

    if verbs is None:
        verbs = ["get", "list"]
    if resources is None:
        resources = ["pods", "configmaps"]
    doc = {
        "apiVersion": "jit.anaeem.na-launch.com/v1alpha1",
        "kind": "JITGrant",
        "metadata": {"name": f"jit-{session_id}"},
        "spec": {
            "sessionId": session_id,
            "requesterSub": requester_sub,
            "agentSpiffeId": agent_spiffe_id,
            "justification": justification,
            "requestedScope": {
                "namespace": namespace,
                "durationMinutes": duration_minutes,
                "rules": [{"verbs": verbs, "resources": resources}],
            },
        },
    }
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)


def _mock_merged_grant(session_id: str, grant_yaml: str, ref: str = "deadbeefcafe") -> None:
    """Mock the Gitea raw-grant fetch for the merged YAML (C2 read)."""
    base_url = "https://git.arsalan.io"
    respx.get(
        f"{base_url}/api/v1/repos/anaeem/nvidia-ida/raw/grants/{session_id}.yaml"
    ).mock(return_value=httpx.Response(200, text=grant_yaml))


def _insert_session(session_id: str, pr_number: int, req: Any) -> None:
    """Insert a pending session bound to a PR number."""
    session_store[session_id] = {
        "id": session_id,
        "state": "pending",
        "pr_url": f"https://git.arsalan.io/anaeem/nvidia-ida/pulls/{pr_number}",
        "pr_number": pr_number,
        "expires_at": None,
        "request": req,
    }


def _mock_vault_issue(session_id: str, role_name: str | None = None) -> None:
    """Mock Vault login, ephemeral role create, creds read, and KV store."""
    vault_addr = "https://vault.apps.anaeem.na-launch.com"
    role = role_name or f"jit-{session_id}"
    respx.post(f"{vault_addr}/v1/auth/jwt/login").mock(
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
    # H3: ephemeral per-session role create
    respx.post(f"{vault_addr}/v1/kubernetes/roles/{role}").mock(
        return_value=httpx.Response(200, json={})
    )
    # creds read from the ephemeral role
    respx.post(f"{vault_addr}/v1/kubernetes/creds/{role}").mock(
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
    respx.post(f"{vault_addr}/v1/secret/data/jit/{session_id}").mock(
        return_value=httpx.Response(200, json={"data": {"version": 1}})
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_store():
    """Clear session store and replay-dedupe state between tests."""
    from jit_approver.store import seen_deliveries

    session_store.clear()
    seen_deliveries.clear()
    yield
    session_store.clear()
    seen_deliveries.clear()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Scope ceiling rejection tests
# ---------------------------------------------------------------------------


class TestScopeCeilingRejections:
    def test_delete_verb_rejected(self, client: TestClient):
        req = _base_request()
        req["verbs"] = ["get", "delete"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert any("delete" in str(d).lower() for d in detail)

    def test_escalate_verb_rejected(self, client: TestClient):
        req = _base_request()
        req["verbs"] = ["get", "escalate"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_impersonate_verb_rejected(self, client: TestClient):
        req = _base_request()
        req["verbs"] = ["impersonate"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_bind_verb_rejected(self, client: TestClient):
        req = _base_request()
        req["verbs"] = ["get", "bind"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_secrets_resource_rejected(self, client: TestClient):
        req = _base_request()
        req["resources"] = ["pods", "secrets"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422
        detail_str = str(resp.json()["detail"])
        assert "secret" in detail_str.lower()

    def test_roles_resource_rejected(self, client: TestClient):
        req = _base_request()
        req["resources"] = ["pods", "roles"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_rolebindings_resource_rejected(self, client: TestClient):
        req = _base_request()
        req["resources"] = ["pods", "rolebindings"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_clusterroles_resource_rejected(self, client: TestClient):
        req = _base_request()
        req["resources"] = ["clusterroles"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_clusterrolebindings_resource_rejected(self, client: TestClient):
        req = _base_request()
        req["resources"] = ["pods", "clusterrolebindings"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_120_minutes_rejected(self, client: TestClient):
        req = _base_request()
        req["duration_minutes"] = 120
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_61_minutes_rejected(self, client: TestClient):
        req = _base_request()
        req["duration_minutes"] = 61
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_zero_minutes_rejected(self, client: TestClient):
        req = _base_request()
        req["duration_minutes"] = 0
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_foreign_namespace_rejected(self, client: TestClient):
        req = _base_request()
        req["namespace"] = "kube-system"
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422
        detail_str = str(resp.json()["detail"])
        assert "kube-system" in detail_str or "allowlist" in detail_str.lower()

    def test_vault_namespace_rejected(self, client: TestClient):
        req = _base_request()
        req["namespace"] = "vault"
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_unknown_verb_rejected(self, client: TestClient):
        req = _base_request()
        req["verbs"] = ["get", "execute"]
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422

    def test_short_justification_rejected(self, client: TestClient):
        req = _base_request()
        req["justification"] = "too short"
        resp = client.post("/requests", json=req)
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    @respx.mock
    def test_valid_request_creates_pr(self, client: TestClient):
        """Valid request triggers Gitea API calls and returns 202 with id + pr_url."""
        base_url = "https://git.arsalan.io"

        # Mock: get branch SHA
        respx.get(f"{base_url}/api/v1/repos/anaeem/nvidia-ida/branches/main").mock(
            return_value=httpx.Response(200, json={"commit": {"id": "abc123"}})
        )
        # Mock: create branch
        respx.post(f"{base_url}/api/v1/repos/anaeem/nvidia-ida/branches").mock(
            return_value=httpx.Response(201, json={"name": "jit/test-session"})
        )
        # Mock: commit file
        respx.post(
            url__regex=r".*/contents/grants/.*\.yaml"
        ).mock(return_value=httpx.Response(201, json={"content": {}}))
        # Mock: create PR
        respx.post(f"{base_url}/api/v1/repos/anaeem/nvidia-ida/pulls").mock(
            return_value=httpx.Response(
                201,
                json={
                    "number": 99,
                    "html_url": "https://git.arsalan.io/anaeem/nvidia-ida/pulls/99",
                },
            )
        )
        # Mock: list labels (for label application)
        respx.get(f"{base_url}/api/v1/repos/anaeem/nvidia-ida/labels").mock(
            return_value=httpx.Response(
                200, json=[{"id": 1, "name": "jit-approval"}]
            )
        )
        # Mock: apply label
        respx.post(
            url__regex=r".*/issues/\d+/labels"
        ).mock(return_value=httpx.Response(200, json=[]))

        req = _base_request()
        resp = client.post("/requests", json=req)
        assert resp.status_code == 202, resp.text
        data = resp.json()
        assert "id" in data
        assert "pr_url" in data
        assert data["pr_url"] == "https://git.arsalan.io/anaeem/nvidia-ida/pulls/99"
        # Session should be in store
        assert data["id"] in session_store
        assert session_store[data["id"]]["state"] == "pending"

    @respx.mock
    def test_agentic_mcp_namespace_allowed(self, client: TestClient):
        """agentic-mcp is in the default allowlist."""
        base_url = "https://git.arsalan.io"
        respx.get(f"{base_url}/api/v1/repos/anaeem/nvidia-ida/branches/main").mock(
            return_value=httpx.Response(200, json={"commit": {"id": "abc123"}})
        )
        respx.post(f"{base_url}/api/v1/repos/anaeem/nvidia-ida/branches").mock(
            return_value=httpx.Response(201, json={"name": "jit/x"})
        )
        respx.post(url__regex=r".*/contents/grants/.*\.yaml").mock(
            return_value=httpx.Response(201, json={"content": {}})
        )
        respx.post(f"{base_url}/api/v1/repos/anaeem/nvidia-ida/pulls").mock(
            return_value=httpx.Response(
                201,
                json={"number": 100, "html_url": "https://git.arsalan.io/anaeem/nvidia-ida/pulls/100"},
            )
        )
        respx.get(f"{base_url}/api/v1/repos/anaeem/nvidia-ida/labels").mock(
            return_value=httpx.Response(200, json=[{"id": 1, "name": "jit-approval"}])
        )
        respx.post(url__regex=r".*/issues/\d+/labels").mock(
            return_value=httpx.Response(200, json=[])
        )

        req = _base_request()
        req["namespace"] = "agentic-mcp"
        resp = client.post("/requests", json=req)
        assert resp.status_code == 202, resp.text


# ---------------------------------------------------------------------------
# Status endpoint
# ---------------------------------------------------------------------------


class TestStatusEndpoint:
    def test_unknown_session_404(self, client: TestClient):
        resp = client.get(f"/requests/{uuid.uuid4()}/status")
        assert resp.status_code == 404

    def test_known_session_returns_state(self, client: TestClient):
        session_id = str(uuid.uuid4())
        session_store[session_id] = {
            "id": session_id,
            "state": "pending",
            "pr_url": "https://git.arsalan.io/anaeem/nvidia-ida/pulls/5",
            "pr_number": 5,
            "expires_at": None,
            "request": None,
        }
        resp = client.get(f"/requests/{session_id}/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "pending"
        assert data["pr_url"] is not None

    def test_issued_session_has_expires_at(self, client: TestClient):
        session_id = str(uuid.uuid4())
        session_store[session_id] = {
            "id": session_id,
            "state": "issued",
            "pr_url": "https://git.arsalan.io/anaeem/nvidia-ida/pulls/7",
            "pr_number": 7,
            "expires_at": "2026-06-11T15:00:00+00:00",
            "request": None,
        }
        resp = client.get(f"/requests/{session_id}/status")
        assert resp.status_code == 200
        assert resp.json()["expires_at"] is not None


# ---------------------------------------------------------------------------
# Webhook tests
# ---------------------------------------------------------------------------


class TestWebhook:
    def test_bad_signature_returns_401(self, client: TestClient):
        payload = _pr_webhook_payload()
        resp = self._post_webhook(client, payload, signature="badhexdigest")
        assert resp.status_code == 401

    def test_missing_signature_returns_401(self, client: TestClient):
        body = json.dumps(_pr_webhook_payload()).encode()
        resp = client.post(
            "/webhooks/gitea",
            content=body,
            headers={"Content-Type": "application/json", "X-Gitea-Event": "pull_request"},
        )
        assert resp.status_code == 401

    def test_non_pr_event_ignored(self, client: TestClient):
        payload = {"action": "push"}
        resp = self._post_webhook(client, payload, event="push")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_pr_opened_ignored(self, client: TestClient):
        payload = _pr_webhook_payload(action="opened")
        resp = self._post_webhook(client, payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_pr_closed_not_merged_ignored(self, client: TestClient):
        payload = _pr_webhook_payload(merged=False)
        resp = self._post_webhook(client, payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_pr_wrong_repo_ignored(self, client: TestClient):
        payload = _pr_webhook_payload(repo="other/repo")
        resp = self._post_webhook(client, payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_pr_missing_jit_label_ignored(self, client: TestClient):
        payload = _pr_webhook_payload(labels=["other-label"])
        resp = self._post_webhook(client, payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_pr_wrong_base_branch_ignored(self, client: TestClient):
        payload = _pr_webhook_payload(base_branch="feature-branch")
        resp = self._post_webhook(client, payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_pr_no_session_for_pr_ignored(self, client: TestClient):
        """Merged+labelled PR but no matching session in store -> ignored."""
        payload = _pr_webhook_payload(pr_number=9999)
        resp = self._post_webhook(client, payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    @respx.mock
    def test_valid_merge_triggers_vault_call(self, client: TestClient):
        """Valid merged PR with matching session triggers Vault credential issuance.

        Issuance is from the MERGED grant YAML (C2), and mints via the EPHEMERAL
        per-session Vault role (H3).
        """
        session_id = str(uuid.uuid4())
        pr_number = 42

        from jit_approver.models import EscalationRequest

        req = EscalationRequest(**_base_request())
        _insert_session(session_id, pr_number, req)

        _mock_merged_grant(session_id, _grant_yaml(session_id))
        _mock_vault_issue(session_id)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            payload = _pr_webhook_payload(pr_number=pr_number)
            resp = self._post_webhook(client, payload)

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "issued"
        assert data["session_id"] == session_id

        # Session state updated and expiry set
        assert session_store[session_id]["state"] == "issued"
        assert session_store[session_id]["expires_at"] is not None
        # The ephemeral role name was recorded (H3)
        assert session_store[session_id]["vault_role"] == f"jit-{session_id}"

    def _post_webhook(
        self,
        client: TestClient,
        payload: dict[str, Any],
        secret: str = "test-webhook-secret",
        event: str = "pull_request",
        signature: str | None = None,
        delivery: str | None = None,
    ) -> httpx.Response:
        body = json.dumps(payload).encode()
        sig = signature if signature is not None else _sign(body, secret)
        headers = {
            "Content-Type": "application/json",
            "X-Gitea-Event": event,
            "X-Gitea-Signature": sig,
            # Unique delivery id per call by default so unrelated tests do not
            # collide on the C4 dedupe set; pass an explicit id to test replay.
            "X-Gitea-Delivery": delivery if delivery is not None else str(uuid.uuid4()),
        }
        return client.post("/webhooks/gitea", content=body, headers=headers)


# ---------------------------------------------------------------------------
# C2 — issue from the REVIEWED merged artifact, never the in-memory request
# ---------------------------------------------------------------------------


def _post_webhook(
    client: TestClient,
    payload: dict[str, Any],
    secret: str = "test-webhook-secret",
    event: str = "pull_request",
    signature: str | None = None,
    delivery: str | None = None,
) -> httpx.Response:
    body = json.dumps(payload).encode()
    sig = signature if signature is not None else _sign(body, secret)
    headers = {
        "Content-Type": "application/json",
        "X-Gitea-Event": event,
        "X-Gitea-Signature": sig,
        "X-Gitea-Delivery": delivery if delivery is not None else str(uuid.uuid4()),
    }
    return client.post("/webhooks/gitea", content=body, headers=headers)


class TestIssueFromReviewedArtifact:
    @respx.mock
    def test_merged_yaml_edited_narrower_is_honored(self, client: TestClient):
        """Reviewer narrowed the merged YAML (get/list,configmaps -> get,pods).

        Issuance must use the NARROWED merged scope, not the original request.
        """
        session_id = str(uuid.uuid4())
        pr_number = 71
        from jit_approver.models import EscalationRequest

        # Original (broad) request stored in memory.
        original = _base_request()
        original["verbs"] = ["get", "list", "watch"]
        original["resources"] = ["pods", "configmaps", "services"]
        original["duration_minutes"] = 45
        _insert_session(session_id, pr_number, EscalationRequest(**original))

        # Reviewer-narrowed merged YAML: only get on pods, 10 minutes.
        narrowed = _grant_yaml(
            session_id, verbs=["get"], resources=["pods"], duration_minutes=10
        )
        _mock_merged_grant(session_id, narrowed)

        role_create = respx.post(
            "https://vault.apps.anaeem.na-launch.com/v1/kubernetes/roles/jit-"
            + session_id
        ).mock(return_value=httpx.Response(200, json={}))
        _mock_vault_issue(session_id)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = _post_webhook(client, _pr_webhook_payload(pr_number=pr_number))

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "issued"

        # Assert the EPHEMERAL ROLE was created from the NARROWED scope, not the
        # broad in-memory request.
        assert role_create.called
        sent = json.loads(role_create.calls.last.request.content)
        rules = sent["generated_role_rules"]
        assert rules == [{"apiGroups": [""], "verbs": ["get"], "resources": ["pods"]}]
        assert sent["allowed_kubernetes_namespaces"] == ["agent-sandbox"]
        assert sent["token_max_ttl"] == "10m"

    @respx.mock
    def test_in_memory_request_not_used_for_issuance(self, client: TestClient):
        """If the in-memory request and merged YAML disagree, the MERGED one wins.

        We make the in-memory request DANGEROUS (would never validate) by bypassing
        pydantic, then prove issuance still succeeds off the safe merged YAML — i.e.
        session['request'] is never read for issuance.
        """
        session_id = str(uuid.uuid4())
        pr_number = 72

        # A bogus in-memory 'request' object that would explode if touched.
        class _Boom:
            def __getattr__(self, name):  # noqa: ANN001
                raise AssertionError(
                    f"session['request'].{name} read during issuance — C2 violated"
                )

        session_store[session_id] = {
            "id": session_id,
            "state": "pending",
            "pr_url": f"https://git.arsalan.io/anaeem/nvidia-ida/pulls/{pr_number}",
            "pr_number": pr_number,
            "expires_at": None,
            "request": _Boom(),
        }

        _mock_merged_grant(
            session_id, _grant_yaml(session_id, verbs=["get"], resources=["pods"])
        )
        _mock_vault_issue(session_id)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = _post_webhook(client, _pr_webhook_payload(pr_number=pr_number))

        # If session['request'] were touched, _Boom would have raised an
        # AssertionError surfaced as a 500/error. Issuance succeeds from YAML.
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "issued"
        assert session_store[session_id]["state"] == "issued"

    @respx.mock
    def test_merged_yaml_over_ceiling_denied(self, client: TestClient):
        """Reviewer (or attacker) edited the merged YAML to exceed the ceiling.

        Re-validation through the pydantic ceiling must FAIL -> deny + audit,
        and NO Vault mint may occur.
        """
        session_id = str(uuid.uuid4())
        pr_number = 73
        from jit_approver.models import EscalationRequest

        _insert_session(session_id, pr_number, EscalationRequest(**_base_request()))

        # Merged YAML asks for 'delete' (forbidden) and 'secrets' (forbidden).
        bad = _grant_yaml(
            session_id, verbs=["get", "delete"], resources=["secrets"]
        )
        _mock_merged_grant(session_id, bad)

        # Wire Vault mints so we can assert they are NEVER called.
        role_create = respx.post(
            url__regex=r".*/v1/kubernetes/roles/.*"
        ).mock(return_value=httpx.Response(200, json={}))
        creds = respx.post(url__regex=r".*/v1/kubernetes/creds/.*").mock(
            return_value=httpx.Response(200, json={"data": {}})
        )

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"), patch(
            "jit_approver.audit.emit_denied"
        ) as emit_denied:
            resp = _post_webhook(client, _pr_webhook_payload(pr_number=pr_number))

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "denied"
        assert session_store[session_id]["state"] == "denied"
        # No credential was minted.
        assert not role_create.called
        assert not creds.called
        # Denial was audited (H5).
        emit_denied.assert_called_once()
        assert emit_denied.call_args.args[0] == session_id


# ---------------------------------------------------------------------------
# C4 — replay / idempotency / once-only issuance
# ---------------------------------------------------------------------------


class TestReplayProtection:
    @respx.mock
    def test_duplicate_delivery_mints_once(self, client: TestClient):
        """Same X-Gitea-Delivery id redelivered: second call ACKs but no second mint."""
        session_id = str(uuid.uuid4())
        pr_number = 81
        from jit_approver.models import EscalationRequest

        _insert_session(session_id, pr_number, EscalationRequest(**_base_request()))
        _mock_merged_grant(session_id, _grant_yaml(session_id))

        creds = respx.post(
            f"https://vault.apps.anaeem.na-launch.com/v1/kubernetes/creds/jit-{session_id}"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "lease_id": "lease-1",
                    "data": {"service_account_token": "k8s-token-xyz"},
                },
            )
        )
        _mock_vault_issue(session_id)  # login, role, kv (creds already mocked above)

        delivery = "delivery-abc-123"
        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            r1 = _post_webhook(
                client, _pr_webhook_payload(pr_number=pr_number), delivery=delivery
            )
            r2 = _post_webhook(
                client, _pr_webhook_payload(pr_number=pr_number), delivery=delivery
            )

        assert r1.status_code == 200 and r1.json()["status"] == "issued"
        assert r2.status_code == 200 and r2.json()["status"] == "ignored"
        # Credential minted exactly once.
        assert creds.call_count == 1

    @respx.mock
    def test_re_merge_distinct_delivery_mints_once(self, client: TestClient):
        """Re-merge (distinct delivery id) on an already-issued session: no second mint.

        The state-machine guard (not just delivery dedupe) must stop the re-mint.
        """
        session_id = str(uuid.uuid4())
        pr_number = 82
        from jit_approver.models import EscalationRequest

        _insert_session(session_id, pr_number, EscalationRequest(**_base_request()))
        _mock_merged_grant(session_id, _grant_yaml(session_id))
        creds = respx.post(
            f"https://vault.apps.anaeem.na-launch.com/v1/kubernetes/creds/jit-{session_id}"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "lease_id": "lease-1",
                    "data": {"service_account_token": "k8s-token-xyz"},
                },
            )
        )
        _mock_vault_issue(session_id)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            r1 = _post_webhook(
                client, _pr_webhook_payload(pr_number=pr_number), delivery="d1"
            )
            # Distinct delivery id -> passes dedupe, but session is already issued.
            r2 = _post_webhook(
                client, _pr_webhook_payload(pr_number=pr_number), delivery="d2"
            )

        assert r1.json()["status"] == "issued"
        assert r2.status_code == 200
        assert r2.json()["status"] == "ok"  # idempotent no-op
        assert creds.call_count == 1


# ---------------------------------------------------------------------------
# H5 — approval / denial decisions are audited
# ---------------------------------------------------------------------------


class TestAuditDecisionBoundary:
    @respx.mock
    def test_emit_approved_called_on_merge(self, client: TestClient):
        session_id = str(uuid.uuid4())
        pr_number = 91
        from jit_approver.models import EscalationRequest

        _insert_session(session_id, pr_number, EscalationRequest(**_base_request()))
        _mock_merged_grant(session_id, _grant_yaml(session_id))
        _mock_vault_issue(session_id)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"), patch(
            "jit_approver.audit.emit_approved"
        ) as emit_approved, patch("jit_approver.audit.emit_issued") as emit_issued:
            resp = _post_webhook(client, _pr_webhook_payload(pr_number=pr_number))

        assert resp.json()["status"] == "issued"
        emit_approved.assert_called_once()
        # (session_id, merged_by, pr_number)
        assert emit_approved.call_args.args[0] == session_id
        assert emit_approved.call_args.args[1] == "approver-user"
        assert emit_approved.call_args.args[2] == pr_number
        emit_issued.assert_called_once()

    def test_emit_denied_called_on_close_without_merge(self, client: TestClient):
        session_id = str(uuid.uuid4())
        pr_number = 92
        from jit_approver.models import EscalationRequest

        _insert_session(session_id, pr_number, EscalationRequest(**_base_request()))

        with patch("jit_approver.audit.emit_denied") as emit_denied:
            resp = _post_webhook(
                client, _pr_webhook_payload(merged=False, pr_number=pr_number)
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"
        assert session_store[session_id]["state"] == "denied"
        emit_denied.assert_called_once()
        assert emit_denied.call_args.args[0] == session_id

    def test_unmerged_no_session_is_silent(self, client: TestClient):
        """Closed-not-merged for an unknown PR: ignored, no denial audit needed."""
        with patch("jit_approver.audit.emit_denied") as emit_denied:
            resp = _post_webhook(
                client, _pr_webhook_payload(merged=False, pr_number=99999)
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"
        emit_denied.assert_not_called()

    def test_emit_denied_called_on_edge_validation_rejection(self, client: TestClient):
        """POST /requests rejected by the ceiling audits a denial (H5)."""
        req = _base_request()
        req["verbs"] = ["get", "delete"]
        with patch("jit_approver.audit.emit_denied") as emit_denied:
            resp = client.post("/requests", json=req)
        assert resp.status_code == 422
        emit_denied.assert_called_once()


# ---------------------------------------------------------------------------
# Webhook: unmerged / wrong-label are ignored and never mint
# ---------------------------------------------------------------------------


class TestWebhookIgnoreNeverMints:
    @respx.mock
    def test_unmerged_pr_never_fetches_grant_or_mints(self, client: TestClient):
        session_id = str(uuid.uuid4())
        pr_number = 61
        from jit_approver.models import EscalationRequest

        _insert_session(session_id, pr_number, EscalationRequest(**_base_request()))
        grant = respx.get(url__regex=r".*/raw/grants/.*").mock(
            return_value=httpx.Response(200, text="should-not-be-read")
        )
        creds = respx.post(url__regex=r".*/v1/kubernetes/creds/.*").mock(
            return_value=httpx.Response(200, json={"data": {}})
        )
        resp = _post_webhook(
            client, _pr_webhook_payload(merged=False, pr_number=pr_number)
        )
        assert resp.json()["status"] == "ignored"
        assert not grant.called
        assert not creds.called
        assert session_store[session_id]["state"] == "denied"

    @respx.mock
    def test_missing_label_never_mints(self, client: TestClient):
        session_id = str(uuid.uuid4())
        pr_number = 62
        from jit_approver.models import EscalationRequest

        _insert_session(session_id, pr_number, EscalationRequest(**_base_request()))
        creds = respx.post(url__regex=r".*/v1/kubernetes/creds/.*").mock(
            return_value=httpx.Response(200, json={"data": {}})
        )
        resp = _post_webhook(
            client, _pr_webhook_payload(labels=["other-label"], pr_number=pr_number)
        )
        assert resp.json()["status"] == "ignored"
        assert not creds.called
        # Untouched — still pending.
        assert session_store[session_id]["state"] == "pending"


# ---------------------------------------------------------------------------
# Summary endpoint
# ---------------------------------------------------------------------------


class TestSummaryEndpoint:
    def test_unknown_session_404(self, client: TestClient):
        resp = client.post(
            f"/requests/{uuid.uuid4()}/summary",
            json={"outcome": "completed successfully", "actions_taken": [], "errors_encountered": []},
        )
        assert resp.status_code == 404

    @respx.mock
    def test_post_summary_records_and_comments(self, client: TestClient):
        session_id = str(uuid.uuid4())
        from jit_approver.models import EscalationRequest

        req = EscalationRequest(**_base_request())
        session_store[session_id] = {
            "id": session_id,
            "state": "issued",
            "pr_url": "https://git.arsalan.io/anaeem/nvidia-ida/pulls/3",
            "pr_number": 3,
            "expires_at": "2026-06-11T15:00:00+00:00",
            "request": req,
        }

        base_url = "https://git.arsalan.io"
        respx.post(
            f"{base_url}/api/v1/repos/anaeem/nvidia-ida/issues/3/comments"
        ).mock(return_value=httpx.Response(201, json={"id": 1}))

        resp = client.post(
            f"/requests/{session_id}/summary",
            json={
                "outcome": "Successfully retrieved pod list for debugging",
                "actions_taken": ["kubectl get pods -n agent-sandbox"],
                "errors_encountered": [],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "recorded"
        assert data["session_id"] == session_id


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


def test_healthz(client: TestClient):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# N1 — session-JWT signing + /jwks + status credential delivery (UC2)
# ---------------------------------------------------------------------------


class TestSessionJwtAndJwks:
    def test_jwks_returns_valid_jwks(self, client: TestClient):
        """GET /jwks returns a standard JWKS with the RSA public key (kty/use/alg/kid)."""
        resp = client.get("/jwks")
        assert resp.status_code == 200
        doc = resp.json()
        assert "keys" in doc and len(doc["keys"]) == 1
        key = doc["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert key["kid"] == "jit-approver-key-1"
        # n/e present (base64url) so the public key is usable for verification.
        assert key["n"] and key["e"]

    def test_minted_jwt_verifies_against_jwks_with_contract_claims(self, client: TestClient):
        """A minted session JWT VERIFIES against /jwks with the contract claims.

        iss/aud match the policy contract, tool_scope contains the dangerous tool,
        exp == iat + duration. We verify with PyJWT using the public JWKS key —
        i.e. exactly what the Kyverno gate does.
        """
        import time

        import jwt as pyjwt

        from jit_approver import signing

        # Near-now issued_at so exp is in the future (the gate validates exp).
        issued_at = int(time.time())
        token = signing.mint_session_jwt(
            session_id="sess-123",
            tool_scope=["add_firewall_rule", "create_firewall_rule_advanced"],
            issued_at=issued_at,
            duration_minutes=15,
            requester_sub="user@example.com",
        )

        # Build the verification key from the served JWKS (what the gate fetches).
        jwks_doc = client.get("/jwks").json()
        verify_key = pyjwt.PyJWK.from_dict(jwks_doc["keys"][0]).key

        claims = pyjwt.decode(
            token,
            verify_key,
            algorithms=["RS256"],
            audience=signing.JIT_SESSION_AUD,
            issuer=signing.JIT_SESSION_ISS,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
        assert claims["iss"] == "https://jit-approver.mcp-gateway.svc.cluster.local:8080"
        assert claims["aud"] == "kyverno-authz"
        assert claims["sub"] == "sess-123"
        assert claims["tool_scope"] == [
            "add_firewall_rule",
            "create_firewall_rule_advanced",
        ]
        assert claims["iat"] == issued_at
        assert claims["exp"] == issued_at + 15 * 60

    def test_minted_jwt_iss_matches_policy_constant(self):
        """signing.JIT_SESSION_ISS must equal the iss string the Kyverno policy asserts."""
        import re
        from pathlib import Path

        from jit_approver import signing

        # tests/test_api.py -> parents: [tests, jit-approver, services, <repo root>]
        policy = Path(
            __file__
        ).resolve().parents[3] / "platform/kyverno/authz/base/dangerous-tools-admins-only.yaml"
        text = policy.read_text()
        # The hasValidJitSession variable asserts Claims["iss"] == "<const>".
        m = re.search(
            r'Claims\["iss"\]\s*==\s*"([^"]+)"', text
        )
        assert m is not None, "policy must assert an iss constant"
        assert m.group(1) == signing.JIT_SESSION_ISS

    def test_bad_signature_jwt_does_not_verify(self, client: TestClient):
        """A token signed by a DIFFERENT key fails verification against /jwks (fail closed)."""
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import rsa

        from jit_approver import signing

        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = pyjwt.encode(
            {
                "iss": signing.JIT_SESSION_ISS,
                "aud": signing.JIT_SESSION_AUD,
                "tool_scope": ["add_firewall_rule"],
                "exp": 9_999_999_999,
                "iat": 1_700_000_000,
            },
            rogue,
            algorithm="RS256",
            headers={"kid": "jit-approver-key-1"},
        )
        verify_key = pyjwt.PyJWK.from_dict(client.get("/jwks").json()["keys"][0]).key
        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(
                forged,
                verify_key,
                algorithms=["RS256"],
                audience=signing.JIT_SESSION_AUD,
                issuer=signing.JIT_SESSION_ISS,
            )

    def test_tool_scope_for_maps_create_firewall(self):
        """A grant that approves create on a firewall/networkpolicy resource maps to
        the dangerous firewall tool names; read-only or unrelated grants do not."""
        from jit_approver import signing
        from jit_approver.models import EscalationRequest

        approve = EscalationRequest(
            agent_spiffe_id="spiffe://x/ns/agent-sandbox/sa/a",
            requester_sub="u@example.com",
            namespace="agent-sandbox",
            verbs=["create", "update"],
            resources=["networkpolicies"],
            duration_minutes=10,
            justification="open a firewall rule for incident INC-1",
        )
        scope = signing.tool_scope_for(approve)
        assert "add_firewall_rule" in scope
        assert "create_firewall_rule_advanced" in scope

        # Read-only grant -> empty tool_scope (the dangerous gate would deny — correct).
        readonly = EscalationRequest(
            agent_spiffe_id="spiffe://x/ns/agent-sandbox/sa/a",
            requester_sub="u@example.com",
            namespace="agent-sandbox",
            verbs=["get", "list"],
            resources=["networkpolicies"],
            duration_minutes=10,
            justification="inspect network policies for incident INC-1",
        )
        assert signing.tool_scope_for(readonly) == []

    @respx.mock
    def test_issued_status_returns_session_jwt_and_sa_token(self, client: TestClient):
        """After a merge that approves a dangerous (create/networkpolicies) grant,
        GET /status (state==issued) returns a session JWT that VERIFIES against
        /jwks with the right iss/aud/tool_scope/exp, plus the ephemeral SA token."""
        import jwt as pyjwt

        from jit_approver import signing
        from jit_approver.models import EscalationRequest

        session_id = str(uuid.uuid4())
        pr_number = 55

        req = EscalationRequest(
            agent_spiffe_id="spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/test-agent",
            requester_sub="user@example.com",
            namespace="agent-sandbox",
            verbs=["create"],
            resources=["networkpolicies"],
            duration_minutes=20,
            justification="open firewall rule for incident INC-9999",
        )
        _insert_session(session_id, pr_number, req)
        _mock_merged_grant(
            session_id,
            _grant_yaml(
                session_id, verbs=["create"], resources=["networkpolicies"], duration_minutes=20
            ),
        )
        _mock_vault_issue(session_id)

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            resp = _post_webhook(client, _pr_webhook_payload(pr_number=pr_number))
        assert resp.status_code == 200 and resp.json()["status"] == "issued"

        status = client.get(f"/requests/{session_id}/status")
        assert status.status_code == 200
        data = status.json()
        assert data["state"] == "issued"
        assert data["sa_token"] == "k8s-token-xyz"
        assert data["sa_token_path"] == f"secret/data/jit/{session_id}"
        assert "add_firewall_rule" in data["tool_scope"]

        # The returned session JWT verifies against /jwks with the contract claims.
        verify_key = pyjwt.PyJWK.from_dict(client.get("/jwks").json()["keys"][0]).key
        claims = pyjwt.decode(
            data["session_jwt"],
            verify_key,
            algorithms=["RS256"],
            audience=signing.JIT_SESSION_AUD,
            issuer=signing.JIT_SESSION_ISS,
        )
        assert claims["sub"] == session_id
        assert "add_firewall_rule" in claims["tool_scope"]
        assert claims["exp"] == claims["iat"] + 20 * 60

    def test_credentials_not_returned_before_issued(self, client: TestClient):
        """Pending/approved sessions never expose session_jwt or sa_token (fail closed)."""
        session_id = str(uuid.uuid4())
        # Even if (defensively) the fields are present in the store, a non-issued
        # state must NOT return them.
        session_store[session_id] = {
            "id": session_id,
            "state": "approved",
            "pr_url": "https://git.arsalan.io/anaeem/nvidia-ida/pulls/5",
            "pr_number": 5,
            "expires_at": None,
            "request": None,
            "session_jwt": "leaked.jwt.value",
            "sa_token": "leaked-sa-token",
            "sa_token_path": "secret/data/jit/x",
            "tool_scope": ["add_firewall_rule"],
        }
        data = client.get(f"/requests/{session_id}/status").json()
        assert data["state"] == "approved"
        assert data["session_jwt"] is None
        assert data["sa_token"] is None
        assert data["sa_token_path"] is None
        assert data["tool_scope"] is None


# ---------------------------------------------------------------------------
# N4 — per-resource apiGroups in generated_role_rules
# ---------------------------------------------------------------------------


class TestApiGroupMapping:
    def test_core_apps_batch_grouped_into_blocks(self):
        """Resources are grouped by apiGroup into separate rule blocks (deterministic
        order): core "" then apps then batch."""
        from jit_approver.models import EscalationRequest
        from jit_approver.vault import _generated_role_rules

        req = EscalationRequest(
            agent_spiffe_id="spiffe://x/ns/agent-sandbox/sa/a",
            requester_sub="u@example.com",
            namespace="agent-sandbox",
            verbs=["get", "list"],
            resources=["pods", "deployments", "jobs", "configmaps", "cronjobs"],
            duration_minutes=10,
            justification="inspect workloads for incident INC-1234",
        )
        rules = _generated_role_rules(req)
        # sorted apiGroup order: "" < "apps" < "batch"
        assert rules == [
            {"apiGroups": [""], "verbs": ["get", "list"], "resources": ["pods", "configmaps"]},
            {"apiGroups": ["apps"], "verbs": ["get", "list"], "resources": ["deployments"]},
            {"apiGroups": ["batch"], "verbs": ["get", "list"], "resources": ["jobs", "cronjobs"]},
        ]

    def test_networking_and_route_groups(self):
        from jit_approver.models import EscalationRequest
        from jit_approver.vault import _generated_role_rules

        req = EscalationRequest(
            agent_spiffe_id="spiffe://x/ns/agent-sandbox/sa/a",
            requester_sub="u@example.com",
            namespace="agent-sandbox",
            verbs=["create"],
            resources=["networkpolicies", "ingresses", "routes"],
            duration_minutes=10,
            justification="open ingress/firewall for incident INC-1",
        )
        rules = _generated_role_rules(req)
        groups = {r["apiGroups"][0]: r["resources"] for r in rules}
        assert groups["networking.k8s.io"] == ["networkpolicies", "ingresses"]
        assert groups["route.openshift.io"] == ["routes"]

    def test_unknown_resource_defaults_core_with_warning(self, caplog):
        import logging

        from jit_approver.models import EscalationRequest
        from jit_approver.vault import _generated_role_rules

        req = EscalationRequest(
            agent_spiffe_id="spiffe://x/ns/agent-sandbox/sa/a",
            requester_sub="u@example.com",
            namespace="agent-sandbox",
            verbs=["get"],
            resources=["widgets"],  # unknown -> core "" + warning
            duration_minutes=10,
            justification="inspect custom resource for incident INC-1",
        )
        with caplog.at_level(logging.WARNING, logger="jit_approver.vault"):
            rules = _generated_role_rules(req)
        assert rules == [{"apiGroups": [""], "verbs": ["get"], "resources": ["widgets"]}]
        assert any("unknown_resource_apigroup" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# N3 — reaper: delete expired ephemeral Vault role + KV; survive not-yet-expired
# ---------------------------------------------------------------------------


class TestReaper:
    @respx.mock
    async def test_reap_once_deletes_expired_role_and_kv(self):
        """reap_once deletes kubernetes/roles/jit-<id> + secret/metadata/jit/<id>
        for an EXPIRED issued session and flips it to expired."""
        from datetime import datetime, timedelta, timezone

        from jit_approver.reaper import reap_once

        vault_addr = "https://vault.apps.anaeem.na-launch.com"
        sid = str(uuid.uuid4())
        role = f"jit-{sid}"
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        session_store[sid] = {
            "id": sid,
            "state": "issued",
            "pr_url": None,
            "pr_number": 1,
            "expires_at": past,
            "request": None,
            "vault_role": role,
        }

        respx.post(f"{vault_addr}/v1/auth/jwt/login").mock(
            return_value=httpx.Response(
                200, json={"auth": {"client_token": "vt", "policies": ["jit-approver"]}}
            )
        )
        role_del = respx.delete(f"{vault_addr}/v1/kubernetes/roles/{role}").mock(
            return_value=httpx.Response(204)
        )
        kv_del = respx.delete(f"{vault_addr}/v1/secret/metadata/jit/{sid}").mock(
            return_value=httpx.Response(204)
        )

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            reaped = await reap_once(now=datetime.now(timezone.utc))

        assert reaped == [sid]
        assert role_del.called
        assert kv_del.called
        assert session_store[sid]["state"] == "expired"

    @respx.mock
    async def test_reap_once_skips_not_yet_expired(self):
        """A session whose expiry is in the FUTURE survives the sweep untouched."""
        from datetime import datetime, timedelta, timezone

        from jit_approver.reaper import reap_once

        vault_addr = "https://vault.apps.anaeem.na-launch.com"
        sid = str(uuid.uuid4())
        role = f"jit-{sid}"
        future = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        session_store[sid] = {
            "id": sid,
            "state": "issued",
            "pr_url": None,
            "pr_number": 2,
            "expires_at": future,
            "request": None,
            "vault_role": role,
        }
        # Wire deletes so we can assert they are NEVER called.
        role_del = respx.delete(f"{vault_addr}/v1/kubernetes/roles/{role}").mock(
            return_value=httpx.Response(204)
        )
        kv_del = respx.delete(f"{vault_addr}/v1/secret/metadata/jit/{sid}").mock(
            return_value=httpx.Response(204)
        )

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            reaped = await reap_once(now=datetime.now(timezone.utc))

        assert reaped == []
        assert not role_del.called
        assert not kv_del.called
        assert session_store[sid]["state"] == "issued"

    @respx.mock
    async def test_reap_once_mixed_only_expired_reaped(self):
        """With one expired and one future session, only the expired one is reaped."""
        from datetime import datetime, timedelta, timezone

        from jit_approver.reaper import reap_once

        vault_addr = "https://vault.apps.anaeem.na-launch.com"
        now = datetime.now(timezone.utc)
        expired_id = str(uuid.uuid4())
        future_id = str(uuid.uuid4())
        session_store[expired_id] = {
            "id": expired_id,
            "state": "issued",
            "pr_number": 3,
            "expires_at": (now - timedelta(minutes=1)).isoformat(),
            "vault_role": f"jit-{expired_id}",
        }
        session_store[future_id] = {
            "id": future_id,
            "state": "issued",
            "pr_number": 4,
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
            "vault_role": f"jit-{future_id}",
        }
        respx.post(f"{vault_addr}/v1/auth/jwt/login").mock(
            return_value=httpx.Response(
                200, json={"auth": {"client_token": "vt", "policies": ["jit-approver"]}}
            )
        )
        respx.delete(url__regex=r".*/v1/kubernetes/roles/.*").mock(
            return_value=httpx.Response(204)
        )
        respx.delete(url__regex=r".*/v1/secret/metadata/jit/.*").mock(
            return_value=httpx.Response(204)
        )

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            reaped = await reap_once(now=now)

        assert reaped == [expired_id]
        assert session_store[expired_id]["state"] == "expired"
        assert session_store[future_id]["state"] == "issued"

    @respx.mock
    async def test_reap_once_delete_failure_leaves_session_unexpired(self):
        """If the Vault delete errors, the session is NOT marked expired (retry next sweep)."""
        from datetime import datetime, timedelta, timezone

        from jit_approver.reaper import reap_once

        vault_addr = "https://vault.apps.anaeem.na-launch.com"
        sid = str(uuid.uuid4())
        role = f"jit-{sid}"
        session_store[sid] = {
            "id": sid,
            "state": "issued",
            "pr_number": 5,
            "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "vault_role": role,
        }
        respx.post(f"{vault_addr}/v1/auth/jwt/login").mock(
            return_value=httpx.Response(
                200, json={"auth": {"client_token": "vt", "policies": ["jit-approver"]}}
            )
        )
        # Role delete returns a hard error (500) -> raises -> session not expired.
        respx.delete(f"{vault_addr}/v1/kubernetes/roles/{role}").mock(
            return_value=httpx.Response(500, json={"errors": ["boom"]})
        )

        with patch("jit_approver.vault._svid_jwt", return_value="fake.svid.jwt"):
            reaped = await reap_once(now=datetime.now(timezone.utc))

        assert reaped == []
        assert session_store[sid]["state"] == "issued"
