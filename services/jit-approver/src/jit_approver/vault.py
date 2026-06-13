"""Vault integration for JIT credential issuance.

Authentication (PoC simplicity):
  JWT SVID is read from the file path in env SVID_JWT_PATH (written by SPIFFE
  workload API helper or Vault Agent) and POSTed to Vault's JWT auth endpoint.
  The README documents the production path using py-spiffe + workload socket.

Issuance flow (C2 + H3):
  The caller passes the REVIEWED grant (an EscalationRequest rebuilt from the
  merged grants/<session-id>.yaml and re-validated through the ceiling) — this
  function NEVER reads session['request']. Issuance is from the reviewed scope.

  1. Login: POST /v1/auth/jwt/login  {role="jit-approver", jwt=<svid>}
  2. Create ephemeral role: POST /v1/kubernetes/roles/jit-<session> with
     generated_role_rules built from the approved verbs/resources,
     allowed_kubernetes_namespaces=[approved ns], token_ttl/token_max_ttl=window.
     This makes the reviewed scope the ENFORCED scope — the static jit-scoped
     role could not enforce per-request rules (H3).
  3. Issue: POST /v1/kubernetes/creds/jit-<session> {kubernetes_namespace, ttl}
  4. Store: PUT /v1/secret/data/jit/<session-id> — agent reads this via injector.
  5. Update session state -> issued, expires_at set (done by the webhook caller
     under the once-only lock).

Cleanup (N3): the ephemeral role kubernetes/roles/jit-<session> AND the KV record
secret/data/jit/<session> are deleted when expiry passes by the reaper task
(reaper.py), in addition to the lease expiring. A leaked ephemeral role is a
latent standing-scope hole, so the reaper exercises the delete capability the
jit-approver Vault policy already grants on kubernetes/roles/jit-*.

Credential delivery (UC2): the KV record is the durable tracking/audit copy. The
agent receives the ephemeral SA token AND the session JWT by polling
GET /requests/{id}/status over the authenticated SVID-mTLS channel once
state==issued — they are never returned before issuance. This supersedes the
original "Vault injector at pod start" delivery (impossible for a dynamically
created session: chicken-and-egg). The agent legitimately wields the SA token to
act (that IS UC2) and presents the session JWT to clear the Kyverno gate. The
session JWT is the agent's OWN scoped/short-lived capability, not a downstream
service credential, so no-downstream-credential-passing (UC1) is not violated.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from jit_approver.store import session_store

logger = logging.getLogger("jit_approver.vault")

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

_SVID_JWT_FILE = "/var/run/secrets/svid.jwt"


def _vault_addr() -> str:
    return os.environ.get("VAULT_ADDR", "https://vault.apps.anaeem.na-launch.com")


def _vault_jwt_role() -> str:
    return os.environ.get("VAULT_JWT_ROLE", "jit-approver")


def _vault_jwt_auth_path() -> str:
    return os.environ.get("VAULT_JWT_AUTH_PATH", "jwt")


def _svid_jwt() -> str:
    """Read SVID JWT from file (written by SPIFFE workload API or Vault Agent)."""
    path = os.environ.get("SVID_JWT_PATH", _SVID_JWT_FILE)
    try:
        with open(path) as fh:
            return fh.read().strip()
    except FileNotFoundError:
        raise RuntimeError(
            f"SVID JWT file not found at {path}. "
            "Ensure SPIFFE workload API is available and SVID_JWT_PATH is set. "
            "In production, use py-spiffe to fetch the JWT SVID via the workload socket."
        )


# ---------------------------------------------------------------------------
# Vault auth
# ---------------------------------------------------------------------------


async def _vault_login(client: httpx.AsyncClient) -> str:
    """Login to Vault using SVID JWT and return a Vault token."""
    addr = _vault_addr()
    role = _vault_jwt_role()
    auth_path = _vault_jwt_auth_path()

    jwt = _svid_jwt()
    resp = await client.post(
        f"{addr}/v1/auth/{auth_path}/login",
        json={"role": role, "jwt": jwt},
    )
    resp.raise_for_status()
    data = resp.json()
    token: str = data["auth"]["client_token"]
    logger.info(
        "vault_login_ok",
        extra={
            "role": role,
            "lease_duration": data["auth"].get("lease_duration"),
            "policies": data["auth"].get("policies"),
        },
    )
    return token


# ---------------------------------------------------------------------------
# Credential issuance
# ---------------------------------------------------------------------------


async def issue_credentials(
    session_id: str,
    req: Any,
    http: httpx.AsyncClient | None = None,
) -> None:
    """Issue short-lived Kubernetes credentials from the REVIEWED scope.

    Parameters
    ----------
    session_id:
        The JIT session UUID (also the KV path and ephemeral-role suffix).
    req:
        The EscalationRequest rebuilt from the merged grants/<session>.yaml and
        already re-validated through the ceiling by the caller (webhook). This
        function does NOT read session['request'] — issuance is strictly from
        the reviewed artifact (C2).

    On success:
      - Vault role kubernetes/roles/jit-<session> is created with the approved
        verbs/resources/namespace/TTL (H3 — reviewed scope == enforced scope).
      - Vault KV path secret/data/jit/<session-id> is written with the token.
      - session expires_at is set (state flip to 'issued' is done by the caller
        atomically before issuance under the once-only lock — C4).
      - the ephemeral SA token and the minted session JWT (N1) are stashed on the
        session so GET /requests/{id}/status can return BOTH once state==issued.

    Credential delivery (UC2 — supersedes the original "Vault injector at pod
    start" idea, which is impossible for a dynamically-created session: the pod
    would need the token before the session exists, a chicken-and-egg). Instead,
    the agent polls GET /requests/{id}/status over the authenticated SVID-mTLS
    channel; once issued, that response carries BOTH the ephemeral SA token (which
    the agent legitimately wields to act — that IS UC2) and the session JWT (which
    the agent presents as X-JIT-Session-JWT to clear the Kyverno dangerous-tool
    gate). The session JWT is the agent's OWN scoped, signed, short-lived
    capability — NOT a downstream service credential — so this does not violate the
    no-downstream-credential-passing invariant (which targets UC1 ext-proc creds).

    The SA token / session JWT are kept in-memory keyed by session and are NEVER
    returned before state==issued (the status endpoint enforces that).
    """
    session = session_store.get(session_id)
    if session is None:
        raise ValueError(f"Session {session_id} not found")

    role_name = f"jit-{session_id}"

    async def _run(client: httpx.AsyncClient) -> None:
        # 1. Login
        vault_token = await _vault_login(client)
        addr = _vault_addr()
        headers = {"X-Vault-Token": vault_token, "Content-Type": "application/json"}
        ttl = f"{req.duration_minutes}m"

        # 2. Create an EPHEMERAL per-session Vault kubernetes role (H3).
        #    The static jit-scoped role cannot enforce per-request rules, so we
        #    mint a role whose generated_role_rules ARE the approved scope and
        #    whose allowed_kubernetes_namespaces is exactly the approved ns.
        #    The matching Vault POLICY capability for kubernetes/roles/jit-* is
        #    provided by the vault-config fixer (assume it exists).
        role_resp = await client.post(
            f"{addr}/v1/kubernetes/roles/{role_name}",
            headers=headers,
            json={
                "allowed_kubernetes_namespaces": [req.namespace],
                "kubernetes_role_type": "Role",
                "token_default_ttl": ttl,
                "token_max_ttl": ttl,
                # Vault's kubernetes engine wants generated_role_rules as a JSON
                # STRING wrapped in {"rules": [...]} — not a raw array (that 400s).
                "generated_role_rules": json.dumps(
                    {"rules": _generated_role_rules(req)}
                ),
            },
        )
        role_resp.raise_for_status()

        # 3. Issue Kubernetes credentials FROM the ephemeral role.
        #    POST /v1/kubernetes/creds/<role> — the role (created above) is what
        #    enforces verbs/resources/namespace/TTL. No role_rules override here;
        #    that field is silently ignored by the creds endpoint (the old bug).
        k8s_resp = await client.post(
            f"{addr}/v1/kubernetes/creds/{role_name}",
            headers=headers,
            json={
                "kubernetes_namespace": req.namespace,
                "ttl": ttl,
            },
        )
        k8s_resp.raise_for_status()
        k8s_data = k8s_resp.json()
        service_account_token: str = k8s_data["data"]["service_account_token"]
        lease_id: str = k8s_data.get("lease_id", "")

        # Compute expiry timestamp
        expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=req.duration_minutes)
        ).isoformat()

        # 4. Store token in Vault KV — agent reads this, approver never returns it
        kv_path = f"{addr}/v1/secret/data/jit/{session_id}"
        kv_resp = await client.post(
            kv_path,
            headers=headers,
            json={
                "data": {
                    "token": service_account_token,
                    "namespace": req.namespace,
                    "session_id": session_id,
                    "expires_at": expires_at,
                    "lease_id": lease_id,
                    "vault_role": role_name,
                    # Audit: hash the token so the KV entry itself is auditable
                    # without exposing the raw credential in logs
                    "token_sha256": hashlib.sha256(
                        service_account_token.encode()
                    ).hexdigest(),
                },
                # No cas guard: the once-only issuance is enforced by the webhook
                # state-machine lock (C4), not by KV cas. A cas failure here would
                # otherwise mint a credential whose tracking record is never
                # written — an untracked, un-revocable lease.
            },
        )
        kv_resp.raise_for_status()

        # 5. Mint the session-capability JWT (N1 / UC2). tool_scope is derived
        #    from the approved (reviewed) verbs/resources. iat/exp == the approved
        #    window. Signed RS256 by the jit-approver key; verified by the Kyverno
        #    gate against /jwks.
        from jit_approver import signing

        issued_at = int(datetime.now(timezone.utc).timestamp())
        tool_scope = signing.tool_scope_for(req)
        session_jwt = signing.mint_session_jwt(
            session_id=session_id,
            tool_scope=tool_scope,
            issued_at=issued_at,
            duration_minutes=req.duration_minutes,
            requester_sub=getattr(req, "requester_sub", ""),
        )

        # 6. Record expiry + the credentials to be handed back ONLY via the
        #    status endpoint once state==issued (state flip is the caller's job,
        #    done atomically before this call under the once-only lock).
        session_store[session_id]["expires_at"] = expires_at
        session_store[session_id]["vault_role"] = role_name
        session_store[session_id]["sa_token"] = service_account_token
        session_store[session_id]["sa_token_path"] = f"secret/data/jit/{session_id}"
        session_store[session_id]["session_jwt"] = session_jwt
        session_store[session_id]["tool_scope"] = tool_scope

        logger.info(
            "vault_issue_ok",
            extra={
                "session_id": session_id,
                "namespace": req.namespace,
                "duration_minutes": req.duration_minutes,
                "expires_at": expires_at,
                "vault_role": role_name,
                "tool_scope": tool_scope,
                # SA token and session JWT deliberately NOT logged. The canonical
                # jit_issued audit event is emitted by the webhook via emit_issued.
            },
        )

    if http is not None:
        await _run(http)
    else:
        # Vault's public route is served by the OpenShift router's wildcard cert,
        # which jit-approver's trust store does not include. VAULT_SKIP_VERIFY=true
        # (PoC) or VAULT_CACERT=<path> selects how the channel is trusted; the SVID
        # login is the security boundary, not the channel cert. Matches ext-proc.
        verify: bool | str = True
        if os.environ.get("VAULT_SKIP_VERIFY", "").lower() == "true":
            verify = False
        elif os.environ.get("VAULT_CACERT"):
            verify = os.environ["VAULT_CACERT"]
        async with httpx.AsyncClient(timeout=30.0, verify=verify) as client:
            await _run(client)


# N4: map each approved resource to its Kubernetes apiGroup so generated_role_rules
# grant the resource in the right group (a single hardcoded core "" group silently
# failed to grant apps/batch/networking/... resources). Plural and common singular
# forms are both mapped. Unknown resources default to the core group "" with a
# logged warning (fail-closed narrowing — issued ⊆ advertised still holds).
_RESOURCE_API_GROUP: dict[str, str] = {
    # core ("")
    "pods": "",
    "pod": "",
    "services": "",
    "service": "",
    "configmaps": "",
    "configmap": "",
    "secrets": "",  # ceiling-blocked upstream, kept here for completeness
    "secret": "",
    "endpoints": "",
    "events": "",
    "namespaces": "",
    "persistentvolumeclaims": "",
    "serviceaccounts": "",
    "replicationcontrollers": "",
    # apps
    "deployments": "apps",
    "deployment": "apps",
    "replicasets": "apps",
    "replicaset": "apps",
    "daemonsets": "apps",
    "daemonset": "apps",
    "statefulsets": "apps",
    "statefulset": "apps",
    # batch
    "jobs": "batch",
    "job": "batch",
    "cronjobs": "batch",
    "cronjob": "batch",
    # networking.k8s.io
    "ingresses": "networking.k8s.io",
    "ingress": "networking.k8s.io",
    "networkpolicies": "networking.k8s.io",
    "networkpolicy": "networking.k8s.io",
    # rbac.authorization.k8s.io (ceiling-blocked upstream, mapped for completeness)
    "roles": "rbac.authorization.k8s.io",
    "role": "rbac.authorization.k8s.io",
    "rolebindings": "rbac.authorization.k8s.io",
    "rolebinding": "rbac.authorization.k8s.io",
    # route.openshift.io
    "routes": "route.openshift.io",
    "route": "route.openshift.io",
}


def _api_group_for(resource: str) -> str:
    rl = resource.lower().strip()
    group = _RESOURCE_API_GROUP.get(rl)
    if group is None:
        logger.warning(
            "unknown_resource_apigroup_defaulting_core",
            extra={"resource": resource},
        )
        return ""
    return group


def _generated_role_rules(req: Any) -> list[dict[str, Any]]:
    """Build Kubernetes RBAC policy rules (for generated_role_rules) from the
    approved scope (N4). Vault's kubernetes engine uses these to generate a Role +
    RoleBinding in the target namespace bound to the ephemeral SA.

    Each approved resource is mapped to its apiGroup and resources are grouped by
    apiGroup into separate rule blocks (a Role rule's apiGroups/resources must be
    consistent). All approved verbs apply to every rule block. Rule blocks are
    emitted in a deterministic apiGroup order so the output is stable/testable.
    """
    by_group: dict[str, list[str]] = {}
    for resource in req.resources:
        group = _api_group_for(resource)
        bucket = by_group.setdefault(group, [])
        if resource not in bucket:
            bucket.append(resource)

    rules: list[dict[str, Any]] = []
    for group in sorted(by_group):
        rules.append(
            {
                "apiGroups": [group],
                "verbs": list(req.verbs),
                "resources": by_group[group],
            }
        )
    return rules


# ---------------------------------------------------------------------------
# Ephemeral-resource teardown (used by the reaper — N3)
# ---------------------------------------------------------------------------


async def delete_ephemeral_role(
    client: httpx.AsyncClient, addr: str, vault_token: str, role_name: str
) -> None:
    """DELETE kubernetes/roles/<role_name>. Idempotent (404 tolerated)."""
    headers = {"X-Vault-Token": vault_token}
    resp = await client.delete(
        f"{addr}/v1/kubernetes/roles/{role_name}", headers=headers
    )
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()


async def delete_kv_record(
    client: httpx.AsyncClient, addr: str, vault_token: str, session_id: str
) -> None:
    """Delete the KV v2 tracking record for a session. Idempotent (404 tolerated).

    Uses the KV v2 metadata path so all versions are destroyed in one call.
    """
    headers = {"X-Vault-Token": vault_token}
    resp = await client.delete(
        f"{addr}/v1/secret/metadata/jit/{session_id}", headers=headers
    )
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()
