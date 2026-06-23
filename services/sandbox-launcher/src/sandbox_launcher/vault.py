"""Vault client — sandbox-launcher grant writer.

Writes a CONSENT GRANT (not a credential) to Vault KV-v2 at:
  secret/data/sandbox-grants/<sandbox-uid>

This is Option-D of the zero-trust agentic PoC design.  The grant document
records WHO authorised WHAT scope for WHICH sandbox.  It is NOT a credential:
no token, bearer, password, or secret field is ever written here.

Authentication strategy
-----------------------
The launcher uses its OWN Kubernetes service-account token (projected at
/var/run/secrets/kubernetes.io/serviceaccount/token) to authenticate against
Vault's kubernetes auth backend.  This is the same SA token the Vault Agent
Injector uses and matches the existing `sandbox-launcher` Vault k8s auth role.

A lightweight SVID-via-tmpfs path (SVID_JWT_PATH -> Vault JWT auth) is also
supported for parity with jit-approver; it is selected when VAULT_JWT_AUTH_PATH
is set.  See _vault_login().

Vault policy requirements
-------------------------
The sandbox-launcher Vault policy MUST be extended to:

  path "secret/data/sandbox-grants/*" {
    capabilities = ["create", "update"]
  }

The ext-proc-delegation Vault policy MUST be extended to:

  path "secret/data/sandbox-grants/*" {
    capabilities = ["read"]
  }

No-credential-passing invariant
--------------------------------
The grant document fields are validated before write to ensure no prohibited
field names are present (access_token, bearer, password, client_secret, svid,
private_key, api_key).  Any violation raises ValueError and the grant is NOT
written (fail-closed).

Environment variables
---------------------
VAULT_ADDR              — Vault address (default: https://vault.apps.ocp-dev.na-launch.com)
VAULT_SKIP_VERIFY       — "true" to skip TLS verification (PoC/dev only)
VAULT_CACERT            — path to CA bundle for Vault TLS
VAULT_K8S_AUTH_PATH     — Vault kubernetes auth mount (default: kubernetes)
VAULT_K8S_AUTH_ROLE     — Vault role for k8s auth (default: sandbox-launcher)
VAULT_JWT_AUTH_PATH     — Vault JWT auth mount; if set, SVID-JWT path is used instead
VAULT_JWT_ROLE          — Vault role for JWT auth (default: sandbox-launcher)
SVID_JWT_PATH           — path to SVID JWT file (default: /var/run/secrets/svid.jwt)
VAULT_GRANT_TTL_SECONDS — default grant TTL seconds when caller does not specify (default: 3600)
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger("sandbox_launcher.vault")

# ---------------------------------------------------------------------------
# Prohibited field names — reviewer gate; no-credential-passing invariant.
# ---------------------------------------------------------------------------

_PROHIBITED_GRANT_FIELDS: frozenset[str] = frozenset({
    "access_token",
    "bearer",
    "password",
    "client_secret",
    "svid",
    "private_key",
    "api_key",
})

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _vault_addr() -> str:
    return os.environ.get("VAULT_ADDR", "https://vault.apps.ocp-dev.na-launch.com").rstrip("/")


def _http_client() -> httpx.Client:
    """Build an httpx.Client that respects VAULT_SKIP_VERIFY / VAULT_CACERT."""
    skip = os.environ.get("VAULT_SKIP_VERIFY", "").lower() == "true"
    if skip:
        verify: bool | str = False
    else:
        ca = os.environ.get("VAULT_CACERT", "").strip()
        verify = ca if ca and os.path.exists(ca) else True
    return httpx.Client(timeout=15.0, verify=verify)


# ---------------------------------------------------------------------------
# Vault authentication
# ---------------------------------------------------------------------------


def _vault_login(http: httpx.Client) -> str:
    """Authenticate to Vault and return a client token.

    Prefers JWT auth (VAULT_JWT_AUTH_PATH set) so the SVID-JWT is used as a
    SPIFFE workload identity, matching jit-approver's pattern.  Falls back to
    Kubernetes service-account token auth (VAULT_K8S_AUTH_PATH), which is what
    the Vault Agent Injector already uses for this pod.

    The returned token is short-lived (TTL driven by the Vault role) and is
    NEVER cached across requests — each grant write mints a fresh login.  This
    keeps the attack surface minimal: a compromised token expires within the
    role TTL.
    """
    addr = _vault_addr()

    jwt_auth_path = os.environ.get("VAULT_JWT_AUTH_PATH", "").strip()
    if jwt_auth_path:
        return _login_jwt(http, addr, jwt_auth_path)
    return _login_k8s(http, addr)


def _login_jwt(http: httpx.Client, addr: str, auth_path: str) -> str:
    """Login via Vault JWT auth using a SPIFFE SVID JWT from disk."""
    svid_path = os.environ.get("SVID_JWT_PATH", "/var/run/secrets/svid.jwt").strip()
    try:
        with open(svid_path) as fh:
            svid_jwt = fh.read().strip()
    except OSError as exc:
        raise RuntimeError(
            f"SVID JWT file not found at {svid_path}: {exc}. "
            "Ensure SPIFFE workload API helper writes the JWT SVID and SVID_JWT_PATH is set."
        ) from exc

    role = os.environ.get("VAULT_JWT_ROLE", "sandbox-launcher").strip()
    resp = http.post(
        f"{addr}/v1/auth/{auth_path}/login",
        json={"role": role, "jwt": svid_jwt},
    )
    resp.raise_for_status()
    token: str = resp.json()["auth"]["client_token"]
    logger.info(
        "vault_login_ok",
        extra={"method": "jwt", "role": role, "auth_path": auth_path},
    )
    return token


def _login_k8s(http: httpx.Client, addr: str) -> str:
    """Login via Vault Kubernetes auth using the in-cluster SA token."""
    sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    try:
        with open(sa_token_path) as fh:
            sa_token = fh.read().strip()
    except OSError as exc:
        raise RuntimeError(
            f"Kubernetes SA token not found at {sa_token_path}: {exc}. "
            "Ensure automountServiceAccountToken=true on the pod."
        ) from exc

    auth_path = os.environ.get("VAULT_K8S_AUTH_PATH", "kubernetes").strip()
    role = os.environ.get("VAULT_K8S_AUTH_ROLE", "sandbox-launcher").strip()
    resp = http.post(
        f"{addr}/v1/auth/{auth_path}/login",
        json={"role": role, "jwt": sa_token},
    )
    resp.raise_for_status()
    token: str = resp.json()["auth"]["client_token"]
    logger.info(
        "vault_login_ok",
        extra={"method": "kubernetes", "role": role, "auth_path": auth_path},
    )
    return token


# ---------------------------------------------------------------------------
# Grant schema validation
# ---------------------------------------------------------------------------


def _validate_grant(grant: dict[str, Any]) -> None:
    """Validate that the grant document contains NO prohibited fields.

    Raises ValueError listing all violations.  The caller must never write to
    Vault if validation fails (fail-closed no-credential-passing invariant).
    """
    required = {"user", "scope", "ttl", "nonce", "created", "sandbox_uid", "version"}
    missing = required - grant.keys()
    if missing:
        raise ValueError(f"Grant is missing required fields: {sorted(missing)}")

    violations = _PROHIBITED_GRANT_FIELDS & grant.keys()
    if violations:
        raise ValueError(
            f"Grant contains prohibited credential fields: {sorted(violations)}. "
            "No-credential-passing invariant violated — grant rejected."
        )

    if grant["version"] != 1:
        raise ValueError(f"Grant version must be 1, got {grant['version']!r}")

    valid_scopes = {"read-only", "read-write", "admin"}
    if grant["scope"] not in valid_scopes:
        raise ValueError(
            f"Grant scope {grant['scope']!r} is not one of {valid_scopes}"
        )

    if not isinstance(grant["ttl"], int) or grant["ttl"] <= 0:
        raise ValueError(f"Grant ttl must be a positive integer, got {grant['ttl']!r}")

    # nonce must be a non-empty string
    if not isinstance(grant["nonce"], str) or not grant["nonce"].strip():
        raise ValueError("Grant nonce must be a non-empty string")

    # sandbox_uid must be a non-empty string
    if not isinstance(grant["sandbox_uid"], str) or not grant["sandbox_uid"].strip():
        raise ValueError("Grant sandbox_uid must be a non-empty string")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_grant(
    sandbox_uid: str,
    user: str,
    scope: str,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    """Build the consent grant document (NOT a credential).

    Parameters
    ----------
    sandbox_uid:
        The k8s Sandbox CR metadata.uid — stable, server-assigned, non-spoofable.
    user:
        Verified user identity (Keycloak preferred_username bare form, e.g.
        "arsalan" — the bare name, not the entity ref).  This is the value
        ext-proc uses as RFC 8693 requested_subject in Phase-1 impersonation.
    scope:
        One of "read-only" | "read-write" | "admin".
    ttl_seconds:
        Grant validity in seconds.  Defaults to VAULT_GRANT_TTL_SECONDS env var
        (default 3600 = 1 hour).

    Returns a dict ready to pass to write_sandbox_grant().
    """
    if ttl_seconds is None:
        ttl_seconds = int(os.environ.get("VAULT_GRANT_TTL_SECONDS", "3600"))

    nonce = uuid.uuid4().hex  # server-generated; never from caller input

    grant: dict[str, Any] = {
        "version": 1,
        "sandbox_uid": sandbox_uid,
        "user": user,
        "scope": scope,
        "ttl": ttl_seconds,
        "nonce": nonce,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
    }
    _validate_grant(grant)
    return grant


def write_sandbox_grant(
    sandbox_uid: str,
    grant: dict[str, Any],
    http: httpx.Client | None = None,
) -> None:
    """Write the consent grant to Vault KV-v2 at secret/data/sandbox-grants/<sandbox-uid>.

    Parameters
    ----------
    sandbox_uid:
        The k8s Sandbox CR UID (path key).
    grant:
        The grant document produced by build_grant().  Validated before write.
    http:
        Optional httpx.Client for testing / dependency injection.  When None,
        a new client is created using the VAULT_* env vars.

    Raises
    ------
    ValueError:
        If the grant contains prohibited fields or fails schema validation.
    RuntimeError:
        If Vault authentication fails (SA token / SVID file absent).
    httpx.HTTPStatusError:
        If the Vault API returns a non-2xx response.

    Fail-closed: any exception from this function causes the caller (launch
    handler) to surface a 502 error rather than proceeding without a grant.
    The in-sandbox agent will not be able to authenticate to ext-proc without
    a valid grant, so launching without writing the grant is worse than failing
    the launch.
    """
    # Validate before any network call — fail-closed on schema violations.
    _validate_grant(grant)

    addr = _vault_addr()
    kv_path = f"{addr}/v1/secret/data/sandbox-grants/{sandbox_uid}"

    t0 = time.monotonic()

    def _run(client: httpx.Client) -> None:
        vault_token = _vault_login(client)
        headers = {
            "X-Vault-Token": vault_token,
            "Content-Type": "application/json",
        }
        resp = client.post(kv_path, headers=headers, json={"data": grant})
        resp.raise_for_status()
        latency_ms = int((time.monotonic() - t0) * 1000)
        logger.info(
            "vault_grant_write_ok",
            extra={
                "sandbox_uid": sandbox_uid,
                "grant_scope": grant["scope"],
                "grant_user": grant["user"],
                "grant_ttl": grant["ttl"],
                # nonce is present (binding key) but its VALUE is not logged —
                # log only presence so ext-proc can correlate without leaking the secret.
                "grant_nonce_present": bool(grant.get("nonce")),
                "vault_path": f"secret/data/sandbox-grants/{sandbox_uid}",
                "latency_ms": latency_ms,
            },
        )

    if http is not None:
        _run(http)
    else:
        with _http_client() as client:
            _run(client)
