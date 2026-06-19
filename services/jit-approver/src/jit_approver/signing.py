"""RS256 session-JWT signing + JWKS for the JIT dangerous-tool gate (N1 / UC2).

Single source of truth for the JIT *session-capability* JWT shape. The Kyverno
ValidatingPolicy ``dangerous-tools-admins-only`` fetches the JWKS this module
serves and asserts, on the dangerous-tool call:

  * the signature validates against this JWKS (RS256, by ``kid``),
  * ``decodedJitJwt.Valid`` (signature + exp/nbf),
  * ``iss == JIT_SESSION_ISS`` (exact string), and
  * the requested MCP tool name is in the ``tool_scope`` claim.

So the constants below MUST stay in lock-step with
``platform/kyverno/authz/base/dangerous-tools-admins-only.yaml``. jit-approver is
the source of truth for the token; the policy's ``iss`` constant is aligned to
``JIT_SESSION_ISS`` here.

Why this is sound w.r.t. the no-credential-passing invariant:
  This session JWT is the AGENT'S OWN approved capability — scoped (tool_scope),
  signed by the approver, and short-lived (exp == approved window). It is NOT a
  downstream service credential proxied via ext-proc (that is UC1). Holding and
  presenting it to clear the Kyverno gate is exactly the UC2 design.

Key material (PoC):
  * If ``JIT_SIGNING_KEY_PATH`` points at a PEM private key, load it.
  * Otherwise generate an ephemeral RSA-2048 keypair at startup (PoC only — keys
    do not survive a restart; production should mount a stable PEM / SVID key).
The public half is published at GET /jwks with a stable ``kid``.
"""

from __future__ import annotations

import logging
import os
import time
from functools import lru_cache
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger("jit_approver.signing")

# ---------------------------------------------------------------------------
# CONTRACT CONSTANTS — must match dangerous-tools-admins-only.yaml exactly.
# ---------------------------------------------------------------------------

# iss claim. The policy asserts decodedJitJwt.Claims["iss"] == this string
# (dangerous-tools-admins-only.yaml). The JWKS *fetch* URL uses http:// (in-
# cluster), but the iss is an opaque identifier, kept identical on both sides.
JIT_SESSION_ISS = "https://jit-approver.mcp-gateway.svc.cluster.local:8080"

# aud claim. The policy documents aud=kyverno-authz (the ext_authz consumer).
JIT_SESSION_AUD = "kyverno-authz"

# tool_scope is the claim name the policy reads: it must contain the requested
# MCP tool name for the call to clear the gate.
JIT_TOOL_SCOPE_CLAIM = "tool_scope"

# Stable key id published in the JWKS and set in the JWT header.
JIT_SIGNING_KID = "jit-approver-key-1"

JIT_SIGNING_ALG = "RS256"

_SIGNING_KEY_PATH_ENV = "JIT_SIGNING_KEY_PATH"


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


class _SigningKeys:
    """Holds the RSA private key (PEM bytes) and the derived public key."""

    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key
        self._private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def private_pem(self) -> bytes:
        return self._private_pem

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._private_key.public_key()


def _load_or_generate_key() -> _SigningKeys:
    """Load the signing key from ``JIT_SIGNING_KEY_PATH`` (PEM) or generate one.

    Generation is a PoC convenience: an ephemeral RSA-2048 keypair so that /jwks
    and minting work out of the box. Production should mount a stable PEM so the
    JWKS (and thus already-issued tokens) survive a restart.
    """
    path = os.environ.get(_SIGNING_KEY_PATH_ENV, "")
    if path:
        try:
            with open(path, "rb") as fh:
                pem = fh.read()
            private_key = serialization.load_pem_private_key(pem, password=None)
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise TypeError("JIT signing key is not an RSA private key")
            logger.info("jit_signing_key_loaded", extra={"path": path, "kid": JIT_SIGNING_KID})
            return _SigningKeys(private_key)
        except FileNotFoundError:
            logger.warning(
                "jit_signing_key_missing_generating_ephemeral",
                extra={"path": path, "kid": JIT_SIGNING_KID},
            )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    logger.info(
        "jit_signing_key_generated_ephemeral",
        extra={"kid": JIT_SIGNING_KID, "note": "PoC ephemeral key; mount a PEM in prod"},
    )
    return _SigningKeys(private_key)


@lru_cache(maxsize=1)
def _keys() -> _SigningKeys:
    """Process-wide singleton signing keys (loaded/generated once)."""
    return _load_or_generate_key()


def reset_keys_for_test() -> None:
    """Test hook: drop the cached keypair so a fresh one is loaded next call."""
    _keys.cache_clear()


# ---------------------------------------------------------------------------
# JWKS (public)
# ---------------------------------------------------------------------------


def jwks() -> dict[str, Any]:
    """Return a standard JWKS document for the public signing key.

    Shape: {"keys": [{kty:"RSA", use:"sig", alg:"RS256", kid:..., n:..., e:...}]}
    No auth — public keys. This is what the Kyverno policy's jwks.Fetch() reads.
    """
    public_key = _keys().public_key
    # RSAAlgorithm.to_jwk emits n/e (base64url) + kty; we add use/alg/kid.
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk.update({"use": "sig", "alg": JIT_SIGNING_ALG, "kid": JIT_SIGNING_KID})
    return {"keys": [jwk]}


# ---------------------------------------------------------------------------
# Tool-scope mapping: approved K8s verbs/resources -> dangerous MCP tool names
# ---------------------------------------------------------------------------

# When a grant approves a mutating verb on a resource that maps to a dangerous
# pfSense/MCP tool, the session is scoped to that tool name (the gate matches the
# MCP ToolCall.Name against tool_scope). The firewall mapping is the concrete UC2
# example from the contract.
_MUTATING_VERBS = frozenset({"create", "update", "patch"})

# resource token (substring) -> dangerous MCP tool names that the gate accepts.
_RESOURCE_TOOL_MAP: dict[str, list[str]] = {
    # pfSense MCP (UC2)
    "firewall": ["create_firewall_rule_advanced", "add_firewall_rule"],
    "networkpolicy": ["create_firewall_rule_advanced", "add_firewall_rule"],
    "networkpolicies": ["create_firewall_rule_advanced", "add_firewall_rule"],
    # OpenShift / Kubernetes MCP (containers/kubernetes-mcp-server tool names).
    # Substring match: "deployment" covers deployments; "pods/exec" gates exec.
    "deployment": ["resources_create_or_update", "resources_scale"],
    "scale": ["resources_scale"],
    "pods/exec": ["pods_exec"],
    "pod": ["resources_create_or_update", "pods_run"],
    "configmap": ["resources_create_or_update"],
    "service": ["resources_create_or_update"],
    "route": ["resources_create_or_update"],
}


def tool_scope_for(req: Any) -> list[str]:
    """Map an approved EscalationRequest to the dangerous MCP tool names it covers.

    Only mutating verbs (create/update/patch) can map to a dangerous tool — a
    read-only grant yields an empty tool_scope (the gate would deny, which is
    correct: read tools are not gated by dangerous-tools-admins-only anyway).
    The mapping is keyed on resource substrings so 'firewall'/'networkpolicies'
    both reach the firewall tools. Deterministic + de-duplicated output.
    """
    verbs = {str(v).lower() for v in getattr(req, "verbs", [])}
    if not (verbs & _MUTATING_VERBS):
        return []
    tools: list[str] = []
    for resource in getattr(req, "resources", []):
        rl = str(resource).lower()
        for token, mapped in _RESOURCE_TOOL_MAP.items():
            if token in rl:
                for tool in mapped:
                    if tool not in tools:
                        tools.append(tool)
    return tools


# ---------------------------------------------------------------------------
# Mint the session-capability JWT (per CONTRACT)
# ---------------------------------------------------------------------------


def sandbox_uid_from_spiffe(spiffe_id: str) -> str:
    """Extract the sandbox UUID from a SPIFFE ID of the form

        spiffe://<trust-domain>/ns/<ns>/sandbox/<uuid>

    Returns "" when the SPIFFE ID is not sandbox-pathed (e.g. an SA-based ID).
    ext-proc binds JIT elevation on this value == the SVID's sandbox_uid, so a
    session JWT minted for a non-sandbox principal cannot elevate a sandbox.
    """
    marker = "/sandbox/"
    idx = (spiffe_id or "").find(marker)
    if idx < 0:
        return ""
    return spiffe_id[idx + len(marker):].split("/", 1)[0]


def mint_session_jwt(
    *,
    session_id: str,
    tool_scope: list[str],
    issued_at: int,
    duration_minutes: int,
    requester_sub: str = "",
    sandbox_uid: str = "",
) -> str:
    """Mint the RS256 X-JIT-Session-JWT for an issued session.

    Claims (CONTRACT):
      iss = JIT_SESSION_ISS          (matches the policy's iss constant)
      aud = JIT_SESSION_AUD          (kyverno-authz)
      sub = session_id               (the session is the subject of the capability)
      tool_scope = [approved tool names]
      iat = nbf = issued_at, exp = issued_at + duration_minutes*60
      sandbox_uid = <uuid>           (present only for sandbox-agent sessions;
                                      ext-proc's SVID path binds elevation on it)
    Header: alg=RS256, kid=JIT_SIGNING_KID.

    ``requester_sub`` is recorded in a non-authoritative ``requester`` claim for
    audit correlation only; the gate keys on iss/exp/tool_scope (+ sandbox_uid on
    the delegated SVID path).
    """
    exp = issued_at + duration_minutes * 60
    claims: dict[str, Any] = {
        "iss": JIT_SESSION_ISS,
        "aud": JIT_SESSION_AUD,
        "sub": session_id,
        "jti": session_id,
        JIT_TOOL_SCOPE_CLAIM: tool_scope,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": exp,
    }
    if requester_sub:
        claims["requester"] = requester_sub
    if sandbox_uid:
        claims["sandbox_uid"] = sandbox_uid
    token = jwt.encode(
        claims,
        _keys().private_pem,
        algorithm=JIT_SIGNING_ALG,
        headers={"kid": JIT_SIGNING_KID, "typ": "JWT"},
    )
    return token


def public_jwk_for_verify() -> Any:
    """Return a PyJWK usable to verify minted tokens (used by tests)."""
    return jwt.PyJWK.from_dict(jwks()["keys"][0])
