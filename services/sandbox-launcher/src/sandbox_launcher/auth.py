"""Caller JWT verification for sandbox-launcher.

The RHDH scaffolder proxy is expected to be configured with:
  credentials: forward
  allowedHeaders: [Content-Type, Authorization]

This forwards the Backstage-issued user JWT (NOT the user's Keycloak OIDC
token — Backstage issues its own RS256 JWT after validating Keycloak OIDC at
sign-in time). The launcher verifies it against the RHDH JWKS endpoint and
extracts the entity ref as the verified owner identity.

If the Authorization header is absent (proxy misconfigured with
credentials: require), the launcher:
  - logs a TODO-hardening warning
  - falls back to the body 'user' field as advisory identity
  - still proceeds (so the PoC works without the proxy change)
  - but marks the owner as UNVERIFIED in the response and audit logs

This fallback MUST be removed in production (change TODO marker to an error
and return 401) once the proxy is switched to credentials: forward.

Environment variables:
  RHDH_JWKS_URL      — JWKS endpoint, e.g.
                        https://developer-hub-rhdh.apps.anaeem.na-launch.com/api/auth/.backstage/jwks.json
  RHDH_TOKEN_ISSUER  — Expected issuer, e.g.
                        https://developer-hub-rhdh.apps.anaeem.na-launch.com
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

import httpx

logger = logging.getLogger("sandbox_launcher.auth")

# ---------------------------------------------------------------------------
# JWKS cache — module-level, refresh when the cache entry is stale (>5 min)
# ---------------------------------------------------------------------------

_jwks_lock = threading.Lock()
_jwks_cache: list[dict[str, Any]] = []
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 300.0  # 5 minutes


def _fetch_jwks() -> list[dict[str, Any]]:
    """Fetch JWKS from RHDH. Returns the list of JWK dicts. Thread-safe with TTL cache."""
    global _jwks_cache, _jwks_fetched_at

    jwks_url = os.environ.get("RHDH_JWKS_URL", "").strip()
    if not jwks_url:
        raise RuntimeError("RHDH_JWKS_URL is not configured")

    with _jwks_lock:
        if _jwks_cache and (time.monotonic() - _jwks_fetched_at) < _JWKS_TTL:
            return _jwks_cache

        # TLS: RHDH's route is edge-terminated with the cluster ingress cert, signed
        # by the self-signed ingress-operator CA that the launcher image doesn't ship.
        # Trust it via the mounted ingress CA (RHDH_JWKS_CA, default /etc/rhdh-ingress-ca/
        # ca.crt); RHDH_JWKS_INSECURE=true skips verify (JWKS is public key material).
        insecure = os.environ.get("RHDH_JWKS_INSECURE", "").strip().lower() == "true"
        ca_path = os.environ.get("RHDH_JWKS_CA", "/etc/rhdh-ingress-ca/ca.crt").strip()
        verify: Any = False if insecure else (ca_path if ca_path and os.path.exists(ca_path) else True)
        with httpx.Client(timeout=10, verify=verify) as http:
            resp = http.get(jwks_url)
        resp.raise_for_status()
        keys = resp.json().get("keys", [])
        _jwks_cache = keys
        _jwks_fetched_at = time.monotonic()
        logger.debug("rhdh_jwks_refreshed", extra={"key_count": len(keys)})
        return keys


def verify_caller_token(token: str) -> dict[str, Any]:
    """Verify a Backstage-issued Bearer token against RHDH JWKS.

    Returns the decoded claims dict on success.
    Raises ValueError (with a safe, non-credential-containing message) on failure.
    Fail-closed: any error -> deny.

    The issuer check uses RHDH_TOKEN_ISSUER env var.
    The audience check is lenient (options={'verify_aud': False}) because
    Backstage-issued user tokens use an internal audience that may vary by
    installation. The issuer check is the binding constraint.
    """
    import jwt as pyjwt  # PyJWT

    issuer = os.environ.get("RHDH_TOKEN_ISSUER", "").strip()
    if not issuer:
        raise RuntimeError("RHDH_TOKEN_ISSUER is not configured")

    try:
        keys = _fetch_jwks()
    except Exception as exc:
        logger.error("rhdh_jwks_fetch_failed", extra={"error": str(exc)})
        raise ValueError("unable to fetch RHDH JWKS for token verification") from exc

    last_exc: Exception | None = None
    for jwk in keys:
        try:
            public_key = pyjwt.PyJWK.from_dict(jwk).key
            claims = pyjwt.decode(
                token,
                public_key,
                algorithms=["RS256", "ES256"],
                issuer=issuer,
                options={
                    "verify_aud": False,  # Backstage internal audience; not fixed
                    "require": ["iss", "sub", "exp"],
                },
            )
            return claims
        except pyjwt.exceptions.InvalidSignatureError:
            last_exc = pyjwt.exceptions.InvalidSignatureError("signature mismatch")
            continue
        except pyjwt.exceptions.ExpiredSignatureError as exc:
            raise ValueError("caller token has expired") from exc
        except pyjwt.exceptions.InvalidIssuerError as exc:
            raise ValueError(f"caller token issuer mismatch (expected: {issuer})") from exc
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            continue

    raise ValueError("caller token signature did not verify against any RHDH JWKS key") from last_exc


def extract_entity_ref(claims: dict[str, Any]) -> str:
    """Extract the user entity ref from Backstage JWT claims.

    Backstage user tokens carry the entity ref in:
      - 'sub': typically 'user:default/username' (primary)
      - 'ent': list of entity refs, e.g. ['user:default/username']

    Returns the first usable entity ref, or raises ValueError.
    """
    # Primary: sub claim
    sub: str = claims.get("sub", "")
    if sub.startswith("user:"):
        return sub

    # Fallback: ent list
    ent = claims.get("ent", [])
    if isinstance(ent, list):
        for ref in ent:
            if isinstance(ref, str) and ref.startswith("user:"):
                return ref

    # Last resort: return sub even without 'user:' prefix (advisory only)
    if sub:
        return sub

    raise ValueError("could not extract user entity ref from Backstage JWT claims")
