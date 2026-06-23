"""Caller JWT verification for sandbox-launcher — multi-issuer (RHDH + Keycloak).

Supported issuers
-----------------
1. RHDH (Backstage) — configured via RHDH_JWKS_URL + RHDH_TOKEN_ISSUER.
   The RHDH scaffolder proxy should be configured with:
     credentials: forward
     allowedHeaders: [Content-Type, Authorization]
   Sub claim carries the entity ref directly: "user:default/<name>".

2. Keycloak — configured via KEYCLOAK_ISSUER (+ optionally KEYCLOAK_JWKS_URL,
   KEYCLOAK_JWKS_CA). Sub is a UUID; entity ref is derived from
   preferred_username (fallback: email localpart). This matches the
   preferredUsernameMatchingUserEntityName Backstage resolver so both paths
   resolve to the same catalog identity.

Fail-closed contract
--------------------
If an issuer cannot be verified (network error, key mismatch, parse failure,
wrong issuer) the token is DENIED. On success, verify_caller_token returns
(claims, issuer_kind) where issuer_kind is "rhdh" or "keycloak". This lets
the caller invoke the appropriate entity-ref extraction path.

Environment variables
---------------------
RHDH_JWKS_URL       — RHDH JWKS endpoint (enables the RHDH issuer)
RHDH_TOKEN_ISSUER   — Expected issuer string for RHDH tokens
RHDH_JWKS_CA        — Path to CA bundle for RHDH JWKS fetch (default:
                       /etc/rhdh-ingress-ca/ca.crt; falls back to system CAs)
RHDH_JWKS_INSECURE  — "true" to skip TLS verification (development only)

KEYCLOAK_ISSUER     — Keycloak realm URL, e.g.
                       https://keycloak.apps.ocp-dev.na-launch.com/realms/agentic
                       (enables the Keycloak issuer)
KEYCLOAK_JWKS_URL   — JWKS endpoint (default: KEYCLOAK_ISSUER +
                       /protocol/openid-connect/certs)
KEYCLOAK_JWKS_CA    — Path to CA bundle for Keycloak JWKS fetch (optional;
                       if absent, system CAs are used)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Literal

import httpx

logger = logging.getLogger("sandbox_launcher.auth")

# ---------------------------------------------------------------------------
# Issuer kind type alias
# ---------------------------------------------------------------------------

IssuerKind = Literal["rhdh", "keycloak"]

# ---------------------------------------------------------------------------
# Per-issuer JWKS cache
# ---------------------------------------------------------------------------
# Each issuer gets its own lock + cache so that a Keycloak JWKS refresh never
# clobbers the RHDH cache and vice-versa.

_JWKS_TTL = 300.0  # 5 minutes

_jwks_locks: dict[str, threading.Lock] = {
    "rhdh": threading.Lock(),
    "keycloak": threading.Lock(),
}
_jwks_caches: dict[str, list[dict[str, Any]]] = {
    "rhdh": [],
    "keycloak": [],
}
_jwks_fetched_at: dict[str, float] = {
    "rhdh": 0.0,
    "keycloak": 0.0,
}


def _fetch_jwks_for(issuer_kind: IssuerKind) -> list[dict[str, Any]]:
    """Fetch and cache JWKS for the given issuer kind. Thread-safe, TTL-backed.

    The raw JWKS URL, CA path, and insecure flag are all read from env at
    call time so that tests can override them without restarting the process.
    """
    lock = _jwks_locks[issuer_kind]
    with lock:
        now = time.monotonic()
        if _jwks_caches[issuer_kind] and (now - _jwks_fetched_at[issuer_kind]) < _JWKS_TTL:
            return _jwks_caches[issuer_kind]

        jwks_url, verify = _jwks_params(issuer_kind)
        with httpx.Client(timeout=10, verify=verify) as http:
            resp = http.get(jwks_url)
        resp.raise_for_status()
        keys: list[dict[str, Any]] = resp.json().get("keys", [])
        _jwks_caches[issuer_kind] = keys
        _jwks_fetched_at[issuer_kind] = time.monotonic()
        logger.debug(
            "jwks_refreshed",
            extra={"issuer_kind": issuer_kind, "key_count": len(keys)},
        )
        return keys


def _jwks_params(issuer_kind: IssuerKind) -> tuple[str, Any]:
    """Return (jwks_url, verify) for the given issuer.

    verify is: False (insecure), a CA-bundle path (string), or True (system CAs).
    Raises RuntimeError when required env vars are absent.
    """
    if issuer_kind == "rhdh":
        jwks_url = os.environ.get("RHDH_JWKS_URL", "").strip()
        if not jwks_url:
            raise RuntimeError("RHDH_JWKS_URL is not configured")
        insecure = os.environ.get("RHDH_JWKS_INSECURE", "").strip().lower() == "true"
        ca_path = os.environ.get("RHDH_JWKS_CA", "/etc/rhdh-ingress-ca/ca.crt").strip()
        verify: Any = (
            False
            if insecure
            else (ca_path if ca_path and os.path.exists(ca_path) else True)
        )
        return jwks_url, verify

    # keycloak
    base = os.environ.get("KEYCLOAK_ISSUER", "").strip()
    if not base:
        raise RuntimeError("KEYCLOAK_ISSUER is not configured")
    # Use the explicit URL if non-empty; fall back to the well-known OIDC path.
    jwks_url = (
        os.environ.get("KEYCLOAK_JWKS_URL", "").strip()
        or (base.rstrip("/") + "/protocol/openid-connect/certs")
    )
    insecure = os.environ.get("KEYCLOAK_JWKS_INSECURE", "").strip().lower() == "true"
    ca_path = os.environ.get("KEYCLOAK_JWKS_CA", "").strip()
    verify = (
        False
        if insecure
        else (ca_path if ca_path and os.path.exists(ca_path) else True)
    )
    return jwks_url, verify


# ---------------------------------------------------------------------------
# Multi-issuer token verification
# ---------------------------------------------------------------------------


def _configured_issuers() -> list[IssuerKind]:
    """Return the list of issuers that are enabled by env var configuration.

    The order is significant: RHDH is tried first (preserves existing behavior),
    then Keycloak. At least one must be configured; if none are configured the
    caller gets a RuntimeError (mis-deployment, not a caller fault).
    """
    issuers: list[IssuerKind] = []
    if os.environ.get("RHDH_JWKS_URL", "").strip() and os.environ.get("RHDH_TOKEN_ISSUER", "").strip():
        issuers.append("rhdh")
    if os.environ.get("KEYCLOAK_ISSUER", "").strip():
        issuers.append("keycloak")
    return issuers


def _expected_issuer(issuer_kind: IssuerKind) -> str:
    """Return the expected 'iss' claim value for the given issuer kind."""
    if issuer_kind == "rhdh":
        return os.environ.get("RHDH_TOKEN_ISSUER", "").strip()
    return os.environ.get("KEYCLOAK_ISSUER", "").strip()


def verify_caller_token(token: str) -> tuple[dict[str, Any], IssuerKind]:
    """Verify a Bearer token against all configured issuers.

    Tries each configured issuer in order (RHDH first, then Keycloak). Returns
    the decoded claims and the matching issuer kind on the first success.

    Fail-closed: if all configured issuers fail (or none are configured) this
    raises. The exception message is safe — it never contains the raw token.

    Returns:
        (claims, issuer_kind): decoded JWT payload + "rhdh" or "keycloak".

    Raises:
        RuntimeError: no issuers are configured (mis-deployment).
        ValueError:   all configured issuers rejected the token.
    """
    import jwt as pyjwt  # PyJWT

    issuers = _configured_issuers()
    if not issuers:
        raise RuntimeError(
            "No auth issuer is configured — set RHDH_JWKS_URL+RHDH_TOKEN_ISSUER "
            "and/or KEYCLOAK_ISSUER"
        )

    # Collect per-issuer failure messages for a consolidated error on full denial.
    denial_reasons: list[str] = []

    for issuer_kind in issuers:
        expected_iss = _expected_issuer(issuer_kind)

        try:
            keys = _fetch_jwks_for(issuer_kind)
        except RuntimeError:
            # Configuration gap — skip this issuer; it will surface as RuntimeError
            # only if it is the ONLY configured issuer and all others also fail.
            denial_reasons.append(f"{issuer_kind}: JWKS fetch config error")
            continue
        except Exception as exc:
            logger.error(
                "jwks_fetch_failed",
                extra={"issuer_kind": issuer_kind, "error": str(exc)},
            )
            denial_reasons.append(f"{issuer_kind}: JWKS fetch failed")
            continue

        # Fix (3): kid-based key selection.
        # Read the JWT header before any crypto work and, if it carries a 'kid'
        # claim, restrict verification to the single JWKS key whose 'kid' matches.
        # This avoids iterating over all keys for every request (CPU/DoS mitigation)
        # and prevents accidental cross-key verification.  Fall back to trying ALL
        # keys only when the token header has no 'kid' or no JWKS key matches the
        # kid — this preserves backward compatibility with JWKS rotations where the
        # new key is not yet propagated to the local cache.
        try:
            token_header = pyjwt.get_unverified_header(token)
        except Exception as exc:  # noqa: BLE001
            denial_reasons.append(f"{issuer_kind}: unreadable token header ({exc})")
            continue

        token_kid: str | None = token_header.get("kid")
        if token_kid:
            matched_keys = [k for k in keys if k.get("kid") == token_kid]
            # If no key matched the kid (cache may be stale), try all keys so that
            # a recently rotated signing key doesn't permanently lock out callers
            # until the JWKS TTL expires.
            keys_to_try = matched_keys if matched_keys else keys
            if not matched_keys:
                logger.debug(
                    "jwks_kid_no_match_falling_back",
                    extra={"issuer_kind": issuer_kind, "token_kid": token_kid},
                )
        else:
            keys_to_try = keys

        last_exc: Exception | None = None
        for jwk in keys_to_try:
            try:
                public_key = pyjwt.PyJWK.from_dict(jwk).key
                claims = pyjwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256", "ES256"],
                    issuer=expected_iss,
                    options={
                        "verify_aud": False,  # audience varies by installation
                        "require": ["iss", "sub", "exp"],
                    },
                )
                # Success — return immediately, do not try further issuers.
                return claims, issuer_kind
            except pyjwt.exceptions.InvalidSignatureError:
                last_exc = pyjwt.exceptions.InvalidSignatureError("signature mismatch")
                continue
            except pyjwt.exceptions.ExpiredSignatureError as exc:
                # Expired tokens are a definitive failure — no point trying other keys.
                raise ValueError("caller token has expired") from exc
            except pyjwt.exceptions.InvalidIssuerError:
                # This key belongs to the right JWKS endpoint but has the wrong iss —
                # the whole issuer is wrong for this token, no point trying more keys.
                last_exc = pyjwt.exceptions.InvalidIssuerError("issuer mismatch")
                break
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue

        denial_reasons.append(
            f"{issuer_kind}: token did not verify ({last_exc})"
        )

    raise ValueError(
        "caller token was rejected by all configured issuers: "
        + "; ".join(denial_reasons)
    )


# ---------------------------------------------------------------------------
# Entity-ref extraction (issuer-aware)
# ---------------------------------------------------------------------------


def extract_entity_ref(claims: dict[str, Any], issuer_kind: IssuerKind = "rhdh") -> str:
    """Extract the RHDH user entity ref from JWT claims.

    RHDH tokens:
        sub carries the entity ref directly, e.g. "user:default/arsalan".
        Falls back to the 'ent' list if sub does not start with "user:".

    Keycloak tokens:
        sub is a UUID — not usable as an entity ref. Use preferred_username
        (matches RHDH's preferredUsernameMatchingUserEntityName resolver).
        Falls back to the email localpart if preferred_username is absent.

    Raises ValueError if no usable identity can be extracted.
    """
    if issuer_kind == "keycloak":
        return _extract_entity_ref_keycloak(claims)
    return _extract_entity_ref_rhdh(claims)


def _extract_entity_ref_rhdh(claims: dict[str, Any]) -> str:
    """Extract entity ref from a Backstage-issued token."""
    sub: str = claims.get("sub", "")
    if sub.startswith("user:"):
        return sub

    # Fallback: ent list
    ent = claims.get("ent", [])
    if isinstance(ent, list):
        for ref in ent:
            if isinstance(ref, str) and ref.startswith("user:"):
                return ref

    # Last resort: return sub without prefix (advisory)
    if sub:
        return sub

    raise ValueError("could not extract user entity ref from Backstage JWT claims")


def _extract_entity_ref_keycloak(claims: dict[str, Any]) -> str:
    """Extract entity ref from a Keycloak-issued token.

    Fix (4): Keycloak identity hardening.

    Uses preferred_username because that is what RHDH's
    preferredUsernameMatchingUserEntityName resolver uses, so the CLI and RHDH
    resolve to the same catalog entity.  Both Keycloak and RHDH resolve to the
    SAME namespace (user:default/<name>), so realm settings MUST prevent username
    reuse and self-registration (registrationAllowed: false, editUsernameAllowed:
    false — see platform/keycloak/base/realm-import.yaml).

    Security constraints on preferred_username:
      - Must be non-empty after stripping whitespace.
      - Must not contain ':' or '/' characters: those are the delimiter chars in
        RHDH entity refs (kind:namespace/name).  A username containing either
        char would corrupt the entity ref and could be used to impersonate another
        catalog identity (e.g. "default/arsalan" -> "user:default/default/arsalan"
        but also tricks the old trailing-segment-only check).

    Falls back to the email localpart ONLY when preferred_username is absent AND
    email_verified is true.  An unverified email is attacker-controlled input on
    most IdP setups and MUST NOT be used to derive an identity.
    """
    username: str = claims.get("preferred_username", "").strip()
    if username:
        # Reject syntactically unsafe usernames that could corrupt entity refs
        # or impersonate another catalog identity.
        if ":" in username or "/" in username:
            raise ValueError(
                f"preferred_username contains unsafe characters (':' or '/') "
                f"and cannot be used as a catalog identity component"
            )
        return f"user:default/{username}"

    # Email localpart as last resort — ONLY when the email address is verified.
    # An unverified email is attacker-supplied and must not be trusted for identity.
    email_verified: bool = bool(claims.get("email_verified", False))
    email: str = claims.get("email", "").strip()
    if email_verified and email and "@" in email:
        localpart = email.split("@")[0]
        if localpart:
            logger.warning(
                "keycloak_entity_ref_from_email_fallback",
                extra={"note": "preferred_username absent; using verified email localpart"},
            )
            return f"user:default/{localpart}"

    if email and not email_verified:
        raise ValueError(
            "could not extract user entity ref from Keycloak JWT claims: "
            "preferred_username is absent and email is present but not verified "
            "(email_verified=false); refusing to use unverified email as identity"
        )

    raise ValueError(
        "could not extract user entity ref from Keycloak JWT claims "
        "(preferred_username and email are both absent)"
    )
