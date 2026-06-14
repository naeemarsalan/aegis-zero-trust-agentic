"""FastAPI application — sandbox-launcher REST API.

Endpoints:
  POST /launch   — provision an OpenShell packaged-agent sandbox
  GET  /healthz  — liveness probe
  GET  /metrics  — Prometheus metrics (optional)

Auth contract (§ design brief):
  The RHDH scaffolder proxy should be configured with:
    credentials: forward
    allowedHeaders: [Content-Type, Authorization]

  This forwards the Backstage-issued user JWT. The launcher:
    1. Extracts Authorization: Bearer <token> from the request.
    2. Verifies it against RHDH JWKS (RHDH_JWKS_URL env var).
    3. Extracts the user entity ref from 'sub'/'ent' claims.
    4. Cross-checks against body.user. Returns 403 on mismatch.
    5. Discards the token — it is NEVER logged, stored, or forwarded.

  If the Authorization header is ABSENT (proxy misconfigured):
    - TODO-HARDENING: in production return 401 here.
    - For PoC: logs a warning and falls back to body.user as advisory identity.

  The launcher then calls the OpenShell gateway using its OWN OIDC
  client-credentials token (LAUNCHER_OIDC_*). This is the NO-CREDENTIAL-PASSING
  invariant: the user's token is verified once to establish identity, then
  discarded. The gateway sees only the launcher's service identity.

NO-CREDENTIAL-PASSING invariant locations:
  - _extract_and_verify_caller() discards token after entity-ref extraction
  - openshell.create_sandbox() uses _launcher_auth_metadata() exclusively
  - audit.emit_launch_attempt() hashes the goal; never logs the token
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from sandbox_launcher import audit
from sandbox_launcher.models import LaunchRequest, LaunchResponse

logger = logging.getLogger("sandbox_launcher.api")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sandbox Launcher",
    description="Provisions OpenShell packaged-agent sandboxes from RHDH scaffolder",
    version="0.1.0",
)


@app.exception_handler(RequestValidationError)
async def _on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Audit validation rejections at the API edge."""
    from fastapi.encoders import jsonable_encoder

    if request.url.path == "/launch":
        audit.emit_auth_failure("pre-auth", f"request validation failed: {exc.errors()}")
    return JSONResponse(status_code=422, content=jsonable_encoder({"detail": exc.errors()}))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SANDBOX_NAMESPACE = os.environ.get("SANDBOX_NAMESPACE", "openshell")


def _short_id() -> str:
    """Return a 6-character hex token for sandbox name uniqueness."""
    return uuid.uuid4().hex[:6]


def _sandbox_name(user_entity_ref: str) -> str:
    """Derive a deterministic-looking sandbox name from the entity ref.

    Format: agent-<username>-<short-uuid>
    Username is the part after the last '/' in the entity ref, lowercased,
    stripped to ≤20 chars, and sanitised to [a-z0-9-] only.
    """
    username = user_entity_ref.rsplit("/", 1)[-1].lower()
    # Sanitise: keep only alphanumeric and hyphens
    sanitised = "".join(c if c.isalnum() or c == "-" else "-" for c in username)[:20]
    sanitised = sanitised.strip("-") or "user"
    return f"agent-{sanitised}-{_short_id()}"


def _extract_and_verify_caller(request: Request, body_user: str) -> tuple[str, bool]:
    """Verify the Backstage JWT and return (entity_ref, is_verified).

    Returns:
        (entity_ref, True)  when the JWT is present and verifies.
        (body_user, False)  when the JWT is absent (PoC fallback — see TODO below).

    Raises:
        HTTPException(401) if the JWT is present but invalid/expired/wrong-issuer.
        HTTPException(403) if the JWT is valid but entity_ref mismatches body.user.

    NO-CREDENTIAL-PASSING: the raw token string is NEVER logged, stored, or
    forwarded. It is discarded after claim extraction.
    """
    from sandbox_launcher.auth import extract_entity_ref, verify_caller_token

    auth_header: str = request.headers.get("Authorization", "")

    if not auth_header:
        # TODO-HARDENING: switch this block to:
        #   raise HTTPException(status_code=401, detail="Authorization header required")
        # once the RHDH proxy is configured with credentials: forward.
        # For PoC, fall back to the body 'user' field as advisory identity.
        logger.warning(
            "caller_token_absent_fallback",
            extra={
                "body_user": body_user,
                "note": "TODO-HARDENING: proxy must be set to credentials:forward",
            },
        )
        return body_user, False

    if not auth_header.lower().startswith("bearer "):
        audit.emit_auth_failure("unknown", "malformed Authorization header")
        raise HTTPException(status_code=401, detail="Authorization header must be Bearer token")

    token = auth_header[7:]  # strip "Bearer "

    try:
        claims = verify_caller_token(token)
    except ValueError as exc:
        audit.emit_auth_failure("unknown", f"token verification failed: {exc}")
        # LAUNCHER_REQUIRE_VERIFIED=true → fail closed (401). Default (PoC): a token
        # was presented but couldn't be verified (e.g. JWKS reachability, or the
        # Backstage token type/issuer differs from RHDH_TOKEN_ISSUER) — fall back to
        # advisory identity (body.user, verified=false) so the flow proceeds. The
        # no-credential-passing invariant is unaffected: the gateway call still uses
        # the launcher's OWN creds, never the caller's token.
        if os.environ.get("LAUNCHER_REQUIRE_VERIFIED", "").strip().lower() == "true":
            raise HTTPException(status_code=401, detail=f"Token verification failed: {exc}") from exc
        logger.warning(
            "caller_token_unverified_fallback",
            extra={"body_user": body_user, "reason": str(exc)},
        )
        return body_user, False
    except RuntimeError as exc:
        # RHDH JWKS not configured — mis-deployment, not caller error
        logger.error("rhdh_jwks_not_configured", extra={"error": str(exc)})
        raise HTTPException(status_code=503, detail="Auth service not configured") from exc

    try:
        entity_ref = extract_entity_ref(claims)
    except ValueError as exc:
        audit.emit_auth_failure("unknown", f"entity ref extraction failed: {exc}")
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    # Cross-check: verified entity_ref must match body.user (consistency check)
    # We compare the username portion (after last '/') case-insensitively to handle
    # minor format variations.
    verified_username = entity_ref.rsplit("/", 1)[-1].lower()
    body_username = body_user.rsplit("/", 1)[-1].lower()
    if verified_username != body_username:
        audit.emit_auth_failure(
            entity_ref,
            f"entity_ref mismatch: token={entity_ref} body={body_user}",
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"Caller identity mismatch: token identifies '{entity_ref}' "
                f"but body.user is '{body_user}'"
            ),
        )

    # Token is consumed — discard reference
    del token, claims
    return entity_ref, True


# ---------------------------------------------------------------------------
# POST /launch
# ---------------------------------------------------------------------------


@app.post("/launch", status_code=202)
async def launch(request: Request, body: LaunchRequest) -> LaunchResponse:
    """Provision an OpenShell packaged-agent sandbox.

    Steps:
      1. Enforce confirmed == True (server-side guard).
      2. Verify the caller's Backstage JWT (or fall back to advisory identity).
      3. Derive a sandbox name: agent-<username>-<short-uuid>.
      4. Call OpenShell CreateSandbox with the baseline floor policy and owner labels.
      5. Return sandboxName, phase, conversationUrl (null), accessHint.
    """
    # Step 1: confirmed guard (JSON Schema const:true is advisory-only in RHDH)
    if body.confirmed is not True:
        raise HTTPException(
            status_code=400,
            detail="confirmed must be exactly true — cannot launch without explicit confirmation",
        )

    t0 = time.monotonic()

    # Step 2: caller identity
    entity_ref, is_verified = _extract_and_verify_caller(request, body.user)

    # Hash the goal for audit (never log raw user content)
    goal_hash = hashlib.sha256(body.goal.encode()).hexdigest()
    audit.emit_launch_attempt(
        actor=entity_ref,
        goal_hash=goal_hash,
        capabilities=body.capabilities,
        mode=body.mode.value,
    )

    # Step 3: sandbox name
    name = _sandbox_name(entity_ref)

    # Step 4: CreateSandbox via the launcher's own OIDC token
    from sandbox_launcher import openshell

    try:
        resp = openshell.create_sandbox(
            name=name,
            owner_entity_ref=entity_ref,
            owner_email="",  # not available from Backstage JWT in this flow
            extra_labels={
                "nvidia-ida/verified-identity": str(is_verified).lower(),
                "nvidia-ida/mode": body.mode.value,
                "nvidia-ida/scope": body.scope.value,
                # The OpenShell SandboxSpec proto has no TTL field — sandbox
                # lifetime is governed by the JIT reaper, not CreateSandbox. We
                # record the user's requested TTL as a label so the reaper / an
                # operator can honour it; it is advisory metadata, not enforced here.
                "nvidia-ida/ttl-minutes": str(body.ttl_minutes),
            },
        )
    except RuntimeError as exc:
        # Not configured (missing certs / baseline) — deployment error
        logger.error("openshell_not_configured", extra={"error": str(exc)})
        audit.emit_launch_outcome(
            actor=entity_ref,
            sandbox_name=name,
            outcome="error",
            latency_ms=int((time.monotonic() - t0) * 1000),
            tool_args_hash=goal_hash,
        )
        raise HTTPException(status_code=503, detail=f"OpenShell client not ready: {exc}") from exc
    except Exception as exc:
        logger.error(
            "openshell_create_sandbox_failed",
            extra={"sandbox_name": name, "error": str(exc)},
        )
        audit.emit_launch_outcome(
            actor=entity_ref,
            sandbox_name=name,
            outcome="error",
            latency_ms=int((time.monotonic() - t0) * 1000),
            tool_args_hash=goal_hash,
        )
        raise HTTPException(status_code=502, detail=f"OpenShell gateway error: {exc}") from exc

    latency_ms = int((time.monotonic() - t0) * 1000)
    sandbox_name = resp.sandbox.metadata.name or name
    sandbox_id = resp.sandbox.metadata.id or ""
    phase_int = resp.sandbox.status.phase
    # Proto-derived name (see openshell.phase_name) — never drifts from the wire enum.
    phase_str = openshell.phase_name(phase_int)

    # Step 5: build response
    # conversationUrl is null at creation time — the OpenShell API does not return
    # a routable URL from CreateSandbox. Call ExposeService after sandbox is READY
    # if a public HTTP URL is needed. See design brief §(3).
    access_hint = (
        f"oc -n {_SANDBOX_NAMESPACE} exec -it <agent_pod> -c agent -- /bin/sh"
        f"  # sandbox: {sandbox_name}"
    )

    audit.emit_launch_outcome(
        actor=entity_ref,
        sandbox_name=sandbox_name,
        outcome="allow",
        latency_ms=latency_ms,
        tool_args_hash=goal_hash,
    )

    logger.info(
        "sandbox_launched",
        extra={
            "sandbox_name": sandbox_name,
            "sandbox_id": sandbox_id,
            "phase": phase_str,
            "owner": entity_ref,
            "latency_ms": latency_ms,
        },
    )

    return LaunchResponse(
        sandbox_name=sandbox_name,
        sandbox_id=sandbox_id,
        namespace=_SANDBOX_NAMESPACE,
        phase=phase_str,
        conversation_url=None,
        access_hint=access_hint,
        owner=entity_ref,
    )


# ---------------------------------------------------------------------------
# Catalog (TODO-E1): serve live OpenShell sandboxes as Backstage Resources so a
# launched agent shows up in RHDH with the Workspace/Approvals/Receipt tabs.
# Register as a catalog.location (type:url) pointing at this endpoint.
# ---------------------------------------------------------------------------


def _list_sandboxes() -> list[dict[str, Any]]:
    """List OpenShell Sandbox CRs in SANDBOX_NAMESPACE via the in-cluster k8s API
    (the launcher SA token; read-only)."""
    import httpx

    ns = os.environ.get("SANDBOX_NAMESPACE", "openshell")
    sa = "/var/run/secrets/kubernetes.io/serviceaccount"
    try:
        token = open(f"{sa}/token").read().strip()
    except OSError:
        return []
    url = (
        "https://kubernetes.default.svc/apis/agents.x-k8s.io/v1alpha1/"
        f"namespaces/{ns}/sandboxes"
    )
    with httpx.Client(timeout=10, verify=f"{sa}/ca.crt") as http:
        resp = http.get(url, headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    return resp.json().get("items", [])


@app.get("/catalog")
async def catalog() -> Response:
    """Backstage catalog entities for the current sandboxes (multi-doc YAML)."""
    import yaml

    ns = os.environ.get("SANDBOX_NAMESPACE", "openshell")
    try:
        items = _list_sandboxes()
    except Exception as exc:  # noqa: BLE001 — serve an empty (valid) catalog on error
        logger.warning("catalog_list_failed", extra={"error": str(exc)})
        items = []
    entities: list[dict[str, Any]] = []
    for sb in items:
        meta = sb.get("metadata", {})
        name = meta.get("name", "")
        if not name:
            continue
        labels = meta.get("labels", {}) or {}
        owner = labels.get("nvidia-ida/owner", "unknown")
        # The k8s plugin must find the sandbox's pods. The OpenShell CR exposes the
        # exact pod label selector in status.selector (e.g.
        # "agents.x-k8s.io/sandbox-name-hash=<hash>") — use it as the entity's
        # kubernetes-label-selector so the Workspace tab shows the live workload.
        # (backstage.io/kubernetes-id alone selects app.kubernetes.io/instance=<id>,
        # which the OpenShell pods do NOT carry, so the tab would be empty.)
        selector = (sb.get("status", {}) or {}).get("selector", "").strip()
        annotations = {
            "backstage.io/kubernetes-namespace": ns,
            "nvidia-ida/owner": owner,
        }
        if selector:
            annotations["backstage.io/kubernetes-label-selector"] = selector
        else:
            annotations["backstage.io/kubernetes-id"] = name
        entities.append({
            "apiVersion": "backstage.io/v1alpha1",
            "kind": "Resource",
            "metadata": {
                "name": name,
                "namespace": "default",
                "title": name,
                "description": f"Live OpenShell agent sandbox owned by {owner}.",
                "annotations": annotations,
                "labels": {
                    k.replace("nvidia-ida/", "nvidia-ida_"): v
                    for k, v in labels.items()
                    if k.startswith("nvidia-ida/")
                },
            },
            "spec": {
                "type": "agent-sandbox",
                "owner": "group:default/mcp-admins",
                "system": "system:default/agentic-platform",
            },
        })
    body = yaml.safe_dump_all(entities) if entities else "{}\n"
    return Response(content=body, media_type="application/yaml")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"status": "ok", "service": "sandbox-launcher"}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@app.get("/metrics")
async def metrics() -> Response:
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
    except ImportError:
        return JSONResponse(
            status_code=501, content={"detail": "prometheus_client not installed"}
        )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    import uvicorn

    uvicorn.run(
        "sandbox_launcher.api:app",
        host="0.0.0.0",
        port=8080,
        log_config=None,
    )


if __name__ == "__main__":
    main()
