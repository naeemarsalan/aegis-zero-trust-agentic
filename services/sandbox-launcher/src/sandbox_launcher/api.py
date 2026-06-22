"""FastAPI application — sandbox-launcher REST API.

Endpoints:
  POST /launch   — provision an OpenShell packaged-agent sandbox
  GET  /healthz  — liveness probe
  GET  /metrics  — Prometheus metrics (optional)

Auth contract (§ design brief):
  Accepts tokens from two issuers:
    1. RHDH (Backstage) — RHDH_JWKS_URL + RHDH_TOKEN_ISSUER
    2. Keycloak          — KEYCLOAK_ISSUER (+ optional KEYCLOAK_JWKS_URL,
                           KEYCLOAK_JWKS_CA)

  The launcher:
    1. Extracts Authorization: Bearer <token> from the request.
    2. Tries each configured issuer's JWKS (fail-closed on all failing).
    3. Extracts the user entity ref using the matching issuer's strategy.
    4. Cross-checks against body.user. Returns 403 on mismatch.
    5. Discards the token — it is NEVER logged, stored, or forwarded.

  If the Authorization header is ABSENT:
    - Default (LAUNCHER_ALLOW_UNVERIFIED unset or "false"): 401 FAIL-CLOSED.
      The launcher is exposed via a public Route; unauthenticated access must
      be rejected.
    - LAUNCHER_ALLOW_UNVERIFIED=true: advisory fallback to body.user (dev
      escape hatch only; never use in production).

  The launcher then calls the OpenShell gateway using its OWN OIDC
  client-credentials token (LAUNCHER_OIDC_*). This is the NO-CREDENTIAL-PASSING
  invariant: the user's token is verified once to establish identity, then
  discarded. The gateway sees only the launcher's service identity.

Grant write (Option-D zero-trust flow):
  After CreateSandbox succeeds, the launcher writes a CONSENT GRANT (not a
  credential) to Vault KV-v2 at secret/data/sandbox-grants/<sandbox-uid>.
  The grant carries {user, scope, ttl, nonce, created, sandbox_uid, version}.
  The in-sandbox agent authenticates with its OWN SPIFFE JWT-SVID; ext-proc
  reads the grant to resolve on-behalf-of identity for RFC 8693 token exchange.
  The user's original token is NEVER stored — only the grant consent record.

NO-CREDENTIAL-PASSING invariant locations:
  - _extract_and_verify_caller() discards token after entity-ref extraction
  - openshell.create_sandbox() uses _launcher_auth_metadata() exclusively
  - audit.emit_launch_attempt() hashes the goal; never logs the token
  - vault.build_grant() validates that no credential field appears in the grant
  - audit.emit_grant_write() hashes grant identity fields; never logs the nonce value
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
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

# Finding 3: platform-wide upper bound on grant validity, matching the JIT
# approver's 60-minute session ceiling. Applied server-side independent of the
# user-supplied ttl_minutes value so the launcher cannot be coerced into writing
# a grant with an arbitrarily long validity window.
MAX_GRANT_TTL_SECONDS: int = int(os.environ.get("MAX_GRANT_TTL_SECONDS", "3600"))


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


def _allow_unverified() -> bool:
    """Return True only when the dev escape hatch is explicitly enabled.

    LAUNCHER_ALLOW_UNVERIFIED=true permits requests without an Authorization
    header to proceed with advisory identity (body.user, is_verified=False).
    Default is False — the launcher is exposed via a public Route so the
    unauthenticated fallback MUST be closed in normal operation.
    """
    return os.environ.get("LAUNCHER_ALLOW_UNVERIFIED", "false").strip().lower() == "true"


def _extract_and_verify_caller(request: Request, body_user: str) -> tuple[str, bool]:
    """Verify the caller's Bearer token and return (entity_ref, is_verified).

    Accepts tokens from any configured issuer (RHDH or Keycloak); see auth.py.

    Returns:
        (entity_ref, True)   when the JWT is present and verifies.
        (body_user, False)   when the JWT is absent AND LAUNCHER_ALLOW_UNVERIFIED=true.

    Raises:
        HTTPException(401)  if the JWT is absent and the escape hatch is off
                            (default), if the header is malformed, or if all
                            configured issuers reject the token.
        HTTPException(403)  if the JWT is valid but entity_ref mismatches body.user.
        HTTPException(503)  if no auth issuer is configured (mis-deployment).

    NO-CREDENTIAL-PASSING: the raw token string is NEVER logged, stored, or
    forwarded. It is discarded after claim extraction.
    """
    from sandbox_launcher.auth import extract_entity_ref, verify_caller_token

    auth_header: str = request.headers.get("Authorization", "")

    if not auth_header:
        if _allow_unverified():
            logger.warning(
                "caller_token_absent_advisory",
                extra={
                    "body_user": body_user,
                    "note": "LAUNCHER_ALLOW_UNVERIFIED=true; using advisory identity",
                },
            )
            return body_user, False
        audit.emit_auth_failure("unknown", "Authorization header absent")
        raise HTTPException(
            status_code=401,
            detail="Authorization header required — sandbox-launcher is publicly routed",
        )

    if not auth_header.lower().startswith("bearer "):
        audit.emit_auth_failure("unknown", "malformed Authorization header")
        raise HTTPException(status_code=401, detail="Authorization header must be Bearer token")

    # Fix (2): Token size bound — reject oversized tokens before any crypto work.
    # 8 192 bytes is generous for a realistic RS256/ES256 JWT with standard claims.
    # Oversized tokens are a DoS vector on the public Route (signature eval is O(n)).
    _TOKEN_MAX_BYTES = 8192
    token = auth_header[7:]  # strip "Bearer "
    if len(token.encode("utf-8")) > _TOKEN_MAX_BYTES:
        audit.emit_auth_failure("unknown", "bearer token exceeds maximum size")
        raise HTTPException(
            status_code=401,
            detail="Authorization token exceeds maximum allowed size",
        )

    try:
        claims, issuer_kind = verify_caller_token(token)
    except ValueError as exc:
        # All configured issuers rejected the token — fail closed.
        audit.emit_auth_failure("unknown", f"token verification failed: {exc}")
        raise HTTPException(status_code=401, detail=f"Token verification failed: {exc}") from exc
    except RuntimeError as exc:
        # No issuers configured — mis-deployment, not a caller fault.
        logger.error("auth_not_configured", extra={"error": str(exc)})
        raise HTTPException(status_code=503, detail="Auth service not configured") from exc

    try:
        entity_ref = extract_entity_ref(claims, issuer_kind)
    except ValueError as exc:
        audit.emit_auth_failure("unknown", f"entity ref extraction failed: {exc}")
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    # Fix (1): Full entity-ref cross-check.
    # Compare the FULL normalized entity ref (kind:namespace/name), not just the
    # trailing name segment.  This prevents a token for "user:default/bob" from
    # satisfying a body.user of "user:admin/bob" (different namespace) or a token
    # for "group:default/bob" from satisfying a user ref.  Normalize to lowercase
    # once so minor case variations (e.g. "User:Default/Bob") are still accepted.
    normalized_token_ref = entity_ref.lower()
    normalized_body_ref = body_user.lower()
    if normalized_token_ref != normalized_body_ref:
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

    # Token is consumed — discard reference so it cannot be forwarded or logged.
    del token, claims
    return entity_ref, True


# ---------------------------------------------------------------------------
# Grant helpers
# ---------------------------------------------------------------------------


def _bare_username(entity_ref: str) -> str:
    """Extract the bare username from an entity ref for Keycloak impersonation.

    Keycloak Phase-1 impersonation (RFC 8693 requested_subject) expects the
    bare preferred_username (e.g. "arsalan"), not the full entity ref
    (e.g. "user:default/arsalan").  The trailing segment after the last '/'
    is used.  If the ref has no '/', the whole string is returned.

    Examples:
        "user:default/arsalan" -> "arsalan"
        "arsalan"              -> "arsalan"
    """
    return entity_ref.rsplit("/", 1)[-1]


def _write_grant(
    actor: str,
    sandbox_uid: str,
    sandbox_name: str,
    scope: str,
    ttl_seconds: int,
    t0: float,
    goal_hash: str,
) -> None:
    """Build and write the consent grant to Vault.  Fail-closed on any error.

    Raises HTTPException(502) if Vault is unreachable or the grant write fails.
    Raises HTTPException(500) if the grant schema is invalid (coding error).

    The user identity written into the grant is the BARE username (trailing
    segment of the entity ref) so ext-proc can use it directly as
    RFC 8693 requested_subject for Keycloak Phase-1 impersonation.

    When VAULT_ADDR is unset or when the sandbox_uid is empty (happens in dev
    when the OpenShell stub returns a mock with no id), the write is skipped
    with a warning rather than failing the launch.  This keeps the dev/test
    path unblocked while the prod path is fail-closed.
    """
    from sandbox_launcher import audit, vault

    # Dev / test escape: if sandbox_uid is empty the KV path would be
    # secret/data/sandbox-grants/ (no key) which is invalid.  Log and skip.
    if not sandbox_uid:
        logger.warning(
            "grant_write_skipped_no_sandbox_uid",
            extra={"sandbox_name": sandbox_name, "actor": actor},
        )
        return

    # Dev escape: if VAULT_ADDR is explicitly set to "" or "disabled", skip.
    vault_addr = os.environ.get("VAULT_ADDR", "").strip()
    if vault_addr.lower() in ("", "disabled"):
        logger.warning(
            "grant_write_skipped_vault_disabled",
            extra={"sandbox_uid": sandbox_uid, "actor": actor},
        )
        return

    grant_t0 = time.monotonic()
    bare_user = _bare_username(actor)

    try:
        grant = vault.build_grant(
            sandbox_uid=sandbox_uid,
            user=bare_user,
            scope=scope,
            ttl_seconds=ttl_seconds,
        )
    except ValueError as exc:
        # build_grant raises ValueError on schema violations — this is a coding
        # error, not a transient failure.  Log and surface as 500.
        logger.error(
            "grant_build_failed",
            extra={"sandbox_uid": sandbox_uid, "error": str(exc)},
        )
        audit.emit_grant_write(
            actor=actor,
            sandbox_uid=sandbox_uid,
            sandbox_name=sandbox_name,
            grant_scope=scope,
            grant_user=bare_user,
            grant_ttl=ttl_seconds,
            grant_nonce_present=False,
            outcome="error",
            latency_ms=int((time.monotonic() - grant_t0) * 1000),
            reason=f"grant_build_failed: {exc}",
        )
        raise HTTPException(
            status_code=500,
            detail=f"Grant build failed (coding error): {exc}",
        ) from exc

    try:
        vault.write_sandbox_grant(sandbox_uid=sandbox_uid, grant=grant)
    except Exception as exc:  # noqa: BLE001 — Vault errors are all RuntimeError / httpx errors
        # Log full exception server-side (never returned to the caller).
        logger.error(
            "grant_write_failed",
            extra={"sandbox_uid": sandbox_uid, "error": str(exc), "exc_type": type(exc).__name__},
        )
        audit.emit_grant_write(
            actor=actor,
            sandbox_uid=sandbox_uid,
            sandbox_name=sandbox_name,
            grant_scope=scope,
            grant_user=bare_user,
            grant_ttl=ttl_seconds,
            grant_nonce_present=bool(grant.get("nonce")),
            outcome="error",
            latency_ms=int((time.monotonic() - grant_t0) * 1000),
            reason=f"vault_write_failed: {type(exc).__name__}",
        )
        # Finding 2: return a GENERIC detail to the client; never expose raw
        # exception text (which can contain X-Vault-Token / internal addresses).
        raise HTTPException(
            status_code=502,
            detail="grant write failed",
        ) from exc

    audit.emit_grant_write(
        actor=actor,
        sandbox_uid=sandbox_uid,
        sandbox_name=sandbox_name,
        grant_scope=scope,
        grant_user=bare_user,
        grant_ttl=ttl_seconds,
        grant_nonce_present=bool(grant.get("nonce")),
        outcome="allow",
        latency_ms=int((time.monotonic() - grant_t0) * 1000),
    )
    logger.info(
        "grant_written",
        extra={
            "sandbox_uid": sandbox_uid,
            "grant_scope": scope,
            "grant_user": bare_user,
            "grant_nonce_present": True,
        },
    )


# ---------------------------------------------------------------------------
# POST /launch
# ---------------------------------------------------------------------------


def _boot_brain_when_ready(
    sandbox_id: str,
    sandbox_name: str,
    goal: str,
    allowed_tools: str,
) -> None:
    """Background task: wait for the sandbox to reach READY, then boot the brain
    natively via ExecSandbox (the gateway reserves OPENSHELL_SANDBOX_COMMAND, so the
    runner cannot be the boot command — it is exec'd into the ready sandbox instead).

    Fully best-effort: any failure here is logged and swallowed. It never affects the
    202 already returned to the caller; the sandbox stays a usable interactive shell.
    Bounded poll (default ~5 min) so a sandbox that never goes Ready can't hang a worker.
    """
    import time as _time

    from sandbox_launcher import openshell

    try:
        deadline = _time.monotonic() + float(
            os.environ.get("BRAIN_BOOT_READY_TIMEOUT_S", "300")
        )
        interval = float(os.environ.get("BRAIN_BOOT_POLL_INTERVAL_S", "5"))
        ready = False
        while _time.monotonic() < deadline:
            try:
                phase = openshell.get_sandbox_phase(sandbox_name)
            except Exception as exc:  # noqa: BLE001 — best-effort poll
                logger.warning(
                    "brain_boot_phase_poll_error",
                    extra={"sandbox_id": sandbox_id, "error": str(exc)},
                )
                phase = ""
            if phase == "READY":
                ready = True
                break
            if phase == "ERROR":
                logger.warning(
                    "brain_boot_abort_sandbox_error",
                    extra={"sandbox_id": sandbox_id, "sandbox_name": sandbox_name},
                )
                return
            _time.sleep(interval)

        if not ready:
            logger.warning(
                "brain_boot_timeout_not_ready",
                extra={"sandbox_id": sandbox_id, "sandbox_name": sandbox_name},
            )
            return

        # SVID-FETCH GATE / DIAGNOSTIC (2026-06-21, round 4 — TRUE ROOT CAUSE found):
        # The round-1..3 story (a SPIRE propagation race + py-spiffe in-process
        # poisoning) was a MISDIAGNOSIS. Proven live this round: the per-sandbox SVID
        # is fetchable the WHOLE time (a fresh ``oc exec`` in the agent container
        # returns the 710-char UUID SVID immediately) — what fails is the GATEWAY's
        # ExecSandbox boot path itself. The gateway/supervisor 0.0.62 ExecSandbox enters
        # the container via a confined ``setns`` and mounts an EMPTY 4k tmpfs OVER
        # ``/spiffe-workload-api`` (proven: /proc/self/mountinfo shows an extra
        # ``0:3874 / /spiffe-workload-api ro …size=4k,mode=555`` on top of the real
        # SPIRE socket tmpfs that PID1 sees), so ANY ExecSandbox-booted process —
        # the brain AND every subprocess it spawns — sees ``spire-agent.sock`` MISSING
        # and can never reach the Workload API. No retry/settle/gate can change that;
        # the socket is structurally masked from the exec mount namespace. The brain's
        # FILE-SVID fallback also can't help today: the spiffe-helper sidecar writes
        # SVIDs to volumes (svid-output ``/opt`` + shared-data ``/shared``) that the
        # AGENT container does NOT mount, and only for the Kagenti audience — there is
        # no shared, agent-visible path carrying an ``mcp-gateway``-audience JWT-SVID.
        #
        # So this probe NO LONGER gates a long wait (it would just burn latency on a
        # condition that can never flip under ExecSandbox). It runs ONCE as ground-truth
        # diagnostics: a positive result means a future fix (un-masking the socket, or a
        # shared file path) has landed and the brain can run autonomously; a negative
        # result is the expected current state and is logged loudly so the blocker is
        # visible in the launch audit. We then boot the brain regardless (no regression
        # vs prior rounds; the sandbox is still a usable interactive shell, and an
        # operator can drive the proven byte-identical ``oc exec`` brain boot manually).
        # Set BRAIN_BOOT_SVID_PROBE_TIMEOUT_S>0 to re-enable polling once a real fix is
        # in (e.g. after the spiffe-helper writes an mcp-gateway SVID to /sandbox).
        floor = float(os.environ.get("BRAIN_BOOT_SVID_SETTLE_S", "5"))
        if floor > 0:
            logger.info(
                "brain_boot_svid_floor_settle",
                extra={"sandbox_id": sandbox_id, "floor_s": floor},
            )
            _time.sleep(floor)

        probe_deadline = _time.monotonic() + float(
            os.environ.get("BRAIN_BOOT_SVID_PROBE_TIMEOUT_S", "0")
        )
        probe_interval = float(os.environ.get("BRAIN_BOOT_SVID_PROBE_INTERVAL_S", "5"))
        svid_ready = False
        probe_attempt = 0
        while True:
            probe_attempt += 1
            try:
                svid_ready = openshell.probe_agent_svid(sandbox_id=sandbox_id)
            except Exception as exc:  # noqa: BLE001 — probe is best-effort diagnostics
                logger.warning(
                    "brain_boot_svid_probe_error",
                    extra={"sandbox_id": sandbox_id, "attempt": probe_attempt, "error": str(exc)},
                )
                svid_ready = False
            if svid_ready:
                logger.info(
                    "brain_boot_svid_probe_positive",
                    extra={"sandbox_id": sandbox_id, "attempt": probe_attempt},
                )
                break
            logger.info(
                "brain_boot_svid_probe_negative",
                extra={"sandbox_id": sandbox_id, "attempt": probe_attempt},
            )
            if _time.monotonic() >= probe_deadline:
                break
            _time.sleep(probe_interval)

        if not svid_ready:
            logger.warning(
                "brain_boot_svid_unreachable_known_blocker_booting_anyway",
                extra={
                    "sandbox_id": sandbox_id,
                    "attempts": probe_attempt,
                    "blocker": (
                        "gateway ExecSandbox masks /spiffe-workload-api (empty 4k tmpfs "
                        "overlay) so the brain cannot reach the SPIRE Workload API socket; "
                        "no agent-visible mcp-gateway-audience SVID file exists either. "
                        "Autonomous brain cannot fetch its SVID via ExecSandbox — needs an "
                        "operator/webhook fix (see ADR / worklog). Booting as interactive "
                        "shell; manual oc-exec brain boot still works."
                    ),
                },
            )

        # LLM-reachability gate (2026-06-22, round-5): the gateway applies the
        # per-sandbox baseline egress policy ~1-2 min AFTER the pod is Ready. The
        # baseline now allows the LiteLLM endpoint (172.16.2.251:4000), but if the
        # one-shot brain fires its first request before the policy settles, the
        # gateway forward proxy returns 403 policy_denied and the brain dies before
        # its gw-403 retry budget (≈48s) can outlast the window. So gate the boot on
        # a fresh-process probe that curls the LLM through the proxy until it returns
        # 200 (policy settled) — the same fresh-ExecSandbox channel pattern as the
        # SVID probe. Bounded; on timeout we boot anyway (the gw-403 retry then has a
        # chance, and an operator can drive the manual oc-exec brain).
        llm_floor = float(os.environ.get("BRAIN_BOOT_LLM_SETTLE_S", "0"))
        if llm_floor > 0:
            _time.sleep(llm_floor)
        llm_deadline = _time.monotonic() + float(
            os.environ.get("BRAIN_BOOT_LLM_PROBE_TIMEOUT_S", "180")
        )
        llm_interval = float(os.environ.get("BRAIN_BOOT_LLM_PROBE_INTERVAL_S", "8"))
        llm_ready = False
        llm_attempt = 0
        while True:
            llm_attempt += 1
            try:
                llm_ready = openshell.probe_llm_reachable(sandbox_id=sandbox_id)
            except Exception as exc:  # noqa: BLE001 — probe is best-effort
                logger.warning(
                    "brain_boot_llm_probe_error",
                    extra={"sandbox_id": sandbox_id, "attempt": llm_attempt, "error": str(exc)},
                )
                llm_ready = False
            if llm_ready:
                logger.info(
                    "brain_boot_llm_probe_positive",
                    extra={"sandbox_id": sandbox_id, "attempt": llm_attempt},
                )
                break
            logger.info(
                "brain_boot_llm_probe_negative",
                extra={"sandbox_id": sandbox_id, "attempt": llm_attempt},
            )
            if _time.monotonic() >= llm_deadline:
                logger.warning(
                    "brain_boot_llm_unreachable_booting_anyway",
                    extra={
                        "sandbox_id": sandbox_id,
                        "attempts": llm_attempt,
                        "note": (
                            "LLM still policy_denied through the gateway egress proxy "
                            "after the probe deadline; the baseline inference endpoint "
                            "(172.16.2.251:4000) may not have settled. Booting anyway — "
                            "the brain gw-403 retry may still recover."
                        ),
                    },
                )
                break
            _time.sleep(llm_interval)

        exit_code = openshell.exec_agent_brain(
            sandbox_id=sandbox_id,
            goal=goal,
            allowed_tools=allowed_tools,
            timeout_seconds=int(os.environ.get("BRAIN_EXEC_TIMEOUT_S", "0")),
        )
        logger.info(
            "brain_boot_completed",
            extra={
                "sandbox_id": sandbox_id,
                "sandbox_name": sandbox_name,
                "exit_code": exit_code,
            },
        )
    except Exception as exc:  # noqa: BLE001 — best-effort; never break the launch
        logger.warning(
            "brain_boot_background_failed",
            extra={"sandbox_id": sandbox_id, "error": str(exc)},
        )


@app.post("/launch", status_code=202)
async def launch(
    request: Request, body: LaunchRequest, background_tasks: BackgroundTasks
) -> LaunchResponse:
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
            # Thread the user's goal into the sandbox as AGENT_GOAL so the
            # brain-enabled runner has work to do (see openshell._brain_env).
            goal=body.goal,
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
        # Log full exception server-side (never returned to the caller).
        logger.error(
            "openshell_create_sandbox_failed",
            extra={"sandbox_name": name, "error": str(exc), "exc_type": type(exc).__name__},
        )
        audit.emit_launch_outcome(
            actor=entity_ref,
            sandbox_name=name,
            outcome="error",
            latency_ms=int((time.monotonic() - t0) * 1000),
            tool_args_hash=goal_hash,
        )
        # Finding 2: return a GENERIC detail to the client; never expose raw
        # exception text (which may contain internal addresses or grpc metadata).
        raise HTTPException(status_code=502, detail="sandbox backend error") from exc

    sandbox_name = resp.sandbox.metadata.name or name
    sandbox_id = resp.sandbox.metadata.id or ""
    phase_int = resp.sandbox.status.phase
    # Proto-derived name (see openshell.phase_name) — never drifts from the wire enum.
    phase_str = openshell.phase_name(phase_int)

    # Step 4b: Write consent grant to Vault (Option-D zero-trust flow).
    # The grant is a CONSENT RECORD keyed by sandbox UID — it is NOT a credential.
    # The user's JWT has already been discarded; only the verified identity string
    # (entity_ref) is carried forward into the grant's 'user' field.
    # The bare username (trailing segment after '/') is what Keycloak impersonation
    # expects as requested_subject in Phase-1 RFC 8693 token exchange.
    # Fail-closed: if we cannot write the grant, the agent will not be able to
    # authenticate through ext-proc, so we surface a 502 rather than launch a
    # sandbox that is unreachable.
    # Finding 3: clamp the grant TTL to the platform maximum independent of the
    # user-supplied ttl_minutes. A user cannot extend their grant beyond the
    # platform ceiling by supplying a large ttl_minutes value.
    effective_ttl_seconds = min(body.ttl_minutes * 60, MAX_GRANT_TTL_SECONDS)
    _write_grant(
        actor=entity_ref,
        sandbox_uid=sandbox_id,
        sandbox_name=sandbox_name,
        scope=body.scope.value,
        ttl_seconds=effective_ttl_seconds,
        t0=t0,
        goal_hash=goal_hash,
    )

    latency_ms = int((time.monotonic() - t0) * 1000)

    # Step 5: build response — the agent pod is named after the sandbox.
    access_hint = f"oc -n {_SANDBOX_NAMESPACE} exec -it {sandbox_name} -c agent -- /bin/sh"

    # Persist scope/ttl/owner + the shell access hint onto the Sandbox CR so the
    # RHDH Agent Workspace card (which reads them via /catalog as entity
    # labels/annotations) shows LIVE values instead of placeholders (TODO-D3).
    # Best-effort: needs sandboxes patch RBAC; a failure just leaves the card on
    # its defaults and never blocks the launch.
    _patch_sandbox_meta(
        sandbox_name,
        labels={
            "nvidia-ida/scope": body.scope.value,
            "nvidia-ida/ttl-minutes": str(body.ttl_minutes),
            "nvidia-ida/owner": openshell._sanitize_label_value(entity_ref),
            "nvidia-ida/mode": body.mode.value,
        },
        annotations={"nvidia-ida/access-hint": access_hint},
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

    # Native brain boot: the sandbox is created on the gateway-fixed sleep-infinity
    # command (OPENSHELL_SANDBOX_COMMAND is reserved/rejected at CreateSandbox); the
    # agent-harness runner is exec'd INTO the ready sandbox via ExecSandbox. Scheduled
    # as a background task so /launch still returns 202 immediately; fully best-effort.
    if (
        sandbox_id
        and openshell._brain_boot_enabled()
        and openshell.available()
    ):
        background_tasks.add_task(
            _boot_brain_when_ready,
            sandbox_id=sandbox_id,
            sandbox_name=sandbox_name,
            goal=body.goal,
            allowed_tools=os.environ.get("AGENT_ALLOWED_TOOLS", "Bash").strip() or "Bash",
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


def _patch_sandbox_meta(
    name: str, labels: dict[str, str], annotations: dict[str, str]
) -> None:
    """Best-effort merge-patch of labels/annotations onto a Sandbox CR via the k8s
    API, so /catalog can read back scope/ttl/owner/access-hint for the Workspace
    card. Requires sandboxes 'patch' RBAC; any failure is logged and swallowed and
    never blocks a launch."""
    import httpx

    ns = os.environ.get("SANDBOX_NAMESPACE", "openshell")
    sa = "/var/run/secrets/kubernetes.io/serviceaccount"
    try:
        token = open(f"{sa}/token").read().strip()
    except OSError:
        return
    url = (
        "https://kubernetes.default.svc/apis/agents.x-k8s.io/v1alpha1/"
        f"namespaces/{ns}/sandboxes/{name}"
    )
    patch = {"metadata": {"labels": labels, "annotations": annotations}}
    try:
        with httpx.Client(timeout=10, verify=f"{sa}/ca.crt") as http:
            r = http.patch(
                url,
                json=patch,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/merge-patch+json",
                },
            )
        if r.status_code >= 300:
            logger.warning(
                "sandbox_meta_patch_failed",
                extra={"sandbox": name, "code": r.status_code, "body": r.text[:200]},
            )
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning("sandbox_meta_patch_error", extra={"sandbox": name, "error": str(exc)})


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
        cr_ann = meta.get("annotations", {}) or {}
        status = sb.get("status", {}) or {}
        owner = labels.get("nvidia-ida/owner", "unknown")
        # The k8s plugin must find the sandbox's pods. The OpenShell CR exposes the
        # exact pod label selector in status.selector (e.g.
        # "agents.x-k8s.io/sandbox-name-hash=<hash>") — use it as the entity's
        # kubernetes-label-selector so the Workspace tab shows the live workload.
        selector = status.get("selector", "").strip()
        # Real phase for the Agent Workspace card (was hard-defaulting to PROVISIONING):
        # prefer status.phase, else derive from the Ready condition.
        phase = status.get("phase")
        if not phase:
            conds = {c.get("type"): c.get("status") for c in status.get("conditions", [])}
            phase = "READY" if conds.get("Ready") == "True" else "PROVISIONING"
        annotations = {
            "backstage.io/kubernetes-namespace": ns,
            "nvidia-ida/owner": owner,
            "nvidia-ida/phase": str(phase),
        }
        annotations["backstage.io/kubernetes-label-selector" if selector else "backstage.io/kubernetes-id"] = (
            selector or name
        )
        # Pass through the shell access hint the launcher patched onto the CR (TODO-D3).
        if cr_ann.get("nvidia-ida/access-hint"):
            annotations["nvidia-ida/access-hint"] = cr_ann["nvidia-ida/access-hint"]
        entities.append({
            "apiVersion": "backstage.io/v1alpha1",
            "kind": "Resource",
            "metadata": {
                "name": name,
                "namespace": "default",
                "title": name,
                "description": f"Live OpenShell agent sandbox owned by {owner}.",
                "annotations": annotations,
                # Keep the nvidia-ida/ label keys verbatim — the Agent Workspace card
                # reads labels['nvidia-ida/scope'] and ['nvidia-ida/ttl-minutes'].
                "labels": {
                    k: v for k, v in labels.items() if k.startswith("nvidia-ida/")
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
