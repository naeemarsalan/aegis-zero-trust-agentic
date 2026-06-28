"""FastAPI application — JIT approver REST API.

Endpoints:
  POST /requests                    — submit escalation request -> 202 {id, pr_url}
  GET  /requests/{id}/status        — poll session state; once issued, also returns
                                      session_jwt + sa_token (UC2 credential delivery)
  POST /requests/{id}/mint          — console-side mint gate (L1): console POSTs
                                      {approver_sub, scope_hash} here; enforces M5
                                      SoD (approver_sub != requester_sub), scope-hash
                                      anti-TOCTOU, and once-only issuance.
  POST /requests/{id}/summary       — agent posts post-session summary
  GET  /jwks                        — public RS256 keys for the session JWT (N1)
  GET  /healthz                     — liveness probe
  GET  /metrics                     — Prometheus metrics (optional)
  POST /webhooks/gitea              — Gitea webhook (see webhook.py)
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from jit_approver import audit, ledger
from jit_approver.gitea import create_approval_pr
from jit_approver.mint_core import _atomic_issue, _enforce_dual_control, _verify_scope_hash
from jit_approver.models import (
    EscalationRequest,
    MintRequest,
    SessionState,
    SessionStatus,
    SessionSummary,
    canonical_scope_hash,
)
from jit_approver.persistence import get_store
from jit_approver.store import session_store
from jit_approver.webhook import router as webhook_router

logger = logging.getLogger("jit_approver.api")

# ---------------------------------------------------------------------------
# Module-level store handle (set during lifespan startup)
# ---------------------------------------------------------------------------
_store_backend: str = "memory"
_store_ready: bool = True  # in-memory is always ready

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(_app: "FastAPI"):
    """App lifespan: store startup check + reaper loop (N3).

    L0 addition: call store.startup_check() on startup so a misconfigured
    durable backend (missing tables, unreachable DB) crashloops the pod
    immediately rather than failing mid-request.  In-memory mode this is a
    no-op.  The store_backend field in /healthz reflects what was discovered.
    """
    import asyncio
    import os as _os

    global _store_backend, _store_ready

    # L0: initialise and health-check the configured store backend.
    try:
        _backend = _os.environ.get("JIT_STORE_BACKEND", "memory").strip().lower()
        _store_backend = _backend
        _store_ready = False
        store = get_store()
        await store.startup_check()
        _store_ready = True
        logger.info("store_backend_ready", extra={"backend": _store_backend})
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "store_backend_startup_failed",
            extra={"backend": _store_backend, "error": str(exc)},
        )
        # Re-raise so FastAPI/uvicorn marks the pod not-ready (fail closed).
        raise

    task = None
    stop = None
    if not _os.environ.get("JIT_DISABLE_REAPER"):
        from jit_approver.reaper import reaper_loop

        stop = asyncio.Event()
        task = asyncio.create_task(reaper_loop(stop_event=stop))
    else:
        logger.info("reaper_disabled_by_env")

    try:
        yield
    finally:
        if stop is not None:
            stop.set()
        if task is not None:
            try:
                await task
            except Exception:  # noqa: BLE001
                pass


app = FastAPI(
    title="JIT Approver",
    description="Just-in-time Kubernetes credential escalation via Gitea PR approval",
    version="0.1.0",
    lifespan=_lifespan,
)

app.include_router(webhook_router)


@app.exception_handler(RequestValidationError)
async def _on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Audit ceiling rejections at the API edge (H5 — validation-rejection path).

    A 422 on POST /requests means the scope ceiling refused the request before
    any Gitea/Vault call. There is no session yet, so we audit a denial keyed by
    the path so the most security-relevant edge rejection is on the audit trail.
    Behaviour (422 + error body) is otherwise unchanged.
    """
    from fastapi.encoders import jsonable_encoder

    if request.url.path == "/requests":
        audit.emit_denied("pre-session", f"request rejected by scope ceiling: {exc.errors()}")
        await ledger.record({
            "event": "jit_denied",
            "session_id": "pre-session",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reason": "request rejected by scope ceiling",
        })
    return JSONResponse(status_code=422, content=jsonable_encoder({"detail": exc.errors()}))


# ---------------------------------------------------------------------------
# POST /requests
# ---------------------------------------------------------------------------


@app.post("/requests", status_code=202)
async def create_request(req: EscalationRequest) -> dict[str, str]:
    """Submit a JIT escalation request.

    Validates scope (verbs, resources, namespace, duration ceiling), creates a
    Gitea branch + commit + PR, and returns 202 with the session ID and PR URL.
    The request is in 'pending' state until the PR is merged.
    """
    session_id = str(uuid.uuid4())

    audit.emit_request(
        session_id=session_id,
        requester_sub=req.requester_sub,
        namespace=req.namespace,
        verbs=req.verbs,
        resources=req.resources,
        justification=req.justification,
    )
    await ledger.record({
        "event": "jit_request",
        "session_id": session_id,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "requester_sub": req.requester_sub,
        "namespace": req.namespace,
        "verbs": req.verbs,
        "resources": req.resources,
        "justification_hash": audit._hash(req.justification),
    })

    # Create Gitea PR
    try:
        pr_url = await create_approval_pr(session_id=session_id, req=req)
    except Exception as exc:  # noqa: BLE001
        logger.error("create_pr_failed", extra={"session_id": session_id, "error": str(exc)})
        raise HTTPException(status_code=502, detail=f"Failed to create Gitea PR: {exc}") from exc

    # Store session
    session_store[session_id] = {
        "id": session_id,
        "state": SessionState.pending.value,
        "pr_url": pr_url,
        "pr_number": _extract_pr_number(pr_url),
        "expires_at": None,
        "request": req,
    }

    logger.info("jit_request_created", extra={"session_id": session_id, "pr_url": pr_url})
    return {"id": session_id, "pr_url": pr_url}


def _extract_pr_number(pr_url: str) -> int | None:
    """Extract PR number from Gitea PR URL like .../pulls/42."""
    try:
        return int(pr_url.rstrip("/").rsplit("/", 1)[-1])
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# GET /requests/{id}/status
# ---------------------------------------------------------------------------


@app.get("/requests/{session_id}/status")
async def get_status(session_id: str) -> SessionStatus:
    """Return the current state of a JIT session.

    Credential delivery (UC2): when (and only when) state==issued, this response
    carries BOTH the session JWT (presented as X-JIT-Session-JWT to clear the
    Kyverno dangerous-tool gate) and the ephemeral SA token (which the agent
    wields to act). They are delivered over the authenticated SVID-mTLS channel
    and are NEVER returned in any other state.
    """
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    state = SessionState(session["state"])
    issued = state == SessionState.issued

    return SessionStatus(
        id=session_id,
        state=state,
        pr_url=session.get("pr_url"),
        expires_at=session.get("expires_at"),
        # Fail-closed: credentials are exposed ONLY once issued.
        session_jwt=session.get("session_jwt") if issued else None,
        sa_token=session.get("sa_token") if issued else None,
        sa_token_path=session.get("sa_token_path") if issued else None,
        tool_scope=session.get("tool_scope") if issued else None,
    )


# ---------------------------------------------------------------------------
# GET /jwks — public signing keys for the session JWT (N1)
# ---------------------------------------------------------------------------


@app.get("/jwks")
async def get_jwks() -> dict[str, Any]:
    """Serve the jit-approver session-JWT signing public key as a JWKS.

    No auth — public keys. The Kyverno ValidatingPolicy
    dangerous-tools-admins-only fetches this to verify X-JIT-Session-JWT.
    """
    from jit_approver import signing

    return signing.jwks()


# ---------------------------------------------------------------------------
# POST /requests/{id}/summary
# ---------------------------------------------------------------------------


@app.post("/requests/{session_id}/summary", status_code=200)
async def post_summary(session_id: str, summary: SessionSummary) -> dict[str, str]:
    """Agent posts a post-session summary.

    The approver:
    1. Emits a jit_summary audit event (outcome and action args hashed)
    2. Posts the summary as a comment on the approval PR
    3. Returns 200
    """
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    req = session["request"]
    audit.emit_summary(
        session_id=session_id,
        requester_sub=req.requester_sub,
        outcome=summary.outcome,
        actions_taken=summary.actions_taken,
    )

    # Persist the summary so GET /requests/{id}/summary and /receipt can serve it
    # to the RHDH receipt plugin. (Previously the summary was only emitted to the
    # audit log + PR comment and then dropped.)
    session["summary"] = summary

    # Post comment on the PR (best-effort)
    pr_number = session.get("pr_number")
    if pr_number is not None:
        try:
            from jit_approver.gitea import GiteaClient

            comment_body = _render_summary_comment(session_id, summary)
            async with httpx.AsyncClient(timeout=30.0) as http:
                gc = GiteaClient(http=http)
                await gc.comment_on_pr(pr_number, comment_body)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "summary_comment_failed",
                extra={"session_id": session_id, "error": str(exc)},
            )

    logger.info(
        "jit_summary_received",
        extra={"session_id": session_id, "outcome": summary.outcome[:80]},
    )
    return {"status": "recorded", "session_id": session_id}


# ---------------------------------------------------------------------------
# POST /requests/{id}/mint — console-side mint gate (L1)
# ---------------------------------------------------------------------------

# Allowlist of SPIFFE IDs permitted to call /mint (console service identity).
# Populated from env JIT_MINT_ALLOWED_SPIFFE_IDS (comma-separated).
# Example: "spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/approval-console"
def _mint_allowed_spiffe_ids() -> frozenset[str]:
    raw = os.environ.get("JIT_MINT_ALLOWED_SPIFFE_IDS", "")
    return frozenset(s.strip() for s in raw.split(",") if s.strip())


def _require_mtls() -> bool:
    return os.environ.get("JIT_MINT_REQUIRE_MTLS", "false").strip().lower() == "true"


def _mint_gate_enabled() -> bool:
    return os.environ.get("JIT_MINT_GATE_ENABLED", "true").strip().lower() != "false"


def _authenticate_mint_caller(request: Request) -> str:
    """Authenticate the caller of POST /mint.

    CALLER-AUTH DECISION (locked): /mint authenticates the caller as the
    console service via mTLS using its SPIFFE SVID.  The jit-approver
    extracts the peer SPIFFE ID from the verified client cert and checks it
    against JIT_MINT_ALLOWED_SPIFFE_IDS.

    INTERIM (JIT_MINT_REQUIRE_MTLS=false, the current PoC default):
      mTLS handshake + SPIRE-registration is not yet live on this hop.  We
      implement and unit-test the SPIFFE-ID extraction logic behind a
      JIT_MINT_REQUIRE_MTLS flag.  When the flag is false we fall back to a
      Kubernetes ServiceAccount TokenReview check via the
      X-Console-SA-Token header so /mint is NEVER open to unauthenticated
      callers during the interim period.

      Live mTLS handshake + SPIRE-registration are recorded as explicit
      on-cluster verify items in ADR-0007.

    Returns the verified caller identity string (SPIFFE ID or SA name).
    Raises HTTPException(401) on auth failure (fail-closed).
    """
    if not _mint_gate_enabled():
        # /mint explicitly disabled — serve 503.
        raise HTTPException(
            status_code=503,
            detail="/mint is disabled (JIT_MINT_GATE_ENABLED=false)",
        )

    # --- mTLS / SPIFFE path (live when JIT_MINT_REQUIRE_MTLS=true) ---
    if _require_mtls():
        # Extract SPIFFE ID from the TLS peer certificate.
        # In production the TLS terminator (envoy / SPIRE workload API) injects
        # the verified peer SPIFFE URI SAN into X-Forwarded-Client-Cert or
        # the connection's TLS state.  Here we read it from a header set by
        # the TLS proxy layer (not from a user-controllable header).
        spiffe_id = request.headers.get("x-peer-spiffe-id", "").strip()
        if not spiffe_id:
            logger.warning("mint.auth_missing_spiffe_id")
            raise HTTPException(
                status_code=401,
                detail="Missing peer SPIFFE ID — mTLS client cert required",
            )
        allowed = _mint_allowed_spiffe_ids()
        if spiffe_id not in allowed:
            logger.warning(
                "mint.auth_spiffe_id_not_allowed",
                extra={"spiffe_id": spiffe_id, "allowed": list(allowed)},
            )
            raise HTTPException(
                status_code=403,
                detail=f"Caller SPIFFE ID {spiffe_id!r} is not in the /mint allowlist",
            )
        logger.info("mint.auth_ok_spiffe", extra={"spiffe_id": spiffe_id})
        return spiffe_id

    # --- Interim: Kubernetes SA TokenReview via X-Console-SA-Token header ---
    # The console sends its projected SA token; we validate it via the
    # Kubernetes TokenReview API.  This is enforced so /mint is NEVER open
    # to unauthenticated callers.  Agent-sandbox pods do not have this token.
    #
    # In the unit-test environment (no live k8s) we accept a synthetic token
    # whose value equals JIT_MINT_CONSOLE_TOKEN_OVERRIDE (test seam).
    sa_token = request.headers.get("x-console-sa-token", "").strip()
    override = os.environ.get("JIT_MINT_CONSOLE_TOKEN_OVERRIDE", "").strip()

    if override:
        # Unit-test / synthetic token override (mock seam — NOT a production path).
        if sa_token != override:
            logger.warning("mint.auth_token_mismatch")
            raise HTTPException(
                status_code=401,
                detail="X-Console-SA-Token does not match expected value",
            )
        logger.info("mint.auth_ok_override")
        return "console-sa-override"

    if not sa_token:
        logger.warning("mint.auth_missing_sa_token")
        raise HTTPException(
            status_code=401,
            detail="Missing X-Console-SA-Token header — console SA auth required",
        )

    # Live TokenReview (requires a reachable k8s API server).
    k8s_api = os.environ.get("KUBERNETES_SERVICE_HOST")
    if not k8s_api:
        # Not running in-cluster.  In PoC dev mode, accept a non-empty token
        # if JIT_MINT_REQUIRE_MTLS is false and no override is set.
        # This deliberately degrades security in dev mode only.
        logger.warning("mint.auth_not_in_cluster_accepting_token")
        return "console-sa-dev"

    try:
        import httpx as _httpx

        k8s_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        k8s_url = f"https://{k8s_api}:{k8s_port}"
        # Read the approver SA token for the TokenReview call.
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
            reviewer_token = f.read().strip()
        with open("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt") as f:
            ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

        import anyio

        async def _do_token_review() -> str:
            async with _httpx.AsyncClient(verify=ca_cert_path, timeout=5.0) as _hc:
                tr_resp = await _hc.post(
                    f"{k8s_url}/apis/authentication.k8s.io/v1/tokenreviews",
                    headers={
                        "Authorization": f"Bearer {reviewer_token}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "apiVersion": "authentication.k8s.io/v1",
                        "kind": "TokenReview",
                        "spec": {"token": sa_token},
                    },
                )
            if not tr_resp.is_success:
                raise HTTPException(status_code=401, detail="TokenReview API call failed")
            tr_data = tr_resp.json()
            status = tr_data.get("status", {})
            if not status.get("authenticated"):
                raise HTTPException(status_code=401, detail="Console SA token not authenticated")
            user_info = status.get("user", {})
            username = user_info.get("username", "")
            # Validate the SA is the console's SA (not an agent sandbox SA).
            allowed_sa_prefix = os.environ.get(
                "JIT_MINT_CONSOLE_SA_PREFIX",
                "system:serviceaccount:mcp-gateway:approval-console",
            )
            if not username.startswith(allowed_sa_prefix):
                raise HTTPException(
                    status_code=403,
                    detail=f"SA {username!r} is not an allowed console SA",
                )
            return username

        # Run the async TokenReview synchronously from this sync context if needed.
        # In the async FastAPI path this is awaited in the handler below.
        return anyio.from_thread.run_sync(lambda: username)  # type: ignore[return-value]
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("mint.auth_token_review_error", extra={"error": str(exc)})
        raise HTTPException(
            status_code=401,
            detail=f"Console SA auth failed: {exc}",
        ) from exc


async def _authenticate_mint_caller_async(request: Request) -> str:
    """Async version of _authenticate_mint_caller for use in the handler.

    Handles the in-cluster TokenReview path asynchronously.
    """
    if not _mint_gate_enabled():
        raise HTTPException(
            status_code=503,
            detail="/mint is disabled (JIT_MINT_GATE_ENABLED=false)",
        )

    if _require_mtls():
        spiffe_id = request.headers.get("x-peer-spiffe-id", "").strip()
        if not spiffe_id:
            logger.warning("mint.auth_missing_spiffe_id")
            raise HTTPException(
                status_code=401,
                detail="Missing peer SPIFFE ID — mTLS client cert required",
            )
        allowed = _mint_allowed_spiffe_ids()
        if spiffe_id not in allowed:
            logger.warning(
                "mint.auth_spiffe_id_not_allowed",
                extra={"spiffe_id": spiffe_id, "allowed": list(allowed)},
            )
            raise HTTPException(
                status_code=403,
                detail=f"Caller SPIFFE ID {spiffe_id!r} is not in the /mint allowlist",
            )
        logger.info("mint.auth_ok_spiffe", extra={"spiffe_id": spiffe_id})
        return spiffe_id

    # Interim: X-Console-SA-Token
    sa_token = request.headers.get("x-console-sa-token", "").strip()
    override = os.environ.get("JIT_MINT_CONSOLE_TOKEN_OVERRIDE", "").strip()

    if override:
        if sa_token != override:
            logger.warning("mint.auth_token_mismatch")
            raise HTTPException(
                status_code=401,
                detail="X-Console-SA-Token does not match expected value",
            )
        logger.info("mint.auth_ok_override")
        return "console-sa-override"

    if not sa_token:
        logger.warning("mint.auth_missing_sa_token")
        raise HTTPException(
            status_code=401,
            detail="Missing X-Console-SA-Token header — console SA auth required",
        )

    k8s_api = os.environ.get("KUBERNETES_SERVICE_HOST")
    if not k8s_api:
        logger.warning("mint.auth_not_in_cluster_accepting_token")
        return "console-sa-dev"

    # In-cluster TokenReview.
    k8s_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    k8s_url = f"https://{k8s_api}:{k8s_port}"
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
            reviewer_token = f.read().strip()
        ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

        async with httpx.AsyncClient(verify=ca_cert_path, timeout=5.0) as hc:
            tr_resp = await hc.post(
                f"{k8s_url}/apis/authentication.k8s.io/v1/tokenreviews",
                headers={
                    "Authorization": f"Bearer {reviewer_token}",
                    "Content-Type": "application/json",
                },
                json={
                    "apiVersion": "authentication.k8s.io/v1",
                    "kind": "TokenReview",
                    "spec": {"token": sa_token},
                },
            )
        if not tr_resp.is_success:
            raise HTTPException(status_code=401, detail="TokenReview API call failed")
        tr_data = tr_resp.json()
        status_info = tr_data.get("status", {})
        if not status_info.get("authenticated"):
            raise HTTPException(status_code=401, detail="Console SA token not authenticated")
        username = status_info.get("user", {}).get("username", "")
        allowed_sa_prefix = os.environ.get(
            "JIT_MINT_CONSOLE_SA_PREFIX",
            "system:serviceaccount:mcp-gateway:approval-console",
        )
        if not username.startswith(allowed_sa_prefix):
            raise HTTPException(
                status_code=403,
                detail=f"SA {username!r} is not an allowed console SA",
            )
        return username
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("mint.auth_token_review_error", extra={"error": str(exc)})
        raise HTTPException(
            status_code=401,
            detail=f"Console SA auth failed: {exc}",
        ) from exc


@app.post("/requests/{session_id}/mint")
async def mint_session(session_id: str, body: MintRequest, request: Request) -> dict[str, Any]:
    """Console-side mint gate (L1) — authenticated issuance with M5 SoD enforcement.

    Auth: the console service authenticates via mTLS SPIFFE SVID (production)
    or Kubernetes SA TokenReview (interim PoC).  An unauthenticated call or a
    call from an agent-sandbox principal is rejected 401/403.

    Flow:
      1. Authenticate caller (console SA / SPIFFE SVID check).
      2. Load the pending session (404 if absent).
      3. Reject if state not in {pending, approved} (409).
      4. Verify scope_hash (canonical_scope_hash(stored_req) == body.scope_hash) (409).
      5. Enforce SoD: body.approver_sub != session.requester_sub (403 on violation,
         BEFORE any state change or Vault call).
      6. _atomic_issue: once-only state flip + emit_approved + issue_credentials +
         emit_issued.
      7. Return {status: issued, session_id, expires_at}.

    Security invariants:
      - fail-closed: any auth failure, hash mismatch, or SoD violation denies
        with no state change and no Vault call.
      - once-only: _atomic_issue uses the same store_lock + _TERMINAL_STATES guard
        as the webhook path; both paths contend on the same flip.
      - approver_sub is taken from the request body, which the console populates
        from server-trusted oauth2-proxy/Keycloak forwarded headers (_actor()).
        NEVER from a field the agent controls.
    """
    # Step 1: authenticate caller.
    caller_identity = await _authenticate_mint_caller_async(request)
    logger.info(
        "mint.caller_authenticated",
        extra={"session_id": session_id, "caller": caller_identity},
    )

    # Step 2: load session.
    session = session_store.get(session_id)
    if session is None:
        audit.emit_denied(session_id, "mint: session not found")
        await ledger.record({
            "event": "jit_denied",
            "session_id": session_id,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reason": "mint: session not found",
        })
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    # Step 3: check state — only pending/approved may be minted.
    from jit_approver.mint_core import _TERMINAL_STATES
    current_state = session.get("state", "")
    if current_state in _TERMINAL_STATES:
        # Idempotent response for already-issued sessions.
        return {
            "status": current_state,
            "session_id": session_id,
            "expires_at": session.get("expires_at"),
        }
    if current_state not in {"pending", "approved"}:
        raise HTTPException(
            status_code=409,
            detail=f"Session {session_id} is in state '{current_state}' and cannot be minted",
        )

    # Step 4: verify scope_hash (anti-TOCTOU).
    stored_req: EscalationRequest = session["request"]
    _verify_scope_hash(stored_req, body.scope_hash)

    # Step 5: SoD check — must be BEFORE any state change or Vault call.
    requester_sub = stored_req.requester_sub
    try:
        _enforce_dual_control(body.approver_sub, requester_sub)
    except HTTPException as exc:
        # Emit audit denial with the session_id.
        audit.emit_denied(
            session_id,
            f"M5 self-approval denied: approver_sub={body.approver_sub!r} requester_sub={requester_sub!r}",
        )
        await ledger.record({
            "event": "jit_denied",
            "session_id": session_id,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "approver_sub": body.approver_sub,
            "requester_sub": requester_sub,
            "reason": "M5 self-approval denied",
        })
        raise

    # Step 6: atomic issuance.
    pr_number = session.get("pr_number")
    try:
        await _atomic_issue(session_id, stored_req, body.approver_sub, pr_number)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("mint.issue_error", extra={"session_id": session_id, "error": str(exc)})
        raise HTTPException(status_code=502, detail=f"Credential issuance failed: {exc}") from exc

    # Step 7: return result.
    session = session_store.get(session_id) or {}
    return {
        "status": "issued",
        "session_id": session_id,
        "expires_at": session.get("expires_at"),
    }


def _render_summary_comment(session_id: str, summary: SessionSummary) -> str:
    actions_md = "\n".join(f"- {a}" for a in summary.actions_taken) or "(none)"
    errors_md = "\n".join(f"- {e}" for e in summary.errors_encountered) or "(none)"
    return (
        f"## JIT Session Summary\n\n"
        f"**Session ID:** `{session_id}`\n\n"
        f"**Outcome:** {summary.outcome}\n\n"
        f"**Actions taken:**\n{actions_md}\n\n"
        f"**Errors encountered:**\n{errors_md}\n\n"
        f"*Posted automatically by the agent via jit-approver.*"
    )


# ---------------------------------------------------------------------------
# Read endpoints for the RHDH Phase-3 plugins (approvals panel + receipt).
#
# CREDENTIAL INVARIANT: none of these expose sa_token / session_jwt — only
# GET /requests/{id}/status does that, and ONLY when state==issued over the
# SVID-mTLS channel. The endpoints below return request METADATA and the
# post-session summary only.
# ---------------------------------------------------------------------------


def _session_sandbox(session: dict[str, Any]) -> str | None:
    """The OpenShell sandbox a session is bound to (request field, or the one the
    webhook widened)."""
    req = session.get("request")
    return getattr(req, "sandbox", None) or session.get("openshell_sandbox")


@app.get("/requests")
async def list_requests(
    sandbox: str | None = None, state: str | None = None
) -> list[SessionStatus]:
    """List JIT sessions, optionally filtered by ?sandbox= and/or ?state=.

    Powers the approvals panel: given a Sandbox the plugin discovers its grant
    sessions without a hardcoded id. Credential fields are NEVER populated here.
    """
    out: list[SessionStatus] = []
    for sid, session in session_store.items():
        if sandbox is not None and _session_sandbox(session) != sandbox:
            continue
        if state is not None and session.get("state") != state:
            continue
        out.append(
            SessionStatus(
                id=sid,
                state=SessionState(session["state"]),
                pr_url=session.get("pr_url"),
                expires_at=session.get("expires_at"),
            )
        )
    return out


@app.get("/requests/{session_id}/detail")
async def get_detail(session_id: str) -> dict[str, Any]:
    """Return the approved/requested scope of a session (no credentials).

    Powers the approvals panel's scope display: verbs/resources/namespace,
    justification, duration, the OpenShell sandbox + network policy_delta.
    """
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    req: EscalationRequest = session["request"]
    return {
        "id": session_id,
        "state": session.get("state"),
        "expires_at": session.get("expires_at"),
        "pr_url": session.get("pr_url"),
        "requester_sub": req.requester_sub,
        "namespace": req.namespace,
        "verbs": req.verbs,
        "resources": req.resources,
        "duration_minutes": req.duration_minutes,
        "justification": req.justification,
        "sandbox": _session_sandbox(session),
        "policy_delta": [pd.model_dump() for pd in req.policy_delta],
    }


@app.get("/requests/{session_id}/summary")
async def get_summary(session_id: str) -> SessionSummary:
    """Return the post-session summary the agent posted, or 404 if none yet."""
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    summary = session.get("summary")
    if summary is None:
        raise HTTPException(
            status_code=404, detail=f"No summary posted for session {session_id} yet"
        )
    return summary


@app.get("/requests/{session_id}/receipt")
async def get_receipt(session_id: str) -> dict[str, Any]:
    """Trust-artifact receipt for a session (no credentials).

    Stitches the agent's posted summary (allowed actions taken + errors) with the
    grant scope. The ext-proc-side DENIALS (dangerous-tool gate / RBAC) are
    sourced from the audit logs in Loki — querying that requires LOKI_URL and is
    left as a documented TODO; until then `denied` is empty and `denied_source`
    explains why, rather than fabricating data.
    """
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    summary: SessionSummary | None = session.get("summary")
    return {
        "id": session_id,
        "state": session.get("state"),
        "expires_at": session.get("expires_at"),
        "tool_scope": session.get("tool_scope"),
        "outcome": summary.outcome if summary else None,
        "allowed": summary.actions_taken if summary else [],
        "errors": summary.errors_encountered if summary else [],
        "denied": [],
        "denied_source": (
            "TODO: aggregate ext-proc credential_delegation + dangerous-tool-gate "
            "denials from Loki ({app=\"ext-proc-delegation\"} | json | session_id=...) "
            "— requires LOKI_URL."
        ),
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, str | bool]:
    """Liveness + readiness probe.

    L0 addition: reports ``store_backend`` and, for durable backends,
    ``store_ready`` (False -> 503 until DB connectivity + schema confirmed).
    """
    if not _store_ready:
        from fastapi.responses import JSONResponse

        return JSONResponse(  # type: ignore[return-value]
            status_code=503,
            content={
                "status": "not_ready",
                "service": "jit-approver",
                "store_backend": _store_backend,
                "store_ready": False,
            },
        )
    return {
        "status": "ok",
        "service": "jit-approver",
        "store_backend": _store_backend,
        "store_ready": _store_ready,
    }


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
        "jit_approver.api:app",
        host="0.0.0.0",
        port=8080,
        log_config=None,
    )


if __name__ == "__main__":
    main()
