"""FastAPI application — JIT approver REST API.

Endpoints:
  POST /requests                    — submit escalation request -> 202 {id, pr_url}
  GET  /requests/{id}/status        — poll session state; once issued, also returns
                                      session_jwt + sa_token (UC2 credential delivery)
  POST /requests/{id}/summary       — agent posts post-session summary
  GET  /jwks                        — public RS256 keys for the session JWT (N1)
  GET  /healthz                     — liveness probe
  GET  /metrics                     — Prometheus metrics (optional)
  POST /webhooks/gitea              — Gitea webhook (see webhook.py)
"""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from jit_approver import audit
from jit_approver.gitea import create_approval_pr
from jit_approver.models import EscalationRequest, SessionState, SessionStatus, SessionSummary
from jit_approver.store import session_store
from jit_approver.webhook import router as webhook_router

logger = logging.getLogger("jit_approver.api")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(_app: "FastAPI"):
    """App lifespan: start/stop the ephemeral-Vault-resource reaper loop (N3).

    The reaper sweeps every ~60s, deleting the ephemeral Vault role + KV record
    for sessions whose expiry has passed and marking them expired. Disabled when
    JIT_DISABLE_REAPER is set (tests drive reap_once() directly).
    """
    import asyncio
    import os as _os

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
# Health
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "jit-approver"}


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
