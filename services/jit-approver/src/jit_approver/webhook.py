"""Gitea webhook receiver — POST /webhooks/gitea.

Security:
- HMAC-SHA256 signature verification using X-Gitea-Signature header
- Secret from env GITEA_WEBHOOK_SECRET (file fallback /vault/secrets/webhook-secret)
- Only process pull_request events with action=closed, merged=true
- Verify label jit-approval is present on the PR
- Verify base branch is main (GITEA_DEFAULT_BRANCH)
- Verify repo matches GITEA_REPO

Replay / idempotency (C4):
- Dedupe by X-Gitea-Delivery id (Gitea redelivery on retry/timeout).
- Session state machine: a session transitions to 'issued' EXACTLY once,
  guarded by an atomic check-and-flip under store_lock. If the session is
  already issued/expired/denied we ACK 200 but DO NOT mint again. Duplicate
  redelivery or re-merge therefore never mints a second lease.

Issuance from reviewed artifact (C2):
- On verified merge we fetch grants/<session-id>.yaml from the MERGED ref
  (merge commit SHA, falling back to the default branch), parse it, and
  re-validate it through the same pydantic ceiling. Issuance is from THAT,
  never from the in-memory session['request']. If the merged YAML fails the
  ceiling we deny + audit (fail closed).

Audit (H5):
- emit_approved is called at the approval decision point (verified merge).
- emit_denied is called for closed-not-merged (denial) and for a merged YAML
  that fails re-validation.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from jit_approver import audit
from jit_approver.mint_core import _atomic_issue, _enforce_dual_control
from jit_approver.models import SessionState
from jit_approver.store import seen_deliveries, session_store, store_lock
from jit_approver.vault import issue_credentials

logger = logging.getLogger("jit_approver.webhook")

router = APIRouter()

# ---------------------------------------------------------------------------
# Secret resolution
# ---------------------------------------------------------------------------

_SECRET_FILE = "/vault/secrets/webhook-secret"

# States that mean issuance has already been decided — no second mint (C4).
_TERMINAL_STATES = frozenset(
    {SessionState.issued.value, SessionState.expired.value, SessionState.denied.value}
)


def _webhook_secret() -> bytes:
    secret = os.environ.get("GITEA_WEBHOOK_SECRET", "")
    if secret:
        return secret.encode()
    try:
        with open(_SECRET_FILE, "rb") as fh:
            return fh.read().strip()
    except FileNotFoundError:
        raise RuntimeError(
            "GITEA_WEBHOOK_SECRET env var not set and /vault/secrets/webhook-secret not found."
        )


def _gitea_repo() -> str:
    return os.environ.get("GITEA_REPO", "anaeem/nvidia-ida")


def _default_branch() -> str:
    return os.environ.get("GITEA_DEFAULT_BRANCH", "main")


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def _verify_signature(body: bytes, signature_header: str | None) -> None:
    """Raise HTTPException(401) if the HMAC-SHA256 signature is invalid."""
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing X-Gitea-Signature header")
    try:
        secret = _webhook_secret()
    except RuntimeError as exc:
        logger.error("webhook_secret_unavailable", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    # Gitea sends the hex digest directly (no "sha256=" prefix)
    sig = signature_header.removeprefix("sha256=")
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


# ---------------------------------------------------------------------------
# PR -> session mapping
# ---------------------------------------------------------------------------


def _find_session_for_pr(pr_number: int) -> str | None:
    """Return the session ID whose PR number matches, or None."""
    for session_id, session in session_store.items():
        if session.get("pr_number") == pr_number:
            return session_id
    return None


def _merge_ref(pr: dict[str, Any]) -> str:
    """Return the ref to read the merged grant from.

    Prefer the merge commit SHA (the exact reviewed+merged state). Fall back to
    the base branch ref (main) if the payload omits it.
    """
    merge_sha = pr.get("merge_commit_sha")
    if merge_sha:
        return str(merge_sha)
    return pr.get("base", {}).get("ref", "") or _default_branch()


# ---------------------------------------------------------------------------
# Webhook handler
# ---------------------------------------------------------------------------


@router.post("/webhooks/gitea")
async def handle_gitea_webhook(
    request: Request,
    x_gitea_event: str | None = Header(None, alias="X-Gitea-Event"),
    x_gitea_signature: str | None = Header(None, alias="X-Gitea-Signature"),
    x_gitea_delivery: str | None = Header(None, alias="X-Gitea-Delivery"),
) -> dict[str, str]:
    """Receive Gitea webhook events and trigger credential issuance on PR merge."""
    body = await request.body()
    _verify_signature(body, x_gitea_signature)

    # C4: dedupe by delivery id. A redelivered (retried) webhook is ACK'd 200
    # without re-processing. We record it under the lock to be concurrency-safe.
    if x_gitea_delivery:
        async with store_lock:
            if x_gitea_delivery in seen_deliveries:
                logger.info("webhook_duplicate_delivery", extra={"delivery": x_gitea_delivery})
                return {"status": "ignored", "reason": "duplicate delivery"}
            seen_deliveries.add(x_gitea_delivery)

    payload: dict[str, Any] = await request.json()

    event = x_gitea_event or ""
    action = payload.get("action", "")

    # Only care about PR closed+merged events
    if event != "pull_request":
        logger.debug("webhook_ignored_event", extra={"event": event})
        return {"status": "ignored", "reason": "not a pull_request event"}

    if action != "closed":
        logger.debug("webhook_ignored_action", extra={"event": event, "action": action})
        return {"status": "ignored", "reason": f"action={action}, expected closed"}

    pr = payload.get("pull_request", {})
    pr_number: int = pr.get("number", 0)
    merged: bool = pr.get("merged", False)
    if not merged:
        # PR closed without merge == denial (H5). Audit it if we can bind it.
        logger.info("webhook_pr_closed_not_merged", extra={"pr_number": pr_number})
        denied_session = _find_session_for_pr(pr_number)
        if denied_session is not None:
            async with store_lock:
                sess = session_store.get(denied_session)
                if sess is not None and sess["state"] not in _TERMINAL_STATES:
                    sess["state"] = SessionState.denied.value
                    audit.emit_denied(denied_session, "PR closed without merge")
        return {"status": "ignored", "reason": "PR closed but not merged"}

    # Verify base branch
    base_branch: str = pr.get("base", {}).get("ref", "")
    if base_branch != _default_branch():
        logger.warning(
            "webhook_wrong_base_branch",
            extra={"base": base_branch, "expected": _default_branch()},
        )
        return {"status": "ignored", "reason": f"base branch {base_branch!r} != {_default_branch()!r}"}

    # Verify repo
    repo_full_name: str = payload.get("repository", {}).get("full_name", "")
    if repo_full_name != _gitea_repo():
        logger.warning(
            "webhook_wrong_repo",
            extra={"repo": repo_full_name, "expected": _gitea_repo()},
        )
        return {"status": "ignored", "reason": f"repo {repo_full_name!r} != {_gitea_repo()!r}"}

    # Verify jit-approval label
    labels: list[dict[str, Any]] = pr.get("labels", [])
    label_names = {lbl.get("name", "") for lbl in labels}
    if "jit-approval" not in label_names:
        logger.info("webhook_missing_label", extra={"labels": list(label_names)})
        return {"status": "ignored", "reason": "PR lacks jit-approval label"}

    session_id = _find_session_for_pr(pr_number)
    if session_id is None:
        logger.warning("webhook_no_session_for_pr", extra={"pr_number": pr_number})
        return {"status": "ignored", "reason": f"no session found for PR #{pr_number}"}

    merged_by = pr.get("merged_by", {}).get("login", "unknown")

    # Early-out only on a missing/terminal session; the M5 SoD check itself
    # runs after the merged grant is loaded (see below).
    async with store_lock:
        _sess_check = session_store.get(session_id)
        if _sess_check is None:
            logger.warning("webhook_no_session_for_pr", extra={"pr_number": pr_number})
            return {"status": "ignored", "reason": f"no session found for PR #{pr_number}"}
        current_state = _sess_check["state"]
        if current_state in _TERMINAL_STATES:
            logger.info(
                "webhook_already_terminal",
                extra={"session_id": session_id, "state": current_state},
            )
            return {"status": "ok", "reason": f"session already {current_state}", "session_id": session_id}

    # NOTE: requester_sub for the M5 SoD check is taken from the RE-VALIDATED
    # merged grant (reviewed_req) below — never from the in-memory
    # session['request'] (C2). This guarantees an authoritative, non-empty
    # value (min_length=1) and closes the empty-requester_sub skip bypass.

    # C2: fetch the REVIEWED merged grant, parse + re-validate through the
    # ceiling, and issue from THAT — never session['request'].
    try:
        reviewed_req = await _load_reviewed_request(session_id, _merge_ref(pr))
    except Exception as exc:  # noqa: BLE001 — re-validation failure => deny+audit
        async with store_lock:
            sess = session_store.get(session_id)
            if sess is not None and sess["state"] not in _TERMINAL_STATES:
                sess["state"] = SessionState.denied.value
        audit.emit_denied(session_id, f"merged grant failed re-validation: {exc}")
        logger.error(
            "webhook_revalidation_failed",
            extra={"session_id": session_id, "error": str(exc)},
        )
        return {"status": "denied", "reason": f"merged grant failed re-validation: {exc}"}

    # M5 SoD check (fail-closed, BEFORE any state change or Vault call), shared
    # with the /mint path via mint_core._enforce_dual_control. requester_sub
    # comes from the RE-VALIDATED merged grant (reviewed_req) — authoritative
    # and, with min_length=1 on the model, guaranteed non-empty, so the webhook
    # mirror path can never silently skip SoD. A self-approval attempt leaves
    # the session pending for a legitimate approver.
    try:
        _enforce_dual_control(merged_by, reviewed_req.requester_sub)
    except Exception as exc:  # noqa: BLE001 — HTTPException from _enforce_dual_control
        audit.emit_denied(
            session_id,
            f"webhook SoD violation: merged_by={merged_by!r} "
            f"requester_sub={reviewed_req.requester_sub!r}",
        )
        logger.warning(
            "webhook_sod_violation",
            extra={
                "session_id": session_id,
                "merged_by": merged_by,
                "requester_sub": reviewed_req.requester_sub,
            },
        )
        return {"status": "denied", "reason": f"SoD violation: {exc}"}

    logger.info(
        "webhook_pr_approved",
        extra={"session_id": session_id, "pr_number": pr_number, "merged_by": merged_by},
    )

    # Trigger credential issuance via the shared mint_core path (C4 once-only
    # flip + emit_approved + issue_credentials + emit_issued).
    try:
        await _atomic_issue(session_id, reviewed_req, merged_by, pr_number)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "webhook_issue_failed",
            extra={"session_id": session_id, "error": str(exc)},
        )
        return {"status": "error", "reason": str(exc)}

    # OpenShell policy elevator: if the REVIEWED grant widens the sandbox's
    # network floor, apply it now via the gateway (incremental AddNetworkRule).
    # Best-effort: the SA token + session JWT are the primary, hard credentials;
    # a policy-widen failure is logged + audited, not fatal (the reaper still
    # reverts on expiry, and the agent can re-request). The sandbox name is
    # stashed on the session so the reaper knows to revert this exact rule.
    sandbox = getattr(reviewed_req, "sandbox", None)
    policy_delta = getattr(reviewed_req, "policy_delta", None) or []
    if sandbox and policy_delta:
        try:
            from jit_approver import openshell

            endpoints = [
                {"host": getattr(e, "host", None) or e["host"],
                 "port": getattr(e, "port", None) or e.get("port", 443)}
                for e in policy_delta
            ]
            if openshell.widen_network(session_id, sandbox, endpoints):
                async with store_lock:
                    sess = session_store.get(session_id)
                    if sess is not None:
                        sess["openshell_sandbox"] = sandbox
        except Exception as exc:  # noqa: BLE001 — widen is best-effort
            logger.error(
                "webhook_policy_widen_failed",
                extra={"session_id": session_id, "sandbox": sandbox, "error": str(exc)},
            )

    return {"status": "issued", "session_id": session_id}


async def _load_reviewed_request(session_id: str, ref: str) -> Any:
    """Fetch + parse + re-validate the merged grant YAML (C2).

    Imported lazily so tests can patch the Gitea client, and to avoid a circular
    import at module load. Raises on any fetch/parse/ceiling failure.
    """
    import httpx

    from jit_approver.gitea import GiteaClient, parse_grant_yaml

    async with httpx.AsyncClient(timeout=30.0) as http:
        gc = GiteaClient(http=http)
        scope_yaml = await gc.fetch_merged_grant(session_id, ref=ref)
    return parse_grant_yaml(scope_yaml)
