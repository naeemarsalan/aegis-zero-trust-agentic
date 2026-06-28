"""Shared issuance code path for the JIT mint gate (L1).

Both the console /mint handler (api.py) and the webhook git-mirror path
(webhook.py) call this module so the M5 self-approval check lives in exactly
one place and cannot drift between the two paths.

Exported helpers
----------------
_enforce_dual_control(approver_sub, requester_sub)
    Raises HTTPException(403) when approver_sub == requester_sub, or when
    either value is empty/whitespace (fail-closed).  MUST be called before
    any state change or Vault call.

_verify_scope_hash(stored_req, presented_hash)
    Raises HTTPException(409) when the canonical scope_hash computed from
    the stored EscalationRequest does not match the hash the console sent.
    Closes the TOCTOU window: the approver's view must match the stored
    request byte-for-byte on the ceiling-relevant fields.

_atomic_issue(session_id, reviewed_req, approver_sub, pr_number)
    Performs the once-only pending/approved -> issued flip under store_lock,
    emits audit events, calls issue_credentials(), and emits the issued
    audit.  On issuance failure it rolls the state back so a retry can
    succeed.  Returns the session dict after issuance.

Security invariants
-------------------
- fail-closed: any ambiguity (empty sub, hash mismatch) DENIES without any
  state change or Vault call.
- once-only: the atomic flip via store_lock + _TERMINAL_STATES guarantees
  a session is minted at most once regardless of how many paths race.
- M5 SoD: the approver_sub vs requester_sub check is done BEFORE any flip.
- No Vault/signing changes: _atomic_issue calls the unchanged
  vault.issue_credentials() path.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from fastapi import HTTPException

from jit_approver import audit, ledger
from jit_approver.models import EscalationRequest, SessionState, canonical_scope_hash
from jit_approver.store import session_store, store_lock
from jit_approver.vault import issue_credentials

logger = logging.getLogger("jit_approver.mint_core")

# States where issuance has already been decided — no second mint (C4).
_TERMINAL_STATES = frozenset(
    {SessionState.issued.value, SessionState.expired.value, SessionState.denied.value}
)


# ---------------------------------------------------------------------------
# M5 Separation-of-Duties check
# ---------------------------------------------------------------------------


def _self_approval_allowed() -> bool:
    """True when JIT_ALLOW_SELF_APPROVAL opts out of the approver!=requester gate.

    Deliberate threat-model decision (LANE A): the control is that a human
    gates-and-logs *every* elevation, not two-human 4-eyes. Self/personal
    approval is acceptable. This flag ONLY relaxes the approver==requester
    rejection — the empty-identity fail-closed checks are NEVER skipped.
    """
    return os.environ.get("JIT_ALLOW_SELF_APPROVAL", "").strip().lower() == "true"


def _enforce_dual_control(approver_sub: str, requester_sub: str) -> None:
    """Raise HTTPException(403) if SoD is violated.

    Violations:
      - approver_sub is empty or whitespace (cannot establish identity -> deny)
      - requester_sub is empty or whitespace (session data corrupt -> deny)
      - approver_sub == requester_sub (self-approval -> M5 gap closed),
        UNLESS JIT_ALLOW_SELF_APPROVAL=true (the empty-identity checks above
        still fail closed regardless of the flag).

    MUST be called before any state change or Vault call (fail-closed).
    """
    approver_clean = (approver_sub or "").strip()
    requester_clean = (requester_sub or "").strip()

    if not approver_clean:
        logger.warning(
            "mint.sod_violation",
            extra={"reason": "empty_approver_sub", "requester_sub": requester_clean},
        )
        audit.emit_denied("pre-session", "SoD violation: empty approver_sub")
        raise HTTPException(
            status_code=403,
            detail="approver_sub must not be empty (SoD violation)",
        )

    if not requester_clean:
        logger.warning(
            "mint.sod_violation",
            extra={"reason": "empty_requester_sub", "approver_sub": approver_clean},
        )
        audit.emit_denied("pre-session", "SoD violation: empty requester_sub in session")
        raise HTTPException(
            status_code=403,
            detail="requester_sub must not be empty (session data error)",
        )

    if approver_clean == requester_clean:
        if _self_approval_allowed():
            # LANE A opt-in: human-gates-and-logs every elevation; self-approval
            # is permitted. Still AUDIT it so the WORM ledger shows the approver
            # == requester decision was made knowingly (do not weaken logging).
            logger.warning(
                "mint.self_approval_permitted",
                extra={
                    "reason": "self_approval_allowed",
                    "approver_sub": approver_clean,
                    "requester_sub": requester_clean,
                    "flag": "JIT_ALLOW_SELF_APPROVAL=true",
                },
            )
            return
        logger.warning(
            "mint.sod_violation",
            extra={
                "reason": "self_approval",
                "approver_sub": approver_clean,
                "requester_sub": requester_clean,
            },
        )
        # Audit the M5 denial (no session_id yet at this call site; callers
        # pass the session_id in the outer emit_denied call).
        raise HTTPException(
            status_code=403,
            detail="approver_sub must differ from requester_sub (self-approval denied)",
        )


# ---------------------------------------------------------------------------
# Scope-hash anti-TOCTOU check
# ---------------------------------------------------------------------------


def _verify_scope_hash(stored_req: EscalationRequest, presented_hash: str) -> None:
    """Raise HTTPException(409) if the presented scope_hash doesn't match the stored request.

    The console computes the hash over the detail it fetched; the mint handler
    recomputes from the stored EscalationRequest.  A mismatch means the scope
    was mutated after the approver viewed it — we reject (anti-TOCTOU).
    """
    expected = canonical_scope_hash(stored_req)
    if expected != (presented_hash or "").strip():
        logger.warning(
            "mint.scope_hash_mismatch",
            extra={"expected": expected, "presented": presented_hash},
        )
        raise HTTPException(
            status_code=409,
            detail="scope_hash mismatch — the reviewed scope has changed since approval view",
        )


# ---------------------------------------------------------------------------
# Atomic once-only issuance (shared by /mint and webhook)
# ---------------------------------------------------------------------------


async def _atomic_issue(
    session_id: str,
    reviewed_req: EscalationRequest,
    approver_sub: str,
    pr_number: int | None,
) -> dict[str, Any]:
    """Perform the once-only state flip and credential issuance.

    Algorithm:
      1. Acquire store_lock.
      2. Check current state — if terminal, return existing session (idempotent).
      3. Flip state to 'issued' (optimistic claim; rolled back on failure).
      4. Release lock.
      5. emit_approved audit.
      6. Call issue_credentials() (Vault lease + RS256 session JWT — unchanged).
      7. On success: emit_issued audit, return session.
      8. On failure: roll back to 'approved', re-raise so caller surfaces error.

    Returns the session dict (with state==issued on success).
    """
    async with store_lock:
        session = session_store.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

        current_state = session["state"]
        if current_state in _TERMINAL_STATES:
            logger.info(
                "mint.already_terminal",
                extra={"session_id": session_id, "state": current_state},
            )
            # Idempotent: already issued/expired/denied — return without re-minting.
            return session

        # Optimistic claim: flip to issued before the (network) Vault call so a
        # concurrent redelivery sees 'issued' and no-ops.
        session["state"] = SessionState.issued.value

    # Outside the lock: audit then issue.
    audit.emit_approved(session_id, approver_sub, pr_number or 0)
    await ledger.record({
        "event": "jit_approved",
        "session_id": session_id,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "approver_sub": approver_sub,
        "pr_number": pr_number or 0,
    })
    logger.info(
        "mint.issuing",
        extra={"session_id": session_id, "approver_sub": approver_sub, "pr_number": pr_number},
    )

    try:
        await issue_credentials(session_id, reviewed_req)
    except Exception as exc:  # noqa: BLE001
        # Roll back so a legitimate retry can still succeed.
        async with store_lock:
            sess = session_store.get(session_id)
            if sess is not None and sess["state"] == SessionState.issued.value:
                sess["state"] = SessionState.approved.value
        logger.error(
            "mint.issue_failed",
            extra={"session_id": session_id, "error": str(exc)},
        )
        raise

    # Stash approver_sub on the session for audit / ledger (L2).
    async with store_lock:
        sess = session_store.get(session_id)
        if sess is not None:
            sess["approver_sub"] = approver_sub

    audit.emit_issued(
        session_id,
        reviewed_req.namespace,
        reviewed_req.duration_minutes,
        session_store[session_id].get("expires_at", ""),
    )
    await ledger.record({
        "event": "jit_issued",
        "session_id": session_id,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "namespace": reviewed_req.namespace,
        "duration_minutes": reviewed_req.duration_minutes,
        "expires_at": session_store[session_id].get("expires_at", ""),
    })

    return session_store[session_id]
