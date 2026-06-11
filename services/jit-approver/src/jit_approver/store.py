"""In-memory session store (replace with Redis or CNPG for multi-replica).

Each entry keyed by session UUID:
{
  "id": str,
  "state": "pending" | "approved" | "issued" | "expired" | "denied",
  "pr_url": str | None,
  "pr_number": int | None,
  "expires_at": str | None,   # ISO-8601 UTC
  "request": EscalationRequest,
}

Note: SNO is single-replica so in-memory is acceptable for PoC. For HA,
back this with a CloudNativePG table or Redis via Kyverno-policy gating.

Concurrency / replay protection (C4):
  - ``store_lock`` is a process-wide asyncio.Lock that guards the once-only
    state transition to ``issued``. The webhook MUST hold this lock while it
    checks-and-flips state so two concurrent (or redelivered) webhook calls
    cannot both mint a credential for the same session.
  - ``seen_deliveries`` records every ``X-Gitea-Delivery`` id we have already
    processed so Gitea redelivery (retry/timeout) is a cheap no-op ACK.
"""

from __future__ import annotations

import asyncio
from typing import Any

# session_id -> session dict
session_store: dict[str, dict[str, Any]] = {}

# Process-wide lock guarding the once-only issuance transition (C4).
store_lock: asyncio.Lock = asyncio.Lock()

# X-Gitea-Delivery ids we have already handled (C4 replay/idempotency dedupe).
seen_deliveries: set[str] = set()
