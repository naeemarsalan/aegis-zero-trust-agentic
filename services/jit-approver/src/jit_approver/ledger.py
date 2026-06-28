"""Tamper-evident WORM audit ledger recorder.

Exposes a single public coroutine::

    await ledger.record(event_dict)

which appends ``event_dict`` to the hash-chain ledger via the shared store
singleton.  The call is **fail-safe**: if the underlying ``append_ledger``
raises (e.g. a transient DB blip), the error is logged and suppressed so
the mint/approval request flow is never interrupted by a ledger write failure.

Security notes
--------------
- Tool arguments / justifications are NEVER stored raw — callers must pass
  pre-hashed values (``justification_hash``, ``outcome_hash``) following the
  same convention as audit.py's ``_hash()`` helper.
- The store singleton (``get_store()``) is the same instance initialised by
  the app lifespan's startup_check, so there is no second pool or second
  in-memory store in production.
"""
from __future__ import annotations

import logging
from typing import Any

from jit_approver.persistence import get_store

logger = logging.getLogger("jit_approver.ledger")

# ---------------------------------------------------------------------------
# Prometheus counter (graceful if prometheus_client not installed)
# ---------------------------------------------------------------------------

try:
    from prometheus_client import Counter

    _counter = Counter(
        "jit_ledger_appends_total",
        "Ledger append operations by result",
        ["result"],
    )

    def _inc(result: str) -> None:
        _counter.labels(result=result).inc()

except ImportError:
    def _inc(result: str) -> None:  # type: ignore[misc]
        pass  # metrics disabled when prometheus_client not installed


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def record(event: dict[str, Any]) -> None:
    """Append *event* to the WORM ledger.  Fail-safe: never propagates exceptions.

    On success increments ``jit_ledger_appends_total{result="ok"}``.
    On failure logs an ERROR to ``jit_approver.ledger`` and increments
    ``jit_ledger_appends_total{result="error"}`` — the caller is NOT notified.

    A ledger write failure is deliberately NOT surfaced to callers: the
    operational session flow (mint / approve / issue) must not be DoS-able
    by a transient DB blip on the audit side.
    """
    store = get_store()
    try:
        await store.append_ledger(event)
        _inc("ok")
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "ledger_append_failed",
            extra={
                "error": str(exc),
                "event_type": event.get("event", "unknown"),
            },
        )
        _inc("error")
        # Intentionally NOT re-raised — fail-safe contract (ADR-WORM).
