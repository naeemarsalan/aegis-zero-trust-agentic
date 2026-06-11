"""Structured JSON audit logger + Prometheus metrics for JIT approver.

Audit events emitted:
  jit_request  — new escalation request received
  jit_approved — PR merged (webhook confirmed)
  jit_issued   — Vault credential issued and stored in KV
  jit_summary  — agent posted a post-session summary
  jit_denied   — PR closed without merge OR validation rejected

Tool arguments are HASHED (sha256) before logging — raw arguments never
appear in audit output. The session ID and requester sub are logged in clear
so that incident responders can correlate events without needing credentials.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from typing import Any


# ---------------------------------------------------------------------------
# Structured JSON handler
# ---------------------------------------------------------------------------


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Merge structured extras
        skip = {
            "name", "msg", "args", "created", "filename", "funcName", "levelname",
            "levelno", "lineno", "module", "msecs", "pathname", "process",
            "processName", "relativeCreated", "stack_info", "thread", "threadName",
            "exc_info", "exc_text",
        }
        for key, val in record.__dict__.items():
            if key not in skip:
                log_entry[key] = val
        return json.dumps(log_entry)


def _setup_logging() -> None:
    root = logging.getLogger()
    if root.handlers:
        return  # already configured
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root.addHandler(handler)
    root.setLevel(logging.INFO)


_setup_logging()
audit_logger = logging.getLogger("jit_approver.audit")


# ---------------------------------------------------------------------------
# Hashing helper
# ---------------------------------------------------------------------------


def _hash(value: str) -> str:
    """Return sha256 hex digest of value — used to hash tool args in audit."""
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Prometheus metrics (optional — graceful if prometheus_client not installed)
# ---------------------------------------------------------------------------

try:
    from prometheus_client import Counter

    _jit_requests_total = Counter(
        "jit_requests_total",
        "Total JIT requests by state",
        ["state"],
    )

    def _inc(state: str) -> None:
        _jit_requests_total.labels(state=state).inc()

except ImportError:
    def _inc(state: str) -> None:  # type: ignore[misc]
        pass  # metrics disabled if prometheus_client not installed


# ---------------------------------------------------------------------------
# Audit event emitters
# ---------------------------------------------------------------------------


def emit_request(session_id: str, requester_sub: str, namespace: str, verbs: list[str], resources: list[str], justification: str) -> None:
    audit_logger.info(
        "jit_request",
        extra={
            "event": "jit_request",
            "session_id": session_id,
            "requester_sub": requester_sub,
            "namespace": namespace,
            "verbs": verbs,
            "resources": resources,
            "justification_hash": _hash(justification),
        },
    )
    _inc("pending")


def emit_approved(session_id: str, merged_by: str, pr_number: int) -> None:
    audit_logger.info(
        "jit_approved",
        extra={
            "event": "jit_approved",
            "session_id": session_id,
            "merged_by": merged_by,
            "pr_number": pr_number,
        },
    )
    _inc("approved")


def emit_issued(session_id: str, namespace: str, duration_minutes: int, expires_at: str) -> None:
    audit_logger.info(
        "jit_issued",
        extra={
            "event": "jit_issued",
            "session_id": session_id,
            "namespace": namespace,
            "duration_minutes": duration_minutes,
            "expires_at": expires_at,
        },
    )
    _inc("issued")


def emit_summary(session_id: str, requester_sub: str, outcome: str, actions_taken: list[str]) -> None:
    audit_logger.info(
        "jit_summary",
        extra={
            "event": "jit_summary",
            "session_id": session_id,
            "requester_sub": requester_sub,
            "outcome_hash": _hash(outcome),
            "actions_count": len(actions_taken),
            # Individual action args hashed
            "action_hashes": [_hash(a) for a in actions_taken],
        },
    )
    _inc("summary")


def emit_denied(session_id: str, reason: str) -> None:
    audit_logger.info(
        "jit_denied",
        extra={
            "event": "jit_denied",
            "session_id": session_id,
            "reason": reason,
        },
    )
    _inc("denied")
