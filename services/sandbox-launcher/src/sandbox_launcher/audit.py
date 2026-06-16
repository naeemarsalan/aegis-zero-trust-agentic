"""Structured JSON audit logger for sandbox-launcher.

Audit contract — every action touching an external system emits:
  {ts, event, actor, namespace, tool_args_hash, outcome, latency_ms}

Tool arguments are sha256-hashed; raw values never appear in audit output.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
from typing import Any


# ---------------------------------------------------------------------------
# Structured JSON formatter (mirrors jit-approver/audit.py)
# ---------------------------------------------------------------------------


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
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
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root.addHandler(handler)
    root.setLevel(logging.INFO)


_setup_logging()
audit_logger = logging.getLogger("sandbox_launcher.audit")


# ---------------------------------------------------------------------------
# Hashing helper — args are NEVER logged raw
# ---------------------------------------------------------------------------


def _hash(value: str) -> str:
    """Return sha256 hex digest. Use for any value that might be sensitive."""
    return hashlib.sha256(value.encode()).hexdigest()


def _args_hash(args: dict[str, Any]) -> str:
    """Deterministic sha256 of a JSON-serialised argument dict."""
    return hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Prometheus metrics (optional)
# ---------------------------------------------------------------------------

try:
    from prometheus_client import Counter

    _launches_total = Counter(
        "sandbox_launches_total",
        "Total sandbox launch attempts by outcome",
        ["outcome"],
    )

    def _inc(outcome: str) -> None:
        _launches_total.labels(outcome=outcome).inc()

except ImportError:
    def _inc(outcome: str) -> None:  # type: ignore[misc]
        pass


# ---------------------------------------------------------------------------
# Audit event emitters
# ---------------------------------------------------------------------------


def emit_launch_attempt(
    actor: str,
    goal_hash: str,
    capabilities: list[str],
    mode: str,
) -> None:
    """Emit when a /launch request is received and validated."""
    audit_logger.info(
        "sandbox.launch_attempt",
        extra={
            "event": "sandbox.launch_attempt",
            "actor": actor,
            "namespace": "mcp-gateway",
            "tool_args_hash": _args_hash(
                {"goal_hash": goal_hash, "capabilities": capabilities, "mode": mode}
            ),
            "outcome": "pending",
            "latency_ms": 0,
        },
    )


def emit_launch_outcome(
    actor: str,
    sandbox_name: str,
    outcome: str,
    latency_ms: int,
    tool_args_hash: str,
) -> None:
    """Emit the final outcome of a sandbox launch (allow/deny/error)."""
    audit_logger.info(
        "sandbox.launch_outcome",
        extra={
            "event": "sandbox.launch_outcome",
            "actor": actor,
            "namespace": "mcp-gateway",
            "sandbox_name": sandbox_name,
            "tool_args_hash": tool_args_hash,
            "outcome": outcome,
            "latency_ms": latency_ms,
        },
    )
    _inc(outcome)


def emit_auth_failure(actor: str, reason: str) -> None:
    """Emit when caller JWT verification fails (deny, fail-closed)."""
    audit_logger.warning(
        "sandbox.auth_failure",
        extra={
            "event": "sandbox.auth_failure",
            "actor": actor,
            "namespace": "mcp-gateway",
            "tool_args_hash": _hash(reason),
            "outcome": "deny",
            "latency_ms": 0,
        },
    )
    _inc("deny")


def emit_grant_write(
    actor: str,
    sandbox_uid: str,
    sandbox_name: str,
    grant_scope: str,
    grant_user: str,
    grant_ttl: int,
    grant_nonce_present: bool,
    outcome: str,
    latency_ms: int,
    reason: str = "",
) -> None:
    """Emit audit event when a consent grant is written to (or fails to write to) Vault.

    Audit contract — one line per grant write attempt.  The nonce VALUE is never
    logged (only its presence is recorded); the grant document is never serialised
    raw.  This satisfies the audit logging contract: every action touching Vault
    emits a structured line with ts/event/actor/namespace/tool_args_hash/outcome/
    latency_ms.
    """
    audit_logger.info(
        "sandbox.grant_write",
        extra={
            "event": "sandbox.grant_write",
            "actor": actor,
            "namespace": "mcp-gateway",
            # Hash of the grant identity fields — never log raw grant content.
            "tool_args_hash": _args_hash({
                "sandbox_uid": sandbox_uid,
                "grant_user": grant_user,
                "grant_scope": grant_scope,
                "grant_ttl": grant_ttl,
            }),
            "sandbox_uid": sandbox_uid,
            "sandbox_name": sandbox_name,
            "grant_scope": grant_scope,
            "grant_user": grant_user,
            "grant_ttl": grant_ttl,
            "grant_nonce_present": grant_nonce_present,
            "vault_path": f"secret/data/sandbox-grants/{sandbox_uid}",
            "outcome": outcome,
            "latency_ms": latency_ms,
            **({"reason": reason} if reason else {}),
        },
    )
    _inc(outcome)
