"""SVID bearer token fetcher for the in-sandbox agent harness.

The agent authenticates to the MCP gateway using its OWN SPIFFE JWT-SVID
(audience="mcp-gateway"). This is NEVER a user credential; the user identity
arrives via the Vault consent grant written by sandbox-launcher.

Design notes
------------
- Reads the SVID from the SPIFFE Workload API socket OR from a file written by
  the svid-vault-fetch sidecar (WRITE_SVID_PATH pattern). File path wins when
  SVID_JWT_PATH is set and the file exists — useful in the sidecar deployment
  model where the Go binary handles the SPIRE socket and writes the token to a
  tmpfs path that this Python process reads.
- If neither the socket nor a fresh file is available this module raises
  RuntimeError (fail-closed: the agent MUST NOT proceed without its own
  identity).
- Token freshness: callers must call fetch_agent_svid() before each query() to
  get a fresh token; this module does NOT cache. Rebuilding the MCP server
  options and re-issuing query() on expiry is handled in agent_runner.py.

Trust domain: spiffe://anaeem.na-launch.com (SECURITY-INVARIANT — never accept
SVIDs from other trust domains; enforced by the Workload API which only issues
SVIDs for the local trust domain configured in the SPIRE agent).

Audience: "mcp-gateway" — MUST match ext-proc EXPECTED_AUDIENCE.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

logger = logging.getLogger("agent_harness.svid_bearer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SPIFFE_AUDIENCE = "mcp-gateway"
SPIFFE_TRUST_DOMAIN = "anaeem.na-launch.com"
SPIFFE_SOCKET_ENV = "SPIFFE_ENDPOINT_SOCKET"
SPIFFE_SOCKET_DEFAULT = "unix:///spiffe-workload-api/spire-agent.sock"
SVID_JWT_PATH_ENV = "SVID_JWT_PATH"
# Default path where the svid-vault-fetch sidecar (WRITE_SVID_PATH mode) writes
# the gateway-audience SVID; distinct from the vault-audience path.
SVID_GW_JWT_DEFAULT = "/var/run/secrets/svid-gateway.jwt"


def fetch_agent_svid() -> str:
    """Return the agent's SPIFFE JWT-SVID string for audience "mcp-gateway".

    Resolution order:
      1. SVID_JWT_PATH env var (file path) — set when the Go svid-writer sidecar
         writes the token to tmpfs. The file must be non-empty and not older than
         SVID_FILE_MAX_AGE_SECONDS (default 300s) to be considered fresh.
      2. Default file path SVID_GW_JWT_DEFAULT if it exists and is fresh.
      3. SPIFFE Workload API (spiffe_workloadapi) — live socket call.

    Raises:
        RuntimeError: no SVID source available or all sources failed.
    """
    # --- File-based path (sidecar model) ---
    svid_path = os.environ.get(SVID_JWT_PATH_ENV, "").strip() or SVID_GW_JWT_DEFAULT
    token = _try_read_svid_file(svid_path)
    if token:
        logger.debug("svid_from_file", extra={"path": svid_path})
        return token

    # --- Workload API (direct socket) ---
    socket = os.environ.get(SPIFFE_SOCKET_ENV, SPIFFE_SOCKET_DEFAULT)
    token = _try_workload_api(socket)
    if token:
        logger.debug("svid_from_workload_api", extra={"socket": socket})
        return token

    raise RuntimeError(
        f"Cannot obtain agent SPIFFE JWT-SVID for audience={SPIFFE_AUDIENCE!r}. "
        f"Checked file paths and SPIFFE socket {socket!r}. "
        "Ensure the SPIRE agent is running and the pod has the workload registration entry."
    )


# ---------------------------------------------------------------------------
# File-based SVID reader
# ---------------------------------------------------------------------------

_SVID_FILE_MAX_AGE_SECONDS = int(os.environ.get("SVID_FILE_MAX_AGE_SECONDS", "300"))


def _try_read_svid_file(path: str) -> str | None:
    """Read a SVID JWT from a file if it exists and is recent.

    Returns None (not raises) on any failure so the caller falls through to the
    Workload API.
    """
    p = Path(path)
    try:
        if not p.exists():
            return None
        # Check file freshness by mtime — the sidecar refreshes before half-expiry.
        mtime = p.stat().st_mtime
        age_s = time.time() - mtime
        if age_s > _SVID_FILE_MAX_AGE_SECONDS:
            logger.warning(
                "svid_file_stale",
                extra={"path": path, "age_s": int(age_s), "max_age_s": _SVID_FILE_MAX_AGE_SECONDS},
            )
            return None
        content = p.read_text().strip()
        if not content:
            logger.warning("svid_file_empty", extra={"path": path})
            return None
        return content
    except OSError as exc:
        logger.warning("svid_file_read_error", extra={"path": path, "error": str(exc)})
        return None


# ---------------------------------------------------------------------------
# Workload API path
# ---------------------------------------------------------------------------


def _try_workload_api(socket: str) -> str | None:
    """Fetch a JWT-SVID from the SPIFFE Workload API.

    Uses py-spiffe (spiffe_workloadapi) when available. Returns None if the
    library is not installed or the socket call fails, so the caller can raise
    a consolidated RuntimeError rather than a spiffe-specific import error.

    The import is guarded so that py_compile passes even when spiffe is absent
    locally (it IS in the container image via requirements.txt).
    """
    try:
        # py-spiffe library — https://github.com/HewlettPackard/py-spiffe
        from spiffe import WorkloadApiClient  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("py_spiffe_not_installed_skipping_workload_api")
        return None

    try:
        # py-spiffe 0.3.0 API: WorkloadApiClient(socket_path=...) and
        # fetch_jwt_svid(audience=<Set[str]>) — NOT spiffe_socket_path/audiences.
        with WorkloadApiClient(socket_path=socket) as client:
            jwt_svid = client.fetch_jwt_svid(
                audience={SPIFFE_AUDIENCE},
            )
        # Validate that the SVID belongs to our trust domain (fail-closed).
        spiffe_id = str(jwt_svid.spiffe_id)
        expected_prefix = f"spiffe://{SPIFFE_TRUST_DOMAIN}/"
        if not spiffe_id.startswith(expected_prefix):
            logger.error(
                "svid_wrong_trust_domain",
                extra={
                    "spiffe_id": spiffe_id,
                    "expected_prefix": expected_prefix,
                },
            )
            return None
        token: str = jwt_svid.token
        logger.info(
            "svid_fetched_workload_api",
            extra={"spiffe_id": spiffe_id, "audience": SPIFFE_AUDIENCE},
        )
        return token
    except Exception as exc:  # noqa: BLE001
        logger.warning("workload_api_fetch_failed", extra={"socket": socket, "error": str(exc)})
        return None
