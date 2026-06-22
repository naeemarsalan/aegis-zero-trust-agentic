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

import base64
import binascii
import json
import logging
import os
import subprocess
import sys
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
# When set, the Workload-API path MUST return an SVID whose spiffe_id contains this
# substring; otherwise it fails closed (returns None) rather than handing back an
# arbitrary SVID. This makes selection DETERMINISTIC when the pod has MULTIPLE
# registered SVIDs for the same audience (e.g. a SA-shaped Kagenti SVID AND a
# per-sandbox-UUID ext-proc SVID). The native OpenShell sandbox sets this to
# "/sandbox/" so it always presents the UUID-shaped ext-proc SVID, not the
# SA-shaped one (which ext-proc would 401). Unset => legacy single-SVID behaviour.
SVID_REQUIRE_PATH_SUBSTR_ENV = "SVID_REQUIRE_PATH_SUBSTR"


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
    # BOUNDED STARTUP RETRY (2026-06-21, round 3): when the launcher boots the brain
    # via ExecSandbox it can fire only a few seconds after the pod goes Running —
    # BEFORE the SPIRE agent has propagated this brand-new sandbox's workload
    # registration entry, so the very first fetch_jwt_svid() raises and the brain
    # exited "SVID fetch failed" without ever making an MCP call (PROVEN: the
    # srcvendor brain booted + imported the SDK fine, then died here ~0.2s in because
    # workload_api_fetch_failed). The socket itself exists immediately; only the entry
    # lags. Retry both sources for a bounded window so the just-booted brain waits out
    # registration propagation instead of failing the whole journey. Tunable via
    # SVID_FETCH_RETRY_SECONDS / SVID_FETCH_RETRY_INTERVAL.
    # Default 240s: a brand-new native OpenShell sandbox's SPIRE workload registration
    # entry can take 90s+ to propagate to the node agent on a loaded single node (PROVEN
    # live: even with the launcher's 75s pre-boot settle, the brain's first fetch at boot
    # still raced and a 90s window exhausted ~just as the SVID became fetchable). Each
    # retry is a cheap fresh subprocess (see _try_workload_api_subprocess), so a wide
    # window is low-cost and ensures the autonomous brain reaches the real pfSense journey
    # rather than dying on a propagation race. Tunable via SVID_FETCH_RETRY_SECONDS.
    retry_window = float(os.environ.get("SVID_FETCH_RETRY_SECONDS", "240"))
    retry_interval = float(os.environ.get("SVID_FETCH_RETRY_INTERVAL", "2"))
    socket = os.environ.get(SPIFFE_SOCKET_ENV, SPIFFE_SOCKET_DEFAULT)
    deadline = time.monotonic() + retry_window
    attempt = 0
    while True:
        attempt += 1

        # --- File-based path (sidecar model) ---
        svid_path = os.environ.get(SVID_JWT_PATH_ENV, "").strip() or SVID_GW_JWT_DEFAULT
        token = _try_read_svid_file(svid_path)
        if token:
            logger.debug("svid_from_file", extra={"path": svid_path})
            return token

        # --- Workload API (fresh subprocess per attempt — avoids in-process poisoning) ---
        # See _try_workload_api_subprocess: a long-lived process that made one failed
        # Workload API call keeps failing, so each retry must be a fresh process.
        use_subproc = os.environ.get("SVID_FETCH_SUBPROCESS", "1").strip() != "0"
        token = (
            _try_workload_api_subprocess(socket) if use_subproc
            else _try_workload_api(socket)
        )
        if token:
            logger.info(
                "svid_from_workload_api",
                extra={"socket": socket, "attempt": attempt, "via": "subprocess" if use_subproc else "inproc"},
            )
            return token

        if time.monotonic() >= deadline:
            break
        logger.warning(
            "svid_fetch_retry",
            extra={"attempt": attempt, "socket": socket, "retry_in_s": retry_interval},
        )
        time.sleep(retry_interval)

    raise RuntimeError(
        f"Cannot obtain agent SPIFFE JWT-SVID for audience={SPIFFE_AUDIENCE!r} "
        f"after {attempt} attempt(s) over {retry_window:.0f}s. "
        f"Checked file paths and SPIFFE socket {socket!r}. "
        "Ensure the SPIRE agent is running and the pod has the workload registration entry."
    )


# ---------------------------------------------------------------------------
# File-based SVID reader
# ---------------------------------------------------------------------------

_SVID_FILE_MAX_AGE_SECONDS = int(os.environ.get("SVID_FILE_MAX_AGE_SECONDS", "300"))


def _jwt_subject(token: str) -> str | None:
    """Best-effort decode of a JWT's `sub` claim WITHOUT verifying the signature.

    Used only for fail-closed SHAPE selection (UUID-vs-SA), never for trust — the
    real signature/audience verification happens at ext-proc. Returns None when the
    token is not a well-formed JWT or has no `sub`.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        # JWT uses base64url WITHOUT padding; restore it for the stdlib decoder.
        padding = "=" * (-len(payload_b64) % 4)
        payload = base64.urlsafe_b64decode(payload_b64 + padding)
        claims = json.loads(payload)
    except (ValueError, binascii.Error, json.JSONDecodeError):
        return None
    sub = claims.get("sub")
    return sub if isinstance(sub, str) else None


def _try_read_svid_file(path: str) -> str | None:
    """Read a SVID JWT from a file if it exists, is recent, and is the right SHAPE.

    Returns None (not raises) on any failure so the caller falls through to the
    Workload API.

    SHAPE GUARD (2026-06-22): when SVID_REQUIRE_PATH_SUBSTR is set, the file token's
    decoded `sub` MUST contain that substring or the file is REJECTED (fail closed).
    This mirrors the Workload-API path's selection so the file path cannot present a
    wrongly-shaped SVID. It is load-bearing here: the AuthBridge spiffe-helper writes
    an mcp-gateway-audience SVID to /shared, but the pod matches BOTH a SA-shaped
    kagenti ClusterSPIFFEID and a UUID-shaped ext-proc ClusterSPIFFEID, and the
    mainline helper jwt_svids entry has no per-entry SPIFFE-ID filter — so SPIRE may
    write the SA-shaped token, which ext-proc would 401. Rejecting it here forces a
    fall-through (to the masked socket -> RuntimeError) rather than a silent 401.
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
        # Fail-closed SHAPE selection: the file path is otherwise trusted verbatim, so
        # enforce the same UUID-vs-SA guard the Workload-API path applies.
        require_substr = os.environ.get(SVID_REQUIRE_PATH_SUBSTR_ENV, "").strip()
        if require_substr:
            sub = _jwt_subject(content)
            if sub is None or require_substr not in sub:
                logger.error(
                    "svid_file_wrong_shape",
                    extra={
                        "path": path,
                        "require_substr": require_substr,
                        "sub": sub or "<unparseable>",
                    },
                )
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

    require_substr = os.environ.get(SVID_REQUIRE_PATH_SUBSTR_ENV, "").strip()
    expected_prefix = f"spiffe://{SPIFFE_TRUST_DOMAIN}/"
    try:
        # py-spiffe 0.3.0 API: WorkloadApiClient(socket_path=...) and
        # fetch_jwt_svid(audience=<Set[str]>) — NOT spiffe_socket_path/audiences.
        with WorkloadApiClient(socket_path=socket) as client:
            if require_substr:
                # Deterministic selection: the pod has >1 registered SVID for this
                # audience (SA-shaped Kagenti + UUID-shaped ext-proc). fetch_jwt_svid
                # (singular) returns whichever SPIRE orders first (non-deterministic),
                # so fetch ALL and pick the one whose spiffe_id contains require_substr.
                svids = client.fetch_jwt_svids(audience={SPIFFE_AUDIENCE})
            else:
                svids = [client.fetch_jwt_svid(audience={SPIFFE_AUDIENCE})]

        # Filter to our trust domain (fail-closed) and, if required, the path substring.
        candidates: list = []
        for s in svids:
            sid = str(s.spiffe_id)
            if not sid.startswith(expected_prefix):
                logger.error(
                    "svid_wrong_trust_domain",
                    extra={"spiffe_id": sid, "expected_prefix": expected_prefix},
                )
                continue
            candidates.append(s)

        if require_substr:
            matched = [s for s in candidates if require_substr in str(s.spiffe_id)]
            if not matched:
                # Fail closed: do NOT hand back a non-matching (e.g. SA-shaped) SVID
                # that ext-proc would 401 on. Surface the available subjects for debug.
                logger.error(
                    "svid_no_path_match",
                    extra={
                        "require_substr": require_substr,
                        "audience": SPIFFE_AUDIENCE,
                        "available": [str(s.spiffe_id) for s in candidates],
                    },
                )
                return None
            chosen = matched[0]
        else:
            if not candidates:
                return None
            chosen = candidates[0]

        spiffe_id = str(chosen.spiffe_id)
        token: str = chosen.token
        logger.info(
            "svid_fetched_workload_api",
            extra={
                "spiffe_id": spiffe_id,
                "audience": SPIFFE_AUDIENCE,
                "selected_by": require_substr or "first",
            },
        )
        return token
    except Exception as exc:  # noqa: BLE001
        logger.warning("workload_api_fetch_failed", extra={"socket": socket, "error": str(exc)})
        return None


def _try_workload_api_subprocess(socket: str) -> str | None:
    """Fetch the JWT-SVID in a FRESH child process, returning the token or None.

    WHY (2026-06-21, round 3 — the SVID-race FINAL fix): when the launcher boots the
    brain via ExecSandbox seconds after the pod is Running, the very first
    WorkloadApiClient call can race the SPIRE agent's workload-registration
    propagation and fail. PROVEN in the live sandbox: once THIS process has made one
    failed Workload API call, EVERY subsequent in-process attempt keeps failing for
    90s+ — while a brand-new process fetches the SVID fine the whole time (a py-spiffe
    /SPIRE per-process quirk; the first failed subscription poisons the process). So
    the retry path runs each attempt as a SEPARATE short-lived python that calls
    _try_workload_api and prints the token, sidestepping the poisoning entirely. The
    child inherits this process's env (SVID_REQUIRE_PATH_SUBSTR etc.) so selection is
    identical. Disable via SVID_FETCH_SUBPROCESS=0 to use the in-process path only.
    """
    code = (
        "import sys;"
        "from agent_harness.svid_bearer import _try_workload_api;"
        "t=_try_workload_api(sys.argv[1]);"
        "sys.stdout.write(t) if t else sys.exit(3)"
    )
    # FRESH-PROCESS HARDENING (2026-06-21, round 4): close_fds=True so the child does
    # NOT inherit the parent brain's open gRPC/Workload-API socket fds (a possible
    # source of the observed cross-process poisoning — the parent made a failed
    # Workload API call, and an inherited half-open connection fd could carry that
    # broken c-ares/HTTP2 state into the child even across exec). Also strip the gRPC
    # tuning env knobs that pin a shared resolver/ares state, and start a clean
    # process group (start_new_session) so the child is fully independent of the
    # parent's session — mirroring the always-works fresh `oc exec` / ExecSandbox
    # probe. The SVID-selection env (SVID_REQUIRE_PATH_SUBSTR, SPIFFE_ENDPOINT_SOCKET)
    # is preserved so selection stays identical.
    child_env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("GRPC_") and k != "GODEBUG"
    }
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code, socket],
            capture_output=True,
            text=True,
            timeout=float(os.environ.get("SVID_FETCH_SUBPROC_TIMEOUT", "15")),
            close_fds=True,
            start_new_session=True,
            env=child_env,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("svid_subprocess_error", extra={"error": str(exc)})
        return None
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return None
