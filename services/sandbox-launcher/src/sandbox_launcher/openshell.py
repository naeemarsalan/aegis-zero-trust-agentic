"""OpenShell gateway gRPC client for sandbox-launcher.

Mirrors the pattern in services/jit-approver/src/jit_approver/openshell.py but:
  - Uses LAUNCHER_OIDC_* env vars for the service's OWN client-credentials token
  - Extends CreateSandbox to pass owner labels (not exposed in jit-approver's wrapper)
  - Reads the baseline policy document from a ConfigMap mount or a local file
  - NEVER uses the caller's Backstage token — only the launcher's own OIDC token

The NO-CREDENTIAL-PASSING invariant is enforced structurally:
  - _launcher_auth_metadata() fetches and caches the launcher service's OWN
    client_credentials token from LAUNCHER_OIDC_TOKEN_URL.
  - The caller's Backstage JWT, once verified, is discarded immediately after
    extracting the entity ref. It is not stored, not logged, not forwarded.

Connection:
  mTLS gRPC to OPENSHELL_GATEWAY_ADDR (default: openshell.openshell.svc:8080)
  using certs from OPENSHELL_CLIENT_TLS_DIR (default: /etc/openshell-client-tls).

If TLS certs are absent the client is DISABLED and any create_sandbox call raises
RuntimeError. This is fail-closed: if we cannot authenticate to the gateway, we
do not proceed.

Environment variables:
  OPENSHELL_GATEWAY_ADDR            — gRPC target (default: openshell.openshell.svc:8080)
  OPENSHELL_CLIENT_TLS_DIR          — dir with ca.crt, tls.crt, tls.key
                                       (default: /etc/openshell-client-tls)
  LAUNCHER_OIDC_TOKEN_URL           — Keycloak token endpoint
  LAUNCHER_OIDC_CLIENT_ID           — defaults to "sandbox-launcher"
  LAUNCHER_OIDC_CLIENT_SECRET       — client secret (plain string; file takes priority)
  LAUNCHER_OIDC_CLIENT_SECRET_FILE  — path to file containing client secret
  LAUNCHER_OIDC_CA                  — CA bundle for token endpoint TLS
  LAUNCHER_OIDC_INSECURE            — "true" to skip TLS verify (dev only)
  OPENSHELL_BASELINE_POLICY_PATH    — path to the baseline YAML
                                       (default: /etc/openshell-baseline/baseline.yaml)
  SANDBOX_IMAGE                     — OCI image for the sandbox workload
                                       (default: oci.arsalan.io/nvidia-ida/sandbox-agent:dev)
  SANDBOX_RUNTIME_CLASS             — runtimeClassName (default: kata)
  KEYCLOAK_REALM_URL                — injected as KEYCLOAK_REALM_URL env in sandbox template
  MCP_GATEWAY_URL                   — injected as MCP_GATEWAY_URL env in sandbox template

Brain boot (sandbox runs a real LLM agent, not `sleep infinity`):
  *** Live-gateway contract (0.0.62). ***
  The gateway RESERVES every env key beginning with `OPENSHELL_` and REJECTS
  CreateSandbox if the caller sets one in SandboxTemplate.environment. The
  supervisor's exec command (`OPENSHELL_SANDBOX_COMMAND`, default "sleep infinity")
  is fixed by the gateway and is NOT a caller-settable lever. So the brain is
  booted NATIVELY, after the sandbox is Ready, via the `ExecSandbox` RPC
  (exec_agent_brain), which DOES accept a caller-supplied command + environment.
  The agent goal, allowed tools, and LLM credentials are delivered as NON-reserved
  env keys (also surfaced in the gateway's OPENSHELL_USER_ENVIRONMENT blob). The
  launcher reads the inference credentials from its OWN pod env (same sourcing
  pattern as LAUNCHER_OIDC_CLIENT_SECRET: *_FILE wins over the plain env var); the
  inference key is NEVER baked into the image.

  NOTE: this requires the SANDBOX_IMAGE to contain the brain runtime (python +
  agent_harness + the system claude CLI + .claude/skills — see the agent-harness
  Dockerfile). A bare webshell image (e.g. sandbox-agent:sh3) has none of these and
  the runner exec fails with `cd: /app: No such file or directory`.

  SANDBOX_BOOT_AGENT                — "true" (default) to boot the agent runner;
                                       "false" to keep the legacy sleep-infinity
                                       sandbox (no brain).
  SANDBOX_BRAIN_COMMAND             — shell string the runner is launched with via
                                       ExecSandbox (default:
                                       "cd /app && exec python -m agent_harness.agent_runner")
  AGENT_ALLOWED_TOOLS               — comma-sep tools for the runner (default: Bash,
                                       which drives the mcp-call JIT self-escalation)
  ANTHROPIC_BASE_URL                — LLM endpoint (e.g. http://172.16.2.251:4000)
  ANTHROPIC_API_KEY / _AUTH_TOKEN   — LiteLLM virtual key (plain env; *_FILE wins)
  ANTHROPIC_API_KEY_FILE etc.       — file paths for the above (Vault/Secret mount)
  AGENT_MODEL                       — inference model id (e.g. anthropic/claude-sonnet-4)
  ANTHROPIC_DEFAULT_SONNET_MODEL    — passed through to the sandbox if set
  ANTHROPIC_DEFAULT_OPUS_MODEL      — passed through to the sandbox if set
  ANTHROPIC_SMALL_FAST_MODEL        — passed through to the sandbox if set
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

import yaml

logger = logging.getLogger("sandbox_launcher.openshell")

# ---------------------------------------------------------------------------
# OIDC token cache (launcher's OWN service account token, not the caller's)
# ---------------------------------------------------------------------------

_token_lock = threading.Lock()
_cached_token: str | None = None
_token_expires_at: float = 0.0


def _launcher_auth_metadata() -> list[tuple[str, str]]:
    """Return gRPC call metadata with the launcher's own OIDC Bearer token.

    Uses LAUNCHER_OIDC_* env vars. The caller's Backstage JWT is NEVER used here.
    Returns [] when OIDC is not configured (gateway must be in unauthenticated mode).
    Fail-soft on fetch error: caller receives UNAUTHENTICATED from gateway if token
    was required, which surfaces as a clear error rather than a silent bypass.
    """
    global _cached_token, _token_expires_at

    token_url = os.environ.get("LAUNCHER_OIDC_TOKEN_URL", "").strip()
    if not token_url:
        return []

    # Resolve secret: file takes priority over env var (Vault Agent Injector pattern)
    secret_file = os.environ.get("LAUNCHER_OIDC_CLIENT_SECRET_FILE", "").strip()
    if secret_file:
        try:
            client_secret = open(secret_file).read().strip()  # noqa: WPS515
        except OSError as exc:
            logger.warning(
                "launcher_oidc_secret_file_unreadable",
                extra={"path": secret_file, "error": str(exc)},
            )
            return []
    else:
        client_secret = os.environ.get("LAUNCHER_OIDC_CLIENT_SECRET", "").strip()

    if not client_secret:
        return []

    client_id = os.environ.get("LAUNCHER_OIDC_CLIENT_ID", "sandbox-launcher").strip()

    with _token_lock:
        if _cached_token and time.monotonic() < (_token_expires_at - 60.0):
            return [("authorization", f"Bearer {_cached_token}")]

        import httpx  # lazy import

        insecure = os.environ.get("LAUNCHER_OIDC_INSECURE", "").strip().lower() == "true"
        if insecure:
            verify: bool | str = False
        else:
            ca_path = os.environ.get("LAUNCHER_OIDC_CA", "/etc/openshell-oidc-ca/ca.crt").strip()
            verify = ca_path if os.path.exists(ca_path) else True

        try:
            with httpx.Client(verify=verify, timeout=10) as http:
                resp = http.post(
                    token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": client_secret,
                    },
                )
            resp.raise_for_status()
            payload = resp.json()
            token = payload["access_token"]
            expires_in = int(payload.get("expires_in", 300))
            _cached_token = token
            _token_expires_at = time.monotonic() + expires_in
            logger.debug(
                "launcher_oidc_token_refreshed",
                extra={"client_id": client_id, "expires_in": expires_in},
            )
            return [("authorization", f"Bearer {token}")]
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "launcher_oidc_token_fetch_failed",
                extra={"token_url": token_url, "error": str(exc)},
            )
            return []


def _config() -> dict[str, str] | None:
    """Resolve gateway address and mTLS cert paths. None means the client is disabled."""
    addr = os.environ.get("OPENSHELL_GATEWAY_ADDR", "openshell.openshell.svc:8080")
    cert_dir = os.environ.get("OPENSHELL_CLIENT_TLS_DIR", "/etc/openshell-client-tls")
    ca, crt, key = (os.path.join(cert_dir, f) for f in ("ca.crt", "tls.crt", "tls.key"))
    if not all(os.path.exists(p) for p in (ca, crt, key)):
        return None
    return {"addr": addr, "ca": ca, "crt": crt, "key": key}


def available() -> bool:
    """Return True if the OpenShell gRPC client is configured (certs present)."""
    return _config() is not None


def _stub_and_channel():
    """Open an mTLS gRPC channel to the OpenShell gateway. Raises if not configured."""
    import grpc

    from sandbox_launcher.osh import openshell_pb2_grpc as gw

    cfg = _config()
    if cfg is None:
        raise RuntimeError(
            "OpenShell client TLS not configured — set OPENSHELL_CLIENT_TLS_DIR "
            "with ca.crt, tls.crt, tls.key"
        )
    creds = grpc.ssl_channel_credentials(
        root_certificates=open(cfg["ca"], "rb").read(),
        private_key=open(cfg["key"], "rb").read(),
        certificate_chain=open(cfg["crt"], "rb").read(),
    )
    channel = grpc.secure_channel(cfg["addr"], creds)
    return gw.OpenShellStub(channel), channel


def _yaml_to_policy(doc: dict[str, Any]):
    """Convert baseline policy YAML mapping -> SandboxPolicy proto.

    Mirrors jit_approver.openshell._yaml_to_policy exactly so both services
    stay in sync with the proto schema. Any change to the baseline YAML format
    must be reflected here and in jit-approver.
    """
    from sandbox_launcher.osh import sandbox_pb2 as sb

    fp = doc.get("filesystem_policy") or {}
    pol = sb.SandboxPolicy(
        version=int(doc.get("version", 1)),
        filesystem=sb.FilesystemPolicy(
            include_workdir=bool(fp.get("include_workdir", True)),
            read_only=list(fp.get("read_only", [])),
            read_write=list(fp.get("read_write", [])),
        ),
        landlock=sb.LandlockPolicy(
            compatibility=(doc.get("landlock") or {}).get("compatibility", "best_effort")
        ),
        process=sb.ProcessPolicy(
            run_as_user=(doc.get("process") or {}).get("run_as_user", "sandbox"),
            run_as_group=(doc.get("process") or {}).get("run_as_group", "sandbox"),
        ),
    )
    for key, rule in (doc.get("network_policies") or {}).items():
        nr = sb.NetworkPolicyRule(
            name=rule.get("name", key),
            endpoints=[
                sb.NetworkEndpoint(
                    host=e["host"],
                    port=int(e.get("port", 443)),
                    protocol=e.get("protocol", "rest"),
                    tls=e.get("tls", "terminate"),
                    enforcement=e.get("enforcement", "enforce"),
                    access=e.get("access", "full"),
                )
                for e in rule.get("endpoints", [])
            ],
            binaries=[sb.NetworkBinary(path=b["path"]) for b in rule.get("binaries", [])],
        )
        pol.network_policies[key].CopyFrom(nr)
    return pol


def _load_baseline_policy() -> dict[str, Any]:
    """Load the baseline policy YAML from the ConfigMap mount or local path.

    Precedence:
      1. OPENSHELL_BASELINE_POLICY_PATH env var
      2. /etc/openshell-baseline/baseline.yaml (ConfigMap mount)
      3. The in-repo copy at platform/openshell/policies/baseline.yaml (dev fallback)

    Raises RuntimeError if no path is readable.
    """
    candidates = [
        os.environ.get("OPENSHELL_BASELINE_POLICY_PATH", "").strip(),
        "/etc/openshell-baseline/baseline.yaml",
    ]
    # Dev fallback: walk up from this file to find the repo root
    _here = os.path.dirname(os.path.abspath(__file__))
    _repo_root = os.path.join(_here, *[".."] * 5)  # src/sandbox_launcher -> repo root
    _dev_path = os.path.normpath(
        os.path.join(_repo_root, "platform/openshell/policies/baseline.yaml")
    )
    candidates.append(_dev_path)

    for path in candidates:
        if path and os.path.exists(path):
            logger.debug("baseline_policy_loaded", extra={"path": path})
            with open(path) as fh:
                return yaml.safe_load(fh)

    raise RuntimeError(
        "Cannot find baseline policy YAML. Set OPENSHELL_BASELINE_POLICY_PATH or mount "
        "the openshell-baseline-policy ConfigMap at /etc/openshell-baseline/baseline.yaml"
    )


def _sanitize_label_value(value: str) -> str:
    """Coerce an arbitrary string into a valid Kubernetes label value.

    Label values must be empty or match [A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?
    and be <=63 chars. Any other char (e.g. ':' '/' '@' in a Backstage entity ref
    or email) becomes '-'; leading/trailing non-alphanumerics are trimmed.
    """
    import re

    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", value or "")[:63]
    cleaned = re.sub(r"^[^A-Za-z0-9]+", "", cleaned)
    cleaned = re.sub(r"[^A-Za-z0-9]+$", "", cleaned)
    return cleaned or "unknown"


def phase_name(phase_int: int) -> str:
    """Map a SandboxPhase enum int to its display name, derived from the proto.

    Uses the generated enum's own Name() so the string can never drift from the
    wire contract (SANDBOX_PHASE_UNSPECIFIED=0, _PROVISIONING=1, _READY=2,
    _ERROR=3, _DELETING=4, _UNKNOWN=5). The SANDBOX_PHASE_ prefix is stripped.
    """
    from sandbox_launcher.osh import openshell_pb2 as ph

    try:
        return ph.SandboxPhase.Name(int(phase_int)).removeprefix("SANDBOX_PHASE_")
    except (ValueError, AttributeError):
        return "UNKNOWN"


def get_sandbox_phase(sandbox_name: str) -> str:
    """Return the current sandbox phase display name (e.g. "READY") via GetSandbox.

    GetSandboxRequest is keyed by sandbox NAME (not the UUID). Uses the launcher's
    OWN OIDC token. Used by the brain-boot background task to wait until the sandbox
    is Ready before exec'ing the runner. Raises on RPC error (the caller treats that
    as a transient poll failure and retries).
    """
    if not available():
        raise RuntimeError("OpenShell client not configured")

    from sandbox_launcher.osh import openshell_pb2 as ph

    stub, channel = _stub_and_channel()
    try:
        resp = stub.GetSandbox(
            ph.GetSandboxRequest(name=sandbox_name),
            timeout=30,
            metadata=_launcher_auth_metadata(),
        )
        return phase_name(resp.sandbox.status.phase)
    finally:
        channel.close()


def _read_env_or_file(name: str) -> str:
    """Resolve a value from <name>_FILE (preferred) or <name> in the launcher's env.

    Mirrors the LAUNCHER_OIDC_CLIENT_SECRET sourcing pattern: a mounted Secret /
    Vault file path (<name>_FILE) takes priority over a plain env var, so the
    inference credential is never baked into an image or a manifest literal.
    Returns "" if neither is set / the file is unreadable.
    """
    file_path = os.environ.get(f"{name}_FILE", "").strip()
    if file_path:
        try:
            return open(file_path).read().strip()  # noqa: WPS515
        except OSError as exc:
            logger.warning(
                "brain_env_file_unreadable",
                extra={"var": name, "path": file_path, "error": str(exc)},
            )
            return ""
    return os.environ.get(name, "").strip()


def _brain_boot_enabled() -> bool:
    """True (default) unless SANDBOX_BOOT_AGENT is explicitly falsey.

    When disabled the sandbox falls back to the gateway's default command
    (sleep infinity) — the pre-brain behaviour — without any other change.
    """
    return os.environ.get("SANDBOX_BOOT_AGENT", "true").strip().lower() not in (
        "false",
        "0",
        "no",
    )


def _brain_env(goal: str, allowed_tools: str) -> dict[str, str]:
    """Build the brain env (goal + allowed-tools + ANTHROPIC_* inference creds).

    *** Live-gateway contract (0.0.62) — see exec_agent_brain() below. ***
    The OpenShell gateway RESERVES every env key beginning with ``OPENSHELL_`` and
    REJECTS CreateSandbox if the caller sets one in SandboxTemplate.environment
    (``spec.template.environment keys starting with OPENSHELL_ are reserved``).
    The supervisor's exec command (``OPENSHELL_SANDBOX_COMMAND``, default
    ``sleep infinity``) is therefore NOT a caller-settable lever: the boot command
    is fixed by the gateway. So this function NO LONGER returns that key — doing so
    produced a 502 at /launch and no sandbox was created at all.

    Instead the brain is booted NATIVELY, after the sandbox is Ready, via the
    OpenShell ``ExecSandbox`` RPC (exec_agent_brain()), which DOES accept a
    caller-supplied command + environment. The env this function builds is the
    *exec environment* (and is ALSO delivered as template.environment so it lands
    in the gateway-controlled ``OPENSHELL_USER_ENVIRONMENT`` blob for any
    sleep-infinity / interactive use). All keys here are non-reserved.

    Inference credentials are sourced from the launcher's OWN pod env (see
    _read_env_or_file) and copied in — the proto environment is map<string,string>,
    so a k8s Secret cannot be referenced by name here.

    Returns {} (and logs a warning) when no inference base URL is configured, so
    the caller can fall back to the legacy sleep-infinity sandbox rather than
    boot a brain that has no LLM to talk to.
    """
    base_url = _read_env_or_file("ANTHROPIC_BASE_URL")
    if not base_url:
        logger.warning(
            "brain_boot_skipped_no_inference",
            extra={"reason": "ANTHROPIC_BASE_URL not set on launcher pod"},
        )
        return {}

    env: dict[str, str] = {
        "AGENT_GOAL": goal,
        "AGENT_ALLOWED_TOOLS": allowed_tools,
        "ANTHROPIC_BASE_URL": base_url,
    }

    # Inference credential: accept either ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN
    # (the claude CLI honours both); populate BOTH in the sandbox from whichever the
    # launcher has, so the brain authenticates regardless of which name LiteLLM wants.
    api_key = _read_env_or_file("ANTHROPIC_API_KEY")
    auth_token = _read_env_or_file("ANTHROPIC_AUTH_TOKEN")
    cred = api_key or auth_token
    if cred:
        env["ANTHROPIC_API_KEY"] = cred
        env["ANTHROPIC_AUTH_TOKEN"] = cred
    else:
        logger.warning(
            "brain_boot_no_inference_key",
            extra={"reason": "neither ANTHROPIC_API_KEY nor ANTHROPIC_AUTH_TOKEN set"},
        )

    # Model ids — pass through whatever the launcher carries (optional).
    for var in (
        "AGENT_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_SMALL_FAST_MODEL",
    ):
        val = _read_env_or_file(var)
        if val:
            env[var] = val

    # ---------------------------------------------------------------------------
    # ext-proc routing plane (real pfSense via the mcp-gateway ext-proc).
    #
    # The ExecSandbox brain env does NOT inherit the brain image's Dockerfile ENV,
    # and mcp-call's routing knobs are *code defaults* the in-image harness picks up
    # implicitly — so the native sandbox brain needs them set EXPLICITLY here, exactly
    # mirroring the e2e-harness recipe that drives the REAL pfSense ext-proc loop:
    #   MCP_GATEWAY_URL  -> the public gateway route (read AND write go here for pfSense)
    #   MCP_SEND_SVID    -> "true": pfSense ext-proc verifies the agent SVID Bearer
    #                       (the OPPOSITE of the k8s/OpenShift session, which sets false)
    #   JIT_TARGET_NAMESPACE -> "agentic-mcp": pfSense write maps to
    #                       verb=create resource=networkpolicies in the JIT request
    #   SVID_REQUIRE_PATH_SUBSTR -> "/sandbox/": svid_bearer fail-closed selection of the
    #                       UUID-shaped ext-proc SVID over the SA-shaped Kagenti SVID
    #                       (the pod has BOTH registered). Without it the socket fetch is
    #                       non-deterministic and may present the SA-shaped one -> 401.
    # Sourced from launcher pod env (read_env_or_file) with mcp-call's own defaults so a
    # missing literal still produces the correct pfSense recipe; secrets are never here.
    mcp_gw = _read_env_or_file("MCP_GATEWAY_URL") or "https://mcp-gateway.apps.anaeem.na-launch.com"
    env["MCP_GATEWAY_URL"] = mcp_gw
    # MCP_READ_URL / MCP_WRITE_URL default to MCP_GATEWAY_URL in mcp-call; set them
    # explicitly only if the launcher overrides (kept unset otherwise so the helper's
    # default-to-gateway logic stays the single source of truth).
    for var in ("MCP_READ_URL", "MCP_WRITE_URL"):
        val = _read_env_or_file(var)
        if val:
            env[var] = val
    env["MCP_SEND_SVID"] = (_read_env_or_file("MCP_SEND_SVID") or "true")
    env["JIT_TARGET_NAMESPACE"] = (_read_env_or_file("JIT_TARGET_NAMESPACE") or "agentic-mcp")
    # Deterministic ext-proc SVID selection (see svid_bearer.SVID_REQUIRE_PATH_SUBSTR).
    # Applies to BOTH the Workload-API path AND (as of 2026-06-22) the file path: when
    # SVID_JWT_PATH is set, svid_bearer._try_read_svid_file decodes the JWT `sub` and
    # rejects the file unless its SPIFFE id contains this substring — so an SA-shaped
    # kagenti token in /shared can NEVER be presented to ext-proc (it would 401).
    env["SVID_REQUIRE_PATH_SUBSTR"] = (_read_env_or_file("SVID_REQUIRE_PATH_SUBSTR") or "/sandbox/")
    # SVID file path (2026-06-22, CORRECTED round 2): the AuthBridge-injected spiffe-helper runs in
    # the NORMAL (attestable) container namespace and fetches the mcp-gateway-audience JWT-SVID that
    # the brain CANNOT fetch itself — the gateway ExecSandbox masks /spiffe-workload-api with an empty
    # tmpfs inside the brain's confined setns/MCS namespace (api.py ~431-458). The helper writes the
    # token to cert_dir=/opt, which is the operator-injected `svid-output` emptyDir (PROVEN in
    # kagenti-operator container_builder.go: svid-output -> /opt). Defect-2 fix: the jwt_svids entry
    # now uses a RELATIVE filename `mcp-gateway-svid.jwt` because Go path.Join("/opt","/shared/..")
    # does NOT escape /opt (it yields /opt/shared/.. — the old absolute value misfiled the token onto
    # svid-output's /opt/shared/ subdir, which nothing then mounted). Defect-1 fix: the sibling Kyverno
    # policy kyverno-mount-svid-output-on-agent.yaml mounts that SAME `svid-output` volume READ-ONLY
    # into the agent UNDER /tmp (at /tmp/svid-out).
    #
    # FILESYSTEM-CONFINEMENT FIX (2026-06-22, round 2 — the TRUE last defect): the gateway
    # ExecSandbox confines the DETACHED brain's filesystem access to a fixed path allowlist
    # (proven live via ExecSandbox probes: opening files succeeds ONLY under /sandbox, /tmp, /app;
    # /opt, /home, /var/tmp, and the old /svid-out mount ALL return EACCES(13) on open() REGARDLESS
    # of DAC mode (644) or SELinux label (exact c-category match) — it is a Landlock-style path
    # confinement, not a perms problem; a foreign-uid-1001 644 file placed under /tmp/<sub> reads
    # fine). So the svid-output mount MUST live under an allowed prefix: /tmp/svid-out. The brain
    # then reads /tmp/svid-out/mcp-gateway-svid.jwt. svid_bearer.fetch_agent_svid() reads
    # SVID_JWT_PATH FIRST (file wins over the masked socket); the UUID-vs-SA guard above keeps it safe.
    env["SVID_JWT_PATH"] = (_read_env_or_file("SVID_JWT_PATH") or "/tmp/svid-out/mcp-gateway-svid.jwt")

    # The bundled claude-agent-sdk binary ignores ANTHROPIC_BASE_URL; the brain
    # image installs the system claude CLI at /usr/local/bin/claude and pins it via
    # CLAUDE_CLI_PATH so the runner spawns the URL-honouring CLI. The image already
    # sets this as ENV, but set it explicitly so a command override cannot drop it.
    env.setdefault("CLAUDE_CLI_PATH", "/usr/local/bin/claude")

    # PYTHONPATH (2026-06-21, round 2): inject the FULL python path in the exec
    # ENVIRONMENT (not only the inline `export` in _brain_boot_command). PROVEN live:
    # the gateway DOES apply the brain image's Dockerfile ENV (PYTHONPATH=/app/src) to
    # the exec process, but the boot wrapper's inline `export PYTHONPATH=...:venv` did
    # NOT survive to the runner (the launcher-booted runner's /proc/<pid>/environ showed
    # only PYTHONPATH=/app/src), so ``from claude_agent_sdk import query`` at module load
    # silently fell to None and run_agent() raised "claude-agent-sdk not installed".
    # Setting PYTHONPATH in the exec environment map lands it deterministically (same
    # channel that delivered /app/src), so the system interpreter sees BOTH /app/src
    # (agent_harness) AND the venv site-packages (claude_agent_sdk). Because
    # ``include-system-site-packages = false`` in the venv, the system py3.11 cannot find
    # the SDK without this. Override the venv path via SANDBOX_BRAIN_VENV_SITE.
    venv_site = (
        os.environ.get("SANDBOX_BRAIN_VENV_SITE", "").strip()
        or "/opt/app-root/lib/python3.11/site-packages"
    )
    env["PYTHONPATH"] = f"/app/src:{venv_site}"
    return env


def _brain_boot_command() -> list[str]:
    """Resolve the argv that boots the agent-harness runner inside the sandbox.

    Used by exec_agent_brain() as the ExecSandbox ``command`` (NOT the reserved
    OPENSHELL_SANDBOX_COMMAND, which the gateway controls). Default cds into the
    brain image WORKDIR (/app) so on-disk skills resolve from .claude/skills, then
    boots the runner DETACHED so it survives the ExecSandbox stream closing.
    Override with SANDBOX_BRAIN_COMMAND (a shell string, run via ``sh -c``) for a
    non-default brain image layout.

    DETACH RATIONALE (the brain-survival fix, 2026-06-21):
    ExecSandbox is a server-STREAMING transient exec — the gateway 0.0.62 supervisor
    runs the command in the exec session/process-group, pipes its stdio, and reaps it
    (sending the ``exit`` event) when the foreground leaf returns or the stream is torn
    down. The previous ``exec python -m agent_harness.agent_runner`` form made the runner
    the single FOREGROUND session-leaf, so its lifetime == the ExecSandbox stream's
    lifetime: the moment the launcher's stream/PTY closed (stdin EOF, SIGHUP to the exec
    process-group) the brain died (~1s). Detaching breaks that 1:1 coupling:
      - ``setsid``      : runner gets its OWN session + process-group, so the exec
                          session's SIGHUP / group-kill on stream close does not reach it;
      - ``nohup``       : belt-and-suspenders SIGHUP ignore;
      - ``</dev/null``  : detach stdin so a launcher stdin-close does not EOF/kill it;
      - ``>/tmp/agent.log 2>&1`` : keep logs (HOME=/tmp in the brain image; the sandbox
                          rootfs/overlay is rw, so /tmp is writable — inspect via a
                          read-only ``oc exec ... cat /tmp/agent.log``);
      - trailing ``&`` + ``exit 0`` : background the runner and make the OUTER sh return
                          immediately so the gateway sees a clean transient exec (the
                          ``exit`` event then carries the wrapper's 0, NOT the brain's).
    The detached child re-parents under the sandbox PID 1 (the gateway-fixed
    ``sleep infinity`` supervisor) and keeps running after ``channel.close()``.

    NOTE: because the wrapper exits 0, exec_agent_brain() returns 0 == "boot dispatched",
    NOT "brain succeeded". A follow-up pgrep readiness check confirms the brain came up.

    PYTHONPATH=/app/src is exported inline because ExecSandbox does NOT inherit the
    brain image's Dockerfile ENV (proven live: the same command WITHOUT PYTHONPATH
    fails ``ModuleNotFoundError: agent_harness``; WITH it the runner starts and emits
    its JSONL init). The ``${PYTHONPATH:+:$PYTHONPATH}`` form appends any value the
    exec environment already carries rather than clobbering it.
    """
    override = os.environ.get("SANDBOX_BRAIN_COMMAND", "").strip()
    # INTERPRETER FIX (2026-06-21, round 2): boot the SYSTEM interpreter
    # /usr/bin/python3.11 (present in the brain image, owned root 0755, needs no
    # pyvenv.cfg) instead of bare ``python``. Bare ``python`` resolves to the
    # UBI app-root VENV interpreter /opt/app-root/bin/python, whose startup
    # ``init_import_site`` reads /opt/app-root/pyvenv.cfg; under OpenShell's
    # confined setns/MCS context (the supervisor runs the brain as the ``sandbox``
    # user, uid 1000) that read fails EPERM, so CPython aborts with
    # ``Fatal Python error: init_import_site`` BEFORE agent_runner even imports
    # (proven: round-1 /tmp/agent.log + locally reproduced). The system
    # interpreter has no pyvenv.cfg dependency, but with
    # ``include-system-site-packages = false`` it does NOT see the venv's
    # site-packages — so the brain deps (claude_agent_sdk etc.) MUST be added to
    # PYTHONPATH explicitly: /opt/app-root/lib/python3.11/site-packages. Proven
    # locally: ``import claude_agent_sdk, agent_harness.agent_runner`` succeeds as
    # uid 1000 with pyvenv.cfg unreadable. Override the interpreter + venv path via
    # SANDBOX_BRAIN_PYTHON / SANDBOX_BRAIN_VENV_SITE for a non-default image layout.
    brain_python = os.environ.get("SANDBOX_BRAIN_PYTHON", "").strip() or "/usr/bin/python3.11"
    venv_site = os.environ.get(
        "SANDBOX_BRAIN_VENV_SITE", ""
    ).strip() or "/opt/app-root/lib/python3.11/site-packages"
    cmd = override or (
        f"export PYTHONPATH=/app/src:{venv_site}${{PYTHONPATH:+:$PYTHONPATH}}; "
        f"cd /app && nohup setsid {brain_python} -m agent_harness.agent_runner "
        ">/tmp/agent.log 2>&1 </dev/null & "
        'echo "brain pid $!"; exit 0'
    )
    return ["sh", "-c", cmd]


def brain_readiness_command() -> list[str]:
    """Argv for a short read-only ExecSandbox that confirms the detached brain is up.

    Run AFTER the detached boot (which returns immediately). ``pgrep -f`` matches the
    runner's argv; a non-empty match (exit 0) means the brain re-parented and is
    resident. Falls back to ``test -s /tmp/agent.log`` so a brain that already emitted
    output but raced past pgrep still reads as up. Override with SANDBOX_BRAIN_READY_CMD.
    """
    override = os.environ.get("SANDBOX_BRAIN_READY_CMD", "").strip()
    # HARDENED (2026-06-21, round 2): the previous probe was RACY and FALSE-POSITIVE:
    # it ran immediately (inside the ~1s window before a crashing interpreter died, so
    # pgrep saw the doomed process) and its ``|| test -s /tmp/agent.log`` fallback
    # reported "up" even when the log held only a Fatal crash dump. The new probe:
    #   1. ``sleep 2`` — let the ~1s startup-crash window pass before probing;
    #   2. if /tmp/agent.log contains a CPython hard-failure signature
    #      (``Fatal Python error`` or ``Traceback (most recent call last)``) the brain
    #      is NOT ready — exit 1 regardless of any transient pgrep match;
    #   3. otherwise require the runner process to actually be RESIDENT (pgrep).
    # The non-empty-log fallback is dropped: a crash log is non-empty too, so it can
    # never again mask a dead brain.
    cmd = override or (
        "sleep 2; "
        "if grep -qE 'Fatal Python error|Traceback \\(most recent call last\\)' "
        "/tmp/agent.log 2>/dev/null; then exit 1; fi; "
        "pgrep -f agent_harness.agent_runner >/dev/null 2>&1"
    )
    return ["sh", "-c", cmd]


def svid_probe_command() -> list[str]:
    """Argv for a short read-only ExecSandbox that confirms the agent SVID is FETCHABLE.

    THE SVID-RACE FIX (2026-06-21, round 4):
    The launcher must NOT boot the brain on phase==READY alone. The sandbox reaches
    READY the moment its pod is Running, but the SPIRE agent then takes ~40-90s MORE
    to propagate this brand-new sandbox's workload-registration entry to the node.
    PROVEN live across rounds 1-3: if the brain's FIRST Workload API call races that
    propagation it fails, and then EVERY in-process retry (and even subprocess retries
    spawned by the poisoned brain) keeps failing for the whole window — while a
    brand-new, independent process (a fresh ``oc exec`` / a fresh ExecSandbox) fetches
    the SVID fine the entire time. Neither the launcher's fixed 75s settle nor the
    brain's 240s subprocess-retry recovered it.

    So instead of timing the boot, we GATE it on ground truth: run THIS probe as a
    separate short-lived ExecSandbox (the same fresh-process channel that always
    works) and only exec the brain once the probe returns a real SVID. The brain's
    own first fetch then succeeds on attempt 1 and never enters the poisoned loop.

    The probe boots the SAME confined system interpreter + PYTHONPATH as the brain
    (so it exercises the identical import + socket + SVID-selection path, including
    SVID_REQUIRE_PATH_SUBSTR) and calls svid_bearer._try_workload_api ONCE with a
    short fetch window. Exit 0 + a SVID on stdout == fetchable; non-zero == not yet.
    Override with SANDBOX_SVID_PROBE_CMD for a non-default image layout.
    """
    override = os.environ.get("SANDBOX_SVID_PROBE_CMD", "").strip()
    venv_site = os.environ.get(
        "SANDBOX_BRAIN_VENV_SITE", ""
    ).strip() or "/opt/app-root/lib/python3.11/site-packages"
    brain_python = os.environ.get("SANDBOX_BRAIN_PYTHON", "").strip() or "/usr/bin/python3.11"
    # One-shot fetch: import svid_bearer in a FRESH process and try the Workload API
    # once. A printed token + exit 0 means the registration entry has propagated.
    py = (
        "from agent_harness.svid_bearer import _try_workload_api;"
        "import os,sys;"
        "t=_try_workload_api(os.environ.get('SPIFFE_ENDPOINT_SOCKET',"
        "'unix:///spiffe-workload-api/spire-agent.sock'));"
        "sys.exit(0) if t else sys.exit(3)"
    )
    cmd = override or (
        f"export PYTHONPATH=/app/src:{venv_site}${{PYTHONPATH:+:$PYTHONPATH}}; "
        f"cd /app && {brain_python} -c \"{py}\""
    )
    return ["sh", "-c", cmd]


def probe_agent_svid(sandbox_id: str, timeout_seconds: int = 20) -> bool:
    """Run svid_probe_command() once via ExecSandbox; True iff the SVID is fetchable.

    A single fresh-process probe inside the sandbox. Returns True on exit 0 (the
    Workload API returned an SVID matching SVID_REQUIRE_PATH_SUBSTR), False on any
    non-zero exit or RPC error. Used by the launcher to GATE the brain boot on the
    SVID actually being available (see svid_probe_command for the race rationale).

    The brain env (SVID_REQUIRE_PATH_SUBSTR, SPIFFE socket, etc.) is delivered so the
    probe selects the SAME UUID-shaped ext-proc SVID the brain will use.
    """
    if not available():
        raise RuntimeError("OpenShell client not configured")
    if not sandbox_id:
        raise RuntimeError("probe_agent_svid requires a sandbox_id (metadata.id)")

    from sandbox_launcher.osh import openshell_pb2 as ph

    # Deliver the same selection knobs the brain uses so the probe picks the
    # UUID-shaped ext-proc SVID (not the SA-shaped Kagenti one). Reuse _brain_env's
    # routing block via a minimal env: only SVID selection + socket matter here.
    probe_env: dict[str, str] = {
        "SVID_REQUIRE_PATH_SUBSTR": (
            _read_env_or_file("SVID_REQUIRE_PATH_SUBSTR") or "/sandbox/"
        ),
    }
    sock = _read_env_or_file("SPIFFE_ENDPOINT_SOCKET")
    if sock:
        probe_env["SPIFFE_ENDPOINT_SOCKET"] = sock

    stub, channel = _stub_and_channel()
    rc = 1
    try:
        req = ph.ExecSandboxRequest(
            sandbox_id=sandbox_id,
            command=svid_probe_command(),
            environment=probe_env,
            timeout_seconds=int(timeout_seconds),
        )
        for ev in stub.ExecSandbox(req, metadata=_launcher_auth_metadata()):
            if ev.WhichOneof("payload") == "exit":
                rc = int(ev.exit.exit_code)
    finally:
        channel.close()
    return rc == 0


def llm_probe_command() -> list[str]:
    """Argv for a short read-only ExecSandbox that confirms the LLM is REACHABLE
    through the gateway's per-sandbox egress proxy (i.e. the OpenShell baseline
    egress policy has applied the inference endpoint for this sandbox).

    THE POLICY-SETTLE-RACE FIX (2026-06-22, round-5): the gateway runs the detached
    brain in a confined netns whose only egress is the gateway forward proxy, which
    enforces the deny-by-default baseline egress allowlist. That allowlist now lists
    the LiteLLM endpoint (172.16.2.251:4000) — but the per-sandbox policy APPLIES
    ~1-2 min AFTER the pod is Ready. If the brain fires its first LLM request before
    the policy settles, the proxy returns 403 {"error":"policy_denied"} and the
    one-shot brain dies before the gw-403 retry budget (≈48s) can outlast the window.
    PROVEN live: a curl through the proxy to the LLM flips 403 -> 200 within ~1-2 min.

    So we GATE the brain boot on this probe (mirroring svid_probe_command): a fresh
    short-lived ExecSandbox curls the LLM through the proxy; only when it returns 200
    do we boot the brain. The probe reads ANTHROPIC_BASE_URL + the inference key from
    the launcher env (same sourcing as the brain) so it exercises the SAME path.

    exit 0 iff the proxy returns HTTP 200 for a tiny /v1/messages call; non-zero
    otherwise (403 policy_denied while the policy is still settling, or any error).
    """
    base = (_read_env_or_file("ANTHROPIC_BASE_URL") or "http://172.16.2.251:4000").rstrip("/")
    key = _read_env_or_file("ANTHROPIC_API_KEY") or _read_env_or_file("ANTHROPIC_AUTH_TOKEN") or ""
    # Minimal valid Anthropic-style request; the brain's CLI hits /v1/messages?beta=true.
    body = (
        '{"model":"' + (_read_env_or_file("AGENT_MODEL") or "anthropic/claude-sonnet-4")
        + '","max_tokens":4,"messages":[{"role":"user","content":"ping"}]}'
    )
    # curl honours the sandbox's HTTP(S)_PROXY env (the gateway forward proxy) exactly
    # as the brain's CLI does; -f makes a 4xx (the 403 policy_denied) a non-zero exit.
    sh = (
        "curl -sf -o /dev/null --max-time 12 "
        "-X POST '" + base + "/v1/messages?beta=true' "
        "-H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' "
        "-H 'x-api-key: " + key + "' -H 'Authorization: Bearer " + key + "' "
        "--data '" + body + "'"
    )
    return ["sh", "-c", sh]


def probe_llm_reachable(sandbox_id: str, timeout_seconds: int = 20) -> bool:
    """Run llm_probe_command() once via ExecSandbox; True iff the LLM returns 200
    through the gateway egress proxy (policy has settled). See llm_probe_command."""
    if not available():
        raise RuntimeError("OpenShell client not configured")
    if not sandbox_id:
        raise RuntimeError("probe_llm_reachable requires a sandbox_id (metadata.id)")

    from sandbox_launcher.osh import openshell_pb2 as ph

    stub, channel = _stub_and_channel()
    rc = 1
    try:
        req = ph.ExecSandboxRequest(
            sandbox_id=sandbox_id,
            command=llm_probe_command(),
            environment={},
            timeout_seconds=int(timeout_seconds),
        )
        for ev in stub.ExecSandbox(req, metadata=_launcher_auth_metadata()):
            if ev.WhichOneof("payload") == "exit":
                rc = int(ev.exit.exit_code)
    finally:
        channel.close()
    return rc == 0


def exec_agent_brain(
    sandbox_id: str,
    goal: str,
    allowed_tools: str,
    timeout_seconds: int = 0,
) -> int:
    """Boot the agent-harness brain inside a READY sandbox via ExecSandbox.

    This is the OpenShell-NATIVE brain-boot lever for gateway 0.0.62: the sandbox
    boots on the gateway-fixed ``sleep infinity`` (the supervisor's exec command is
    not caller-settable — OPENSHELL_* env keys are reserved/rejected at CreateSandbox),
    then the launcher execs the runner INTO that ready sandbox. ExecSandbox accepts a
    caller-supplied command + environment (proven on the live gateway), runs as the
    confined ``sandbox`` user, and inherits the sandbox's SVID + policy + workload-API
    socket — so the brain calls MCP through ext-proc with its OWN SVID (ADR-0011 hybrid).

    Uses the launcher's OWN OIDC token. The caller's Backstage token is never seen here.

    Args:
        sandbox_id: SandboxResponse.metadata.id (the UUID, NOT the name).
        goal: Natural-language goal -> AGENT_GOAL in the exec environment.
        allowed_tools: Comma-sep tools -> AGENT_ALLOWED_TOOLS.
        timeout_seconds: Per-exec timeout (0 = no timeout; the runner self-bounds turns).

    Returns:
        The runner's exit code (0 = success). Returns a non-zero sentinel when the
        brain env is unconfigured (no inference) so the caller can keep the sandbox
        as a plain sleep-infinity / interactive shell rather than fail the launch.

    Raises:
        RuntimeError: If the OpenShell client is not configured.
        grpc.RpcError: If the gateway exec stream fails.
    """
    if not available():
        raise RuntimeError("OpenShell client not configured")
    if not sandbox_id:
        raise RuntimeError("exec_agent_brain requires a sandbox_id (metadata.id)")

    from sandbox_launcher.osh import openshell_pb2 as ph

    exec_env = _brain_env(goal=goal, allowed_tools=allowed_tools)
    if not exec_env:
        # No inference configured — do NOT boot a brain with no LLM to talk to.
        logger.warning(
            "brain_exec_skipped_no_inference",
            extra={"sandbox_id": sandbox_id},
        )
        return -1

    command = _brain_boot_command()
    req = ph.ExecSandboxRequest(
        sandbox_id=sandbox_id,
        command=command,
        environment=exec_env,
        timeout_seconds=int(timeout_seconds),
    )

    logger.info(
        "sandbox_brain_exec_starting",
        extra={
            "sandbox_id": sandbox_id,
            "command": command,
            "allowed_tools": allowed_tools,
            "model": exec_env.get("AGENT_MODEL", ""),
            # NEVER log the inference credential or base URL value.
            "inference_key_present": bool(exec_env.get("ANTHROPIC_API_KEY")),
        },
    )

    stub, channel = _stub_and_channel()
    exit_code = 0
    try:
        for ev in stub.ExecSandbox(req, metadata=_launcher_auth_metadata()):
            which = ev.WhichOneof("payload")
            if which == "exit":
                exit_code = int(ev.exit.exit_code)
        # With the DETACHED boot wrapper (see _brain_boot_command) this exit_code is
        # the WRAPPER's (expected 0 == "boot dispatched"), NOT the brain's — the brain
        # is now backgrounded under the sandbox PID 1 and survives this stream closing.
        logger.info(
            "sandbox_brain_exec_finished",
            extra={
                "sandbox_id": sandbox_id,
                "exit_code": exit_code,
                "meaning": "boot_dispatched" if exit_code == 0 else "boot_failed",
            },
        )
    finally:
        channel.close()

    # Follow-up readiness probe: a second short read-only exec confirming the detached
    # brain actually re-parented and is resident. Best-effort — never fails the launch
    # (the sandbox is still a usable shell either way); just records ground truth.
    if exit_code == 0:
        try:
            ready_rc = 0
            ready_stub, ready_channel = _stub_and_channel()
            try:
                ready_req = ph.ExecSandboxRequest(
                    sandbox_id=sandbox_id,
                    command=brain_readiness_command(),
                    timeout_seconds=10,
                )
                for ev in ready_stub.ExecSandbox(
                    ready_req, metadata=_launcher_auth_metadata()
                ):
                    if ev.WhichOneof("payload") == "exit":
                        ready_rc = int(ev.exit.exit_code)
            finally:
                ready_channel.close()
            logger.info(
                "sandbox_brain_readiness",
                extra={
                    "sandbox_id": sandbox_id,
                    "running": ready_rc == 0,
                    "readiness_exit_code": ready_rc,
                },
            )
        except Exception as exc:  # noqa: BLE001 — readiness probe is advisory only
            logger.warning(
                "sandbox_brain_readiness_probe_failed",
                extra={"sandbox_id": sandbox_id, "error": str(exc)},
            )

    return exit_code


def create_sandbox(
    name: str,
    owner_entity_ref: str,
    owner_email: str = "",
    extra_labels: dict[str, str] | None = None,
    goal: str = "",
) -> Any:
    """Launch an OpenShell sandbox born with the baseline floor policy.

    Uses the launcher's OWN OIDC token (_launcher_auth_metadata()) for the
    gateway call. The caller's Backstage token is never seen here.

    Args:
        name: Sandbox name (e.g. 'agent-arsalan-a1b2c3').
        owner_entity_ref: Verified (or advisory) entity ref of the requesting user.
        owner_email: User email, if available (advisory, label only).
        extra_labels: Additional labels to attach to the sandbox.
        goal: Natural-language goal threaded into the sandbox as AGENT_GOAL so the
            brain-enabled runner has work to do. Ignored when brain boot is
            disabled (SANDBOX_BOOT_AGENT=false) or no inference is configured.

    Returns:
        SandboxResponse proto from the gateway.

    Raises:
        RuntimeError: If the OpenShell client is not configured.
        grpc.RpcError: If the gateway call fails.
    """
    if not available():
        raise RuntimeError("OpenShell client not configured")

    from sandbox_launcher.osh import openshell_pb2 as ph

    baseline_doc = _load_baseline_policy()

    image = os.environ.get("SANDBOX_IMAGE", "oci.arsalan.io/nvidia-ida/sandbox-agent:dev")
    runtime_class = os.environ.get("SANDBOX_RUNTIME_CLASS", "kata")

    # Env vars injected into the sandbox workload template
    tmpl_env: dict[str, str] = {}
    keycloak_url = os.environ.get("KEYCLOAK_REALM_URL", "")
    mcp_gw_url = os.environ.get("MCP_GATEWAY_URL", "")
    if keycloak_url:
        tmpl_env["KEYCLOAK_REALM_URL"] = keycloak_url
    if mcp_gw_url:
        tmpl_env["MCP_GATEWAY_URL"] = mcp_gw_url

    # Brain env: deliver goal + allowed-tools + inference creds as NON-reserved
    # template.environment keys. The gateway packs these into the sandbox's
    # OPENSHELL_USER_ENVIRONMENT blob (proven: they appear as real env in the child),
    # so they're available to an interactive shell AND become the defaults for the
    # native ExecSandbox brain boot (see exec_agent_brain / api.launch). We do NOT
    # set OPENSHELL_SANDBOX_COMMAND here — that key is gateway-reserved and rejects
    # CreateSandbox; the runner is started via ExecSandbox after the sandbox is Ready.
    if _brain_boot_enabled():
        allowed_tools = os.environ.get("AGENT_ALLOWED_TOOLS", "Bash").strip() or "Bash"
        brain_env = _brain_env(goal=goal, allowed_tools=allowed_tools)
        if brain_env:
            tmpl_env.update(brain_env)
            logger.info(
                "sandbox_brain_env_configured",
                extra={
                    "sandbox_name": name,
                    "allowed_tools": allowed_tools,
                    "model": brain_env.get("AGENT_MODEL", ""),
                    # NEVER log the inference credential or base URL value.
                    "inference_key_present": bool(
                        brain_env.get("ANTHROPIC_API_KEY")
                    ),
                },
            )

    tmpl = ph.SandboxTemplate(image=image, runtime_class_name=runtime_class)
    if tmpl_env:
        tmpl.environment.update(tmpl_env)

    spec = ph.SandboxSpec(policy=_yaml_to_policy(baseline_doc), template=tmpl)

    # Owner labels — user identity goes ONLY into labels, not into authz decisions.
    # A Backstage entity ref like "user:default/arsalan" contains ':' and '/' which
    # are illegal in a label VALUE (must be alphanumeric / '-' / '_' / '.', and begin
    # and end with an alphanumeric, <=63 chars). Sanitise so the gateway accepts it
    # while still recording who launched the sandbox.
    labels: dict[str, str] = {
        "nvidia-ida/owner": _sanitize_label_value(owner_entity_ref),
        "nvidia-ida/purpose": "packaged-agent",
        "backstage.io/kubernetes-id": "sandbox-launcher",
    }
    if owner_email:
        labels["nvidia-ida/owner-email"] = _sanitize_label_value(owner_email)
    if extra_labels:
        labels.update({k: _sanitize_label_value(v) for k, v in extra_labels.items()})

    req = ph.CreateSandboxRequest(name=name, spec=spec, labels=labels)

    stub, channel = _stub_and_channel()
    try:
        resp = stub.CreateSandbox(
            req,
            timeout=120,
            metadata=_launcher_auth_metadata(),
        )
        logger.info(
            "openshell_sandbox_created",
            extra={
                "sandbox_name": resp.sandbox.metadata.name,
                "owner_entity_ref": owner_entity_ref,
            },
        )
        return resp
    finally:
        channel.close()
