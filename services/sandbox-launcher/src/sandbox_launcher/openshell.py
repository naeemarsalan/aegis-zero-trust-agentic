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

    # The bundled claude-agent-sdk binary ignores ANTHROPIC_BASE_URL; the brain
    # image installs the system claude CLI at /usr/local/bin/claude and pins it via
    # CLAUDE_CLI_PATH so the runner spawns the URL-honouring CLI. The image already
    # sets this as ENV, but set it explicitly so a command override cannot drop it.
    env.setdefault("CLAUDE_CLI_PATH", "/usr/local/bin/claude")
    return env


def _brain_boot_command() -> list[str]:
    """Resolve the argv that boots the agent-harness runner inside the sandbox.

    Used by exec_agent_brain() as the ExecSandbox ``command`` (NOT the reserved
    OPENSHELL_SANDBOX_COMMAND, which the gateway controls). Default cds into the
    brain image WORKDIR (/app) so on-disk skills resolve from .claude/skills, then
    execs the runner module. Override with SANDBOX_BRAIN_COMMAND (a shell string,
    run via ``sh -c``) for a non-default brain image layout.
    """
    override = os.environ.get("SANDBOX_BRAIN_COMMAND", "").strip()
    cmd = override or "cd /app && exec python -m agent_harness.agent_runner"
    return ["sh", "-c", cmd]


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
        logger.info(
            "sandbox_brain_exec_finished",
            extra={"sandbox_id": sandbox_id, "exit_code": exit_code},
        )
        return exit_code
    finally:
        channel.close()


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
