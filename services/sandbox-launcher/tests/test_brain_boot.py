"""Unit tests for the sandbox brain-boot wiring (openshell._brain_env et al.).

Live-gateway contract (0.0.62): the gateway RESERVES every env key beginning with
``OPENSHELL_`` and REJECTS CreateSandbox if the caller sets one in
SandboxTemplate.environment. The supervisor's exec command
(``OPENSHELL_SANDBOX_COMMAND``, default "sleep infinity") is therefore NOT a
caller-settable lever. The brain is booted NATIVELY via the ``ExecSandbox`` RPC
after the sandbox is Ready (openshell.exec_agent_brain). These tests pin:
  - brain boot is on by default and toggleable via SANDBOX_BOOT_AGENT
  - the inference credential is sourced from the launcher's OWN env (file > plain)
  - the goal, allowed-tools, and ANTHROPIC_* creds land in the env map
  - _brain_env NEVER emits the reserved OPENSHELL_SANDBOX_COMMAND key
  - no inference base URL -> empty env (caller falls back to sleep-infinity)
  - the native boot command (_brain_boot_command) defaults to the runner and is
    overridable via SANDBOX_BRAIN_COMMAND
  - the credential is never logged (covered by inspecting the returned dict only)
"""

from __future__ import annotations

import os
from unittest.mock import patch

from sandbox_launcher import openshell


_BRAIN_ENV_KEYS = {
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "AGENT_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
    # ext-proc routing knobs (defaulted in _brain_env; cleared here for hermetic tests)
    "MCP_GATEWAY_URL",
    "MCP_READ_URL",
    "MCP_WRITE_URL",
    "MCP_SEND_SVID",
    "JIT_TARGET_NAMESPACE",
    "SVID_REQUIRE_PATH_SUBSTR",
    "SVID_JWT_PATH",
}


def _clear_brain_env() -> dict[str, str]:
    """Return an env-patch dict that clears every brain var so the test is hermetic."""
    return {k: "" for k in _BRAIN_ENV_KEYS | {f"{k}_FILE" for k in _BRAIN_ENV_KEYS}}


class TestBrainBootEnabled:
    def test_default_enabled(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SANDBOX_BOOT_AGENT", None)
            assert openshell._brain_boot_enabled() is True

    def test_explicit_true(self):
        with patch.dict(os.environ, {"SANDBOX_BOOT_AGENT": "true"}):
            assert openshell._brain_boot_enabled() is True

    def test_disabled_false(self):
        for val in ("false", "0", "no", "FALSE", "No"):
            with patch.dict(os.environ, {"SANDBOX_BOOT_AGENT": val}):
                assert openshell._brain_boot_enabled() is False


class TestReadEnvOrFile:
    def test_plain_env(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "plain-key", "ANTHROPIC_API_KEY_FILE": ""}):
            assert openshell._read_env_or_file("ANTHROPIC_API_KEY") == "plain-key"

    def test_file_wins_over_env(self, tmp_path):
        f = tmp_path / "key"
        f.write_text("file-key\n")
        with patch.dict(
            os.environ,
            {"ANTHROPIC_API_KEY": "plain-key", "ANTHROPIC_API_KEY_FILE": str(f)},
        ):
            assert openshell._read_env_or_file("ANTHROPIC_API_KEY") == "file-key"

    def test_missing_file_returns_empty(self):
        with patch.dict(
            os.environ,
            {"ANTHROPIC_API_KEY": "plain", "ANTHROPIC_API_KEY_FILE": "/no/such/file"},
        ):
            assert openshell._read_env_or_file("ANTHROPIC_API_KEY") == ""


class TestBrainEnv:
    def test_no_base_url_returns_empty(self):
        with patch.dict(os.environ, _clear_brain_env()):
            assert openshell._brain_env(goal="g", allowed_tools="Bash") == {}

    def test_full_env_built(self):
        patch_env = _clear_brain_env()
        patch_env.update(
            {
                "ANTHROPIC_BASE_URL": "http://172.16.2.251:4000",
                "ANTHROPIC_API_KEY": "sk-litellm-xyz",
                "AGENT_MODEL": "anthropic/claude-sonnet-4",
            }
        )
        with patch.dict(os.environ, patch_env):
            env = openshell._brain_env(goal="audit firewall", allowed_tools="Bash")
        # The reserved key is NEVER emitted — setting it rejects CreateSandbox.
        assert "OPENSHELL_SANDBOX_COMMAND" not in env
        assert env["AGENT_GOAL"] == "audit firewall"
        assert env["AGENT_ALLOWED_TOOLS"] == "Bash"
        assert env["ANTHROPIC_BASE_URL"] == "http://172.16.2.251:4000"
        # EXACTLY ONE credential env name is emitted (AUTH_TOKEN preferred) — setting
        # both makes the claude CLI warn "auth may not work". API_KEY-only falls back
        # onto AUTH_TOKEN and API_KEY itself is not re-emitted.
        assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-litellm-xyz"
        assert "ANTHROPIC_API_KEY" not in env
        assert env["AGENT_MODEL"] == "anthropic/claude-sonnet-4"
        # the runner needs the URL-honouring system CLI, not the bundled SDK binary
        assert env["CLAUDE_CLI_PATH"] == "/usr/local/bin/claude"
        # PYTHONPATH must carry BOTH /app/src (agent_harness) AND the venv site-packages
        # (claude_agent_sdk) via the exec ENVIRONMENT — an inline `export` in the boot
        # wrapper proved unreliable (the gateway re-applies the image's PYTHONPATH=/app/src
        # to the exec process, dropping the SDK path), so the SDK is set here too.
        assert env["PYTHONPATH"] == "/app/src:/opt/app-root/lib/python3.11/site-packages"

    def test_no_reserved_openshell_keys(self):
        """The brain env must contain ZERO keys with the gateway-reserved prefix."""
        patch_env = _clear_brain_env()
        patch_env.update(
            {"ANTHROPIC_BASE_URL": "http://x:4000", "ANTHROPIC_API_KEY": "k"}
        )
        with patch.dict(os.environ, patch_env):
            env = openshell._brain_env(goal="g", allowed_tools="Bash")
        assert not any(k.startswith("OPENSHELL_") for k in env), env

    def test_auth_token_only_single_emit(self):
        patch_env = _clear_brain_env()
        patch_env.update(
            {
                "ANTHROPIC_BASE_URL": "http://172.16.2.251:4000",
                "ANTHROPIC_AUTH_TOKEN": "auth-only",
            }
        )
        with patch.dict(os.environ, patch_env):
            env = openshell._brain_env(goal="g", allowed_tools="Bash")
        # Only AUTH_TOKEN is emitted — never both.
        assert env["ANTHROPIC_AUTH_TOKEN"] == "auth-only"
        assert "ANTHROPIC_API_KEY" not in env

    def test_both_set_emits_only_auth_token(self):
        """When both creds are in the launcher env, only AUTH_TOKEN is forwarded."""
        patch_env = _clear_brain_env()
        patch_env.update(
            {
                "ANTHROPIC_BASE_URL": "http://172.16.2.251:4000",
                "ANTHROPIC_AUTH_TOKEN": "the-auth-token",
                "ANTHROPIC_API_KEY": "the-api-key",
            }
        )
        with patch.dict(os.environ, patch_env):
            env = openshell._brain_env(goal="g", allowed_tools="Bash")
        assert env["ANTHROPIC_AUTH_TOKEN"] == "the-auth-token"
        assert "ANTHROPIC_API_KEY" not in env

    def test_model_passthrough_optional(self):
        """Model vars are passed through only when set; absent ones are omitted."""
        patch_env = _clear_brain_env()
        patch_env.update(
            {
                "ANTHROPIC_BASE_URL": "http://172.16.2.251:4000",
                "ANTHROPIC_API_KEY": "k",
            }
        )
        with patch.dict(os.environ, patch_env):
            env = openshell._brain_env(goal="g", allowed_tools="Bash")
        assert "AGENT_MODEL" not in env
        assert "ANTHROPIC_SMALL_FAST_MODEL" not in env

    def test_extproc_routing_defaults(self):
        """With nothing set on the launcher, the brain env carries the pfSense recipe:
        gateway route, MCP_SEND_SVID=true, JIT ns agentic-mcp, /sandbox/ SVID select."""
        patch_env = _clear_brain_env()
        patch_env.update(
            {"ANTHROPIC_BASE_URL": "http://x:4000", "ANTHROPIC_API_KEY": "k"}
        )
        with patch.dict(os.environ, patch_env):
            env = openshell._brain_env(goal="g", allowed_tools="Bash")
        assert env["MCP_GATEWAY_URL"] == "https://mcp-gateway.apps.ocp-dev.na-launch.com"
        assert env["MCP_SEND_SVID"] == "true"
        assert env["JIT_TARGET_NAMESPACE"] == "agentic-mcp"
        assert env["SVID_REQUIRE_PATH_SUBSTR"] == "/sandbox/"
        # The brain reads its mcp-gateway SVID from the AuthBridge spiffe-helper's file. The
        # helper writes it to cert_dir=/opt (the svid-output volume); the sibling Kyverno policy
        # kyverno-mount-svid-output-on-agent.yaml mounts that volume read-only into the agent at
        # /svid-out. (Corrected from /shared/...: Go path.Join("/opt","/shared/..") does not escape
        # /opt, so the absolute value misfiled the token to /opt/shared/.. — the round-1 blocker.)
        assert env["SVID_JWT_PATH"] == "/tmp/svid-out/mcp-gateway-svid.jwt"
        # MCP_READ_URL/MCP_WRITE_URL stay unset so mcp-call's default-to-gateway wins.
        assert "MCP_READ_URL" not in env
        assert "MCP_WRITE_URL" not in env

    def test_extproc_routing_overridable(self):
        """Launcher pod env overrides the defaults (e.g. a different JIT namespace)."""
        patch_env = _clear_brain_env()
        patch_env.update(
            {
                "ANTHROPIC_BASE_URL": "http://x:4000",
                "ANTHROPIC_API_KEY": "k",
                "MCP_SEND_SVID": "false",
                "JIT_TARGET_NAMESPACE": "mcp-demo",
                "SVID_REQUIRE_PATH_SUBSTR": "/sa/",
                "MCP_WRITE_URL": "https://write.example",
                "SVID_JWT_PATH": "/custom/svid.jwt",
            }
        )
        with patch.dict(os.environ, patch_env):
            env = openshell._brain_env(goal="g", allowed_tools="Bash")
        assert env["MCP_SEND_SVID"] == "false"
        assert env["JIT_TARGET_NAMESPACE"] == "mcp-demo"
        assert env["SVID_REQUIRE_PATH_SUBSTR"] == "/sa/"
        assert env["MCP_WRITE_URL"] == "https://write.example"
        assert env["SVID_JWT_PATH"] == "/custom/svid.jwt"


class TestBrainBootCommand:
    """The native ExecSandbox boot command (NOT the reserved OPENSHELL_SANDBOX_COMMAND)."""

    def test_default_command(self):
        with patch.dict(
            os.environ,
            {
                "SANDBOX_BRAIN_COMMAND": "",
                "SANDBOX_BRAIN_PYTHON": "",
                "SANDBOX_BRAIN_VENV_SITE": "",
            },
        ):
            cmd = openshell._brain_boot_command()
        # ExecSandbox does NOT inherit the brain image ENV, so PYTHONPATH=/app/src
        # must be exported inline or the runner dies ModuleNotFoundError: agent_harness.
        # And the brain MUST boot the SYSTEM interpreter /usr/bin/python3.11 (bare
        # ``python`` is the venv interp, which aborts init_import_site reading
        # /opt/app-root/pyvenv.cfg under the confined uid 1000) with the venv
        # site-packages on PYTHONPATH so claude_agent_sdk etc. still import.
        assert cmd == [
            "sh",
            "-c",
            "export PYTHONPATH=/app/src:/opt/app-root/lib/python3.11/site-packages"
            "${PYTHONPATH:+:$PYTHONPATH}; "
            "cd /app && nohup setsid /usr/bin/python3.11 -m agent_harness.agent_runner "
            ">/tmp/agent.log 2>&1 </dev/null & "
            'echo "brain pid $!"; exit 0',
        ]

    def test_default_command_exports_pythonpath(self):
        with patch.dict(os.environ, {"SANDBOX_BRAIN_COMMAND": ""}):
            cmd = openshell._brain_boot_command()
        assert "PYTHONPATH=/app/src" in cmd[2]

    def test_default_command_uses_system_interpreter_not_bare_python(self):
        """Bare ``python`` is the venv interp that crashes init_import_site under
        the confined uid; the boot MUST call the system /usr/bin/python3.11."""
        with patch.dict(
            os.environ, {"SANDBOX_BRAIN_COMMAND": "", "SANDBOX_BRAIN_PYTHON": ""}
        ):
            cmd = openshell._brain_boot_command()
        assert "/usr/bin/python3.11 -m agent_harness.agent_runner" in cmd[2]
        # the venv site-packages must be on PYTHONPATH or claude_agent_sdk won't import
        assert "/opt/app-root/lib/python3.11/site-packages" in cmd[2]
        # and it stays DETACHED (the brain-survival fix must not regress)
        assert "nohup setsid" in cmd[2]

    def test_interpreter_and_venv_overridable(self):
        with patch.dict(
            os.environ,
            {
                "SANDBOX_BRAIN_COMMAND": "",
                "SANDBOX_BRAIN_PYTHON": "/usr/bin/python3.12",
                "SANDBOX_BRAIN_VENV_SITE": "/custom/site",
            },
        ):
            cmd = openshell._brain_boot_command()
        assert "/usr/bin/python3.12 -m agent_harness.agent_runner" in cmd[2]
        assert "/custom/site" in cmd[2]

    def test_override(self):
        with patch.dict(os.environ, {"SANDBOX_BRAIN_COMMAND": "python -m custom.runner"}):
            cmd = openshell._brain_boot_command()
        assert cmd == ["sh", "-c", "python -m custom.runner"]


class TestBrainReadinessCommand:
    """The follow-up readiness probe must not false-positive on a crashed brain."""

    def test_default_readiness_detects_crash_and_requires_resident_process(self):
        with patch.dict(os.environ, {"SANDBOX_BRAIN_READY_CMD": ""}):
            cmd = openshell.brain_readiness_command()
        body = cmd[2]
        # sleeps past the ~1s startup-crash window
        assert "sleep 2" in body
        # treats a Fatal/Traceback log as NOT ready (exit 1) — the old false-positive
        assert "Fatal Python error" in body
        assert "Traceback" in body
        # requires the runner process to actually be resident
        assert "pgrep -f agent_harness.agent_runner" in body
        # the old non-empty-log fallback (which masked crashes) is GONE
        assert "test -s /tmp/agent.log" not in body

    def test_readiness_overridable(self):
        with patch.dict(os.environ, {"SANDBOX_BRAIN_READY_CMD": "true"}):
            cmd = openshell.brain_readiness_command()
        assert cmd == ["sh", "-c", "true"]

    def test_exec_skips_when_no_inference(self):
        """exec_agent_brain returns the no-inference sentinel without touching gRPC."""
        patch_env = _clear_brain_env()  # clears ANTHROPIC_BASE_URL -> _brain_env == {}
        with patch.dict(os.environ, patch_env):
            with patch.object(openshell, "available", return_value=True):
                rc = openshell.exec_agent_brain(
                    sandbox_id="uuid-123", goal="g", allowed_tools="Bash"
                )
        assert rc == -1


class TestSvidProbeCommand:
    """The SVID-fetch GATE probe — boots a fresh in-sandbox process to confirm the
    SPIRE workload-registration entry has propagated before the brain is exec'd."""

    def test_default_probe_command(self):
        with patch.dict(
            os.environ,
            {
                "SANDBOX_SVID_PROBE_CMD": "",
                "SANDBOX_BRAIN_PYTHON": "",
                "SANDBOX_BRAIN_VENV_SITE": "",
            },
        ):
            cmd = openshell.svid_probe_command()
        body = cmd[2]
        # same confined system interpreter + venv site-packages as the brain
        assert "/usr/bin/python3.11" in body
        assert "/opt/app-root/lib/python3.11/site-packages" in body
        # exercises the real Workload API path (so it shares SVID selection logic)
        assert "_try_workload_api" in body
        # exits non-zero when no SVID yet (so the launcher keeps polling)
        assert "sys.exit(3)" in body

    def test_probe_command_overridable(self):
        with patch.dict(os.environ, {"SANDBOX_SVID_PROBE_CMD": "true"}):
            cmd = openshell.svid_probe_command()
        assert cmd == ["sh", "-c", "true"]

    def test_probe_requires_sandbox_id(self):
        import pytest

        with patch.object(openshell, "available", return_value=True):
            with pytest.raises(RuntimeError):
                openshell.probe_agent_svid(sandbox_id="")

    def test_probe_returns_true_on_exit_zero(self):
        """A probe ExecSandbox that streams an exit-0 event => SVID fetchable."""
        from types import SimpleNamespace

        exit_ev = SimpleNamespace(
            exit=SimpleNamespace(exit_code=0),
            WhichOneof=lambda _self: "exit",
        )
        fake_stub = SimpleNamespace(ExecSandbox=lambda *a, **k: iter([exit_ev]))
        fake_channel = SimpleNamespace(close=lambda: None)
        with patch.dict(os.environ, _clear_brain_env()):
            with patch.object(openshell, "available", return_value=True):
                with patch.object(
                    openshell, "_stub_and_channel", return_value=(fake_stub, fake_channel)
                ):
                    with patch.object(openshell, "_launcher_auth_metadata", return_value=[]):
                        assert openshell.probe_agent_svid(sandbox_id="uuid-1") is True

    def test_probe_returns_false_on_nonzero_exit(self):
        from types import SimpleNamespace

        exit_ev = SimpleNamespace(
            exit=SimpleNamespace(exit_code=3),
            WhichOneof=lambda _self: "exit",
        )
        fake_stub = SimpleNamespace(ExecSandbox=lambda *a, **k: iter([exit_ev]))
        fake_channel = SimpleNamespace(close=lambda: None)
        with patch.dict(os.environ, _clear_brain_env()):
            with patch.object(openshell, "available", return_value=True):
                with patch.object(
                    openshell, "_stub_and_channel", return_value=(fake_stub, fake_channel)
                ):
                    with patch.object(openshell, "_launcher_auth_metadata", return_value=[]):
                        assert openshell.probe_agent_svid(sandbox_id="uuid-1") is False
