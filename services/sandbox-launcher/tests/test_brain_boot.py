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
        # both credential env names get populated from whichever the launcher has
        assert env["ANTHROPIC_API_KEY"] == "sk-litellm-xyz"
        assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-litellm-xyz"
        assert env["AGENT_MODEL"] == "anthropic/claude-sonnet-4"
        # the runner needs the URL-honouring system CLI, not the bundled SDK binary
        assert env["CLAUDE_CLI_PATH"] == "/usr/local/bin/claude"

    def test_no_reserved_openshell_keys(self):
        """The brain env must contain ZERO keys with the gateway-reserved prefix."""
        patch_env = _clear_brain_env()
        patch_env.update(
            {"ANTHROPIC_BASE_URL": "http://x:4000", "ANTHROPIC_API_KEY": "k"}
        )
        with patch.dict(os.environ, patch_env):
            env = openshell._brain_env(goal="g", allowed_tools="Bash")
        assert not any(k.startswith("OPENSHELL_") for k in env), env

    def test_auth_token_only_populates_both(self):
        patch_env = _clear_brain_env()
        patch_env.update(
            {
                "ANTHROPIC_BASE_URL": "http://172.16.2.251:4000",
                "ANTHROPIC_AUTH_TOKEN": "auth-only",
            }
        )
        with patch.dict(os.environ, patch_env):
            env = openshell._brain_env(goal="g", allowed_tools="Bash")
        assert env["ANTHROPIC_API_KEY"] == "auth-only"
        assert env["ANTHROPIC_AUTH_TOKEN"] == "auth-only"

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


class TestBrainBootCommand:
    """The native ExecSandbox boot command (NOT the reserved OPENSHELL_SANDBOX_COMMAND)."""

    def test_default_command(self):
        with patch.dict(os.environ, {"SANDBOX_BRAIN_COMMAND": ""}):
            cmd = openshell._brain_boot_command()
        assert cmd == ["sh", "-c", "cd /app && exec python -m agent_harness.agent_runner"]

    def test_override(self):
        with patch.dict(os.environ, {"SANDBOX_BRAIN_COMMAND": "python -m custom.runner"}):
            cmd = openshell._brain_boot_command()
        assert cmd == ["sh", "-c", "python -m custom.runner"]

    def test_exec_skips_when_no_inference(self):
        """exec_agent_brain returns the no-inference sentinel without touching gRPC."""
        patch_env = _clear_brain_env()  # clears ANTHROPIC_BASE_URL -> _brain_env == {}
        with patch.dict(os.environ, patch_env):
            with patch.object(openshell, "available", return_value=True):
                rc = openshell.exec_agent_brain(
                    sandbox_id="uuid-123", goal="g", allowed_tools="Bash"
                )
        assert rc == -1
