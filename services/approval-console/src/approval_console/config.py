"""Runtime configuration — all values arrive via environment variables.

No secrets in source. GITEA_TOKEN is read server-side only; the browser
never sees it.
"""

from __future__ import annotations

import os


def _require(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise RuntimeError(
            f"Required environment variable {name!r} is not set. "
            "See the approval-console README for the env contract."
        )
    return val


def _optional(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


class Config:
    """Lazily-read config — evaluated once at first access."""

    @staticmethod
    def jit_approver_url() -> str:
        """Base URL of the jit-approver service, e.g. http://jit-approver:8080."""
        return _require("JIT_APPROVER_URL")

    @staticmethod
    def gitea_url() -> str:
        """Gitea base URL, e.g. https://git.arsalan.io."""
        return _require("GITEA_URL")

    @staticmethod
    def gitea_token() -> str:
        """Gitea API token — server-side only, never sent to browser.

        Resolution order:
          1. env GITEA_TOKEN
          2. file /vault/secrets/gitea-token  (Vault Agent Injector)
        """
        token = os.environ.get("GITEA_TOKEN", "").strip()
        if token:
            return token
        try:
            with open("/vault/secrets/gitea-token") as fh:
                return fh.read().strip()
        except FileNotFoundError:
            raise RuntimeError(
                "GITEA_TOKEN env var not set and /vault/secrets/gitea-token not found."
            )

    @staticmethod
    def gitea_owner() -> str:
        """Gitea repo owner (left side of owner/repo).

        Falls back to parsing GITEA_REPO env var if GITEA_OWNER is absent,
        matching jit-approver's GITEA_REPO='anaeem/nvidia-ida' convention.
        """
        explicit = _optional("GITEA_OWNER")
        if explicit:
            return explicit
        repo = _optional("GITEA_REPO", "anaeem/nvidia-ida")
        return repo.split("/")[0] if "/" in repo else repo

    @staticmethod
    def gitea_repo() -> str:
        """Gitea repo name (right side of owner/repo)."""
        explicit = _optional("GITEA_REPO_NAME")
        if explicit:
            return explicit
        repo = _optional("GITEA_REPO", "anaeem/nvidia-ida")
        parts = repo.split("/")
        return parts[1] if len(parts) >= 2 else repo

    @staticmethod
    def poll_interval_seconds() -> int:
        """How often the browser polls for updates (default 5 s)."""
        try:
            return int(_optional("POLL_INTERVAL_SECONDS", "5"))
        except ValueError:
            return 5

    # ------------------------------------------------------------------
    # Agent-harness / troubleshoot session config
    # ------------------------------------------------------------------

    @staticmethod
    def harness_namespace() -> str:
        """Kubernetes namespace where the e2e-harness pod runs."""
        return _optional("HARNESS_NAMESPACE", "agent-sandbox")

    @staticmethod
    def harness_selector() -> str:
        """Label selector to find the harness pod (e.g. app=e2e-harness)."""
        return _optional("HARNESS_SELECTOR", "app=e2e-harness")

    @staticmethod
    def harness_container() -> str:
        """Container name inside the harness pod."""
        return _optional("HARNESS_CONTAINER", "agent")

    @staticmethod
    def k8s_mcp_read_url() -> str:
        """URL of the read-only k8s MCP service surfaced inside the harness."""
        return _optional(
            "K8S_MCP_READ_URL",
            "http://k8s-mcp-view.k8s-mcp.svc.cluster.local:8080",
        )

    @staticmethod
    def k8s_mcp_write_url() -> str:
        """URL of the write/JIT-gated k8s MCP service surfaced inside the harness."""
        return _optional(
            "K8S_MCP_WRITE_URL",
            "http://jit-gate-k8s.k8s-mcp.svc.cluster.local:8000",
        )

    @staticmethod
    def jit_target_namespace() -> str:
        """Kubernetes namespace the agent targets for the troubleshoot demo."""
        return _optional("JIT_TARGET_NAMESPACE", "mcp-demo")

    @staticmethod
    def agent_allowed_tools() -> str:
        """Comma-separated list of tools the agent harness may use."""
        return _optional("AGENT_ALLOWED_TOOLS", "Bash")

    @staticmethod
    def agent_max_turns() -> str:
        """Maximum number of agent turns (string — injected as env var)."""
        return _optional("AGENT_MAX_TURNS", "20")

    # ------------------------------------------------------------------
    # oauth2-proxy / identity-forwarding header names
    # ------------------------------------------------------------------

    @staticmethod
    def fwd_username_header() -> str:
        """HTTP header injected by oauth2-proxy carrying the OIDC preferred_username."""
        return _optional("FWD_USERNAME_HEADER", "x-forwarded-preferred-username")

    @staticmethod
    def fwd_email_header() -> str:
        """HTTP header injected by oauth2-proxy carrying the OIDC email claim."""
        return _optional("FWD_EMAIL_HEADER", "x-forwarded-email")

    @staticmethod
    def fwd_user_header() -> str:
        """HTTP header injected by oauth2-proxy as a generic user identifier."""
        return _optional("FWD_USER_HEADER", "x-forwarded-user")

    @staticmethod
    def default_goal() -> str:
        """Default troubleshooting goal injected into the browser textarea.

        Tells the agent that mcp-call is a SHELL command so it does not give
        up looking for native Kubernetes/MCP tools that do not exist in the
        harness environment.
        """
        return _optional(
            "DEFAULT_GOAL",
            (
                "You troubleshoot OpenShift using a SHELL COMMAND named mcp-call "
                "(run it with Bash: mcp-call <tool> '<json-args>'). "
                "Do NOT look for native Kubernetes/MCP tools; mcp-call is your ONLY path, "
                "just run it in Bash. "
                "The Deployment broken-app in namespace mcp-demo has 0 running pods. "
                "STEP 1 diagnose: run "
                " mcp-call pods_list_in_namespace '{\"namespace\":\"mcp-demo\"}' "
                " and "
                " mcp-call resources_get '{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\","
                "\"name\":\"broken-app\",\"namespace\":\"mcp-demo\"}' . "
                "STEP 2 fix: run "
                " mcp-call resources_scale '{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\","
                "\"name\":\"broken-app\",\"namespace\":\"mcp-demo\",\"scale\":1}' "
                " — this write is denied and needs human approval; "
                "mcp-call files the request and WAITS; keep waiting until it returns. "
                "STEP 3 verify with mcp-call resources_get that replicas is 1, then report."
            ),
        )
