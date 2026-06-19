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
