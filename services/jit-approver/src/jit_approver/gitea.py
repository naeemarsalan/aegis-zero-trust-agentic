"""Gitea integration — create branch, commit scope YAML, open JIT-approval PR.

Token resolution order:
  1. env GITEA_TOKEN
  2. file /vault/secrets/gitea-token  (Vault injector tmpfs)

The PR body renders the full requested scope as a reviewable YAML document so
that the approver (human or automated policy) can diff exactly what will be
issued. PR merge == approval (webhook.py picks up the merge event).
"""

from __future__ import annotations

import hashlib
import logging
import os
import textwrap
from datetime import datetime, timezone
from typing import Any

import httpx
import yaml  # PyYAML — available in python:3.12-slim via pip

from jit_approver.models import EscalationRequest

logger = logging.getLogger("jit_approver.gitea")

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

_TOKEN_FILE = "/vault/secrets/gitea-token"


def _gitea_token() -> str:
    token = os.environ.get("GITEA_TOKEN", "")
    if token:
        return token
    try:
        with open(_TOKEN_FILE) as fh:
            return fh.read().strip()
    except FileNotFoundError:
        raise RuntimeError(
            "GITEA_TOKEN env var not set and /vault/secrets/gitea-token not found. "
            "Ensure the Vault injector annotation is configured."
        )


def _gitea_base_url() -> str:
    return os.environ.get("GITEA_BASE_URL", "https://git.arsalan.io")


def _gitea_repo() -> str:
    """Return owner/repo, e.g. 'anaeem/nvidia-ida'."""
    return os.environ.get("GITEA_REPO", "anaeem/nvidia-ida")


def _gitea_default_branch() -> str:
    return os.environ.get("GITEA_DEFAULT_BRANCH", "main")


def _default_reviewer() -> str | None:
    return os.environ.get("GITEA_DEFAULT_REVIEWER", "")


# ---------------------------------------------------------------------------
# YAML document rendered into the PR commit
# ---------------------------------------------------------------------------


def _render_scope_yaml(session_id: str, req: EscalationRequest) -> str:
    """Render the requested scope as a human-reviewable YAML document."""
    doc = {
        "apiVersion": "jit.anaeem.na-launch.com/v1alpha1",
        "kind": "JITGrant",
        "metadata": {
            "name": f"jit-{session_id}",
            "creationTimestamp": datetime.now(timezone.utc).isoformat(),
        },
        "spec": {
            "sessionId": session_id,
            "requesterSub": req.requester_sub,
            "agentSpiffeId": req.agent_spiffe_id,
            "justification": req.justification,
            "requestedScope": {
                "namespace": req.namespace,
                "durationMinutes": req.duration_minutes,
                "rules": [
                    {
                        "verbs": req.verbs,
                        "resources": req.resources,
                    }
                ],
            },
            # Vault role caps documented inline for reviewer. The reviewed scope
            # above is the ENFORCED scope: at issuance an EPHEMERAL Vault role
            # kubernetes/roles/jit-<sessionId> is created from exactly these
            # verbs/resources/namespace/TTL, then read once. There is no static
            # role whose rules could silently override the review.
            "vaultRoleCaps": {
                "role": "jit-<sessionId> (ephemeral, created per approval)",
                "allowedNamespaces": [req.namespace],
                "ttlMax": f"{req.duration_minutes}m",
                "permissionsGranted": (
                    "single-namespace SA token via kubernetes/creds/jit-<sessionId>; "
                    "generated_role_rules == the reviewed verbs/resources above"
                ),
                "credentialDelivery": (
                    "stored in Vault KV secret/data/jit/<sessionId>; "
                    "agent reads via injector template — never returned over HTTP"
                ),
                "cleanupBackstop": (
                    "the expiry reaper MUST delete kubernetes/roles/jit-<sessionId> "
                    "in addition to revoking the lease and the KV entry"
                ),
            },
        },
    }
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)


def _pr_body(session_id: str, req: EscalationRequest, scope_yaml: str) -> str:
    """Render the PR body including scope, justification and denial context."""
    return textwrap.dedent(f"""\
        ## JIT Escalation Request

        | Field | Value |
        |-------|-------|
        | Session ID | `{session_id}` |
        | Requester | `{req.requester_sub}` |
        | Agent SPIFFE | `{req.agent_spiffe_id}` |
        | Namespace | `{req.namespace}` |
        | Verbs | `{", ".join(req.verbs)}` |
        | Resources | `{", ".join(req.resources)}` |
        | Duration | `{req.duration_minutes}m` |

        ### Justification

        {req.justification}

        ### Requested Scope (reviewable YAML)

        ```yaml
        {scope_yaml}
        ```

        ### Vault Role Caps (what will actually be issued)

        - Vault role: `jit-{session_id}` — an **ephemeral** role created at issuance time
          from the reviewed scope above (`generated_role_rules` == the verbs/resources in this
          PR). The reviewed scope is the **enforced** scope; there is no static role to override it.
        - Namespace cap: `{req.namespace}` only
        - TTL cap: `{req.duration_minutes}m` (hard max 60m)
        - Credential delivery: stored in Vault KV `secret/data/jit/{session_id}` — the agent's
          pod has an injector template reading exactly that path. The approver (this service)
          **never** returns the token over HTTP.
        - Cleanup: on expiry the reaper deletes `kubernetes/roles/jit-{session_id}` plus the lease
          and the KV entry.

        > **Editing this PR:** a reviewer MAY narrow the scope by editing
        > `grants/{session_id}.yaml` before merging. Issuance reads the **merged** YAML and
        > re-validates it through the ceiling — the edited (narrower) scope is honored, and a
        > scope that exceeds the ceiling is denied. The original request is never used to mint.

        ### Denial Context

        Merging this PR approves the grant. **Closing without merging** constitutes denial.
        The requester will be notified of the outcome via the session status API.

        ---
        *Auto-generated by jit-approver service. Human review is required before merging.*
    """)


# ---------------------------------------------------------------------------
# Gitea API client
# ---------------------------------------------------------------------------


class GiteaClient:
    """Thin async wrapper around the Gitea API."""

    def __init__(self, http: httpx.AsyncClient | None = None):
        self._http = http  # injected in tests; built lazily in production

    def _client(self) -> httpx.AsyncClient:
        if self._http is not None:
            return self._http
        raise RuntimeError("Call within an async context manager or inject a client")

    async def _get_default_branch_sha(self, repo: str, branch: str) -> str:
        """Return the HEAD SHA of `branch`."""
        base = _gitea_base_url()
        resp = await self._client().get(
            f"{base}/api/v1/repos/{repo}/branches/{branch}",
            headers={"Authorization": f"token {_gitea_token()}"},
        )
        resp.raise_for_status()
        return resp.json()["commit"]["id"]

    async def create_branch(self, session_id: str, base_sha: str) -> str:
        """Create branch jit/<session-id> from base_sha. Returns branch name."""
        repo = _gitea_repo()
        base = _gitea_base_url()
        branch_name = f"jit/{session_id}"
        resp = await self._client().post(
            f"{base}/api/v1/repos/{repo}/branches",
            headers={
                "Authorization": f"token {_gitea_token()}",
                "Content-Type": "application/json",
            },
            json={"new_branch_name": branch_name, "old_branch_name": _gitea_default_branch()},
        )
        resp.raise_for_status()
        logger.info("created_branch", extra={"branch": branch_name, "session": session_id})
        return branch_name

    async def commit_scope_file(
        self, session_id: str, branch: str, scope_yaml: str
    ) -> None:
        """Commit grants/<session-id>.yaml to the branch."""
        repo = _gitea_repo()
        base = _gitea_base_url()
        import base64 as b64mod

        content_b64 = b64mod.b64encode(scope_yaml.encode()).decode()
        resp = await self._client().post(
            f"{base}/api/v1/repos/{repo}/contents/grants/{session_id}.yaml",
            headers={
                "Authorization": f"token {_gitea_token()}",
                "Content-Type": "application/json",
            },
            json={
                "message": f"jit: add scope for session {session_id}",
                "content": content_b64,
                "branch": branch,
            },
        )
        resp.raise_for_status()
        logger.info("committed_scope_file", extra={"session": session_id, "branch": branch})

    async def open_pr(
        self, session_id: str, branch: str, req: EscalationRequest, body: str
    ) -> str:
        """Open a PR and return its HTML URL."""
        repo = _gitea_repo()
        base = _gitea_base_url()
        title = (
            f"[JIT] {req.requester_sub} requests "
            f"{','.join(req.verbs)} on {','.join(req.resources)} "
            f"in {req.namespace} for {req.duration_minutes}m"
        )
        payload: dict[str, Any] = {
            "title": title,
            "head": branch,
            "base": _gitea_default_branch(),
            "body": body,
            "labels": [],  # label IDs resolved separately
        }
        reviewer = _default_reviewer()
        if reviewer:
            payload["reviewers"] = [reviewer]

        resp = await self._client().post(
            f"{base}/api/v1/repos/{repo}/pulls",
            headers={
                "Authorization": f"token {_gitea_token()}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        resp.raise_for_status()
        pr_url: str = resp.json()["html_url"]

        # Best-effort: apply jit-approval label (label must exist in repo)
        pr_number: int = resp.json()["number"]
        await self._apply_label(repo, pr_number, "jit-approval")

        logger.info(
            "opened_pr",
            extra={"session": session_id, "pr_url": pr_url, "pr_number": pr_number},
        )
        return pr_url

    async def _apply_label(self, repo: str, pr_number: int, label_name: str) -> None:
        """Resolve label by name then apply to PR — swallows errors (label may not exist)."""
        base = _gitea_base_url()
        try:
            resp = await self._client().get(
                f"{base}/api/v1/repos/{repo}/labels",
                headers={"Authorization": f"token {_gitea_token()}"},
                params={"limit": 50},
            )
            resp.raise_for_status()
            label_id: int | None = None
            for lbl in resp.json():
                if lbl.get("name") == label_name:
                    label_id = lbl["id"]
                    break
            if label_id is None:
                logger.warning("label_not_found", extra={"label": label_name, "repo": repo})
                return
            resp2 = await self._client().post(
                f"{base}/api/v1/repos/{repo}/issues/{pr_number}/labels",
                headers={
                    "Authorization": f"token {_gitea_token()}",
                    "Content-Type": "application/json",
                },
                json={"labels": [label_id]},
            )
            resp2.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            logger.warning("apply_label_failed", extra={"error": str(exc), "label": label_name})

    async def comment_on_pr(self, pr_number: int, body: str) -> None:
        """Post a comment on an existing PR."""
        repo = _gitea_repo()
        base = _gitea_base_url()
        resp = await self._client().post(
            f"{base}/api/v1/repos/{repo}/issues/{pr_number}/comments",
            headers={
                "Authorization": f"token {_gitea_token()}",
                "Content-Type": "application/json",
            },
            json={"body": body},
        )
        resp.raise_for_status()

    async def fetch_merged_grant(self, session_id: str, ref: str | None = None) -> str:
        """Fetch the raw, REVIEWED grants/<session-id>.yaml from the merged ref.

        This is the C2 anti-TOCTOU read: issuance must mint from the artifact a
        human actually reviewed and merged, NOT the in-memory request captured
        at submit time. We read the raw file content from ``ref`` (the merge
        commit SHA, or the default branch if not supplied) via the Gitea raw
        contents API. Returns the YAML text.
        """
        repo = _gitea_repo()
        base = _gitea_base_url()
        branch = ref or _gitea_default_branch()
        resp = await self._client().get(
            f"{base}/api/v1/repos/{repo}/raw/grants/{session_id}.yaml",
            headers={"Authorization": f"token {_gitea_token()}"},
            params={"ref": branch},
        )
        resp.raise_for_status()
        return resp.text


# ---------------------------------------------------------------------------
# Parse + re-validate a reviewed grant YAML back into an EscalationRequest
# ---------------------------------------------------------------------------


def parse_grant_yaml(scope_yaml: str) -> EscalationRequest:
    """Parse a reviewed JITGrant YAML and RE-VALIDATE it through the ceiling.

    The merged YAML is the source of truth for issuance (C2). It may legitimately
    differ from the original request because a reviewer narrowed/edited the scope.
    We rebuild an :class:`EscalationRequest` from ``spec.requestedScope`` and the
    surrounding spec fields, which runs the SAME pydantic ceiling validators
    (verbs/resources/namespace/duration). If the reviewed YAML exceeds the
    ceiling, pydantic raises and the caller MUST deny + audit (fail closed).
    """
    doc = yaml.safe_load(scope_yaml)
    if not isinstance(doc, dict):
        raise ValueError("merged grant YAML is not a mapping")

    spec = doc.get("spec") or {}
    scope = spec.get("requestedScope") or {}
    rules = scope.get("rules") or []
    if not rules:
        raise ValueError("merged grant YAML has no requestedScope.rules")

    # Collapse all rule blocks into a flat verbs/resources set (the Vault role
    # we build is a single generated_role_rules block, so we union them).
    verbs: list[str] = []
    resources: list[str] = []
    for rule in rules:
        verbs.extend(rule.get("verbs") or [])
        resources.extend(rule.get("resources") or [])

    # Re-run the ceiling. ValueError/ValidationError here => deny.
    return EscalationRequest(
        agent_spiffe_id=spec.get("agentSpiffeId", ""),
        requester_sub=spec.get("requesterSub", ""),
        namespace=scope.get("namespace", ""),
        verbs=verbs,
        resources=resources,
        duration_minutes=scope.get("durationMinutes", 0),
        justification=spec.get("justification", ""),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def create_approval_pr(
    session_id: str,
    req: EscalationRequest,
    http: httpx.AsyncClient | None = None,
) -> str:
    """Create a Gitea JIT approval PR and return its HTML URL.

    Parameters
    ----------
    session_id : str
        The UUID for this JIT session.
    req : EscalationRequest
        The validated escalation request.
    http : httpx.AsyncClient | None
        Injected HTTP client (for testing). If None, a real client is created.

    Returns
    -------
    str
        HTML URL of the newly-opened PR.
    """
    async def _run(client: httpx.AsyncClient) -> str:
        gc = GiteaClient(http=client)
        scope_yaml = _render_scope_yaml(session_id, req)
        branch = await gc.create_branch(session_id, base_sha="")
        await gc.commit_scope_file(session_id, branch, scope_yaml)
        body = _pr_body(session_id, req, scope_yaml)
        pr_url = await gc.open_pr(session_id, branch, req, body)
        return pr_url

    if http is not None:
        return await _run(http)

    async with httpx.AsyncClient(timeout=30.0) as client:
        return await _run(client)
