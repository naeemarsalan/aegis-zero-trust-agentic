"""Pydantic v2 models for the JIT approver service.

Scope ceiling (enforced at validation time):
- verbs: subset of {get,list,watch,create,update,patch} — delete/escalate/impersonate rejected
- resources: must NOT contain secrets, roles, rolebindings, clusterroles
- namespace: must be in JIT_ALLOWED_NAMESPACES (default: agent-sandbox,agentic-mcp)
- duration_minutes: 1..60 (hard cap)
"""

from __future__ import annotations

import os
from enum import Enum
from typing import Annotated, List

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_VERBS = frozenset({"get", "list", "watch", "create", "update", "patch"})
DENIED_VERBS = frozenset({"delete", "deletecollection", "escalate", "impersonate", "bind"})

# Sub-string blacklist — reject any resource that contains these tokens
DENIED_RESOURCE_TOKENS = frozenset({"secret", "role", "rolebinding", "clusterrole"})


def _get_allowed_namespaces() -> frozenset[str]:
    raw = os.environ.get("JIT_ALLOWED_NAMESPACES", "agent-sandbox,agentic-mcp")
    return frozenset(ns.strip() for ns in raw.split(",") if ns.strip())


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class EscalationRequest(BaseModel):
    """Incoming JIT escalation request.

    Validated strictly — any violation raises a 422 before any Gitea or Vault
    call is made, preventing scope creep at the edge.
    """

    agent_spiffe_id: str = Field(
        ...,
        description="SPIFFE ID of the requesting agent workload, e.g. "
        "spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/my-agent",
    )
    requester_sub: str = Field(
        ...,
        description="OIDC sub claim of the human or agent principal requesting access",
    )
    namespace: str = Field(
        ...,
        description="Target Kubernetes namespace — must be in JIT_ALLOWED_NAMESPACES",
    )
    verbs: List[str] = Field(
        ...,
        min_length=1,
        description="Kubernetes verbs to grant — must be subset of get,list,watch,create,update,patch",
    )
    resources: List[str] = Field(
        ...,
        min_length=1,
        description="Kubernetes resource types to grant — secrets/roles/rolebindings/clusterroles forbidden",
    )
    duration_minutes: Annotated[int, Field(ge=1, le=60)] = Field(
        ...,
        description="Duration for the credential grant, 1–60 minutes (hard ceiling)",
    )
    justification: str = Field(
        ...,
        min_length=10,
        description="Human-readable justification for audit / PR body",
    )

    @field_validator("verbs", mode="before")
    @classmethod
    def validate_verbs(cls, v: list[str]) -> list[str]:
        normalised = [verb.lower().strip() for verb in v]
        denied = DENIED_VERBS.intersection(normalised)
        if denied:
            raise ValueError(
                f"Verbs {sorted(denied)} are not permitted in JIT requests "
                "(delete/escalate/impersonate/bind are never allowed)"
            )
        unknown = frozenset(normalised) - ALLOWED_VERBS
        if unknown:
            raise ValueError(
                f"Unknown or disallowed verbs: {sorted(unknown)}. "
                f"Allowed: {sorted(ALLOWED_VERBS)}"
            )
        return normalised

    @field_validator("resources", mode="before")
    @classmethod
    def validate_resources(cls, v: list[str]) -> list[str]:
        normalised = [r.lower().strip() for r in v]
        for resource in normalised:
            for token in DENIED_RESOURCE_TOKENS:
                if token in resource:
                    raise ValueError(
                        f"Resource '{resource}' is not permitted in JIT requests "
                        f"(contains forbidden token '{token}'). "
                        "Secrets, roles, rolebindings, and clusterroles are never grantable via JIT."
                    )
        return normalised

    @model_validator(mode="after")
    def validate_namespace(self) -> "EscalationRequest":
        allowed = _get_allowed_namespaces()
        if self.namespace not in allowed:
            raise ValueError(
                f"Namespace '{self.namespace}' is not in the JIT allowlist {sorted(allowed)}. "
                "Set JIT_ALLOWED_NAMESPACES env var to add namespaces."
            )
        return self


# ---------------------------------------------------------------------------
# Status model
# ---------------------------------------------------------------------------


class SessionState(str, Enum):
    pending = "pending"
    approved = "approved"
    issued = "issued"
    expired = "expired"
    denied = "denied"


class SessionStatus(BaseModel):
    """Current state of a JIT session.

    Credential fields (UC2) — session_jwt / sa_token / sa_token_path — are
    populated ONLY when state==issued and are returned over the authenticated
    SVID-mTLS channel. They are never set in any other state (the status endpoint
    enforces this). The agent presents session_jwt as X-JIT-Session-JWT to clear
    the Kyverno dangerous-tool gate, and wields sa_token to act (that IS UC2).
    """

    id: str = Field(..., description="Session UUID")
    state: SessionState = Field(..., description="Current lifecycle state")
    pr_url: str | None = Field(None, description="Gitea PR URL for the approval record")
    expires_at: str | None = Field(
        None,
        description="ISO-8601 UTC timestamp when the credential expires (set after issuance)",
    )
    session_jwt: str | None = Field(
        None,
        description="RS256 X-JIT-Session-JWT minted by jit-approver — the agent's "
        "own scoped, short-lived capability to clear the dangerous-tool gate. "
        "Only present when state==issued.",
    )
    sa_token: str | None = Field(
        None,
        description="Ephemeral Kubernetes ServiceAccount token (from Vault) the "
        "agent wields to act. Only present when state==issued.",
    )
    sa_token_path: str | None = Field(
        None,
        description="Vault KV path holding the durable tracking copy of the SA "
        "token (audit / revocation). Only present when state==issued.",
    )
    tool_scope: List[str] | None = Field(
        None,
        description="Dangerous MCP tool names this session is approved for "
        "(matches the session JWT tool_scope claim). Only present when issued.",
    )


# ---------------------------------------------------------------------------
# Session summary (agent posts after using credentials)
# ---------------------------------------------------------------------------


class SessionSummary(BaseModel):
    """Summary posted by the agent after it has finished using the JIT credential."""

    outcome: str = Field(
        ...,
        min_length=5,
        description="Short human-readable outcome of the privileged operation",
    )
    actions_taken: List[str] = Field(
        default_factory=list,
        description="List of discrete API calls or operations performed under the grant",
    )
    errors_encountered: List[str] = Field(
        default_factory=list,
        description="Any errors encountered during the privileged session",
    )
