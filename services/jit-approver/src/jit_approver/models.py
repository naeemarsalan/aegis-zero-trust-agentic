"""Pydantic v2 models for the JIT approver service.

Scope ceiling (enforced at validation time):
- verbs: subset of {get,list,watch,create,update,patch} — delete/escalate/impersonate rejected
- resources: must NOT contain secrets, roles, rolebindings, clusterroles
- namespace: must be in JIT_ALLOWED_NAMESPACES (default: agent-sandbox,agentic-mcp)
- duration_minutes: 1..60 (hard cap)
"""

from __future__ import annotations

import hashlib
import json
import os
from enum import Enum
from typing import Annotated, List, Optional

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
    base = {ns.strip() for ns in raw.split(",") if ns.strip()}
    # Demo namespaces pinned here so they survive a gitops env re-sync (this file is
    # mounted as an override; the deploy env is managed by ArgoCD). Also honors the env.
    base |= {ns.strip() for ns in os.environ.get("JIT_PINNED_NAMESPACES", "mcp-demo,kagenti-test").split(",") if ns.strip()}
    return frozenset(base)


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class PolicyNetworkEndpoint(BaseModel):
    """One egress endpoint a grant may temporarily open on the OpenShell floor."""

    host: str = Field(..., min_length=1, description="Destination host (FQDN)")
    port: Annotated[int, Field(ge=1, le=65535)] = Field(
        default=443, description="Destination port"
    )


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
        min_length=1,
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
    duration_minutes: Annotated[int, Field(ge=10, le=60)] = Field(
        ...,
        description="Duration for the credential grant, 10–60 minutes. Floor is 10: "
        "the Kubernetes TokenRequest API rejects ServiceAccount tokens with an "
        "expiration under 10 minutes, and the ephemeral SA token TTL is derived "
        "from this value.",
    )
    justification: str = Field(
        ...,
        min_length=10,
        description="Human-readable justification for audit / PR body",
    )
    # OpenShell policy elevator (the "request changes" for the network floor).
    # When set, an approved grant ALSO widens the named sandbox's egress to these
    # endpoints for the grant window (via openshell.py), reverting on expiry —
    # the same time-boxed, audited shape as the SA token. Optional: omit for a
    # pure Kubernetes-RBAC grant.
    sandbox: str | None = Field(
        default=None,
        description="OpenShell sandbox name to widen (required if policy_delta is set)",
    )
    policy_delta: List[PolicyNetworkEndpoint] = Field(
        default_factory=list,
        description="Network endpoints to temporarily allow egress to (host+port). "
        "Deny-by-default baseline otherwise.",
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


# ---------------------------------------------------------------------------
# L1: MintRequest — body of POST /requests/{id}/mint
# ---------------------------------------------------------------------------


class MintRequest(BaseModel):
    """Body of POST /requests/{id}/mint.

    approver_sub is the Keycloak-resolved identity of the human approver,
    taken from server-trusted oauth2-proxy forwarded headers in the console
    and forwarded here. NEVER accepted from an untrusted source.

    scope_hash binds the approver's view of the scope to the stored request
    (anti-TOCTOU): the console computes canonical_scope_hash(detail) and
    sends it; the mint handler recomputes from the stored EscalationRequest
    and rejects on mismatch.
    """

    approver_sub: str = Field(
        ...,
        min_length=1,
        description="Keycloak preferred_username / OIDC sub of the approving operator",
    )
    reviewed_scope: Optional[dict] = Field(
        default=None,
        description="Optional echo of the scope the operator reviewed (for audit); "
        "issuance is from the stored request, not this field.",
    )
    scope_hash: str = Field(
        ...,
        min_length=1,
        description="SHA-256 hex of canonical_scope_hash(stored_req) — must match "
        "the server-side recomputed hash to prevent TOCTOU scope substitution.",
    )


# ---------------------------------------------------------------------------
# L1: canonical_scope_hash — single source of truth for scope binding
# ---------------------------------------------------------------------------


def canonical_scope_hash(req: "EscalationRequest") -> str:
    """Return the SHA-256 hex digest of the canonical JSON representation of the
    ceiling-relevant scope fields.

    The fields included mirror agent_harness.agent_runner._hash_args (the hash
    the agent computes over tool arguments).  Sorting is applied to all
    collection fields so the hash is stable under reordering.

    Fields:
      namespace         — target Kubernetes namespace
      verbs             — sorted list of requested verbs
      resources         — sorted list of requested resources
      duration_minutes  — grant duration
      sandbox           — OpenShell sandbox name (None if absent)
      policy_delta      — sorted list of "host:port" strings

    The console's _canonical_scope_hash() helper MUST produce identical output
    for the same scope (tested in test_mint.py::test_canonical_scope_hash_cross_check).
    """
    delta_sorted = sorted(
        f"{pd.host}:{pd.port}" for pd in (req.policy_delta or [])
    )
    canonical: dict = {
        "namespace": req.namespace,
        "verbs": sorted(req.verbs),
        "resources": sorted(req.resources),
        "duration_minutes": req.duration_minutes,
        "sandbox": req.sandbox,
        "policy_delta": delta_sorted,
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()
