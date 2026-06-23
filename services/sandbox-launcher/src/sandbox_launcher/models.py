"""Pydantic v2 models for sandbox-launcher.

Request validation enforces:
  - goal: non-empty, max 500 chars
  - capabilities: non-empty list of non-blank strings; max 20 entries
  - mode: 'task' | 'project'
  - user: non-empty; used only as advisory label (no authz decision is made from it
    unless a verified Backstage JWT is also present to cross-check)
  - confirmed: must be exactly True (server-side guard per design brief §(1) caveat 5)
  - ttl_minutes: 5–480
"""

from __future__ import annotations

from enum import Enum
from typing import List

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LaunchMode(str, Enum):
    task = "task"
    project = "project"


class LaunchScope(str, Enum):
    """Permission tier the agent operates at — recorded as sandbox metadata only.

    The launcher does NOT enforce this; it is the tier the in-flow JIT/elevator
    gate keys on (read-only stays on the deny-by-default floor; read-write/admin
    tools trigger a JIT approval). Mirrors the template's `scope` enum.
    """

    read_only = "read-only"
    read_write = "read-write"
    admin = "admin"


class LaunchRequest(BaseModel):
    """Body for POST /launch.

    The 'user' field carries the entity ref from the RHDH scaffolder template
    (e.g. 'user:default/arsalan'). It is:
      - cross-checked against the verified Backstage JWT 'sub' claim when the
        caller token is present and verifiable.
      - used ONLY as advisory metadata (sandbox owner label); it is NOT used for
        any authorization decision by itself.

    The caller MUST send a verified Backstage token via Authorization: Bearer
    (proxy must be configured with credentials: forward) for the user identity
    to be cryptographically bound. See auth.py for the verification flow.

    Field aliases match the camelCase keys the RHDH scaffolder template POSTs
    (userRef, ttlMinutes); populate_by_name keeps the snake_case names usable
    from Python (tests, internal callers). extra='ignore' tolerates any future
    template field without a brittle 422.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    goal: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Natural-language goal for the packaged agent (max 500 chars)",
    )
    capabilities: List[str] = Field(
        ...,
        min_length=1,
        description="Catalog entity names of capabilities to enable (non-empty)",
    )
    skills: List[str] = Field(
        default_factory=list,
        description=(
            "Skill directory names to load into the sandbox. Threaded onto the "
            "Sandbox CR podTemplate as the 'agents.x-k8s.io/skills' annotation, which "
            "the mutate-openshell-sandbox-skills-loader Kyverno policy reads to inject "
            "a skills-loader init-container (git-clones the selected skills into the "
            "agent's .claude/skills emptyDir). Empty = no extra skills loaded."
        ),
    )
    harness_image: str = Field(
        default="",
        alias="harnessImage",
        description=(
            "Optional OCI image for the brain-bearing agent-harness. When set, the "
            "launcher uses this image for the Sandbox instead of the default "
            "SANDBOX_IMAGE. Must be a known-good harness image (the caller picks from "
            "a catalog in the launch form). Empty = use the launcher default."
        ),
    )
    mode: LaunchMode = Field(
        ...,
        description="'task' for a single-goal run; 'project' for a multi-step session",
    )
    scope: LaunchScope = Field(
        default=LaunchScope.read_only,
        description="Permission tier (read-only|read-write|admin) — recorded as a "
        "sandbox label; the JIT gate enforces it, not the launcher.",
    )
    user: str = Field(
        ...,
        min_length=1,
        alias="userRef",
        description=(
            "RHDH entity ref of the requesting user (e.g. 'user:default/arsalan'). "
            "Advisory only — cross-checked against the Backstage JWT when present. "
            "Sent by the template as 'userRef'."
        ),
    )
    confirmed: bool = Field(
        ...,
        description="Must be exactly true — prevents accidental scaffolder dry-runs from launching sandboxes. "
        "The template always sends it (templated from the _confirm review step).",
    )
    ttl_minutes: int = Field(
        default=60,
        ge=5,
        le=480,
        alias="ttlMinutes",
        description="Sandbox lifetime in minutes (5–480). Sent by the template as 'ttlMinutes'.",
    )

    @field_validator("capabilities", mode="before")
    @classmethod
    def validate_capabilities(cls, v: list[str]) -> list[str]:
        if len(v) > 20:
            raise ValueError("capabilities list must not exceed 20 entries")
        cleaned = [c.strip() for c in v]
        blanks = [c for c in cleaned if not c]
        if blanks:
            raise ValueError("capabilities entries must not be blank")
        return cleaned

    @field_validator("user", mode="before")
    @classmethod
    def validate_user(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("user must not be blank")
        return v

    @field_validator("skills", mode="before")
    @classmethod
    def validate_skills(cls, v: list[str] | None) -> list[str]:
        if not v:
            return []
        if len(v) > 10:
            raise ValueError("skills list must not exceed 10 entries")
        cleaned = [s.strip() for s in v]
        if any(not s for s in cleaned):
            raise ValueError("skill names must not be blank")
        return cleaned


class LaunchResponse(BaseModel):
    """Response from POST /launch."""

    sandbox_name: str = Field(..., description="OpenShell sandbox name (stable lookup key)")
    sandbox_id: str = Field(..., description="Stable UUID assigned by the gateway")
    namespace: str = Field(
        default="openshell",
        description="Kubernetes namespace where the sandbox runs",
    )
    phase: str = Field(
        ...,
        description="SandboxPhase at creation time (PROVISIONING on success)",
    )
    conversation_url: str | None = Field(
        default=None,
        description=(
            "Public conversation URL — null until ExposeService is called after sandbox reaches READY. "
            "Use access_hint to reach the sandbox via oc exec in the interim."
        ),
    )
    access_hint: str = Field(
        ...,
        description="oc exec command to reach the agent once the sandbox is READY",
    )
    owner: str = Field(..., description="Verified or advisory entity ref of the sandbox owner")
