"""Pydantic v2 models for the persistent-agent layer (C1).

Agent     — a persistent OpenShell sandbox + identity + workspace.
AgentSession — a child task run under an Agent.
CreateAgentRequest — body for POST /api/agents.
"""

from __future__ import annotations

import datetime
import enum
from typing import List

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentState(str, enum.Enum):
    PROVISIONING = "PROVISIONING"
    READY = "READY"
    ARCHIVED = "ARCHIVED"
    ERROR = "ERROR"
    DELETED = "DELETED"


class Agent(BaseModel):
    """Persistent agent record.

    agent_id is the stable primary key (hex uuid).
    sandbox_id is the OpenShell gateway UUID — also used as the SVID path segment
    and the Vault grant key (ADR-0018 binding).
    """

    model_config = ConfigDict(populate_by_name=True)

    agent_id: str = Field(..., description="Stable hex UUID for this agent")
    display_name: str = Field(..., description="Human-readable label")
    owner: str = Field(..., description="Keycloak preferred_username of the creator")
    sandbox_name: str = Field(default="", description="OpenShell sandbox resource name")
    sandbox_id: str = Field(default="", description="OpenShell gateway UUID (SVID segment)")
    namespace: str = Field(default="openshell", description="Kubernetes namespace")
    pvc_name: str = Field(default="", description="Workspace PVC name")
    gitea_repo: str = Field(default="", description="Full Gitea repo URL")
    skills: List[str] = Field(default_factory=list, description="Loaded skill directory names")
    state: AgentState = Field(default=AgentState.PROVISIONING)
    created_at: str = Field(default_factory=lambda: _now_rfc3339())
    archived_at: str | None = Field(default=None)

    def is_active(self) -> bool:
        return self.state in {AgentState.PROVISIONING, AgentState.READY}


class AgentSessionState(str, enum.Enum):
    RUNNING = "RUNNING"
    DONE = "DONE"
    ERROR = "ERROR"


class AgentSession(BaseModel):
    """A child task run under a persistent Agent."""

    session_id: str = Field(..., description="Hex UUID, FK into the in-memory _SESSIONS map")
    agent_id: str = Field(..., description="Parent Agent agent_id")
    goal: str = Field(..., description="Natural-language goal for this session")
    state: AgentSessionState = Field(default=AgentSessionState.RUNNING)
    created_at: str = Field(default_factory=lambda: _now_rfc3339())


class CreateAgentRequest(BaseModel):
    """Body for POST /api/agents.

    skills: list of skill directory names to load from the central skills repo.
    Validated against the skills allowlist in the route handler.
    """

    model_config = ConfigDict(extra="ignore")

    display_name: str = Field(
        ...,
        min_length=1,
        max_length=80,
        description="Human-readable name for the agent",
    )
    skills: List[str] = Field(
        default_factory=list,
        description="Skill names to load (from central skills repo)",
    )
    harness_image: str = Field(
        default="",
        description=(
            "Optional brain-harness OCI image, chosen from the launch form's harness "
            "catalog. Empty = launcher default."
        ),
    )

    @field_validator("skills", mode="before")
    @classmethod
    def validate_skills(cls, v: list[str]) -> list[str]:
        if len(v) > 10:
            raise ValueError("skills list must not exceed 10 entries")
        cleaned = [s.strip() for s in v]
        blanks = [s for s in cleaned if not s]
        if blanks:
            raise ValueError("skill names must not be blank")
        return cleaned

    @field_validator("display_name", mode="before")
    @classmethod
    def validate_display_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("display_name must not be blank")
        return v


def _now_rfc3339() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
