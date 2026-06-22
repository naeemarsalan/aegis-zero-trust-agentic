"""Pydantic models for Gitea API responses (C2)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GiteaRepo(BaseModel):
    """Minimal subset of a Gitea repository response."""

    id: int = Field(default=0)
    name: str = Field(default="")
    full_name: str = Field(default="")
    html_url: str = Field(default="")
    clone_url: str = Field(default="")
    ssh_url: str = Field(default="")
    private: bool = Field(default=True)


class GiteaDeployKey(BaseModel):
    """Gitea deploy key response."""

    id: int = Field(default=0)
    title: str = Field(default="")
    key: str = Field(default="")
    read_only: bool = Field(default=True)
