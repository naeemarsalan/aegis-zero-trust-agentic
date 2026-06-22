"""GET /api/skills — list available skills from the central Gitea skills repo (C3).

Returns a list of {name, description} objects.  The description is derived from
the first non-empty line of the skill's SKILL.md (if readable via the Gitea API);
otherwise just the directory name.

Fail-closed: if the Gitea API is unreachable, return 502.
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from approval_console.gitea import client as gitea_client
from approval_console.gitea.client import GiteaClientError

logger = logging.getLogger("approval_console.skills.routes")

router = APIRouter(prefix="/api/skills", tags=["skills"])

_SKILLS_REPO_FULL_NAME = os.environ.get("SKILLS_REPO_FULL_NAME", "agents/skills")


@router.get("")
async def list_skills() -> JSONResponse:
    """Return available skills from the central Gitea skills repo.

    Reads the top-level directory listing; each directory is a skill.
    The description is read from <skill>/SKILL.md first line (best-effort).
    """
    try:
        entries = await gitea_client.list_repo_contents(_SKILLS_REPO_FULL_NAME, path="")
    except GiteaClientError as exc:
        raise HTTPException(status_code=502, detail=f"Skills repo unavailable: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        logger.error("skills.list_error: %s", exc)
        raise HTTPException(status_code=502, detail="Skills repo unavailable") from exc

    skills = []
    for entry in entries:
        if entry.get("type") != "dir":
            continue
        name = entry.get("name", "")
        if not name or name.startswith("."):
            continue
        description = await _read_skill_description(name)
        skills.append({"name": name, "description": description})

    return JSONResponse(content=skills)


async def _read_skill_description(skill_name: str) -> str:
    """Read the first non-heading line of the skill's SKILL.md for a short description."""
    try:
        entries = await gitea_client.list_repo_contents(
            _SKILLS_REPO_FULL_NAME, path=f"{skill_name}/SKILL.md"
        )
        # Gitea returns a single file object with 'content' (base64-encoded).
        import base64

        content_b64 = entries.get("content", "")  # type: ignore[union-attr]
        if not content_b64:
            return skill_name
        text = base64.b64decode(content_b64).decode("utf-8", errors="replace")
        for line in text.splitlines():
            stripped = line.strip().lstrip("#").strip()
            if stripped and not stripped.startswith("---"):
                return stripped[:120]
    except Exception:  # noqa: BLE001
        pass
    return skill_name
