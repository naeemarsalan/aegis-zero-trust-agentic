"""Unit tests for skills loader and routes (C3).

No network, no cluster.
"""

from __future__ import annotations

import base64
import os

import pytest
import respx
from httpx import Response

os.environ.setdefault("GITEA_URL", "https://gitea-mock")
os.environ.setdefault("GITEA_TOKEN", "test-gitea-token")
os.environ.setdefault("GITEA_ORG", "agents")
os.environ.setdefault("SKILLS_REPO_FULL_NAME", "agents/skills")

from approval_console.skills.loader import build_init_container, build_skills_volume  # noqa: E402


# ---------------------------------------------------------------------------
# Loader unit tests
# ---------------------------------------------------------------------------


def test_build_init_container_returns_dict() -> None:
    spec = build_init_container(["pfsense-firewall", "openshift-troubleshoot"])
    assert spec["name"] == "skills-loader"
    # Skill names are passed via SKILL_NAMES env var (not hardcoded in the command).
    skill_env = next(e for e in spec["env"] if e["name"] == "SKILL_NAMES")
    assert "pfsense-firewall,openshift-troubleshoot" == skill_env["value"]
    # Volume mount is present.
    mounts = spec["volumeMounts"]
    assert any(m["name"] == "claude-skills" for m in mounts)
    # GITEA_TOKEN sourced from secretKeyRef — never hardcoded.
    token_env = next(e for e in spec["env"] if e["name"] == "GITEA_TOKEN")
    assert "secretKeyRef" in token_env["valueFrom"]


def test_build_init_container_empty_skills() -> None:
    spec = build_init_container([])
    assert spec["name"] == "skills-loader"
    # No skills → SKILL_NAMES is empty string; script exits gracefully.
    skill_env = next(e for e in spec["env"] if e["name"] == "SKILL_NAMES")
    assert skill_env["value"] == ""


def test_build_skills_volume() -> None:
    vol = build_skills_volume()
    assert vol["name"] == "claude-skills"
    assert "emptyDir" in vol


# ---------------------------------------------------------------------------
# Skills route unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_list_skills_happy_path() -> None:
    """GET /api/skills returns a list of {name, description} from the Gitea repo tree."""
    # Mock the directory listing.
    respx.get("https://gitea-mock/api/v1/repos/agents/skills/contents/").mock(
        return_value=Response(
            200,
            json=[
                {"name": "pfsense-firewall", "type": "dir"},
                {"name": "openshift-troubleshoot", "type": "dir"},
                {"name": ".gitignore", "type": "file"},  # should be skipped
            ],
        )
    )
    # Mock SKILL.md reads (best-effort; may fail silently).
    respx.get("https://gitea-mock/api/v1/repos/agents/skills/contents/pfsense-firewall/SKILL.md").mock(
        return_value=Response(
            200,
            json={
                "content": base64.b64encode(b"# pfSense Firewall\nManage rules.\n").decode(),
            },
        )
    )
    respx.get("https://gitea-mock/api/v1/repos/agents/skills/contents/openshift-troubleshoot/SKILL.md").mock(
        return_value=Response(404, json={"message": "not found"})
    )

    from httpx import AsyncClient, ASGITransport
    from approval_console.app import app
    from approval_console.skills.routes import router as skills_router

    app.include_router(skills_router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        r = await client.get("/api/skills")

    assert r.status_code == 200, r.text
    data = r.json()
    names = [s["name"] for s in data]
    assert "pfsense-firewall" in names
    assert "openshift-troubleshoot" in names
    # .gitignore (file type) must not appear.
    assert ".gitignore" not in names
    # Description from SKILL.md first line.
    pf = next(s for s in data if s["name"] == "pfsense-firewall")
    assert "pfSense" in pf["description"]


@pytest.mark.asyncio
@respx.mock
async def test_list_skills_gitea_unreachable() -> None:
    """GET /api/skills returns 502 when Gitea is unreachable."""
    import httpx

    respx.get("https://gitea-mock/api/v1/repos/agents/skills/contents/").mock(
        side_effect=httpx.ConnectError("refused")
    )

    from httpx import AsyncClient, ASGITransport
    from approval_console.app import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        r = await client.get("/api/skills")

    assert r.status_code == 502
