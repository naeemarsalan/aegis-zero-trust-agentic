"""Unit tests for the Gitea client stub (C2).

Uses respx to mock all httpx calls.  No real network.
"""

from __future__ import annotations

import json
import os

import pytest
import respx
from httpx import Response

os.environ.setdefault("GITEA_URL", "https://gitea-mock")
os.environ.setdefault("GITEA_TOKEN", "test-gitea-token")
os.environ.setdefault("GITEA_ORG", "agents")

from approval_console.gitea import client as gitea_client  # noqa: E402
from approval_console.gitea.client import GiteaClientError  # noqa: E402
from approval_console.gitea.models import GiteaRepo, GiteaDeployKey  # noqa: E402


@pytest.mark.asyncio
@respx.mock
async def test_create_agent_repo_happy_path() -> None:
    """create_agent_repo returns a GiteaRepo with html_url."""
    # Org exists.
    respx.get("https://gitea-mock/api/v1/orgs/agents").mock(return_value=Response(200, json={"username": "agents"}))
    # Repo create.
    respx.post("https://gitea-mock/api/v1/orgs/agents/repos").mock(
        return_value=Response(
            201,
            json={
                "id": 42,
                "name": "test-agent-id",
                "full_name": "agents/test-agent-id",
                "html_url": "https://gitea-mock/agents/test-agent-id",
                "clone_url": "https://gitea-mock/agents/test-agent-id.git",
                "ssh_url": "git@gitea-mock:agents/test-agent-id.git",
                "private": True,
            },
        )
    )

    repo = await gitea_client.create_agent_repo(agent_id="test-agent-id", owner_username="alice")
    assert isinstance(repo, GiteaRepo)
    assert repo.html_url == "https://gitea-mock/agents/test-agent-id"
    assert repo.private is True


@pytest.mark.asyncio
@respx.mock
async def test_create_agent_repo_gitea_error() -> None:
    """create_agent_repo raises GiteaClientError on non-2xx Gitea response."""
    respx.get("https://gitea-mock/api/v1/orgs/agents").mock(return_value=Response(200, json={"username": "agents"}))
    respx.post("https://gitea-mock/api/v1/orgs/agents/repos").mock(return_value=Response(422, json={"message": "already exists"}))

    with pytest.raises(GiteaClientError) as exc_info:
        await gitea_client.create_agent_repo(agent_id="dupe-agent", owner_username="alice")
    assert exc_info.value.status_code == 422
    # Raw args must NOT appear in the exception message (hash only in audit log).
    # The exception message may contain the repo name (from Gitea response), but
    # the raw tool_args dict is never included in logs — only the sha256 hash.


@pytest.mark.asyncio
@respx.mock
async def test_create_deploy_key() -> None:
    """create_deploy_key returns a GiteaDeployKey with id and title."""
    respx.post("https://gitea-mock/api/v1/repos/agents/myrepo/keys").mock(
        return_value=Response(
            201,
            json={"id": 7, "title": "agent-myagent", "key": "ssh-ed25519 AAAA...", "read_only": True},
        )
    )

    key = await gitea_client.create_deploy_key(
        repo_full_name="agents/myrepo",
        agent_id="myagent",
        public_key="ssh-ed25519 AAAA...",
    )
    assert isinstance(key, GiteaDeployKey)
    assert key.id == 7
    assert key.title == "agent-myagent"

    # Verify the request body included the correct title.
    last_req = respx.calls.last.request
    body = json.loads(last_req.content)
    assert body["title"] == "agent-myagent"
    assert body["read_only"] is True


@pytest.mark.asyncio
@respx.mock
async def test_archive_repo() -> None:
    """archive_repo issues PATCH with name + archived=true."""
    respx.patch("https://gitea-mock/api/v1/repos/agents/old-name").mock(
        return_value=Response(200, json={"name": "old-name-archived-20260622"})
    )

    await gitea_client.archive_repo(
        repo_full_name="agents/old-name",
        archived_name="old-name-archived-20260622",
    )

    last_req = respx.calls.last.request
    body = json.loads(last_req.content)
    assert body["name"] == "old-name-archived-20260622"
    assert body["archived"] is True


@pytest.mark.asyncio
@respx.mock
async def test_delete_repo() -> None:
    """delete_repo issues DELETE and succeeds on 204."""
    respx.delete("https://gitea-mock/api/v1/repos/agents/gone").mock(return_value=Response(204))
    await gitea_client.delete_repo(repo_full_name="agents/gone")


@pytest.mark.asyncio
@respx.mock
async def test_list_repo_contents_error() -> None:
    """list_repo_contents raises GiteaClientError on 404."""
    respx.get("https://gitea-mock/api/v1/repos/agents/skills/contents/").mock(return_value=Response(404, json={"message": "not found"}))

    with pytest.raises(GiteaClientError) as exc_info:
        await gitea_client.list_repo_contents("agents/skills", path="")
    assert exc_info.value.status_code == 404
