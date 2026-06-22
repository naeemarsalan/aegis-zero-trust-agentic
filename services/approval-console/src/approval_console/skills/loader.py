"""Skills init-container spec builder (C3).

build_init_container(skill_names) returns a dict representing the Kubernetes
init-container spec that clones selected skills from the central skills repo
into the agent's .claude/skills emptyDir.

This dict is used two ways:
  1. In the Kyverno ClusterPolicy
     (platform/kyverno/guardrails/base/mutate-openshell-sandbox-skills-loader.yaml)
     which injects it automatically when the sandbox has the
     'agents.x-k8s.io/skills' annotation set.
  2. Directly by the sandbox-launcher when calling the OpenShell CreateSandbox
     API with an initContainers field (if/when the API supports it).

The init-container image is intentionally parameterised via SKILLS_LOADER_IMAGE
(default: alpine/git:latest) so it can be pinned to an internal mirror in Phase D.

Security:
  - The skills repo read token is sourced from a k8s Secret 'skills-repo-read-token'
    in ns 'openshell', mounted as an env var by the Kyverno policy — never baked in.
  - Never logs the token. tool_args_hash covers the skill names only.
"""

from __future__ import annotations

import os

SKILLS_LOADER_IMAGE = os.environ.get("SKILLS_LOADER_IMAGE", "alpine/git:latest")
SKILLS_REPO_URL = os.environ.get("SKILLS_REPO_URL", "https://git.arsalan.io/agents/skills.git")
SKILLS_MOUNT_PATH = os.environ.get("SKILLS_MOUNT_PATH", "/app/src/agent_harness/.claude/skills")
SKILLS_VOLUME_NAME = "claude-skills"


def build_init_container(skill_names: list[str]) -> dict:
    """Return a Kubernetes init-container spec dict for cloning the given skills.

    skill_names: list of directory names within the skills repo (e.g. ["pfsense-firewall"]).
    Returns a dict suitable for use in pod.spec.initContainers.
    """
    skill_list = ",".join(skill_names)
    return {
        "name": "skills-loader",
        "image": SKILLS_LOADER_IMAGE,
        "env": [
            {
                "name": "SKILLS_REPO_URL",
                "value": SKILLS_REPO_URL,
            },
            {
                "name": "SKILL_NAMES",
                "value": skill_list,
            },
            {
                "name": "GITEA_TOKEN",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": "skills-repo-read-token",
                        "key": "token",
                    }
                },
            },
        ],
        "command": [
            "sh",
            "-c",
            # clone → copy selected dirs → exit 0
            (
                "set -e; "
                "mkdir -p /skills-target; "
                "git clone --depth=1 "
                "\"https://x-token:${GITEA_TOKEN}@${SKILLS_REPO_URL#https://}\" "
                "/tmp/skills-src; "
                "for skill in $(echo \"$SKILL_NAMES\" | tr ',' ' '); do "
                "  if [ -d \"/tmp/skills-src/$skill\" ]; then "
                "    cp -r \"/tmp/skills-src/$skill\" \"/skills-target/$skill\"; "
                "  else "
                "    echo \"WARNING: skill $skill not found in skills repo\" >&2; "
                "  fi; "
                "done"
            ),
        ],
        "volumeMounts": [
            {
                "name": SKILLS_VOLUME_NAME,
                "mountPath": "/skills-target",
            }
        ],
        "securityContext": {
            "runAsNonRoot": False,  # alpine/git needs root for git clone
            "allowPrivilegeEscalation": False,
            "capabilities": {
                "drop": ["ALL"],
            },
        },
        "resources": {
            "requests": {"cpu": "50m", "memory": "64Mi"},
            "limits": {"cpu": "200m", "memory": "128Mi"},
        },
    }


def build_skills_volume() -> dict:
    """Return the emptyDir volume spec for the claude-skills volume."""
    return {"name": SKILLS_VOLUME_NAME, "emptyDir": {}}


def build_skills_volume_mount() -> dict:
    """Return the volumeMount for the main agent container to pick up the cloned skills."""
    return {
        "name": SKILLS_VOLUME_NAME,
        "mountPath": SKILLS_MOUNT_PATH,
    }
