# Phase C — Product Console: Detailed Plan

**Status:** Authored 2026-06-22. Phase A core journey PROVEN; B/C are unblockable.
**Branch:** `feat/openshell-native-svid-grant`
**Apex:** `docs/plans/openshell-agentic-platform-master-plan.md`

---

## Context and invariants carried into every loop

The product console is an extension of `services/approval-console` (FastAPI + inline HTML, no JS build).
It already has: Keycloak auth via oauth2-proxy, SSE session launch, JIT approve.
All new work is **additive new files only** — the working handlers in `app.py` must not be rewritten.

Hard invariant (non-negotiable, enforced by every loop's verify step):

> The agent holds only its SPIFFE SVID. No long-lived, broadly-scoped credential is stored, forwarded,
> or injected by any loop in this plan. Every privileged action is read-only via a scoped identity, or
> human-approved + JIT + short-lived + attributed to a real human. The ext-proc per-tool gate remains in
> front as the scope enforcer and audit emitter on every tool call.

Phase-A dependency: Loops C1–C4 describe the full product design, but the **cluster-mutating integration**
steps (deploy PVC, deploy sandbox with init-container, wire webshell service, expose Route) are GATED
pending confirmed Phase-A completion (last-mile seams: unattended-SVID file-handoff, ACM reverter,
ExecSandbox autonomy). Code for all loops can be written NOW; only the cluster deploys wait.

---

## Loop C1 — Persistent-agent + session model

### Goal
Introduce an **Agent** object (a durable record, not just an in-memory session) that encapsulates
an OpenShell sandbox, its SPIFFE identity, a workspace PVC, its Gitea repo URL, and the set of loaded
skills. Sessions are child runs of an Agent: the existing `_SESSIONS` map and `_do_k8s_exec` path become
the session execution path; the Agent is the parent that survives across sessions.

### Data model

```
Agent {
  agent_id:      uuid (stable primary key)
  display_name:  str  (human-readable, e.g. "pfsense-auditor-1")
  owner:         str  (Keycloak preferred_username — set at creation)
  sandbox_name:  str  (OpenShell sandbox resource name)
  sandbox_id:    str  (OpenShell gateway UUID == SVID path segment == Vault grant key)
  namespace:     str  (default: openshell)
  pvc_name:      str  (workspace PVC, <agent_id>-workspace)
  gitea_repo:    str  (full URL https://git.arsalan.io/<owner>/<agent_id>)
  skills:        list[str]  (names of loaded skill directories, e.g. ["pfsense-firewall"])
  state:         enum AgentState {PROVISIONING, READY, ARCHIVED, DELETED}
  created_at:    RFC3339 str
  archived_at:   RFC3339 str | None
}

AgentSession {
  session_id:    uuid (FK into existing _SESSIONS map)
  agent_id:      uuid (FK → Agent)
  goal:          str
  state:         enum {RUNNING, DONE, ERROR}
  created_at:    RFC3339 str
}
```

Storage: for v1, use an **in-memory dict** (same pattern as `_SESSIONS`) with a thread lock.
The model is designed so a future swap to a CNPG-backed table is purely additive (the API shape
stays; only the store backend changes). A CNPG migration is Phase D work.

### API (new module `approval_console/agents/store.py` + routes in `approval_console/agents/routes.py`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/agents` | Create a new Agent (calls sandbox-launcher via gRPC/HTTP, creates PVC, calls Gitea to create repo, loads skills) |
| GET | `/api/agents` | List agents visible to the authenticated user |
| GET | `/api/agents/{agent_id}` | Get Agent detail including session list |
| POST | `/api/agents/{agent_id}/sessions` | Launch a new session under this agent |
| GET | `/api/agents/{agent_id}/sessions/{session_id}/stream` | SSE transcript (re-uses existing `_gen()` logic) |
| POST | `/api/agents/{agent_id}/archive` | Soft-archive: sets state=ARCHIVED, renames Gitea repo |
| DELETE | `/api/agents/{agent_id}` | Hard-delete (GATED — requires confirmed=true + owner check) |

Reaping: a background task (`approval_console/agents/reaper.py`) runs every 60 s, checks for agents
whose sandbox is no longer in the `READY` phase (query sandbox-launcher or k8s API), and transitions
them to `state=ERROR`. Archive-triggered cleanup fires inline (rename repo, label PVC for GC).

### Lifecycle diagram

```
POST /api/agents
  → validate (owner from Keycloak header, skill names whitelist)
  → [GATED] launch OpenShell sandbox via sandbox-launcher API
  → [GATED] create workspace PVC  <agent_id>-workspace  (10Gi, ReadWriteOnce)
  → create Gitea repo (C2 client)
  → clone skills into agent PVC init-container (C3 loader — init annotation on sandbox)
  → write Agent{state=PROVISIONING} to store
  → poll sandbox-launcher until sandbox.state=READY (max 120 s)
  → write Agent{state=READY}
  → return agent_id

POST /api/agents/{id}/sessions
  → verify Agent.state == READY
  → call _new_session(goal, owner)
  → _launch_agent_thread(sid, goal, actor, agent_id=agent_id)  (extended to target agent sandbox)
  → write AgentSession to store
  → return {session_id}

POST /api/agents/{id}/archive
  → set state=ARCHIVED, archived_at=now
  → rename Gitea repo to <name>-archived-<yyyymmdd>  (soft-delete)
  → patch sandbox with a TTL annotation (Phase D: garbage collector reads it)
  → return {agent_id, state}
```

### Files authored (new — do NOT modify existing handlers)

- `services/approval-console/src/approval_console/agents/__init__.py`
- `services/approval-console/src/approval_console/agents/store.py` — Agent/AgentSession in-memory store, thread-safe
- `services/approval-console/src/approval_console/agents/models.py` — Pydantic v2 models: AgentState, Agent, AgentSession, CreateAgentRequest
- `services/approval-console/src/approval_console/agents/routes.py` — FastAPI router (`router = APIRouter(prefix="/api/agents")`)
- `services/approval-console/src/approval_console/agents/reaper.py` — background reaping task
- `services/approval-console/tests/test_agents.py` — unit tests (happy path + error/deny paths)

Routes are mounted into the existing `app` instance via `app.include_router(agents_router)` added to
`approval_console/__init__.py` (new file, import-safe, does not touch `app.py`).

### Verify/exit

Unit tests: `pytest services/approval-console/tests/test_agents.py -v`
- Happy path: POST /api/agents returns 201 with agent_id; GET /api/agents returns it; archive flips state.
- Deny path: archive by non-owner returns 403; session on ARCHIVED agent returns 409.
- No network, no cluster calls (sandbox-launcher and Gitea are monkeypatched).

Integration (GATED — requires live cluster, Phase A complete):
- POST /api/agents creates a real OpenShell sandbox visible in `oc get sandboxes -n openshell`
- The agent's SVID appears in `oc get clusterregistrationentries` within 30 s
- PVC `<agent_id>-workspace` exists in ns `openshell`

---

## Loop C2 — Per-agent Gitea repo auto-created at launch

### Goal
When a new Agent is created, automatically create a Gitea repository scoped to that agent. The repo is
the agent's workspace remote: the agent can push its output and state there. Access is scoped via a
**per-agent deploy key** (not the admin token) injected into the sandbox as a tmpfs-mounted k8s Secret.

### Gitea client stub (`approval_console/gitea/client.py`)

The client wraps the Gitea v1 REST API using `httpx.AsyncClient`. Config values:

| Config key | Env var | Description |
|------------|---------|-------------|
| `gitea_url` | `GITEA_URL` | Already in Config |
| `gitea_admin_token` | `GITEA_TOKEN` | Already in Config (server-side only) |
| `gitea_org` | `GITEA_ORG` | Target org for agent repos (default: `agents`) |

Operations exposed:

```python
async def create_agent_repo(agent_id: str, owner_username: str) -> GiteaRepo:
    """Create a private Gitea repo named <agent_id> under GITEA_ORG.

    Creates the org if it doesn't exist. Returns GiteaRepo{html_url, clone_url, ssh_url}.
    Fails closed: raises GiteaClientError on any non-2xx response.
    """

async def create_deploy_key(repo_full_name: str, agent_id: str, public_key: str) -> int:
    """Add a read-only deploy key to the repo. Returns key_id."""

async def archive_repo(repo_full_name: str, archived_name: str) -> None:
    """Rename and archive a repo (soft-delete on agent archive).

    Renames to <original>-archived-<yyyymmdd> and sets archived=true via PATCH /repos/{owner}/{repo}.
    """

async def delete_repo(repo_full_name: str) -> None:
    """Hard-delete a repo. Only called from DELETE /api/agents/{id} (gated + confirmed=true)."""
```

Audit: every call emits a structured log line (event=`gitea.<verb>.<object>`, actor, outcome, latency_ms,
tool_args_hash). Tool arguments are sha256-hashed; never logged raw.

### Access scoping (deploy key pattern)

At agent creation:
1. Generate an ed25519 keypair in-memory (Python `cryptography` library).
2. Write the **private key** to a k8s Secret `agent-<agent_id>-gitea-key` in ns `openshell` (tmpfs-mounted by the sandbox).
3. Register the **public key** as a read-write deploy key on the repo via `create_deploy_key`.
4. Store `gitea_repo` URL on the Agent object.

The private key Secret is:
- Created with `ownerReferences` pointing to the sandbox Pod (garbage-collected when sandbox is deleted).
- Never logged, never passed through agent memory.
- Mounted at `/vault/secrets/gitea-deploy-key` in the sandbox (matches the Vault-injector path convention).

The sandbox's `.gitconfig` is bootstrapped by the skills-loader init-container (C3) to set `core.sshCommand`
to use the mounted key.

### Repo lifecycle (resolving the open decision from the master plan)

| Event | Action | Delay |
|-------|--------|-------|
| Agent archived | Rename to `<name>-archived-<yyyymmdd>`, set `archived=true` | Immediate (inline) |
| 30 days post-archive | Hard-delete (Phase D cron job reads `archived_at`) | Phase D |
| Agent hard-deleted | Hard-delete immediately | Immediate |

### Files authored (new)

- `services/approval-console/src/approval_console/gitea/__init__.py`
- `services/approval-console/src/approval_console/gitea/client.py` — async Gitea client stub
- `services/approval-console/src/approval_console/gitea/models.py` — GiteaRepo, GiteaDeployKey Pydantic models
- `services/approval-console/tests/test_gitea_client.py` — unit tests with respx mocks

### Verify/exit

Unit tests: `pytest services/approval-console/tests/test_gitea_client.py -v`
- Happy path: `create_agent_repo` returns GiteaRepo with correct html_url; `archive_repo` issues PATCH + rename.
- Deny/error path: non-2xx from Gitea raises GiteaClientError; response body not logged raw (hash only).
- Deploy-key creation: assert the POST body contains the public key and title `agent-<id>`.

Integration (GATED):
- POST /api/agents → repo visible at `https://git.arsalan.io/agents/<agent_id>`
- Deploy key listed under the repo's settings; private key Secret exists in ns `openshell`
- Archive → repo renamed + archived flag = true in Gitea UI

---

## Loop C3 — Skills repo + selectable loading

### Goal
Provide a central Gitea **`skills`** repository (org `agents`, repo name `skills`) seeded from
`services/agent-sandbox/agent-harness/.claude/skills`. A UI skill-picker lets the human select which
skills to load. Selected skills are cloned into the agent at launch via an init-container that git-clones
into an emptyDir at `.claude/skills`; the harness image's `.claude/skills` is read-only.

### Skills repo (platform manifest)

The skills repo is a one-time seed. Content mirrors the existing skill directories exactly:

```
skills/
  list-firewall-rules/
    SKILL.md
  openshift-troubleshoot/
    SKILL.md
  pfsense-firewall/
    SKILL.md
```

A Kubernetes Job (`platform/gitea/skills-repo/seed-job/seed-job.yaml`) initialises this repo at
cluster bootstrap time. It uses the `GITEA_TOKEN` from a Secret, calls the Gitea API to create the repo
if absent, then git-pushes the seed content. The job is idempotent (checks repo existence first).

Adding a new skill: commit a new `<skill-name>/SKILL.md` to the `agents/skills` repo in Gitea. The
console's `/api/skills` endpoint reads the repo tree via Gitea API and returns the list dynamically.

### Skills loader init-container

When `POST /api/agents` includes `skills: ["pfsense-firewall", "openshift-troubleshoot"]`, the agent's
sandbox template is annotated so a Kyverno mutating policy injects an init-container:

```yaml
initContainers:
  - name: skills-loader
    image: alpine/git:latest
    env:
      - name: SKILLS_REPO_URL
        value: "https://git.arsalan.io/agents/skills.git"
      - name: SKILL_NAMES
        value: "pfsense-firewall,openshift-troubleshoot"
      - name: GITEA_TOKEN   # read-only deploy token for the skills repo
        valueFrom:
          secretKeyRef:
            name: skills-repo-read-token
            key: token
    command:
      - sh
      - -c
      - |
        set -e
        mkdir -p /skills-target
        git clone --depth=1 \
          "https://x-token:${GITEA_TOKEN}@${SKILLS_REPO_URL#https://}" \
          /tmp/skills-src
        for skill in $(echo "$SKILL_NAMES" | tr ',' ' '); do
          if [ -d "/tmp/skills-src/$skill" ]; then
            cp -r "/tmp/skills-src/$skill" "/skills-target/$skill"
          fi
        done
    volumeMounts:
      - name: claude-skills
        mountPath: /skills-target
volumes:
  - name: claude-skills
    emptyDir: {}
```

The main agent container mounts the same `claude-skills` emptyDir at `/app/src/agent_harness/.claude/skills`
(or whatever path the harness loads skills from — confirm against `agent_runner.py`'s CLAUDE_SKILLS_DIR).
The harness image path is read-only by image layer; the emptyDir overlays it.

The `skills-repo-read-token` Secret contains a Gitea token scoped to read-only access to `agents/skills`.
It is created out-of-band (not in git).

### Console skill-picker endpoint

```
GET /api/skills        → list of {name, description} loaded from Gitea repo tree
```

The UI renders a checkbox list above the "Launch agent" form. Selected skill names are posted as
`skills: [...]` in the `POST /api/agents` body.

### Files authored (new)

- `services/approval-console/src/approval_console/skills/__init__.py`
- `services/approval-console/src/approval_console/skills/routes.py` — `GET /api/skills` (reads Gitea repo tree via API)
- `services/approval-console/src/approval_console/skills/loader.py` — builds the init-container spec dict from skill names
- `services/approval-console/tests/test_skills.py` — unit tests
- `platform/gitea/skills-repo/kustomization.yaml`
- `platform/gitea/skills-repo/seed-job/seed-job.yaml` — one-time seed Job
- `platform/gitea/skills-repo/seed-job/skills-repo-read-secret.example.yaml` — example Secret (no real token)
- `platform/kyverno/guardrails/base/mutate-openshell-sandbox-skills-loader.yaml` — Kyverno ClusterPolicy that injects the init-container when `agents.x-k8s.io/skills` annotation is set on the sandbox

### Verify/exit

Unit tests:
- `GET /api/skills` with a respx mock of the Gitea tree API returns a list of skill objects.
- `loader.build_init_container(["pfsense-firewall"])` returns a dict with the correct volumeMounts and env.
- Deny path: unknown skill name in POST body returns 422 (validated against the skills list from Gitea).

Integration (GATED):
- Job `seed-skills-repo` completes 0/1; repo `agents/skills` visible in Gitea with 3 skill directories.
- POST /api/agents with `skills: ["pfsense-firewall"]` → sandbox has `agents.x-k8s.io/skills=pfsense-firewall` annotation → Kyverno mutated pod shows `skills-loader` init-container in `oc describe pod`.
- Agent's `.claude/skills/pfsense-firewall/SKILL.md` is readable from inside the sandbox.

---

## Loop C4 — Webshell

### Goal
A browser terminal embedded in the console lets a human spin up a new agent, or attach to an existing
one, and interact live. The terminal is Keycloak-gated (same oauth2-proxy sidecar as the rest of the
console) and flows over the existing OpenShift Route's WebSocket support (the heartbeat + timeout
pattern already proven for SSE is equally applicable to WS).

### Technology recommendation: ttyd (resolving the open decision from the master plan)

**Recommendation: ttyd** (not OpenShell's own webshell, not wetty).

Rationale:
- ttyd is a lightweight, single-binary C program that exposes a PTY over WebSocket using xterm.js on
  the browser side. No Node.js runtime dependency.
- It is NOT a new network-accessible service on its own: ttyd runs as a sidecar in the approval-console
  pod, listening on `127.0.0.1:7681` (loopback only). The oauth2-proxy sidecar fronts it under a
  `/webshell` sub-path, so the Keycloak session gate applies automatically.
- OpenShell's own webshell is only reachable via the OpenShell gateway's WebSocket API, which would
  bypass the ext-proc gate (ADR-0011 violation). ttyd targeting the OpenShell sandbox via `oc exec`
  keeps ext-proc in front.
- wetty adds a heavier Node.js dependency for no gain over ttyd in this environment.

The ttyd sidecar runs:
```
ttyd --once --writable \
     --port 7681 \
     --interface 127.0.0.1 \
     oc exec -it -n openshell <sandbox_pod> -- /bin/bash
```
...where `<sandbox_pod>` is resolved dynamically from a query parameter (`?agent_id=...`) by a thin
shim endpoint `GET /api/agents/{agent_id}/webshell-cmd` that returns the exec command. The shim
validates the agent_id, verifies the Keycloak actor is the owner (or an admin), then lets ttyd connect.

Because ttyd `--once` exits after the session ends, the approval-console manages a small pool of ttyd
processes (one per active webshell), supervised by a thread in `approval_console/webshell/supervisor.py`.

Alternatively, the console can proxy WebSocket frames directly without ttyd using a small asyncio WS
bridge to the Kubernetes `exec` WebSocket protocol. This avoids the external binary but is more code.
Either path is safe; the plan authors the ttyd path as it is simpler and battle-tested.

### Route wiring

The approval-console's oauth2-proxy already terminates at port 4180 and proxies to `127.0.0.1:8090`.
For the webshell, oauth2-proxy's `--upstream` does not easily split paths to different backends.

Solution: mount a second upstream in oauth2-proxy via `--upstream=file:///<path>` skip-auth trick,
or — more cleanly — add a **second oauth2-proxy arg set** (different `--upstream` for `127.0.0.1:7681`)
triggered via path prefix `/webshell`. This is supported by oauth2-proxy's `--skip-auth-route` +
`--upstream` combination.

Simpler alternative (recommended for v1): the FastAPI app itself proxies WebSocket frames:
- `GET /api/agents/{agent_id}/webshell` — the console app opens a subprocess to `oc exec` and
  bridges the WebSocket connection bidirectionally using `anyio` streams.
- The Keycloak actor is verified server-side before the exec is opened.
- This avoids the ttyd binary and the oauth2-proxy split-path complexity.

The plan authors the FastAPI WS-bridge stub as the v1 approach; the ttyd path is the upgrade path
for v2 if PTY fidelity becomes important.

### Files authored (new)

- `services/approval-console/src/approval_console/webshell/__init__.py`
- `services/approval-console/src/approval_console/webshell/routes.py` — `GET /api/agents/{id}/webshell` WebSocket endpoint (FastAPI `WebSocket`) stub with actor validation
- `services/approval-console/src/approval_console/webshell/bridge.py` — asyncio bridge between WebSocket client and `oc exec` subprocess PTY
- `services/approval-console/tests/test_webshell.py` — unit tests (actor validation, deny for non-owner)

### Verify/exit

Unit tests:
- Non-owner actor attempting webshell on another user's agent returns 403.
- ARCHIVED agent returns 409 (cannot attach to an archived sandbox).
- WebSocket handshake for a READY agent (exec subprocess monkeypatched) completes and proxies bytes.

Integration (GATED — requires Phase A, live sandbox, working `oc exec`):
- Browser opens `/api/agents/<id>/webshell` (logged in as owner via Keycloak).
- Terminal renders; `ls /app/src` shows the harness; `.claude/skills` shows loaded skills.
- Keycloak-unauthenticated request returns 401 via oauth2-proxy (before reaching FastAPI).
- ext-proc audit log shows no direct tool calls from the webshell session (PTY is human-operated).

---

## Loop C5 — In-console JIT/token panels

### Goal
Surface the full JIT approve → mint → token + receipt flow directly in the product console UI,
unifying Phase B into the UX. The existing "JIT Approval Console" section of the page (the pending/all
requests tables and the Approve button) is already functional. This loop extends it with:

1. **Agent-scoped request filter**: a dropdown on the requests table to filter by `agent_id` (uses the
   existing `?sandbox=` query param that `list_requests` already passes through to jit-approver).
2. **Token receipt panel**: after approval, display the `expires_at`, `session_state`, and a masked
   `session_id` for the mcp-call argument. Currently shown in a toast; promote to a persistent panel
   below the approval table.
3. **JIT history per agent**: `GET /api/agents/{agent_id}/jit-history` aggregates past approvals from
   jit-approver's `/requests?sandbox=<sandbox_id>` and surfaces them in the agent detail view.
4. **Self-approval guard UX**: when the actor matches `requester_sub`, the Approve button is greyed
   out with "You cannot approve your own request" before the POST is even sent. (Server still enforces
   it; this is UX polish to prevent accidental submissions.)
5. **Revoke panel** (Phase D stub): a "Revoke" button that POSTs to jit-approver's future
   `/requests/{id}/revoke` endpoint. The button renders as disabled with "Coming in Phase D" until
   that endpoint exists.

All of this is HTML/JS changes to the `_HTML` constant in `app.py`. Because the rule is "do NOT rewrite
working handlers", these UI changes are isolated to a new **`_AGENT_HTML` template fragment** in a new
module `approval_console/ui/fragments.py` that `app.py` imports at startup (additive import, no handler
changes). The `index()` handler gains a single line: `html = html + _AGENT_HTML` (or similar).

Actually, to strictly avoid touching `app.py`, the new agent UI page is a **separate route**:
`GET /agents` → `approval_console/ui/routes.py` serves the extended agent-centric HTML page.
The existing `GET /` remains the legacy JIT-only console. This is the clean additive approach.

### Files authored (new)

- `services/approval-console/src/approval_console/ui/__init__.py`
- `services/approval-console/src/approval_console/ui/routes.py` — `GET /agents` route: extended HTML with agent list, skill picker, session panel, JIT filter, token receipt
- `services/approval-console/src/approval_console/ui/fragments.py` — HTML fragment generators (agent card, JIT history row, token receipt panel)
- `services/approval-console/tests/test_ui.py` — unit tests (HTML renders with correct agent_id; self-approval guard JS logic)

### Verify/exit

Unit tests:
- `GET /agents` returns 200 with HTML containing the agent list section and skills picker form.
- `GET /api/agents/<id>/jit-history` returns a list from jit-approver mock.
- Self-approval guard: if whoami returns `alice` and detail.requester_sub is `alice`, the route
  returns a flag `can_approve: false` in `GET /api/agents/<id>/jit-history?actor=alice`.

Integration (GATED — after Phase B live):
- End-to-end: agent runs, hits 403, human sees request in `/agents` panel, clicks Approve, token
  receipt appears, agent completes write.
- Revoke button is rendered as disabled (no 500, no click action).

---

## Cross-loop dependencies and parallelism

```
C1 (agent model + store)
  └─► C2 (Gitea repo) — depends on C1 agent_id
  └─► C3 (skills) — depends on C1 for the init-container annotation path
  └─► C4 (webshell) — depends on C1 for agent_id lookup + owner check
  └─► C5 (JIT panels) — depends on C1 for agent-scoped filter

C2 code: independent of Phase A (uses Gitea API only)
C3 seed job: independent of Phase A
C3 init-container Kyverno policy: independent of Phase A (no cluster mutations needed to author)
C4 code: independent of Phase A; cluster integration (oc exec target) GATED
C5 code: independent of Phase A and Phase B
```

All code CAN BE written now. Cluster-mutating integration steps are marked GATED below.

---

## Gated cluster mutations (do NOT execute; describe and wait)

| Gate | What it requires | When |
|------|-----------------|------|
| G-C1a | Deploy PVC `<agent_id>-workspace` in ns `openshell` | Phase A last-mile complete |
| G-C1b | POST `/api/agents` calling live sandbox-launcher gRPC (creates a real sandbox) | Phase A last-mile complete |
| G-C2a | Create Gitea org `agents` + deploy first repo via API | No Phase A dependency; GATED on Gitea admin access |
| G-C2b | Write `agent-<id>-gitea-key` Secret into ns `openshell` | Phase A sandbox running |
| G-C3a | Apply `seed-job.yaml` to cluster (creates `agents/skills` Gitea repo + pushes seed) | G-C2a complete |
| G-C3b | Apply `mutate-openshell-sandbox-skills-loader.yaml` Kyverno ClusterPolicy | Phase A complete + Kyverno admission 1/1 (confirmed live) |
| G-C3c | Create `skills-repo-read-token` Secret in ns `openshell` | G-C3a complete |
| G-C4a | Route `/api/agents/{id}/webshell` WebSocket endpoint (requires OpenShift Route WebSocket passthrough) | Phase A complete + Route config |
| G-C5a | Wire jit-approver `/requests/{id}/revoke` endpoint | Phase B complete |
| G-C5b | Deploy updated approval-console image carrying new routes | CI/CD gated on all unit tests green |

---

## File touch-points (all new files; existing files not modified)

### services/approval-console (new source files)

```
src/approval_console/
  __init__.py                         [NEW — mounts all new routers into app]
  agents/
    __init__.py
    store.py                          [NEW — in-memory Agent + AgentSession store]
    models.py                         [NEW — Pydantic: AgentState, Agent, AgentSession, CreateAgentRequest]
    routes.py                         [NEW — APIRouter prefix=/api/agents]
    reaper.py                         [NEW — background sandbox-state reaper]
  gitea/
    __init__.py
    client.py                         [NEW — async Gitea API client stub]
    models.py                         [NEW — GiteaRepo, GiteaDeployKey]
  skills/
    __init__.py
    routes.py                         [NEW — GET /api/skills]
    loader.py                         [NEW — init-container spec builder]
  webshell/
    __init__.py
    routes.py                         [NEW — WebSocket /api/agents/{id}/webshell]
    bridge.py                         [NEW — asyncio oc-exec WS bridge]
  ui/
    __init__.py
    routes.py                         [NEW — GET /agents extended console page]
    fragments.py                      [NEW — HTML fragment generators]
tests/
  test_agents.py                      [NEW]
  test_gitea_client.py                [NEW]
  test_skills.py                      [NEW]
  test_webshell.py                    [NEW]
  test_ui.py                          [NEW]
```

### platform/gitea (new manifests)

```
platform/gitea/
  skills-repo/
    kustomization.yaml
    seed-job/
      seed-job.yaml                   [NEW — one-time skills repo seed Job]
      skills-repo-read-secret.example.yaml  [NEW — example only, no real token]
```

### platform/kyverno (new policy)

```
platform/kyverno/guardrails/base/
  mutate-openshell-sandbox-skills-loader.yaml  [NEW — inject init-container on skills annotation]
```

---

## Risk register (Phase C specific)

| ID | Risk | Mitigation |
|----|------|------------|
| R-C1 | In-memory Agent store lost on pod restart | Acceptable for PoC; design is swap-ready for CNPG in Phase D |
| R-C2 | Gitea admin token used for repo creation has broad scope | Token is server-side only (Config.gitea_token()), never forwarded; per-agent deploy keys scope post-creation access |
| R-C3 | Skills loader clones from public Gitea using a read-only token | Token rotated at Phase D; skills repo is private (org-level access) |
| R-C4 | WebSocket bridge gives PTY access to the sandbox | Gated by Keycloak actor == agent owner check; ext-proc remains in front of any MCP tool calls from the PTY |
| R-C5 | Self-approval guard is client-side only (JS) | Server enforces via jit-approver M5 SoD; the JS is UX, not a security gate |
| R-C6 | ACM work-agent reverter clobbers the launcher image | Phase C defers to Phase D gitops-durability (pin ManifestWork on hub); workaround: overlay pinning |
| R-C7 | ExecSandbox autonomy regression (issue #24 / #26) | C1's session path uses _do_k8s_exec via the console-pod exec, not ExecSandbox; no regression surface |

---

## Definition of done (Phase C)

From the console (browser, Keycloak-authed):

1. Click "Launch agent" → pick skills → agent appears in agent list with state=READY.
2. Gitea shows `agents/<agent_id>` repo; deploy key listed.
3. Click "Open webshell" → browser terminal opens into the sandbox.
4. Click "New session" → transcript streams; tool calls appear.
5. Tool hits 403 → JIT panel shows the request; a second logged-in user (approver != requester) clicks Approve → token receipt appears → agent completes the write.
6. Click "Archive" → agent state=ARCHIVED; Gitea repo renamed.
7. No stored write credential visible at any point. ext-proc audit log confirms all tool calls went through the gate.
