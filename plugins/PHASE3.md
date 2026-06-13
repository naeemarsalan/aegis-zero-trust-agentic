# Phase-3 Frontend Plugin Roadmap

RHDH target: upstream-2.6.3 helm chart (RHDH 1.9.4), shared instance "Migration Discovery Hub".
Delivery: HTTPS tgz via Gitea attachment (the proven working path on this instance — confirmed from
`developer-hub-dynamic-plugins` ConfigMap: migration-discovery plugin uses
`https://git.arsalan.io/attachments/<uuid>` with `integrity: sha512-...`).
CLI: `@red-hat-developer-hub/cli@1.9.0` to match RHDH 1.9.4 version series.

---

## Screen-to-mountPoint map

| Screen | Plugin package | mountPoint | entityTab? | Condition |
|--------|---------------|-----------|-----------|-----------|
| 1 — Plan/Consent | `plan-consent` (KEYSTONE — owned by separate artifact) | `dynamicRoutes` path `/agent-consent` | No (standalone page — entity does not exist at consent time) | n/a |
| 2 — Agent Workspace | `agent-workspace` (this repo: `plugins/agent-workspace/`) | `entity.page.workspace/cards` | Yes: path `/workspace` title "Workspace" | `isKind: resource` AND `isType: agent-sandbox` |
| 3 — Approvals Panel | `approvals-panel` (this repo: `plugins/approvals-panel/`) | `entity.page.approvals/cards` | Yes: path `/approvals` title "Approvals" | `isKind: resource` AND `isType: agent-sandbox` |
| 4 — Session Receipt | `receipt` (this repo: `plugins/receipt/`) | `entity.page.overview/cards` | No (adds a card to the existing Overview tab) | `isKind: resource` AND `isType: agent-sandbox` |

The `entity.page.<custom>` mountPoint name for tabs (workspace, approvals) is valid per
RHDH main-branch `docs/dynamic-plugins/frontend-plugin-wiring.md` and confirmed on this
cluster for the existing `entity.page.overview/cards` pattern.

---

## BLOCKING PREREQUISITE for Screens 2-4 — no sandbox entity is ever registered

**THIS IS THE HARDEST GATE FOR SCREENS 2-4 AND MUST BE RESOLVED BEFORE THOSE PLUGINS
ARE USEFUL IN ANY DEMO OR TEST.**

Screens 2-4 mount only on catalog entities of `kind: Resource` and `spec.type: agent-sandbox`.
The `if: allOf: [isKind: resource, isType: agent-sandbox]` conditions in the mountPoint
config are correct, but **they will match nothing** until an agent-sandbox Resource entity
is present in the Backstage catalog.

The scaffolder template (`platform/devhub/templates/run-agent/template.yaml`) has a
`catalog:register` step (Step 3) that would create this entity, but it is **commented out**
(lines 263-269) with the note "DEFERRED — uncomment when launcher emits catalogInfoUrl".
The sandbox-launcher's `POST /launch` response (`LaunchResponse`) does not emit a
`catalogInfoUrl` field today.

Until this is resolved, the entity page for an agent-sandbox will never appear in RHDH,
and Screens 2-4 will never render.

**TODO-E1 (BLOCKING for Screens 2-4)** — Two-part fix required:

1. `services/sandbox-launcher/src/sandbox_launcher/api.py`: after `CreateSandbox` succeeds,
   construct and return a `catalogInfoUrl` field in the `LaunchResponse` JSON pointing at a
   `catalog-info.yaml` that the launcher either (a) writes to a known Git repo path or
   (b) generates inline as a data-URI. The simplest PoC approach: emit a URL pointing at a
   pre-committed static `catalog-info.yaml` template in this repo, with the sandbox name
   substituted in as an annotation. Example response field:
   ```json
   "catalogInfoUrl": "https://git.arsalan.io/anaeem/nvidia-ida/raw/branch/main/platform/devhub/sandbox-catalog-info.yaml"
   ```
   A more correct approach: the launcher writes a per-sandbox `catalog-info.yaml` to a
   Gitea repo branch (one file per sandbox, named by sandbox ID) and returns its raw URL.

2. `platform/devhub/templates/run-agent/template.yaml` lines 263-269: uncomment the
   `catalog:register` step once the launcher emits `catalogInfoUrl`.

Until TODO-E1 is done, the entity-page tabs for Screens 2-4 are correctly wired but
will never be reached by a real user journey.

---

---

## Real data source per screen

### Screen 1 — Plan/Consent (keystone artifact, not in this repo)

| Data item | Real source | Status |
|-----------|------------|--------|
| `sandbox_name`, `scope`, `ttl`, `capabilities` | Scaffolder output → query params in `/agent-consent?sandbox=...` URL | REAL — all emitted by `POST /launch` (LaunchResponse) which the template calls |
| Capability metadata (jit-required label, tier) | Backstage catalog REST `/api/catalog/entities/by-name/resource/default/{name}` | REAL — no custom backend needed |
| TTL countdown seed | `ttl` query param; pure client-side setInterval | REAL |
| `conversation_url` | `LaunchResponse.conversation_url` | ALWAYS NULL at launch — `TODO-D1` |
| DenyButton (sandbox teardown) | No `DELETE /launch/{name}` endpoint | MISSING — navigate-away fallback; sandbox auto-expires via TTL |

### Screen 2 — Agent Workspace (`plugins/agent-workspace/`)

| Data item | Real source | Status |
|-----------|------------|--------|
| Sandbox phase | Kubernetes API via `useKubernetesObjects()` — `agents.x-k8s.io/v1alpha1 Sandbox`, field `status.phase` | REAL once k8s plugin custom resource wired (k8s-plugin.md step 1) |
| `nvidia-ida/ttl-minutes` label | Same k8s object | REAL — launcher stamps at CreateSandbox |
| `nvidia-ida/scope` label | Same k8s object | REAL — launcher stamps at CreateSandbox |
| `access_hint` | `nvidia-ida/access-hint` annotation on Sandbox CR | MISSING — `TODO-D3`: launcher's `openshell.py` must patch CR after CreateSandbox |
| `conversation_url` | `POST /sandboxes/{name}/expose` endpoint | MISSING — `TODO-D1`: add to sandbox-launcher; calls `ExposeService` gRPC after READY |
| JIT session state badge | `GET /api/proxy/jit-approver/requests/{id}/status` | REAL endpoint; requires `/jit-approver` proxy entry (`TODO-proxy`) and `TODO-B2` to enumerate IDs |

### Screen 3 — Approvals Panel (`plugins/approvals-panel/`)

| Data item | Real source | Status |
|-----------|------------|--------|
| `state`, `pr_url`, `expires_at`, `tool_scope` | `GET /api/proxy/jit-approver/requests/{session_id}/status` → `SessionStatus` | REAL — api.py:get_status() line 155 |
| Session list for a sandbox | `GET /requests?sandbox=<name>` | MISSING — `TODO-B2`: add to jit-approver api.py; filter `session_store.values()` by `session["request"].sandbox` |
| `verbs`, `resources`, `namespace`, `policy_delta` | `GET /requests/{id}/detail` | MISSING — `TODO-B1`: add endpoint returning stored `EscalationRequest` fields + current state |
| Forgejo PR approval action | `pr_url` from status endpoint — external link; approval = PR merge | REAL |
| TTL countdown | `expires_at` (ISO-8601 from status) − now(); client-side | REAL |
| UpdateConfig (network floor widen) outcome | Loki only: `{app="jit-approver"} \| json \| msg="openshell_widen_ok"` | NO REST surface — log-only; best-effort in openshell.py |

Polling: 30-second `setInterval` from the panel. Push not available: Forgejo
webhook delivery unreliable on homelab (SNO ingress not reachable from Forgejo).

### Screen 4 — Session Receipt (`plugins/receipt/`)

| Data item | Real source | Status |
|-----------|------------|--------|
| `session_id` lookup for sandbox | `GET /requests?sandbox=<name>` | MISSING — `TODO-B2` (same as Screen 3) |
| `state`, `pr_url`, `expires_at` | `GET /api/proxy/jit-approver/requests/{id}/status` | REAL |
| `actions_taken`, `errors_encountered`, `outcome` | `GET /requests/{id}/summary` | MISSING — `TODO-C1`: (a) store summary in session_store in post_summary(); (b) add GET endpoint |
| ext-proc denial events | `GET /requests/{id}/receipt` aggregating Loki | MISSING — `TODO-C2`: add to jit-approver; queries Loki internally; returns pre-shaped receipt |
| Kube-audit attribution (SA token use) | `oc adm node-logs` kube-apiserver audit log | NOT REACHABLE via REST — `TODO-C3`: Phase-4 stretch; ext-proc `credential_injected=true` Loki events are the PoC substitute |

---

## Missing backend glue — ordered by priority

All TODOs below are in working-tree scope only (no cluster mutation).

### Priority 1 — Unblocks Screens 3 and 4 (jit-approver additions)

**TODO-B2** — `services/jit-approver/src/jit_approver/api.py`
Add:
```python
@app.get("/requests")
async def list_requests(sandbox: str | None = None, state: str | None = None) -> list[SessionStatus]:
    results = list(session_store.values())
    if sandbox:
        results = [s for s in results if getattr(s.get("request"), "sandbox", None) == sandbox]
    if state:
        results = [s for s in results if s["state"] == state]
    return [SessionStatus(id=s["id"], state=SessionState(s["state"]), pr_url=s.get("pr_url"), expires_at=s.get("expires_at")) for s in results]
```

**TODO-C1** — `services/jit-approver/src/jit_approver/api.py` + `store.py` + `models.py`
1. In `post_summary()`: add `session["summary"] = summary` after `audit.emit_summary()`.
2. Add `GET /requests/{session_id}/summary` returning `session.get("summary")` or 404.
3. Optional: add `summary: SessionSummary | None` field to `SessionStatus` Pydantic model so
   the existing GET /status response can include the summary inline.

**TODO-B1** — `services/jit-approver/src/jit_approver/api.py`
Add `GET /requests/{session_id}/detail` returning:
```json
{
  "id": "...",
  "state": "issued",
  "expires_at": "...",
  "verbs": ["get","list"],
  "resources": ["pods"],
  "namespace": "agent-sandbox",
  "justification": "...",
  "policy_delta": [{"host":"10.0.0.1","port":443}],
  "sandbox": "agent-arsalan-a3f2"
}
```
Source: `session_store[session_id]["request"]` (EscalationRequest fields) + current state.

**TODO-C2** — `services/jit-approver/src/jit_approver/api.py`
Add `GET /requests/{session_id}/receipt` that queries Loki at `$LOKI_URL/loki/api/v1/query_range`
for `{app="ext-proc-delegation"} | json | session_id="<id>"` and returns:
```json
{
  "allowed": 4,
  "denied": 1,
  "tool_calls": [{"tool":"get_firewall_rules","decision":"allow","ts":"..."}],
  "session_outcome": "completed",
  "expires_at": "2026-06-13T14:00:00Z"
}
```
Requires `LOKI_URL` env var (value: `http://172.16.2.252:3100` on anaeem cluster).
Correlate by `session_id` in the `caller_user.sub` or an explicit session header —
see ext-proc audit.go `session_id` field in `AgentInfo` (confirmed present in golden file
`usecases/uc1-delegated-tool-call/expected/audit-event.golden.json`).

### Priority 2 — Unblocks Screen 2 workspace URL (sandbox-launcher additions)

**TODO-D1** — `services/sandbox-launcher/src/sandbox_launcher/api.py`
Add:
```python
@app.post("/sandboxes/{sandbox_name}/expose")
async def expose_sandbox(sandbox_name: str) -> dict:
    # 1. Poll GetSandbox until phase==READY (timeout: 120s, interval: 5s)
    # 2. Call ExposeService gRPC — stub already in osh/openshell_pb2_grpc.py
    # 3. Return {"conversation_url": resp.endpoint_url, "phase": "READY"}
```
The `ExposeService` gRPC stub is confirmed in
`services/sandbox-launcher/src/sandbox_launcher/osh/openshell_pb2_grpc.py`.
Only the Python caller code is missing.

**TODO-D3** — `services/sandbox-launcher/src/sandbox_launcher/openshell.py`
After `CreateSandbox` succeeds, patch the Sandbox CR:
```python
# oc patch agents.x-k8s.io/v1alpha1 sandbox/<name> -n openshell \
#   --type merge -p '{"metadata":{"annotations":{"nvidia-ida/access-hint":"<value>"}}}'
```
This makes `access_hint` readable by the workspace card via the Kubernetes plugin context
without any new RHDH proxy endpoint.

**TODO-D2** — Phase-4 stretch: WebSocket-to-`ExecSandboxInteractive` gRPC bridge.
`ExecSandboxInteractive` is confirmed in the proto stub (line 116–130 of openshell_pb2_grpc.py)
but requires a new bridge service. Not in scope for Phase-3.

### Priority 3 — RHDH proxy wiring (platform delta, no service code)

**TODO-proxy** — `platform/devhub/app-config-jit.yaml` (file now exists)

The file has been created at `platform/devhub/app-config-jit.yaml`. See that file
for the full hand-merge instructions and auth design rationale.

```yaml
# HAND-MERGE DELTA — merge into developer-hub-app-config, key app-config.yaml
proxy:
  endpoints:
    /jit-approver:
      target: http://jit-approver.mcp-gateway.svc:8080
      changeOrigin: true
      credentials: forward        # NOT require — see rationale below
      allowedHeaders:
        - Content-Type
        - Authorization           # required to forward the Backstage JWT upstream
      pathRewrite:
        '^/api/proxy/jit-approver/': '/'
```

**Why `credentials: forward`, not `credentials: require`:**
An earlier draft of this document and the original skeleton used `credentials: require`
following a generic hardening recommendation. That choice is incorrect for this use-case.

`credentials: require` authenticates the caller but then STRIPS the Authorization header
before the request reaches jit-approver — so the upstream service receives no
cryptographic user identity. The browser-originated GETs from the three card plugins
use `useApi(fetchApiRef).fetch()` which attaches the Backstage user JWT in
`Authorization: Bearer <token>`. Under `credentials: require`, that JWT is stripped and
jit-approver cannot scope the session list to the requesting user.

`credentials: forward` (the proven choice from `/mcp-launcher` in `app-config-launcher.yaml`)
keeps the same caller-authentication requirement but forwards the JWT upstream, allowing
jit-approver to verify the user identity for per-user session scoping and audit events.

`Authorization` must also be in `allowedHeaders`; without it the proxy-backend strips
the header even under `credentials: forward`.

All three plugins (agent-workspace, approvals-panel, receipt) need this proxy entry
to reach `GET /requests/*` and `GET /requests/{id}/summary` endpoints.

**Plugin auth requirement:** All three card plugins MUST use `useApi(fetchApiRef).fetch()`
(NOT the raw browser `fetch()`). The fetchApiRef implementation attaches the Backstage JWT
automatically. The skeletons have been updated to import `fetchApiRef` and call
`fetchApi.fetch()` as of this fix.

### TtlCountdownChip — inlined live implementation in all three card plugins

The shared `TtlCountdownChip` component in `plugins/plan-consent/src/components/TtlCountdownChip.tsx`
implements a live `setInterval` countdown that ticks the remaining time every second. All three
card plugins (agent-workspace, approvals-panel, receipt) cannot import the real one because
`@nvidia-ida/plugin-plan-consent` is not yet published as an npm package available to the other
plugins.

Each card plugin therefore carries an **inline copy** of the same `setInterval`-based countdown
logic. The inline implementations:
- tick every 1 second using `setInterval` — they are not static
- transition through the same colour states (muted → amber at <5 min → red at expired)
- support both the `expiresAt` (ISO-8601, authoritative, issued state) and `ttlMinutes`
  (advisory seed, pre-issuance) paths exactly as the real component does

This is a **duplication**, not a functional divergence. The behaviour is equivalent to the
real `TtlCountdownChip`. The only divergence is that the copies won't receive upstream fixes
automatically until replaced.

Fix (when ready): once `@nvidia-ida/plugin-plan-consent` is published to an internal registry
or Gitea npm feed, remove the inline copy from each plugin and replace the component with:
```ts
import { TtlCountdownChip } from '@nvidia-ida/plugin-plan-consent';
```
and add `@nvidia-ida/plugin-plan-consent` to each plugin's `dependencies` in `package.json`.

### Priority 4 — Honest stubs / Phase-4 items

**TODO-C3** — Kube-audit attribution: not reachable via any REST API the RHDH frontend
can call without a privileged node-proxy. Stub in the receipt card with a note pointing
to the existing Grafana JIT Audit dashboard (confirmed working in
`platform/observability/grafana-dashboards/base/jit-audit-dashboard-cm.yaml`).

---

## Recommended build order (keystone first)

```
1.  plan-consent plugin (KEYSTONE — owned separately)
    Rationale: The keystone consent page is the primary CTA from the scaffolder
    output. Users arrive here before the entity page loads. All other screens are
    unreachable until the sandbox exists and is registered in the catalog.

2.  backend gaps (jit-approver + sandbox-launcher — no UI)
    Implement TODO-B2, TODO-C1, TODO-B1, TODO-D1, TODO-D3 first.
    These have no UI risk and unblock all three plugins.

3.  approvals-panel (Screen 3)
    Rationale: highest demo value — shows the JIT PR flow live. Depends on
    TODO-B2 (session list) and the /jit-approver proxy entry.

4.  receipt (Screen 4)
    Rationale: depends on TODO-C1 (summary GET) and TODO-B2 (session ID lookup).
    Renders on the entity Overview tab without a new entityTab wiring.

5.  agent-workspace (Screen 2)
    Rationale: the access_hint fallback (TODO-D3) is the minimal viable version.
    The full conversation_url (TODO-D1) requires sandbox-launcher changes.
    The interactive shell (TODO-D2) is Phase-4.
```

---

## Dynamic-plugin deploy steps for this RHDH instance

RHDH instance: `developer-hub` deployment in namespace `rhdh`.
Proven delivery: HTTPS tgz with `integrity: sha512-...` — confirmed from live ConfigMap.

### Per plugin:

```bash
# 1. Build
cd plugins/<plugin-dir>
yarn install
npx @red-hat-developer-hub/cli@1.9.0 plugin export \
  --no-generate-module-federation-assets --clean

# 2. Pack
cd dist-dynamic
npm pack
HASH=$(npm pack --json | jq -r '.[0].integrity')
# e.g. sha512-abc123...

# 3. Host
# Upload the .tgz to https://git.arsalan.io as a Gitea release attachment.
# Note the attachment URL: https://git.arsalan.io/attachments/<uuid>
```

### ConfigMap delta (developer-hub-dynamic-plugins, namespace rhdh):

Edit in-cluster:
```bash
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  -n rhdh edit configmap developer-hub-dynamic-plugins
```

Add under `data.dynamic-plugins.yaml -> plugins:` — preserve ALL existing entries:

```yaml
# ── agent-workspace ──────────────────────────────────────────────────────
- disabled: false
  package: https://git.arsalan.io/attachments/<uuid-agent-workspace>.tgz
  integrity: sha512-<HASH-agent-workspace>
  pluginConfig:
    dynamicPlugins:
      frontend:
        nvidia-ida.plugin-agent-workspace:
          entityTabs:
            - path: /workspace
              title: Workspace
              mountPoint: entity.page.workspace
          mountPoints:
            - mountPoint: entity.page.workspace/cards
              importName: SandboxWorkspaceCard
              config:
                layout:
                  gridColumnEnd: span 12
                if:
                  allOf:
                    - isKind: resource
                    - isType: agent-sandbox

# ── approvals-panel ───────────────────────────────────────────────────────
- disabled: false
  package: https://git.arsalan.io/attachments/<uuid-approvals-panel>.tgz
  integrity: sha512-<HASH-approvals-panel>
  pluginConfig:
    dynamicPlugins:
      frontend:
        nvidia-ida.plugin-approvals-panel:
          entityTabs:
            - path: /approvals
              title: Approvals
              mountPoint: entity.page.approvals
          mountPoints:
            - mountPoint: entity.page.approvals/cards
              importName: JitApprovalsPanelCard
              config:
                layout:
                  gridColumnEnd: span 12
                if:
                  allOf:
                    - isKind: resource
                    - isType: agent-sandbox

# ── receipt ───────────────────────────────────────────────────────────────
- disabled: false
  package: https://git.arsalan.io/attachments/<uuid-receipt>.tgz
  integrity: sha512-<HASH-receipt>
  pluginConfig:
    dynamicPlugins:
      frontend:
        nvidia-ida.plugin-receipt:
          mountPoints:
            - mountPoint: entity.page.overview/cards
              importName: AgentSessionReceiptCard
              config:
                layout:
                  gridColumnEnd: span 12
                if:
                  allOf:
                    - isKind: resource
                    - isType: agent-sandbox
```

### Proxy delta (developer-hub-app-config, namespace rhdh):

Edit in-cluster:
```bash
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  -n rhdh edit configmap developer-hub-app-config
```

Merge under `proxy.endpoints` (PRESERVE existing `/mcp-launcher` entry).
Full hand-merge instructions are in `platform/devhub/app-config-jit.yaml`.
Summary snippet:
```yaml
proxy:
  endpoints:
    # ... existing /mcp-launcher entry (credentials: forward) ...
    /jit-approver:
      target: http://jit-approver.mcp-gateway.svc:8080
      changeOrigin: true
      credentials: forward        # NOT require — matches /mcp-launcher precedent
      allowedHeaders:
        - Content-Type
        - Authorization           # required: forwards the Backstage JWT to jit-approver
      pathRewrite:
        '^/api/proxy/jit-approver/': '/'
```

### Restart:
```bash
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  -n rhdh rollout restart deployment/developer-hub
# Watch initContainer logs for "Loading plugin nvidia-ida.plugin-..."
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  -n rhdh logs -f deployment/developer-hub -c install-dynamic-plugins
```

### Validation per plugin:

| Plugin | Validation step |
|--------|----------------|
| agent-workspace | Navigate to a `kind:Resource type:agent-sandbox` entity page; confirm "Workspace" tab appears |
| approvals-panel | Navigate to a `kind:Resource type:agent-sandbox` entity page; confirm "Approvals" tab appears with "No active JIT sessions" empty state |
| receipt | Navigate to Overview tab of a `kind:Resource type:agent-sandbox` entity; confirm "Session Receipt" card appears with "No JIT session recorded" empty state |

The empty states confirm the plugin loaded and the `if` condition matched — the
TODO placeholders display correctly until the backend endpoints are implemented.

---

## Shared instance guard

RHDH at `developer-hub-rhdh.apps.anaeem.na-launch.com` also hosts
`migration-catalog` and `ansible-collection-discovery`. All plugin entries
added above use `if: allOf: [isKind: resource, isType: agent-sandbox]` conditions —
they render ONLY on Sandbox entities and are invisible to all other catalog entities.
The `includes: - dynamic-plugins.default.yaml` line in the ConfigMap must not be removed.
Existing plugin entries must not be altered.
