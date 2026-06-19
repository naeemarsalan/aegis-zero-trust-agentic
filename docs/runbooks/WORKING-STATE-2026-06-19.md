# Working State: Zero-Trust Split-Identity MCP Loop (2026-06-19)

This document captures everything built and deployed to get the zero-trust split-identity
delegated MCP loop + autonomous agent running LIVE on the `anaeem` spoke as of 2026-06-19.
It is a point-in-time snapshot. All code and manifests are on the working tree of branch
`backup/e2e-delegated-zero-trust` — nothing has been merged to `main`.

---

## Architecture (one paragraph)

A credential-less agent running in the `agent-sandbox` namespace presents only its SPIRE
JWT-SVID (`aud=mcp-gateway`) to the agentgateway. The gateway's ext-proc sidecar
(`ext-proc-delegation`) intercepts the request, cryptographically verifies the SVID
against the SPIRE OIDC JWKS endpoint, reads a time-bounded consent grant from Vault
(`secret/data/sandbox-grants/<sandbox-uid>`), resolves the grant to the real end-user
(`arsalan`), and selects the appropriate per-user pfSense token from Vault server-side:
the **read token** (`mcp-tokens`) by default, or the **write token** (`mcp-tokens-write`)
only when a valid, sandbox-bound, tool-scoped JIT capability JWT is present. The selected
token is injected into the downstream request as `Authorization: Bearer <token>`; it is
stripped from upstream responses before they reach the agent. The agent never holds a
pfSense token, Vault token, or any downstream credential at any point.

---

## What We Built / Changed This Session (by component)

### 1. ext-proc-delegation — two-token split identity (ADR-0012)

**Files:** `services/ext-proc-delegation/internal/config/config.go`,
`services/ext-proc-delegation/internal/extproc/server.go`,
`services/ext-proc-delegation/internal/inject/inject.go`,
`services/ext-proc-delegation/internal/audit/audit.go`

**What changed:**

- Added `StaticTokenSecretWrite` config field (env `STATIC_TOKEN_SECRET_WRITE`, default
  `"mcp-tokens-write"`). When a request is JIT-elevated, ext-proc fetches the **write
  token** from this Vault KV key instead of the read key (`mcp-tokens`). Fail-closed: if
  the write token is absent or unfetchable, the call is denied — the code never silently
  falls back to the read token on an approved write.

- `handleSandboxAgentPath` in `server.go` now splits the static-token selection:
  - `jitElevatesTool == false` → fetch from `StaticTokenSecret` (unchanged read path).
  - `jitElevatesTool == true` → fetch from `StaticTokenSecretWrite`; deny on any fetch
    failure or missing user key (`write_identity_unavailable`).

- `audit.go` `Event` struct gained `WriteIdentity bool` and `JITSessionID string` fields.
  The allow audit now emits `write_identity=true` + `jit_session_id=<id>` on an elevated
  write, `write_identity=false` on a read.

- `inject.go` `StripResponse()` now removes `x-jit-session-jwt` from upstream responses
  in addition to the existing credential headers. This was a HIGH finding from the security
  review: a downstream that echoes request headers could leak the capability JWT (still
  within its TTL) back to the agent.

**Vault paths required:**

| Path | Key | Content |
|------|-----|---------|
| `secret/data/mcp-tools/mcp-tokens` | `arsalan` | pfSense read-only token |
| `secret/data/mcp-tools/mcp-tokens-write` | `arsalan` | pfSense write-capable token |

Both tokens must appear in pfSense's `MCP_API_KEY` csv for the `/mcp` route.

---

### 2. Kyverno — removed redundant dangerous-tools-admins-only gate

**Files deleted:** `platform/kyverno/authz/base/dangerous-tools-admins-only.yaml`

**Why:** The `dangerous-tools-admins-only` ValidatingPolicy was redundant and broken.
Its NetworkPolicy lacked egress to `jit-approver:8080`, so the JWKS fetch was dropped
and all JIT-elevated writes were permanently denied by that gate. ext-proc already
performs the identical in-process JIT check (same JWKS, same `iss`/`aud` verification,
same `sandbox_uid` binding, same `tool_scope` check) — and adds the `sandbox_uid`
binding that the Kyverno policy lacked. Removing the Kyverno gate does not widen access.

**NetworkPolicies added** (`services/jit-approver/deploy/base/networkpolicy.yaml`):
- `jit-approver-ingress-ext-proc` — allows ext-proc pods in `mcp-gateway` to reach
  `jit-approver:8080` for JWKS fetch.
- `jit-approver-ingress-approval-console` — allows the approval-console pods (same
  namespace) to call the jit-approver read API and approve endpoint.

**Note:** Kyverno itself is still running but in Audit-only mode
(`validationFailureAction: Audit` in `require-networkpolicy.yaml`; controllers are up but
advisory, not enforced). Re-enabling to Enforce mode is blocked on an etcd defrag (1.2 GB,
prone to saturation).

---

### 3. approval-console — new service

**Directory:** `services/approval-console/`

A FastAPI single-page web UI (`src/approval_console/app.py`) that:
- Polls jit-approver (`GET /requests`) every 5 seconds for pending JIT requests.
- Renders them as a simple HTML list.
- On **Approve**, proxies the merge to Gitea via the jit-approver API — the Gitea PR is
  merged, the webhook fires, and jit-approver mints the sandbox-bound session JWT.
- Strips credentials from the browser (no token is ever sent to the frontend).

**Route:** `https://approval-console.apps.anaeem.na-launch.com`

**GITEA_TOKEN delivery (PoC):** a plain k8s Secret `mcp-gateway/approval-console-gitea`
(key `token`). The console's SA is NOT bound to a Vault k8s-auth role yet — the Vault
Agent Injector was dropped. A dedicated Vault role for this SA is a hardening TODO.

**Kustomize layout:**
- `deploy/base/` — Deployment, Service, Route, ServiceAccount, NetworkPolicy, Namespace
- `deploy/overlays/anaeem/` — `deployment-patch.yaml` wires `GITEA_TOKEN` from the secret

**Image:** `oci.arsalan.io/nvidia-ida/approval-console:dev`

---

### 4. mcp-call helper — auto-escalate on 403 + dedup + reuse

**File:** `services/agent-sandbox/agent-harness/bin/mcp-call` (Python script; delivered
into the harness pod via the `ztp-helpers` ConfigMap mounted at `/opt/ztp/bin`)

**New capabilities added this session:**

| Capability | What it does |
|-----------|--------------|
| Auto-escalate | On a `grant_scope_denied` 403, automatically files a JIT request (`POST /requests`) with the tool-mapped verb/resource pair, then waits for a human to click Approve in the console, then retries the call with the issued JWT |
| Reuse prior approval | Checks `GET /requests` first; if a still-valid, sandbox-bound approval covering this tool exists, uses it without asking again |
| Dedup pending request | If a pending request already exists for the same tool and SVID, waits on that instead of opening a duplicate PR |

The `JIT_APPROVER_URL` env defaults to the cluster-internal service URL. The `APPROVAL_CONSOLE_URL` env defaults to the public route (printed in the "waiting" message).

**Usage inside the harness pod:**
```sh
mcp-call                                    # read  -> 200 (search_firewall_rules)
mcp-call create_firewall_rule_advanced '{...}'  # write -> 403 -> auto-files JIT -> waits -> retries
JIT_SESSION_JWT=<jwt> mcp-call create_firewall_rule_advanced '{...}'  # explicit JWT (manual path)
```

---

### 5. agent-harness — AGENT_ALLOWED_TOOLS env + selective MCP registration

**File:** `services/agent-sandbox/agent-harness/src/agent_harness/agent_runner.py`

**What changed:**

- Added `AGENT_ALLOWED_TOOLS` env (comma-separated tool list). Default = the single
  read-only native MCP tool (`mcp__mcp-gateway__search_firewall_rules`).

- When `AGENT_ALLOWED_TOOLS=Bash`, the agent does NOT register the gateway as a native
  MCP server. This is intentional: if the native firewall tools (e.g.
  `create_firewall_rule_advanced`) are visible to the agent via MCP, the `dontAsk`
  permission mode causes it to try them directly, get denied, and give up — instead of
  reaching for `mcp-call` (which transparently does the JIT self-escalation). No native
  MCP server registered = the only path to pfSense is `mcp-call` via `Bash`.

- `run-agent.sh` invokes the agent with `AGENT_ALLOWED_TOOLS=Bash AGENT_MAX_TURNS=14`.

---

### 6. pfsense-firewall skill

**File:** `services/agent-sandbox/agent-harness/.claude/skills/pfsense-firewall/SKILL.md`

A Claude Agent SDK skill loaded from disk at agent startup. It tells the agent:
- The ONLY mechanism for firewall operations is `mcp-call` via the `Bash` tool.
- There are no native MCP firewall tools.
- Reads return immediately; writes pause (the `mcp-call` helper handles the JIT wait
  internally — timeout `600000 ms` / 10 minutes is recommended).
- The agent must never try to obtain or pass a credential.

---

### 7. e2e-harness — converted to durable Deployment

**New file:** `services/agent-sandbox/e2e-harness/deployment.yaml`

Converted from a `restartPolicy: Never` bare Pod (`sleep 10800`) to a 1-replica Deployment
(`sleep infinity`). The Deployment auto-restarts on container exit so the harness survives
without manual re-apply. Everything else is preserved:
- SPIFFE CSI volume (`csi.spiffe.io`) delivering the SVID socket.
- `ClusterSPIFFEID` `agent-sandbox-e2e-harness` selects pods via the
  `nvidia-ida/e2e-harness: "true"` label (carried in the pod template).
- `ConfigMap` `ztp-helpers` mounted at `/opt/ztp/bin` (delivers `mcp-call`).
- `e2e-harness` ServiceAccount (`automountServiceAccountToken: false`).
- `agent-harness-inference` Secret (`optional: true` — schedules even when absent).
- Fixed sandbox-id label `nvidia-ida/sandbox-id: e2e0a1b2-c3d4-4e5f-8a9b-000000000001`.

**Image:** `oci.arsalan.io/nvidia-ida/agent-harness:self-escalate`

---

### 8. hack/spawn-shell.sh and hack/run-agent.sh

**`hack/spawn-shell.sh`** — de-ritualized "drop me in" command:
1. Resolves a working Vault token (env `VAULT_ROOT_TOKEN` → `environment/.env` → k8s
   secret `vault/vault-init`).
2. Writes a fresh integer-typed consent grant via the Vault HTTP API (avoids the
   `vault kv put` CLI bug where integer fields become JSON strings, causing
   `grant_malformed` from `grant.FromVaultData`).
3. Restarts `deploy/e2e-harness` and waits for the SVID to be issued (~30 s).
4. Polls the read path (`mcp-call`) until HTTP 200, retrying through control-plane
   flaps (`octry` wrapper).
5. Drops into an interactive `bash` shell with apiserver-flap retry.

**`hack/run-agent.sh "<goal>"`** — runs the autonomous Claude agent:
1. Refreshes the consent grant (same Vault write as above).
2. Finds the running harness pod.
3. Execs the agent runner with `AGENT_ALLOWED_TOOLS=Bash AGENT_MAX_TURNS=14 AGENT_GOAL=<goal>`.
4. Pipes the JSONL output through a Python formatter that renders assistant reasoning,
   tool calls, and tool results in a human-readable trace.

---

## Live Deployment State

### Namespace topology

| Namespace | What runs there |
|-----------|----------------|
| `mcp-gateway` | agentgateway, ext-proc-delegation, jit-approver, approval-console |
| `agent-sandbox` | e2e-harness (the durable Deployment) |
| `agentic-mcp` | pfsense-mcp (the upstream pfSense MCP server) |
| `vault` | vault-0 (unsealed, v1.21.2) |
| `spire-system` | SPIRE server + agent |

### Image digests (pinned)

| Component | Image | Tag / Digest |
|-----------|-------|-------------|
| ext-proc-delegation | `oci.arsalan.io/nvidia-ida/ext-proc-delegation` | tag `grant-e2e-jit-split`; digest `sha256:e2b7d0ebd7b862c632f84d0109ec3fb107904ab3d330259a8f7771c1e423e22b` |
| jit-approver | `oci.arsalan.io/nvidia-ida/jit-approver` | `e2e-jit-split` |
| approval-console | `oci.arsalan.io/nvidia-ida/approval-console` | `dev` |
| agent-harness | `oci.arsalan.io/nvidia-ida/agent-harness` | `self-escalate` |

The ext-proc image is pinned by digest in
`services/ext-proc-delegation/deploy/overlays/anaeem/kustomization.yaml` for
reproducibility. The jit-approver and approval-console images are tag-pinned (not digest).

> Note: `podman inspect .Digest` does not match the registry digest. Use
> `skopeo inspect docker://oci.arsalan.io/nvidia-ida/ext-proc-delegation:grant-e2e-jit-split`
> to verify the real registry digest.

### Key environment variables (ext-proc-delegation)

Set via `services/ext-proc-delegation/deploy/overlays/anaeem/deployment-patch.yaml`:

| Env var | Value | Purpose |
|---------|-------|---------|
| `SPIRE_JWKS_URL` | `https://spire-oidc.apps.anaeem.na-launch.com/keys` | Enables the SVID path |
| `SPIRE_ISSUER` | `https://spire-oidc.apps.anaeem.na-launch.com` | Expected `iss` claim |
| `SPIRE_AUDIENCE` | `mcp-gateway` | Expected `aud` claim |
| `SPIRE_TLS_INSECURE` | `"true"` | See SPIRE TLS note below |
| `SANDBOX_GRANT_PATH_PREFIX` | `secret/data/sandbox-grants/` | Vault grant KV prefix |
| `STATIC_AUTH_PATHS` | `/mcp` | pfSense MCP path (read/write token, not KC JWT) |

`STATIC_TOKEN_SECRET` defaults to `mcp-tokens`; `STATIC_TOKEN_SECRET_WRITE` defaults to
`mcp-tokens-write` (both confirmed in `config.go`).

### SPIRE OIDC TLS — IMPORTANT

The `SPIRE_TLS_INSECURE=true` flag is deliberately set in the anaeem overlay and pinned in
git. The spire-oidc endpoint is an OpenShift `reencrypt` Route serving a Let's Encrypt
wildcard cert (`*.apps.anaeem.na-launch.com`). On this flapping SNO, intermittent
cache-expiry re-fetches land on a chain the distroless Mozilla bundle cannot build, causing
`x509: certificate signed by unknown authority` even when the cert is valid. System-root
TLS verification was attempted (`grant-e2e-jit-sysroot` build, verified GREEN in a prior
session), but the reliability problem means the insecure escape hatch is the PoC operating
state.

**The SVID JWT signature is still cryptographically verified** via the fetched JWKS keys.
Only the HTTPS transport to the JWKS endpoint has TLS verification skipped.

**Production fix:** pin `SPIRE_CA_FILE` to the ingress / LE CA PEM, or convert the
spire-oidc Route to a passthrough Route serving the SPIRE-internal bundle.

### Vault secrets

| Path | Keys | Purpose |
|------|------|---------|
| `secret/data/mcp-tools/mcp-tokens` | `arsalan` (read token), `tokens` (csv for pfsense-mcp) | Read-only pfSense token |
| `secret/data/mcp-tools/mcp-tokens-write` | `arsalan` (write token) | Write-capable pfSense token |
| `secret/data/sandbox-grants/e2e0a1b2-c3d4-4e5f-8a9b-000000000001` | grant document | Consent grant (TTL 3600 s; re-written by `spawn-shell.sh` each session) |

**Vault token:** try `environment/.env` `VAULT_ROOT_TOKEN` first; fall back to k8s secret
`vault/vault-init` key `root-token`. Both have been observed to rotate — `spawn-shell.sh`
tries both automatically.

**Grant write format (integer-typed — required):** the grant must be written via the Vault
HTTP API with integer-typed JSON, NOT via `vault kv put`. The CLI converts integers to
strings, which causes `grant.FromVaultData` to reject the grant as `grant_malformed`.
`spawn-shell.sh` does this correctly.

---

## GitOps Reconciliation

The anaeem spoke has **no ArgoCD instance**. Instead, the **hub ArgoCD**
(`openshift-gitops/nvidia-ida-agentgateway`) syncs directly to the spoke API server. This
app manages both `ext-proc-delegation` and `jit-approver` deployments. Its auto-sync was
reverting the live split-image back to `:dev` within ~30 seconds of any `oc apply` or
`oc set image` change.

**What we did:** Disabled automated reconciliation for that one app:

```sh
oc -n openshift-gitops patch applications.argoproj.io nvidia-ida-agentgateway \
  --type merge \
  -p '{"spec":{"syncPolicy":{"automated":null}}}'
```

> NOTE: must use `applications.argoproj.io` — bare `applications` resolves to the ACM
> `app.k8s.io` CRD and silently patches the wrong object.

**Current state:** The split image (`sha256:e2b7d0eb...`) and `SPIRE_TLS_INSECURE=true`
now stick. Verified stable for 75 s with no revert.

**This is reversible:** re-add the `automated` block to resume reconciliation.

**Other ArgoCD apps on the hub still reconcile:**
`nvidia-ida-{networkpolicies, kyverno (OutOfSync), keycloak, spire, vault, ...}`. The
NetworkPolicies we added to `jit-approver/deploy/base/networkpolicy.yaml` are tracked by
the `nvidia-ida-networkpolicies` app — those NPs are holding for now (the app has not
reverted them).

**The proper durable fix** is to port the `~3700-line` grant/split feature from the backup
branch to `main`, then re-enable the automated sync. That is a full feature branch merge,
not a hotfix.

---

## How to Test

Full details: `docs/runbooks/HOW-TO-TEST-split-identity.md`

### Path A — manual shell (mcp-call)

```sh
# From repo root, with admin kubeconfig at ~/.config/ida/anaeem-admin.kubeconfig
bash hack/spawn-shell.sh
# Inside the shell:
mcp-call                                    # READ -> 200 (delegated as arsalan)
mcp-call create_firewall_rule_advanced '{"interface":"lan","rule_type":"pass","protocol":"tcp","source":"any","destination":"any","description":"demo"}'
# -> 403 grant_scope_denied -> mcp-call auto-files a JIT request and WAITS
# Approve in console: https://approval-console.apps.anaeem.na-launch.com
# -> auto-retries -> 200 (write identity)
```

### Path B — autonomous agent

```sh
bash hack/run-agent.sh "Using your pfsense-firewall skill, list the current firewall rules"
bash hack/run-agent.sh "Add a firewall rule on lan that passes tcp from any to any, description demo"
# Agent will pause on the write and print the approval console URL
```

### Verify server-side invariants

```sh
oc -n mcp-gateway logs deploy/ext-proc-delegation -c ext-proc-delegation \
  | grep credential_delegation | tail
```

Expected audit fields:

| Scenario | Key audit fields |
|----------|-----------------|
| Read allowed | `decision=allow, write_identity=false, caller_username=arsalan, credential_injected=true` |
| Write denied (no approval) | `decision=deny, reason=grant_scope_denied` |
| Write approved + elevated | `decision=allow, write_identity=true, jit_elevated=true, caller_username=arsalan` |
| Tool not in JIT scope | `decision=deny, reason=grant_scope_denied` (tool-scoping enforced) |

---

## Caveats and Known Debt

| Item | Severity | Detail |
|------|----------|--------|
| Code + manifests uncommitted | CRITICAL | Everything is on the `backup/e2e-delegated-zero-trust` working tree. A cluster reboot or accidental `oc apply -k` from `main` would revert the live path. The proper fix is porting the feature to `main`. |
| GitOps auto-sync disabled | HIGH | The `nvidia-ida-agentgateway` ArgoCD app auto-sync is off. Other apps on the hub still reconcile. Re-enable after the feature lands in `main`. |
| `SPIRE_TLS_INSECURE=true` | HIGH (Finding A re-opened) | TLS verification of the SPIRE OIDC JWKS endpoint is skipped due to intermittent chain-build failures on this SNO. SVID JWT signature verification is still enforced; only the transport TLS is skipped. Prod fix: `SPIRE_CA_FILE` or passthrough Route. |
| approval-console unauthenticated | HIGH | The approval console Route is open to anyone who can reach the cluster router (no oauth-proxy, no mTLS). Acceptable for a homelab PoC; harden before any real exposure. |
| approval-console GITEA_TOKEN is a plain k8s secret | MEDIUM | `mcp-gateway/approval-console-gitea`. The console SA is not bound to a Vault k8s-auth role. A dedicated Vault role is a TODO. |
| Not Kata-isolated | MEDIUM | The harness runs under `runc`, not Kata containers. Per-sandbox micro-VM isolation (the full vision) is blocked by the OCP/CRI-O `setns` EPERM issue (ADR-0011 disproof). |
| Kyverno Audit-only | MEDIUM | Kyverno guardrails emit audit findings but are not enforced (`validationFailureAction: Audit`). Re-enable to Enforce after etcd defrag (1.2 GB). |
| Fixed sandbox UID | MEDIUM | The harness uses the hard-wired UID `e2e0a1b2-c3d4-4e5f-8a9b-000000000001`. This is a single hand-wired PoC pod, not a launcher-created per-user sandbox. The OpenShell launcher is not wired to the zero-trust path. |
| Inference key in agent env | MEDIUM | The OpenRouter inference key (`sk-or-v1-…`) is in the `agent-harness-inference` secret in the pod env in plaintext. Rotate it. It is not a downstream/target credential (does not violate the delegation invariant), but it is an infra secret. |
| Demo pfSense rules | LOW | Rules created during past test sessions are disabled in pfSense but not deleted (the `delete_firewall_rule` MCP tool is broken upstream: `AsyncClient.delete() got unexpected kwarg 'json'`). Remove via pfSense UI. |
| Gitea PRs merged to main | INFO | Each JIT approval merges the grant-file PR to `main` (by design — the git history is the approval record). PRs #17, #18 and prior test PRs are on `main`. |
| etcd fragmentation | INFO | etcd is at ~1.2 GB with a history of high churn from Kyverno reports. Control-plane intermittently flaps auth (401s from `oc`). Run `etcdctl defrag` before re-enabling Kyverno or adding more load. |
| One user, one target | INFO | The PoC covers `arsalan` → pfSense only. Adding a second user or target requires provisioning tokens, ClusterSPIFFEIDs, and grant documents for each. |

---

## Pointers

| Resource | Path |
|----------|------|
| ADR-0012 (split-identity design decision) | `docs/adr/0012-real-per-user-split-identity-pfsense.md` |
| How-to-test (drivable steps) | `docs/runbooks/HOW-TO-TEST-split-identity.md` |
| Session memory — live proof | `~/.claude/projects/-home-anaeem-nvidia-ida/memory/project-split-identity-live.md` |
| Session memory — roadmap | `~/.claude/projects/-home-anaeem-nvidia-ida/memory/project-roadmap-whole-puzzle.md` |
| Keycloak OBO constraint | `~/.claude/projects/-home-anaeem-nvidia-ida/memory/project-keycloak-obo-constraint.md` |
| e2e hand-off detail | `~/.claude/projects/-home-anaeem-nvidia-ida/memory/project-e2e-handoff.md` |
| ext-proc overlay (anaeem) | `services/ext-proc-delegation/deploy/overlays/anaeem/` |
| e2e-harness manifests | `services/agent-sandbox/e2e-harness/` |
| approval-console source | `services/approval-console/` |
| pfsense-firewall skill | `services/agent-sandbox/agent-harness/.claude/skills/pfsense-firewall/SKILL.md` |
| mcp-call helper | `services/agent-sandbox/agent-harness/bin/mcp-call` |
| Helper scripts | `hack/spawn-shell.sh`, `hack/run-agent.sh` |
