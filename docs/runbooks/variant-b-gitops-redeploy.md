# Runbook — GitOps-durable redeploy of the Variant-B zero-trust stack

**Goal:** restore the proven Variant-B delegated-loop stack so it survives namespace cleanup /
ArgoCD reconciliation (the durability gap that let it vanish), and re-run the full ida-TUI journey
against it. **Scope = the 3 missing core services** (the proven Variant-B path uses the
`e2e-harness` pod as the sandbox stand-in; OpenShell native is NOT needed here and is blocked
anyway per ADR-0011's disproof). OpenShell redeploy is a **separate, deferred** track (Stage 6).

**Status:** PLAN — nothing applied. Awaiting approval + secret values + scope confirmation.

## Current state (verified 2026-06-16, read-only)
- 3-node cluster `api.anaeem.na-launch.com`. All cluster operators `True`.
- **0 of the zero-trust namespaces exist**; `sandboxes` CRD absent; no sandbox/ext-proc/harness pods.
- ArgoCD app-of-apps `nvidia-ida → gitops/applications/` (kustomize, explicit `resources:` list).
  Children exist for agentgateway, isolation, keycloak, kyverno, networkpolicies, observability,
  operators, rhoai, showroom, **spire (Synced/Healthy)**, **vault (Synced/Healthy)**. **No app for
  ext-proc-delegation, jit-approver, agent-sandbox.** ← the gap.
- ArgoCD child syncPolicy pattern: `project: nvidia-ida`, `automated{prune:true, selfHeal:false}`,
  `CreateNamespace=true`, `ServerSideApply=true`, `sync-wave` annotation, no finalizers.
- All required images present in `oci.arsalan.io/nvidia-ida`: `ext-proc-delegation:grant-e2e-jit`,
  `jit-approver:e2e-jit`, `agent-harness:dev`, `svid-vault-fetch:dev`. **No rebuild needed.**
- ⚠️ Control plane is flaky: etcd member `172.16.1.3` flapping (105 restarts) caused inconsistent
  reads. **Stage 0 is a hard go/no-go gate.**

## Stage 0 — health gate (go/no-go; do not skip)
- etcd: all 3 members stable, no recent restarts on `172.16.1.3`; consider `etcd` defrag if DB large.
- Consistent reads: `oc get ns <x>` agrees with `oc get ns | grep <x>` across 3 tries.
- Vault unsealed; SPIRE server+agent Ready; Keycloak realm `agentic` reachable.
- **If reads are inconsistent, STOP** — redeploying onto a divergent control plane is unreliable.
  (Triage etcd first; needs separate approval for any restart/defrag.)

## Stage 1 — repo durability fixes (on `backup/e2e-delegated-zero-trust`, then PR → `main`)
ArgoCD watches `main` on `git.arsalan.io/anaeem/nvidia-ida`. Land these, push to main, let it sync.

1. **ext-proc-delegation overlay** (`services/ext-proc-delegation/deploy/overlays/anaeem/`):
   - Add a `deployment-patch.yaml` setting the grant-backend env (absent in git today — code-default
     leaves the SPIRE path OFF): `SPIRE_JWKS_URL=<spire OIDC/JWKS endpoint>`,
     `SANDBOX_GRANT_PATH_PREFIX=secret/data/sandbox-grants/`, `STATIC_AUTH_PATHS=/mcp`.
   - Update `images:` tag `grant-e2e-nonfatal → grant-e2e-jit` (the JIT-wired image; in registry).
2. **jit-approver overlay** (`services/jit-approver/deploy/overlays/anaeem/`):
   - Update `images:` tag `dev → e2e-jit` (stamps `sandbox_uid` into the session JWT; in registry).
3. **agent-sandbox/e2e-harness** (`services/agent-sandbox/e2e-harness/`):
   - Create `overlays/anaeem/kustomization.yaml` (namespace `agent-sandbox`, pin `agent-harness:dev`).
4. **ArgoCD apps** (`gitops/applications/`): add `ext-proc-delegation.yaml`, `jit-approver.yaml`,
   `agent-sandbox.yaml` mirroring `spire.yaml`; extend `kustomization.yaml` `resources:`. Sync-waves:
   ext-proc + jit-approver = wave 2 (after spire/vault/keycloak = wave 1), harness = wave 3.
5. **SPIRE CSID**: verify `platform/spire/base/cluster-spiffe-ids.yaml` includes
   `agent-sandbox-e2e-harness` (className `zero-trust-workload-identity-manager-spire`, SVID
   `…/ns/agent-sandbox/sandbox/<uid>`); add if missing (it was created live before).
6. **Security review** the ext-proc grant-env patch before merge (touches the credential path) —
   confirm no-credential-passing invariant intact.

## Stage 2 — pre-create live secrets (NOT gitops; values you hold)
These are referenced by the manifests; pods fail-closed without them. Create before/at sync:
| secret | namespace | contents / source |
|---|---|---|
| `openshell-client-tls` | mcp-gateway | TLS client cert (jit-approver mount; blocks pod start if absent) |
| ext-proc Keycloak exchange secret (`EXCHANGE_SECRET_FILE`) | mcp-gateway | mcp-gateway client secret from Keycloak realm `agentic` |
| `jit-approver-egress-gitea` | mcp-gateway | Gitea PAT for PR creation/merge |
| `agent-harness-inference` | agent-sandbox | OpenRouter API creds (was in `environment/.env`?) |
| jit-approver signing key (if not auto-gen) | mcp-gateway | JWT signing key for session JWTs |

## Stage 3 — Vault + Keycloak durability check (mostly already GitOps)
- Vault: unsealed; ext-proc policy reads `secret/data/sandbox-grants/*` (`platform/vault/config/ext-proc.hcl`);
  `auth/jwt` config trusts the SPIRE/Keycloak issuer; JWT role `VAULT_JWT_ROLE` exists.
- Keycloak realm `agentic` (`platform/keycloak/base/realm-import.yaml`): clients `mcp-gateway` +
  `ida-cli`; `service-account-mcp-gateway` has realm-management `impersonation`; feature
  `token-exchange` on. Confirm realm-import covers these (some were live kcadm edits — make durable).

## Stage 4 — merge to main, watch ArgoCD
- PR backup → main; merge. App-of-apps syncs → 3 child apps created → namespaces created → pods up.
- Verify: each new app `Synced/Healthy`; ext-proc + jit-approver + harness pods Running; routes resolve.

## Stage 5 — seed runtime data + run the journey (Phase E)
- Write the Vault grant for the harness `sandbox_uid`: `secret/data/sandbox-grants/<uid>`
  `{version:1,sandbox_uid:<uid>,user:arsalan,scope:read-only,ttl:3600,nonce:<hex>,created:<RFC3339Nano>}`.
- Run from ida TUI (loop-until-green): login → launch/select harness → `mcp-call search_firewall_rules`
  (delegated read → 200, 20 rules, downstream id=arsalan) → `create_firewall_rule_advanced` (403
  grant_scope_denied) → Approvals tab → Gitea PR merge → elevated retry → Receipt shows the audit.

## Stage 6 — OpenShell (DEFERRED, separate track)
Only for the unified/native vision + the userns/cap diagnostic
(`phaseA-userns-cap-diagnostic.md`). Requires restructuring `platform/openshell/` (Helm values +
Sandbox CR) into an ArgoCD-deployable Helm Application + installing the `sandboxes` CRD/controller.
Native `provider_spiffe` stays OFF (blocked per ADR-0011). Not needed for the Variant-B journey.
