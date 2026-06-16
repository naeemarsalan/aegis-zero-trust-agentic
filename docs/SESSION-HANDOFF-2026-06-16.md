# Session hand-off — e2e zero-trust delegated loop (2026-06-16)

Long session. Goal: prove the full zero-trust agentic journey end-to-end (ADR-0010 hybrid
TUI + the no-credential delegated MCP loop, "Variant B"). We got **all of it working live
except the final Keycloak token-mint**, which is blocked by a confirmed Keycloak 26.6.3 bug.
A mid-session node reboot (requested) triggered a long cluster-recovery detour (all
root-caused + recovered). Start the next session from **"Resume here"** at the bottom.

## TL;DR
- ✅ **Phase 1 (ADR-0010 hybrid ida refactor): DONE, green, security-reviewed.** Committed.
- ✅ **Delegated loop proven LIVE through user-resolution:** in-sandbox agent presents only its
  SPIRE **SVID** → ext-proc verifies it → reads the **Vault consent grant** → resolves to the
  **user** (`caller_username: arsalan`, `grant_result: valid`) → **fail-closed** at every unmet
  condition. Repeatedly observed in the ext-proc audit log.
- ❌ **Final step blocked:** the RFC 8693 on-behalf (impersonation) exchange at Keycloak returns
  HTTP 500 — a **Keycloak 26.6.3 bug**, not a config gap (see below).
- ⚠️ **Cluster is in a modified/degraded state** from the recovery (Kyverno scaled to 0, etc.) —
  see "Live cluster state" before doing anything.

## The final blocker — Keycloak 26.6.3 v1 token-exchange NPE
ext-proc's `ExchangeOnBehalf` does `grant_type=token-exchange` + `requested_subject=arsalan`
with **no subject_token** (Option D — the user token was discarded). That routes to Keycloak's
**`V1TokenExchangeProvider`**, which calls `UserPermissionsV2.canImpersonate()` **with a null
realm** → `NullPointerException` → HTTP 500:
```
NullPointerException: ...RealmModel.getName() because "realm" is null
  at UserPermissionsV2.canImpersonate(UserPermissionsV2.java:123)
  at UserPermissionsV2.canClientImpersonate(...172)
  at V1TokenExchangeProvider.tokenExchange(...169)
```
**Exhausted (none fix it):** removing the `admin-fine-grained-authz` feature (now off — running
`token-exchange:v1` only), toggling realm `adminPermissionsEnabled` true/false, granting the
`impersonation` realm-management role to `service-account-mcp-gateway`, creating fgap-v2
permissions via kcadm (the scope-permission API kept erroring). The v1 provider calls
`UserPermissionsV2` unconditionally. **This is a Keycloak code bug.**

### Two ways to finish (next session — pick one)
1. **ext-proc code tweak (recommended).** On the pfSense static-auth path (`/mcp`), the *injected*
   credential is `arsalan`'s **pre-provisioned static token** (selected by the grant); the RFC 8693
   exchange is, per the code's own comment, "for audit + JWT-aware downstreams." Make the exchange
   **non-fatal on the static-auth path** in `services/ext-proc-delegation/internal/extproc/server.go`
   (`handleSandboxAgentPath`) → the grant-selected token injects → downstream sees `arsalan`, loop
   closes. This is correct (the exchanged JWT isn't even the pfSense credential) and proves
   delegated identity. Needs an ext-proc rebuild + **git push to main** (ArgoCD reverts spoke-side
   image edits — see GitOps note).
2. **Bump Keycloak** off 26.6.3 to a build without the NPE, then the existing impersonation
   (with the granted role) works as-is.

## GitOps reality (IMPORTANT)
**ArgoCD on the hub auto-syncs `main` and reverts ANY spoke-side change** to managed resources
(it reverted both the Keycloak CR feature edit *and* the ext-proc `:grant-e2e` image — back to
`:dev`). So every durable fix must land in `main`. We already pushed the Keycloak feature change
(`main` commit `9c37f92`). The ext-proc grant image (`:grant-e2e`) is NOT in git → ArgoCD keeps
reverting the live Deployment to `:dev` (which lacks the grant/SVID code). To persist the grant
backend, update the ext-proc Deployment image in the repo + push.

## What's proven (artifacts/evidence)
- ext-proc audit line (live): `agent_spiffe_id=spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/e2e0a1b2-… , vault_result=success, grant_result=valid, caller_username=arsalan, mcp_tool=search_firewall_rules, keycloak_result=exchange_5xx, decision=deny, reason=on_behalf_exchange_failed`.
- Fail-closed proven: `401 no_identity` (bad/stale SVID), `403 grant_vault_error` / `grant absent` / `on_behalf_exchange_failed`.
- Harness runs the Claude agent via **OpenRouter** (`anthropic/claude-sonnet-4.5`, system `claude` CLI in-image), loads the `list-firewall-rules` skill, emits redacted JSONL.

## Live cluster state changed this session (anaeem SNO; kubeconfig `~/.config/ida/anaeem-admin.kubeconfig`)
- **Kyverno admission + background controllers SCALED TO 0** (`oc -n kyverno scale deploy/kyverno-admission-controller deploy/kyverno-background-controller --replicas=0`), and resource webhooks relaxed to `Ignore`. **Do NOT blindly scale Kyverno back up** until the root cause is fixed (below) — re-enabling will regenerate the bad NPs.
- **SPIRE:** added NetworkPolicy `allow-spire-infra` in ns `zero-trust-workload-identity-manager` (restores egress to the apiserver). **Keep it.** spire-server 2/2, agent 1/1, issuing SVIDs.
- **Vault:** **unsealed** (keys in `environment/.env`: `VAULT_UNSEAL_KEY_1..5`, `VAULT_ROOT_TOKEN`). Vault `auth/jwt/config` `oidc_discovery_ca_pem` **cleared** (was pinned to the old ingress CA; now trusts the restored Let's Encrypt cert via system CAs). ext-proc Vault policy now reads `secret/data/sandbox-grants/*` (live + repo `platform/vault/config/ext-proc.hcl`).
- **Demo grant** at `secret/data/sandbox-grants/e2e0a1b2-c3d4-4e5f-8a9b-000000000001` (`user=arsalan, scope=read-only, ttl=3600`). **TTL is 1h — REWRITE before re-testing** (see resume).
- **SPIRE CSID** `agent-sandbox-e2e-harness` (has `className: zero-trust-workload-identity-manager-spire` — required, else the controller ignores it) → SVID `…/ns/agent-sandbox/sandbox/<demo-uuid>`.
- **Keycloak:** `service-account-mcp-gateway` granted realm-management `impersonation` role; realm `adminPermissionsEnabled=false`; CR feature now `token-exchange` (pushed to `main`). Admin: secret `keycloak-initial-admin` (user `temp-admin`); kcadm needs `--config /tmp/kcadm.config` (HOME unwritable).
- **Harness:** sleeper pod `e2e-harness` in ns `agent-sandbox` (`command: sleep 3600` — recreate if gone); Secret `agent-harness-inference` (OpenRouter creds — NOT in git).
- **ida-admin cluster-admin escalation** still active (MSA `ida-admin` + ClusterRoleBinding) — cleanup pending.

## CLUSTER OUTAGE root cause (fix before re-enabling Kyverno)
The Kyverno ClusterPolicy **`require-networkpolicy`** (rule `generate-default-deny-networkpolicy`)
generates a **bare deny-all NetworkPolicy (no companion allow rules)** into namespaces. When its
background controller reconciled (~10:14–11:06), it dropped deny-all into infra namespaces
(`zero-trust-workload-identity-manager`, `keycloak`, `agentic-observability`) that had no
allow-egress rules → those pods lost the **apiserver ClusterIP (172.30.0.1)** → SPIRE/controllers
crashlooped → cascade. **Fix:** exclude infra/system namespaces from `require-networkpolicy`, OR
have it also generate `allow-egress-apiserver`+`allow-egress-dns`. Then re-enable Kyverno.

## Git state
- Branch `backup/e2e-delegated-zero-trust`: `d7e2979` (full session backup, 100 files — ida hybrid
  refactor, harness, ext-proc grant code, ADRs) + `2dec369` (keycloak feature drop).
- `main`: `9c37f92` keycloak feature drop (pushed; ArgoCD synced).
- Images built+pushed: `oci.arsalan.io/nvidia-ida/agent-harness:dev`,
  `oci.arsalan.io/nvidia-ida/ext-proc-delegation:grant-e2e`.

## Resume here (next session — fastest path to closing the loop)
1. **Verify cluster health:** `oc --kubeconfig ~/.config/ida/anaeem-admin.kubeconfig get co | grep -v True` ; spire-server 2/2 + agent 1/1 ; Vault unsealed (`vault status`). Unseal if resealed.
2. **Ensure ext-proc runs `:grant-e2e`** (ArgoCD may have reverted to `:dev`): `oc -n mcp-gateway get deploy ext-proc-delegation -o jsonpath='{...image}'`. If `:dev`, either push the image ref to `main` (durable) or `oc set image …=:grant-e2e` and race.
3. **Rewrite the demo grant** (1h TTL expires): write `secret/data/sandbox-grants/e2e0a1b2-c3d4-4e5f-8a9b-000000000001` `{version:1,sandbox_uid:<uid>,user:arsalan,scope:read-only,ttl:3600,nonce:<hex>,created:<RFC3339Nano>}` via root or the launcher SA.
4. **Implement the chosen fix** (ext-proc static-path-exchange-non-fatal, recommended) → rebuild → push image ref to `main`.
5. **Run the proof:** from the `e2e-harness` pod, SVID-only MCP `tools/call search_firewall_rules` against `https://mcp-gateway.apps.anaeem.na-launch.com/mcp` (init → Mcp-Session-Id → tools/call). Expect `decision=allow`, firewall rules returned, downstream identity = `arsalan`, no credential in the agent.
6. Then Phase 3 (JIT escalation) + Phase 4 (full journey via the ida TUI), per `~/.claude/plans/zany-coalescing-russell.md`.

## Cleanup owed (after the e2e or if abandoning)
- Demo: `ClusterSPIFFEID agent-sandbox-e2e-harness`, Vault `sandbox-grants/<uid>`, pod `e2e-harness`, Secret `agent-harness-inference`, NP `allow-egress-e2e-harness`.
- Re-enable Kyverno (after fixing `require-networkpolicy`) + restore its webhook failurePolicies.
- Remove the `ida-admin` cluster-admin escalation.
