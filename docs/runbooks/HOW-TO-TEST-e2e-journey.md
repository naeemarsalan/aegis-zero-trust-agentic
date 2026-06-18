# How to test the Variant-B delegated zero-trust journey yourself

The stack is **live** and the full journey was **proven green end-to-end** (workflow `wf_c76c68cf-26f`,
2026-06-17 — adversarially verified from the ext-proc audit). This is how you re-drive it.

> Note: the cluster control plane has been intermittently flapping auth (`oc` calls sometimes 401
> with "server has asked for the client to provide credentials"). It has good windows — just retry
> the `oc` command. If it's sustained, the control plane needs attention (likely an **etcd defrag** —
> DB was ~1.1 GB; see the e2e hand-off memory). The journey's data path (harness → gateway route →
> ext-proc → pfsense-mcp) does NOT use the kube apiserver; only `oc exec`/Logs-tab do.

```sh
KC=~/.config/ida/anaeem-admin.kubeconfig
oc() { command oc --kubeconfig "$KC" "$@"; }
UID=e2e0a1b2-c3d4-4e5f-8a9b-000000000001
```

## Step 0 — refresh the two things that expire (do this before every test run)
The consent grant has a **3600 s TTL** and the harness pod (`restartPolicy: Never`, `sleep 10800`)
self-terminates after 3 h. Refresh both:

```sh
# (a) rewrite the consent grant with a fresh timestamp.
#  ⚠️ Use the Vault HTTP API (or `vault kv put @file.json`) — do NOT use `vault kv put version=1
#  ttl=3600`: the CLI serializes scalars as JSON *strings*, and ext-proc's grant parser only accepts
#  *integer* version/ttl → otherwise the read leg fails with `grant_malformed: unsupported grant
#  version 0`. The working root token is VAULT_ROOT_TOKEN in environment/.env.
VT=$(grep -E '^VAULT_ROOT_TOKEN=' environment/.env | cut -d= -f2- | tr -d '"')
NONCE=$(openssl rand -hex 16); NOW=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
curl -sk -H "X-Vault-Token: $VT" -H 'Content-Type: application/json' -X POST \
  https://vault.apps.anaeem.na-launch.com/v1/secret/data/sandbox-grants/$UID \
  -d "{\"data\":{\"version\":1,\"sandbox_uid\":\"$UID\",\"user\":\"arsalan\",\"scope\":\"read-only\",\"ttl\":3600,\"nonce\":\"$NONCE\",\"created\":\"$NOW\"}}" \
  | python3 -m json.tool   # expect "data":{...} with no "errors"

# (b) recreate the harness pod (if Completed) and wait for its SVID
oc -n agent-sandbox delete pod e2e-harness --ignore-not-found
oc apply -k services/agent-sandbox/e2e-harness
oc -n agent-sandbox wait pod/e2e-harness --for=condition=Ready --timeout=120s
```

## Path A — quick CLI proof (from the harness shell)
```sh
# READ (delegated, SVID-only) -> expect 200 + ~20 pfSense rules
oc -n agent-sandbox exec e2e-harness -c agent -- mcp-call
# DANGEROUS (read-only grant) -> expect 403 grant_scope_denied
oc -n agent-sandbox exec e2e-harness -c agent -- mcp-call create_firewall_rule_advanced '{"interface":"lan","protocol":"tcp"}'
# Watch the server-side decision (no credential ever in the agent):
oc -n mcp-gateway logs deploy/ext-proc-delegation --tail=20 | grep credential_delegation
#   -> decision=allow, caller_username=arsalan, grant_result=valid, credential_injected=true (read)
#   -> decision=deny,  reason=grant_scope_denied (dangerous)
```

## Path B — the full journey via the ida TUI (the operator experience)
```sh
export IDA_GITEA_TOKEN=$(grep -E '^GITEA_TOKEN=' environment/.env | cut -d= -f2- | tr -d '"')   # for the Approve/merge
ida login                # Keycloak ROPC as arsalan (ROPC verified working on client ida-cli)
ida                      # TUI: sidebar = sandboxes; tabs = Approvals / Receipt / Logs
```
1. **Read/deny:** run `mcp-call` (Path A) from the harness — read 200, dangerous 403.
2. **Request:** the JIT request opens a **Gitea PR** (branch `jit/<id>`, label `jit-approval`).
3. **Approve:** in the **Approvals** tab, merge the PR (or merge in Gitea) → the webhook fires →
   jit-approver mints a **sandbox-bound, tool-scoped session JWT**.
4. **Retry:** re-run the dangerous tool with `JIT_SESSION_JWT=<jwt> mcp-call create_firewall_rule_advanced …`
   → **200, `jit_elevated=true`**; a *different* dangerous tool with the same JWT still **403** (tool-scoped).
5. **Receipt:** the **Receipt** tab shows the request→approve→elevated-call audit chain.

## What "green" looks like (assert the invariants)
- The agent presents **only its SVID**; `caller_sub` is empty in the audit — identity is resolved
  server-side from the Vault grant. The pfSense token is injected by ext-proc and **stripped from
  the response**; it never appears in the harness env/fs/MCP args. (Verified: harness has no
  Vault/pfSense creds; SVID via `/spiffe-workload-api` socket.)
- Forged/absent SVID → 401; expired grant → 403; out-of-scope tool → 403 (fail-closed).

## Status of prior follow-ups (verified 2026-06-18)
1. ✅ **ext-proc finding-A CLOSED + verified.** Live ext-proc runs `grant-e2e-jit-sysroot`
   (`sha256:2a66aa0…`) with `SPIRE_TLS_INSECURE` **removed**; boot log: *"SPIRE JWKS TLS anchored to
   system root CAs (trusts LE reencrypt route)"* + *"SPIRE verifier enabled"*. System-roots validates
   the Let's Encrypt route cert — TLS verification is real, not bypassed. The read leg returned 200
   under this config.
2. ✅ **Gitea webhook HMAC verified.** Hook id=6 has the secret matching
   `secret/jit-approver/webhook-secret`; a live test delivery returned 200 and a bad-HMAC probe
   returned 401 (signature enforced).

## Open follow-ups (non-blocking)
3. **Keycloak on-behalf exchange** returns 5xx (26.6.3 NPE) — non-fatal static fallback works;
   root-cause to restore true RFC8693 OBO.
4. **sandbox-launcher Vault policy** lacks `create`/`update` on `secret/data/sandbox-grants/*` (only
   deny), so the launcher can't write grants itself — extend the role in
   `platform/vault/config/ext-proc.hcl` (per the comment in `sandbox-launcher/vault.py`).
5. **Cleanup:** disabled demo rules `id=48` + `id=49` (`jit-e2e-test-leg5`) — delete in the pfSense
   UI (MCP `delete_firewall_rule` is broken: `AsyncClient.delete() json kwarg`). JIT demo PRs #15,
   #16 were merged to `main` (by design — the grant-file approval mechanism).
