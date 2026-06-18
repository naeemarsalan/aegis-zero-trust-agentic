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
# (a) rewrite the consent grant with a fresh timestamp (working Vault token is in the k8s secret)
RT=$(oc -n vault get secret vault-init -o jsonpath='{.data.root-token}' | base64 -d)
oc -n vault exec vault-0 -- sh -c "export VAULT_TOKEN='$RT'; vault kv put secret/sandbox-grants/$UID \
  version=1 sandbox_uid=$UID user=arsalan scope=read-only ttl=3600 \
  nonce=\$(od -An -N16 -tx1 /dev/urandom|tr -d ' \n') created=\$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

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

## Open follow-ups (non-blocking; tracked in memory project-e2e-handoff)
1. **Verify the corrected ext-proc** (`grant-e2e-jit-sysroot`, digest `sha256:2a66aa0…`): it's
   applied (system-roots TLS, no `SPIRE_TLS_INSECURE`) but the read leg wasn't re-verified under the
   apiserver flapping. Check the boot log once stable: `oc -n mcp-gateway logs deploy/ext-proc-delegation | grep -i "SPIRE verifier"` — expect **"SPIRE verifier enabled"**. If instead "init failed/disabled" (system-roots didn't validate the LE cert), set `SPIRE_CA_FILE` to the ingress CA or temporarily add `SPIRE_TLS_INSECURE=true` to the overlay and re-apply. (Evidence says system-roots works: the route serves a Let's Encrypt cert, distroless ships the Mozilla CA, and Vault validates the same endpoint via system CAs.)
2. **Gitea webhook HMAC:** webhook id=6 exists (pull_request events, `jit-approval` label) but has
   **no HMAC secret** — set it to `vault kv get -field=secret secret/jit-approver/webhook-secret`
   so jit-approver enforces the `X-Gitea-Signature` (the journey passed without it, but it should be enforced).
3. **Keycloak on-behalf exchange** returns 5xx (26.6.3 NPE) — non-fatal static fallback works;
   root-cause to restore true RFC8693 OBO.
4. **Cleanup:** disabled demo rule `E2E-LEG5-JIT-ELEVATED-RULE` (id=48) — delete in the pfSense UI
   (MCP `delete_firewall_rule` is broken: `AsyncClient.delete() json kwarg`).
