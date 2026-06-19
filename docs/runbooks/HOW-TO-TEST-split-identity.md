# How to test the split-identity zero-trust loop (de-ritualized)

This is the **simple, drivable** version of the journey. The agent shell holds **no
credentials** — only its SPIRE SVID. Reads are allowed; writes need an approval you
click in a web console (recorded via a merged git PR). Two distinct downstream
identities are used: a **read** token by default, a **write** token only after approval.

Live endpoints (anaeem spoke):
- Agent shell: `oc -n agent-sandbox exec -it deploy/e2e-harness -c agent -- bash`
- Approval console: <https://approval-console.apps.anaeem.na-launch.com>
- JIT API: <https://jit-approver-api.apps.anaeem.na-launch.com>

## 1. Spawn your agent shell (one command)
```sh
hack/spawn-shell.sh           # writes a fresh consent grant, restarts the harness, drops you in
# (reads VAULT_ROOT_TOKEN from environment/.env; override with --user / --uid / --ttl)
```
This de-ritualizes the old flow: no manual Vault grant rewrite, no pod recreation.

## 2. Inside the shell — read is allowed, write is denied
```sh
mcp-call                                              # READ search_firewall_rules -> 200 (delegated as you)
mcp-call create_firewall_rule_advanced '{"interface":"lan","rule_type":"pass","protocol":"tcp"}'
                                                      # WRITE -> 403 grant_scope_denied (read-only baseline)
```
The banner shows you present only your SVID — no user token, no downstream secret.

## 3. Approve the write in the web console
If you ran `mcp-call` manually and hit the 403, `mcp-call` **automatically** files the JIT
request and starts waiting — you will see a printed approval URL. If you used `mcp-call`
in mcp-call auto-mode (the default), skip to step 4.

For a fully manual flow (no mcp-call auto-escalate), POST to the jit-approver:
```sh
curl -s https://jit-approver-api.apps.anaeem.na-launch.com/requests \
  -H 'Content-Type: application/json' \
  -d '{"agent_spiffe_id":"spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/e2e0a1b2-c3d4-4e5f-8a9b-000000000001",
       "requester_sub":"spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/e2e0a1b2-c3d4-4e5f-8a9b-000000000001",
       "namespace":"agentic-mcp","verbs":["create"],"resources":["networkpolicies"],
       "duration_minutes":30,"justification":"manual test"}'
```
Then:
1. Open the **approval console** (`https://approval-console.apps.anaeem.na-launch.com`),
   find the pending request, click **Approve**. The console merges the Gitea PR (the
   approval is recorded in git on `main`), the webhook fires, and jit-approver mints a
   **sandbox-bound, tool-scoped** capability JWT.
2. For the manual path, fetch the JWT:
   `GET jit-approver-api/requests/<id>/status` → `session_jwt` (when `state=issued`).

## 4. Re-run the write — elevated, with the write identity

**Auto-mode (mcp-call):** `mcp-call` retries automatically after approval. No action
needed — it will print "approved — retrying … under your write identity" and complete.

**Manual mode (explicit JWT):**
```sh
JIT_SESSION_JWT=<jwt> mcp-call create_firewall_rule_advanced '{"interface":"lan","rule_type":"pass","protocol":"tcp","source":"any","destination":"any","description":"test"}'
#   -> 200, jit_elevated=true, served under the per-user WRITE token
JIT_SESSION_JWT=<jwt> mcp-call create_alias '{"name":"x","type":"host"}'
#   -> 403 — the JWT is scoped to firewall tools only (tool-scoping)
```
> pfSense's `create_firewall_rule_advanced` requires `rule_type` (pass/block/reject),
> `interface`, `protocol`, `source`, `destination`. It rejects bare `descr`/`type`.
> Run `mcp-call tools_list` for the exact schema. Auth/identity is proven regardless
> of tool argument validation.

## 5. Verify the invariants (the proof)
```sh
oc -n mcp-gateway logs deploy/ext-proc-delegation -c ext-proc-delegation | grep credential_delegation | tail
```
- READ:  `decision=allow ... write_identity=false ... caller_username=arsalan`
- WRITE (no approval): `decision=deny reason=grant_scope_denied`
- WRITE (approved): `decision=allow ... write_identity=true jit_elevated=true caller_username=arsalan`
- The agent never holds a pfSense token; the downstream is attributed to the user; the
  injected token is stripped from the response. SVID forged/absent → 401; expired grant → 403.

## 6. Autonomous agent path

Instead of a manual shell, run the autonomous Claude agent:

```sh
bash hack/run-agent.sh "List the current firewall rules and count them"
bash hack/run-agent.sh "Add a firewall rule on lan passing tcp from any to any, description demo"
```

The agent uses the `pfsense-firewall` skill and the `mcp-call` helper exclusively. On a
write it pauses autonomously, files a JIT request, waits, and continues after approval.

## Notes / cleanup

- Each approval merges a grant-file PR to `main` (the git-recorded approval — by design).
- `mcp-call` deduplicates pending requests and reuses still-valid approvals automatically.
- Keycloak/RFC8693 is intentionally **not** in this path: pfSense consumes per-user opaque
  tokens, not JWTs (see ADR-0012). The real OIDC exchange is a fast-follow on echo-mcp.
- Two per-user tokens live in Vault: `secret/data/mcp-tools/mcp-tokens` (read, key `arsalan` +
  `tokens` csv consumed by pfSense) and `secret/data/mcp-tools/mcp-tokens-write` (write, key `arsalan`).
- `SPIRE_TLS_INSECURE=true` is set on ext-proc (SNO flap workaround). SVID JWT signatures
  are still cryptographically verified; only the JWKS transport TLS is skipped.
- Full working-state snapshot: `docs/runbooks/WORKING-STATE-2026-06-19.md`
