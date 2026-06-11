# UC2 — JIT Escalation (Human-in-the-Loop via Gitea PR)

Demonstrates the full just-in-time credential escalation lifecycle, including the
**signed session-capability JWT** that allows the agent to prove its approved session
to the Kyverno gateway gate statelessly (ADR 0006).

```
Agent (demo-agent Kata pod)
  |
  |--> tools/call add_firewall_rule (NO X-JIT-Session-JWT) --> 403 DENIED by Kyverno
  |
  |--> POST /requests to jit-approver (with tool_scope) --> Gitea PR created
  |
  |    [HUMAN: reviews PR, merges to approve]
  |
  |--> jit-approver webhook fires:
  |      1. vault write kubernetes/roles/jit-<session>  (ephemeral role)
  |      2. vault read  kubernetes/creds/jit-<session>  (mint sa_token)
  |      3. mint RS256 session_jwt  (tool_scope claim, signed /jwks key)
  |      4. write both to secret/data/jit/<session>  (KV v2 — N2 fix)
  |
  |--> GET /requests/{id}/status (SVID-mTLS) -> state==issued
  |      response: { session_jwt, sa_token, expires_at }
  |      NOTE: Vault injector-at-pod-start is impossible for a dynamic session
  |      (the Vault role doesn't exist until after the PR merges).
  |      Credentials are returned in the /status body over the mTLS channel.
  |      See ADR 0006.
  |
  |--> tools/call add_firewall_rule (X-JIT-Session-JWT: <session_jwt>) --> 200 OK
  |      Kyverno verifies JWT signature vs jit-approver JWKS, checks exp/aud/iss,
  |      confirms add_firewall_rule in tool_scope — stateless gate, no live callback.
  |
  |--> tools/call add_firewall_rule (NO header) --> 403 (gate still denies)
  |
  |--> oc get pods -n agent-sandbox (sa_token works)
  |--> oc get pods -n kyverno (sa_token DENIED -- scope limit)
  |      Kube audit log: system:serviceaccount:agent-sandbox:jit-<session>
  |
  |--> Token / JWT expire:
  |      session_jwt rejected by Kyverno gate (exp elapsed, decodedJitJwt.Valid=false)
  |      sa_token rejected by Kube API (Vault lease expired)
  |      jit-approver reaper: vault delete kubernetes/roles/jit-<session>  (N3 fix)
  |      jit-approver reaper: vault delete secret/data+metadata/jit/<session>
  |
  |--> POST /summary --> PR comment + Loki audit event
```

**The approval channel is Gitea PR merge — there is no Slack.** The PR body
contains the full requested scope as reviewable YAML. Merging = approve;
closing without merging = deny.

## Signed session-capability JWT mechanic

The `X-JIT-Session-JWT` is the agent's own scoped capability token — not a downstream
service credential:

| Property | Value |
|----------|-------|
| Algorithm | RS256 |
| Issuer (`iss`) | `https://jit-approver.mcp-gateway.svc.cluster.local:8080` |
| Audience (`aud`) | `kyverno-authz` |
| Subject (`sub`) | `<session_id>` (UUIDv4) |
| `tool_scope` | List of approved MCP tool names from the reviewed YAML |
| Validity | `nbf`/`iat`/`exp` aligned to the approved window |
| JWKS | `http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks` |

The Kyverno `dangerous-tools-admins-only` policy fetches the jit-approver JWKS and verifies
the JWT statelessly at each request.  No live callback to jit-approver at gate evaluation time.

**Why not Vault injector at pod start?** The Vault Kubernetes role (`kubernetes/roles/jit-<session>`)
does not exist until after the PR is merged — it is created by jit-approver as part of the
issuance step.  A pod that starts before approval has no role to reference in its annotation,
making injector-at-pod-start a chicken-and-egg problem for dynamic sessions.  Instead,
jit-approver returns both `session_jwt` and `sa_token` in the `/status` response body once
`state == issued`, over the SVID-mTLS channel.  See ADR 0006.

**Invariant preserved:** `session_jwt` is the agent's own approved capability (scoped, signed,
short-lived).  Holding it does NOT violate the no-credential-passing invariant, which targets
downstream service credentials the agent proxies via ext-proc in UC1.

## What / Why

| Component | Role in UC2 |
|-----------|-------------|
| Kyverno `dangerous-tools-admins-only` | Verifies X-JIT-Session-JWT cryptographically; denies without valid signed JWT |
| jit-approver | Validates scope ceiling, creates Gitea PR, polls for merge, calls Vault, mints session JWT, serves both credentials on /status |
| jit-approver `/jwks` | Serves RS256 public key(s) for Kyverno to verify session JWTs |
| Gitea `anaeem/nvidia-ida` | JIT approval channel — PR merge triggers webhook |
| Vault kubernetes secrets engine | Issues ephemeral per-session role + SA token, auto-revokes on lease expiry |
| Vault KV (`secret/data/jit/*`) | Stores sa_token + session_jwt for /status retrieval; reaped by jit-approver on expiry |
| jit-approver reaper | Deletes ephemeral Vault role + KV record after session expiry (N3 fix) |
| Kube API audit log | Attributes all API calls to `jit-<session-id>` SA token |

## Prerequisites

1. Platform stack deployed and healthy:
   - jit-approver running in `mcp-gateway` (`oc get deploy -n mcp-gateway jit-approver`)
   - jit-approver `/jwks` endpoint reachable from Kyverno (`http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks`)
   - Vault unsealed with Kubernetes secrets engine configured (no static `jit-scoped` role — per-session roles only)
   - Gitea webhook configured: `POST https://jit-approver.apps.anaeem.na-launch.com/webhooks/gitea`
   - demo-agent pod running in `agent-sandbox` (from UC1 manifests or UC2 manifests)
   - `dangerous-tools-admins-only` Kyverno policy deployed and active

2. `environment/.env` populated:
   ```
   DEMO_ADMIN_USER=arsalan
   DEMO_ADMIN_PASSWORD=<password>
   DEMO_CLIENT_ID=mcp-demo-client
   GITEA_URL=https://git.arsalan.io
   JIT_APPROVER_URL=https://jit-approver.apps.anaeem.na-launch.com
   ```
   User `arsalan` must be in group `mcp-admins` in Keycloak realm `agentic`.

3. Gitea prerequisites:
   - Label `jit-approval` exists in repo `anaeem/nvidia-ida`
   - Webhook configured (see platform/jit-approver/deploy/base/): `POST /webhooks/gitea`
   - User with merge permissions available for the approval step

4. Vault jit-approver policy (`platform/vault/config/jit-approver.hcl`) must grant
   `create`/`update`/`read`/`delete` on `secret/data/jit/*` (N2 fix — the approver
   writes the issuance record; ext-proc-delegation does not write this path).

## Apply Order

```bash
# 1. Apply RBAC for the demo
kustomize build usecases/uc2-jit-escalation/manifests | oc apply -f -

# 2. Verify jit-approver is reachable and /jwks is served
curl -f https://jit-approver.apps.anaeem.na-launch.com/healthz
curl -f http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks   # from within cluster

# 3. Run the demo (step 3 requires human approval in Gitea)
./usecases/uc2-jit-escalation/run.sh
```

## Dry-run (no cluster needed)

```bash
SKIP_LIVE=1 ./usecases/uc2-jit-escalation/run.sh
```

Validates script syntax and prints all steps and expected behavior without
making any network calls.  Step 3 (human approval) is indicated but skipped.

## Expected Output Transcript

```
=== STEP 0: Obtain token for 'arsalan' (mcp-admins group) ===
[ok]  Token obtained for arsalan
[uc2] Requester sub: abc123-keycloak-uuid

=== STEP 1: Attempt add_firewall_rule WITHOUT X-JIT-Session-JWT -> expect 403 ===
[ok]  ASSERT PASS: add_firewall_rule without X-JIT-Session-JWT is denied — HTTP 403
[ok]  CONFIRMED: dangerous tools require a cryptographically valid X-JIT-Session-JWT (Kyverno enforced)

=== STEP 2: POST EscalationRequest to jit-approver ===
[ok]  EscalationRequest accepted — session ID: a1b2c3d4-...
[ok]  Gitea PR created: https://git.arsalan.io/anaeem/nvidia-ida/pulls/42

=== STEP 3: HUMAN STEP — Review and merge the Gitea PR ===
[HUMAN ACTION REQUIRED] Navigate to Gitea and review the PR:
  https://git.arsalan.io/anaeem/nvidia-ida/pulls/42
  MERGE the PR to APPROVE the escalation.

=== STEP 4: Poll session status until 'issued', extract session_jwt + sa_token ===
[uc2] NOTE: credentials arrive in the /status response body over the SVID-mTLS channel.
[uc2] Attempt 1/60: state = pending
[uc2] Attempt 2/60: state = pending
[uc2] Attempt 3/60: state = approved
[uc2] Attempt 4/60: state = issued
[ok]  Session state: ISSUED
[ok]  session_jwt obtained (RS256, exp=2026-06-11T13:00:00Z)
[ok]  sa_token obtained (Vault kubernetes/creds/jit-a1b2c3d4-...)
[ok]  Credentials available until: 2026-06-11T13:00:00Z

=== STEP 5: add_firewall_rule WITH X-JIT-Session-JWT -> expect 200 (Kyverno gate passed) ===
[uc2] Response status: 200
[ok]  ASSERT PASS: add_firewall_rule WITH valid X-JIT-Session-JWT passes Kyverno gate — HTTP 200
[ok]  CONFIRMED: valid signed session JWT passes the dangerous-tools gate

=== STEP 6: add_firewall_rule WITHOUT X-JIT-Session-JWT -> still 403 ===
[uc2] Response status: 403
[ok]  ASSERT PASS: add_firewall_rule WITHOUT X-JIT-Session-JWT is still denied — HTTP 403
[ok]  CONFIRMED: missing/omitted session JWT still results in 403 — gate is fail-closed

=== STEP 7: Kube API action with sa_token -> succeeds; attribution in audit log ===
NAME           READY   STATUS    RESTARTS   AGE
demo-agent-0   1/1     Running   0          5m
[ok]  ASSERT PASS: sa_token can list pods in agent-sandbox (found: demo-agent)
[ok]  Kube API action succeeded with JIT sa_token
[uc2] Verifying scope limit: trying to list pods in 'kyverno' (should fail)
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:agent-sandbox:jit-..."
[ok]  ASSERT PASS: sa_token cannot access out-of-scope namespace (found: FORBIDDEN)
[ok]  Scope limit enforced: cannot access 'kyverno' namespace
[uc2] Audit log entries matching 'jit-a1b2c3d4': 3
[ok]  Attribution confirmed: 3 audit events attributed to jit-a1b2c3d4

=== STEP 8: After expiry: session_jwt rejected (exp elapsed) + Vault role reaped ===
[ok]  ASSERT PASS: expired session_jwt rejected by Kyverno gate — HTTP 403
[ok]  CONFIRMED: expired session_jwt is rejected (exp claim elapsed)
[ok]  ASSERT PASS: expired sa_token rejected by Kube API (Unauthorized) (found: Unauthorized)
[ok]  REVOCATION CONFIRMED: expired sa_token rejected by Kube API

=== STEP 9: POST session summary to jit-approver -> PR comment ===
[ok]  Summary recorded and posted as PR comment: https://git.arsalan.io/.../pulls/42

=== Audit Trail Summary ===
  Loki: {app="jit-approver"} | json | session_id = "a1b2c3d4-..."
  # Session JWT signed-capability mechanic (see ADR 0006)
  # JWKS: http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks

=== UC2 complete ===
[ok]  All live steps completed
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Step 1 returns 200 (not 403) | Kyverno policy not loaded or in audit mode | Check: `oc get validatingpolicy -n kyverno dangerous-tools-admins-only` |
| Step 2 POST returns 422 | Scope validation rejected | Check: namespace in JIT_ALLOWED_NAMESPACES, verbs valid, justification >= 10 chars |
| Step 2 POST returns 502 | Gitea unreachable or token invalid | Check: `GITEA_TOKEN` in jit-approver's Vault secret, Gitea connectivity |
| Poll never reaches 'issued' | Webhook not firing | Check: Gitea webhook at git.arsalan.io → Settings → Webhooks, verify URL |
| Poll never reaches 'issued' | jit-approver not receiving webhook | Check: `oc logs -n mcp-gateway deploy/jit-approver` for webhook events |
| Poll never reaches 'issued' | KV write failing (N2) | Check: `jit-approver.hcl` grants create+update on `secret/data/jit/*`; verify with `vault policy read jit-approver` |
| Step 4: session_jwt missing | jit-approver not minting JWT | Check: `/jwks` endpoint exists; jit-approver has RS256 key configured |
| Step 5: 403 despite valid JWT | JWKS unreachable from Kyverno | Check: NetworkPolicy allows Kyverno → jit-approver:8080; `curl http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks` from kyverno namespace |
| Step 5: 403 with "wrong iss" | iss claim mismatch | iss in session_jwt must match what dangerous-tools-admins-only.yaml asserts exactly |
| Step 6: 200 instead of 403 | Header accidentally included | Confirm no X-JIT-Session-JWT in step 6 curl command |
| Step 7: token rejected | Vault lease expired early | Vault revoked the lease — check Vault audit logs |
| Step 7: scope limit not working | Vault role allows all namespaces | Check `allowed_kubernetes_namespaces` in Vault role `kubernetes/roles/jit-<session>` |
| Step 8: Vault role not reaped | Reaper not implemented | jit-approver background task must call `vault delete kubernetes/roles/jit-<session>` |
| Audit step: no log hits | SNO node-logs access | Try: `oc adm node-logs anaeem-sno --path=kube-apiserver/audit.log` |

## Gitea Webhook Setup

The jit-approver webhook endpoint must be registered in Gitea:

1. Go to: `https://git.arsalan.io/anaeem/nvidia-ida/settings/hooks`
2. Add webhook:
   - URL: `https://jit-approver.apps.anaeem.na-launch.com/webhooks/gitea`
   - Content type: `application/json`
   - Secret: (matches `GITEA_WEBHOOK_SECRET` in jit-approver config)
   - Trigger: **Pull Request** events (specifically: `pull_request` merged)

## Audit Events

The expected sequence of audit events is in `expected/jit-audit-sequence.golden.json`.

Event sequence for a successful session:
```
jit_request -> jit_approved -> jit_issued -> jit_summary
```

For a denied session (PR closed without merge):
```
jit_request -> jit_denied
```

Loki queries:
```logql
# Full lifecycle
{app="jit-approver"} | json | session_id = "<SESSION_ID>"

# Only issuance events (includes session_jwt_jti)
{app="jit-approver"} | json | event = "jit_issued"

# Denials in the last 24h
{app="jit-approver"} | json | event = "jit_denied" | __error__ = ""
```

## Related decisions

- **ADR 0006** (`docs/decisions/0006-jit-session-capability-jwt.md`) — why jit-approver
  mints the session JWT, why injector-at-pod-start is impossible for dynamic sessions,
  and why the session JWT is the agent's own scoped capability (not a downstream cred).
- **ADR 0005** — Gitea PR merge as the sole approval channel (no Slack).
- **ADR 0002** — Vault Kubernetes secrets engine for per-session ephemeral roles.
