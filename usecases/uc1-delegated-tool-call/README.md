# UC1 — Delegated Tool Call

Demonstrates the end-to-end zero-trust identity forwarding flow:

```
User (arsalan) --> Keycloak token --> MCP Gateway
   --> ext-proc-delegation (identity forwarded, args hashed)
   --> pfsense-mcp / echo-mcp (sees USER identity, never agent)
```

The critical invariant: **downstream MCP servers always see the user's identity,
never the agent's SVID.** The echo-mcp server echoes back the identity it received,
providing a testable proof.

## What / Why

| Component | Role in UC1 |
|-----------|-------------|
| Keycloak realm `agentic` | Issues JWT for user `arsalan` (groups: mcp-users) |
| agentgateway | JWT validation (strict), forwards to ext-proc |
| ext-proc-delegation | Token exchange (user JWT → pfsense-mcp audience), Vault credential injection, audit log |
| Kyverno authz-server | Policy enforcement: mcp-users may only call read-only tools |
| pfsense-mcp | Firewall rules tool — backend uses Vault-injected API key |
| echo-mcp | Identity echo — proves forwarded-user is `arsalan`, not the agent |
| demo-agent pod | Kata VM, no mounted credentials (see manifests/README-pod-inspection.md) |

## Prerequisites

1. Platform stack deployed:
   - SPIRE running in `zero-trust-workload-identity-manager`
   - Keycloak running in `keycloak`, realm `agentic` configured
   - Vault unsealed in `vault`
   - agentgateway + ext-proc-delegation running in `mcp-gateway`
   - Kyverno authz-server running in `kyverno`
   - pfsense-mcp + echo-mcp running in `agentic-mcp`
   - demo-agent pod running in `agent-sandbox` (see `manifests/`)

2. `environment/.env` populated:
   ```
   DEMO_USER=arsalan
   DEMO_PASSWORD=<arsalan-password-in-keycloak>
   DEMO_CLIENT_ID=mcp-demo-client
   # Optional: DEMO_CLIENT_SECRET if client is confidential
   # Optional: DEMO_NOGROUPUSER + DEMO_NOGROUPPASSWORD for step 7 negative test
   ```

3. Keycloak client `mcp-demo-client` configured in realm `agentic`:
   - Direct Access Grants: **Enabled** (for automation/demo ROPC flow)
   - Standard Flow: Enabled (for device-flow in production)
   - Audiences mapper: `mcp-gateway`
   - Client scopes include: `openid`, `profile`, `groups`

4. User `arsalan` exists in realm `agentic` with group membership `mcp-users`.

5. For step 7 (group-stripped negative test): User `arsalan-no-groups` exists
   in realm `agentic` WITHOUT `mcp-users` group.

## Apply Order

```bash
# 1. Apply the demo agent pod (once platform is up)
kustomize build usecases/uc1-delegated-tool-call/manifests | oc apply -f -

# 2. Verify the pod is running in a Kata VM
oc get pod -n agent-sandbox -l app=demo-agent
# See manifests/README-pod-inspection.md for credential absence checks

# 3. Run the demo script
./usecases/uc1-delegated-tool-call/run.sh
```

## Dry-run (no cluster needed)

```bash
SKIP_LIVE=1 ./usecases/uc1-delegated-tool-call/run.sh
```

Validates script syntax and prints all steps with expected behavior without
making any network calls.

## Expected Output Transcript

```
[uc1] === STEP 1: Obtain user token for 'arsalan' via ROPC ===
[ok]  Token obtained for arsalan (truncated): eyJhbGciOiJSUzI1NiIsIn...
[uc1] JWT claims:
{
  "sub": "abc123-...",
  "preferred_username": "arsalan",
  "groups": ["mcp-users"],
  "aud": ["mcp-gateway"],
  "iss": "https://keycloak.apps.anaeem.na-launch.com/realms/agentic",
  ...
}

[uc1] === STEP 2: MCP initialize ===
[ok]  MCP session initialized
[ok]  ASSERT PASS: initialize returns protocolVersion

[uc1] === STEP 3: tools/list ===
[ok]  tools/list succeeded
[ok]  ASSERT PASS: tools/list returns tools array

[uc1] === STEP 4: tools/call get_firewall_rules ===
[ok]  get_firewall_rules call succeeded
[ok]  ASSERT PASS: tool call returns result

[uc1] === STEP 5: echo-mcp identity assertion ===
[ok]  ASSERT PASS: echo-mcp sees user identity (not agent) (found: arsalan)
[ok]  IDENTITY DELEGATION VERIFIED: echo-mcp saw 'arsalan' — not the agent SVID

[uc1] === STEP 6: Negative — no token -> expect HTTP 401 ===
[ok]  ASSERT PASS: no-token call rejected 401 — HTTP 401

[uc1] === STEP 7: Negative — token without mcp-users group -> expect HTTP 403 ===
[ok]  ASSERT PASS: no-group call rejected 403 — HTTP 403

[uc1] === STEP 8: Where to see audit events ===
  Loki LogQL: {app="ext-proc-delegation"} |= "session_id"
  Grafana: http://172.16.2.252:3000

[uc1] === UC1 complete ===
[ok]  All live assertions passed
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Token request fails with 401 | Wrong client_id or Direct Access Grants disabled | Enable Direct Access Grants on `mcp-demo-client` in Keycloak |
| Token request fails with 400 | Invalid username/password | Check DEMO_USER/DEMO_PASSWORD |
| MCP call returns 401 | JWT not valid for `mcp-gateway` audience | Add audiences mapper to `mcp-demo-client` |
| MCP call returns 403 | User not in `mcp-users` group | Add arsalan to `mcp-users` group in Keycloak |
| echo_identity returns agent SVID | ext-proc not forwarding user identity | Check ext-proc-delegation logs: `oc logs -n mcp-gateway deploy/ext-proc-delegation` |
| initialize fails | Gateway not reachable | Check Route: `oc get route -n mcp-gateway` |
| Step 7 skipped | Missing DEMO_NOGROUPUSER env var | Set in .env or export before running |
| Kata pod won't start | KataConfig not installed | Check: `oc get kataconfig` and `oc get runtimeclass kata` |

## Audit Event

The expected shape of the audit event emitted by ext-proc-delegation is in
`expected/audit-event.golden.json`. Tool arguments are hashed (sha256), never
logged raw — this is a non-negotiable security invariant.

To query audit events in Loki:

```logql
{app="ext-proc-delegation"} | json | caller_username = "arsalan" | decision = "allow"
```
