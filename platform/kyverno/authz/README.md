# platform/kyverno/authz

## What

Deploys the Kyverno Envoy authz server (`kyverno-authz-server`) into the `kyverno` namespace on the anaeem cluster, plus four `ValidatingPolicy` resources that run in Envoy mode to enforce authentication and authorization on every MCP tool call routed through agentgateway.

Image: `ghcr.io/kyverno/kyverno-envoy-plugin:v0.3.0`
Source: https://github.com/kyverno/kyverno-envoy-plugin (latest stable 2025-10-06)

## Why

The agentgateway ext_authz filter calls `kyverno-authz-server.kyverno.svc.cluster.local:9081` (gRPC) before forwarding any MCP request to downstream servers.  Kyverno evaluates CEL policies against the Envoy `CheckRequest` and returns allow/deny with HTTP status codes.  This enforces:

- JWT authentication against the Keycloak `agentic` realm JWKS
- Group-based tool allowlisting for `mcp-users` (read-only pfSense tools only)
- JIT session requirement for write/dangerous tools (`mcp-admins` + `X-JIT-Session` header)
- Hard block for identities in the `restricted` group

## Policies

| File | Purpose | Default deny |
|---|---|---|
| `no-unauthenticated-calls.yaml` | Valid Bearer JWT required (except OPTIONS + `/.well-known/*`); group must be `mcp-users` or `mcp-admins`; `decodedJwt.Valid` asserted before trusting any claim | 401 |
| `tool-allowlist-mcp-users.yaml` | `mcp-users` may only call `get_firewall_rules`, `get_interfaces`, `get_dhcp_leases`; `decodedJwt.Valid` asserted (H4) | 403 |
| `dangerous-tools-admins-only.yaml` | Write tools require `mcp-admins` group (validated JWT) AND a cryptographically verified `X-JIT-Session-JWT`; plain non-empty string is NOT accepted (C3) | 403 |
| `deny-restricted-group.yaml` | `restricted` group members are unconditionally blocked; invalid/malformed tokens also denied fail-closed (H4) | 403 |

## JIT session verification — C3 design

**Problem:** kyverno-envoy-plugin v0.3.0 CEL mode does not expose an `http.Get()` / `apiCall`
primitive that can reach cluster-internal endpoints at policy evaluation time.  Therefore the
previous pattern of checking `X-JIT-Session != ""` (a non-empty string) was the only gate —
any `mcp-admins` member could supply an arbitrary header value and clear the gate.

**Solution:** Signed session JWT (`X-JIT-Session-JWT`).

When jit-approver transitions a session to `issued` it mints a short-lived JWT containing:

```json
{
  "jti": "<session-id>",
  "sub": "<user-sub>",
  "tool_scope": ["<approved-tool>", ...],
  "iss": "https://jit-approver.mcp-gateway.svc.cluster.local:8080",
  "aud": "kyverno-authz",
  "iat": <now>,
  "exp": <now + approved_duration>
}
```

ext-proc injects this JWT as the `X-JIT-Session-JWT` header.  The Kyverno policy:

1. Fetches the jit-approver JWKS from `http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks`.
2. Calls `jwt.Decode(jitSessionJwtString, jitJwks)` — signature and expiry are verified.
3. Asserts `decodedJitJwt.Valid == true` (not expired, not before, audience correct).
4. Asserts `iss == "https://jit-approver.mcp-gateway.svc.cluster.local:8080"`.
5. Asserts `tool_scope` claim contains the requested tool name.

A missing, empty, or invalid `X-JIT-Session-JWT` causes `hasValidJitSession = false` → 403.
The old plain `X-JIT-Session` header is no longer checked.

## decodedJwt.Valid precondition — H4

All four group-check policies now gate every `Claims[...]` access behind
`variables.decodedJwt.Valid && variables.jwtString != ""`.  An expired, not-yet-valid, or
audience-mismatched token that nonetheless yields populated `.Claims` from `jwt.Decode` is
treated as unauthenticated.  `deny-restricted-group` additionally introduces an explicit
`isTokenInvalid` variable and denies when the token did not validate (fail-closed for the
hard-block path).

## Apply order

1. Kyverno operator must be installed in the `kyverno` namespace (via `platform/00-operators`).
2. Keycloak must be running and realm `agentic` initialized (JWKS reachable at `https://keycloak.apps.ocp-dev.na-launch.com/realms/agentic/protocol/openid-connect/certs`).
3. Apply this component:
   ```bash
   kustomize build platform/kyverno/authz/overlays/anaeem | oc apply -f -
   ```
4. Or apply via the aggregating overlay:
   ```bash
   kustomize build platform/kyverno/overlays/anaeem | oc apply -f -
   ```

## Verify

```bash
# Authz server pod running
oc get pods -n kyverno -l app.kubernetes.io/name=kyverno-authz-server

# Service endpoint matches contract
oc get svc kyverno-authz-server -n kyverno

# ValidatingPolicies loaded
oc get validatingpolicies -n kyverno

# Test: unauthenticated request should get 401 from agentgateway
curl -s -o /dev/null -w "%{http_code}" \
  https://mcp-gateway.apps.ocp-dev.na-launch.com/mcp \
  -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_firewall_rules","arguments":{}}}'
# Expected: 401

# Test: mcp-users token calling allowed tool → 200
MCP_TOKEN=$(curl -s -X POST \
  https://keycloak.apps.ocp-dev.na-launch.com/realms/agentic/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=mcp-gateway&username=<mcp-user>&password=<pw>' \
  | jq -r .access_token)
curl -s -o /dev/null -w "%{http_code}" \
  https://mcp-gateway.apps.ocp-dev.na-launch.com/mcp \
  -X POST -H "Authorization: Bearer ${MCP_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_firewall_rules","arguments":{}}}'
# Expected: 200
```
