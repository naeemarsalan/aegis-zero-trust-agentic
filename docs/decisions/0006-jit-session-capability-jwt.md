# ADR 0006 — JIT session-capability JWT for the dangerous-tools gate

## Status

Accepted.

## Context

### Finding C3/H3 PARTIAL — the gate is closed but the positive path is unimplemented

The security review addendum (2026-06-11) graded the dangerous-tools gate **PARTIAL**:

- **C3 (PARTIAL):** The original bypass (a non-empty plain `X-JIT-Session` header) was
  eliminated.  The gate now requires a cryptographically valid `X-JIT-Session-JWT` —
  RS256-signed against the jit-approver JWKS, with `exp`/`aud`/`iss` validated and the
  requested tool inside a `tool_scope` claim.  Fail-closed direction is correct.
  BUT: nothing was minting this JWT (no jit-approver `/jwks` route, no signing code,
  no `tool_scope` claim anywhere).  Dangerous tools were permanently un-approvable.

- **H3 (PARTIAL, N2/N3):** Per-session ephemeral Vault roles fix the "advertised != enforced"
  scope problem.  BUT:
  - N2: `jit-approver.hcl` granted only `read` on `secret/data/jit/*`; jit-approver
    needs `create`/`update` to write the issuance record (KV v2 write → 403 → rollback).
    The comment also misattributed the writer as "ext-proc-delegation", which is wrong.
  - N3: The ephemeral Vault role `kubernetes/roles/jit-<session>` was never cleaned up
    by any reaper (only K8s SA/RoleBinding were deleted), causing roles to accumulate.

### Why "Vault injector at pod start" is impossible for dynamic sessions

The original idea was to use the Vault Agent sidecar injector to deliver the session JWT
and SA token to the agent pod via a pod annotation referencing `secret/data/jit/<session>`.
This does not work for JIT sessions:

1. The injector annotation is part of the pod spec, which is fixed at pod-start time.
2. The Vault Kubernetes role (`kubernetes/roles/jit-<session>`) does not exist until
   jit-approver creates it after the Gitea PR is merged.
3. There is no session-specific Vault path to reference in a static pod annotation.

This is a structural chicken-and-egg: the pod that needs the credentials has to start
before the approval that creates the Vault role.  The injector pattern works for standing
credentials (mcp-tools/pfsense, etc.) but cannot work for per-approval dynamic sessions.

### The session-capability JWT pattern

The approved design (realised in `dangerous-tools-admins-only.yaml` and the jit-approver
service) uses a **signed session-capability JWT** approach:

- jit-approver mints a short-lived RS256 JWT on issuance.
- The JWT is returned in the `GET /requests/{id}/status` response body (alongside `sa_token`)
  over the SVID-mTLS channel once `state == issued`.
- The Kyverno ext_authz policy verifies this JWT statelessly (JWKS fetch + `jwt.Decode` CEL
  builtin) — no live HTTP callback to jit-approver at gate evaluation time.
- The `tool_scope` claim contains the list of approved MCP tool names from the reviewed YAML.
- The agent presents the JWT as `X-JIT-Session-JWT`; the gateway forwards it to Kyverno
  before ext-proc runs.

## Decision

### 1. jit-approver mints the session JWT on issuance

When a session transitions to `issued`:

1. jit-approver calls `vault write kubernetes/roles/jit-<session>` (ephemeral role).
2. jit-approver calls `vault read kubernetes/creds/jit-<session>` (mint `sa_token`).
3. jit-approver mints an RS256 session-capability JWT with the following claims:

   ```json
   {
     "jti": "<session_id>",
     "sub": "<session_id>",
     "iss": "https://jit-approver.mcp-gateway.svc.cluster.local:8080",
     "aud": ["kyverno-authz"],
     "tool_scope": ["<approved MCP tool name>", ...],
     "nbf": <issuance Unix time>,
     "iat": <issuance Unix time>,
     "exp": <issuance + approved_window_seconds>
   }
   ```

   The signing key is the jit-approver's RS256 keypair; the corresponding public key(s)
   are served at `GET http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks`.

4. jit-approver writes both credentials to `secret/data/jit/<session>` (KV v2):

   ```json
   {
     "sa_token":    "<Vault-minted k8s SA token>",
     "session_jwt": "<signed RS256 JWT>",
     "expires_at":  "<RFC3339>",
     "namespace":   "<approved namespace>",
     "tool_scope":  ["<tool>", ...]
   }
   ```

   This requires `create`/`update` capability on `secret/data/jit/*` in `jit-approver.hcl`
   (N2 fix; previous policy granted only `read`; comment now correctly names jit-approver
   as the writer).

### 2. Credential delivery via /status over SVID-mTLS

`GET /requests/{id}/status` returns both `session_jwt` and `sa_token` in the response body
once `state == issued`.  The channel is the existing SVID-mTLS session between the agent
pod and jit-approver (SPIFFE mTLS).  No separate injection mechanism is needed.

The agent reads both fields and:
- For a **dangerous MCP tool call through the gateway**: sends
  `Authorization: Bearer <keycloak-token>` AND `X-JIT-Session-JWT: <session_jwt>`.
- For a **direct Kubernetes API action**: uses `sa_token` with `kubectl --token`.

### 3. Kyverno gate — stateless, fail-closed

`platform/kyverno/authz/base/dangerous-tools-admins-only.yaml` verifies `X-JIT-Session-JWT`:

```yaml
- name: jitJwks
  expression: |
    jwks.Fetch("http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks")

- name: hasValidJitSession
  expression: |
    variables.jitSessionJwtString != "" &&
    variables.decodedJitJwt.Valid &&
    ("iss" in variables.decodedJitJwt.Claims) &&
    variables.decodedJitJwt.Claims["iss"] == "https://jit-approver.mcp-gateway.svc.cluster.local:8080" &&
    ("tool_scope" in variables.decodedJitJwt.Claims) &&
    variables.decodedJitJwt.Claims["tool_scope"].exists(s, s == variables.toolName)
```

The gate is **stateless**: no live HTTP call to jit-approver per request.  The signed JWT
carries all necessary state (approved tool list, expiry).  Missing, invalid, or expired
JWT → 403.

### 4. The session JWT is the agent's own scoped capability — not a downstream credential

The no-credential-passing invariant (UC1) states that agent pods must not hold downstream
service credentials (e.g., the pfSense API key delivered via ext-proc).

The `session_jwt` is categorically different: it is the **agent's own approved capability**,
scoped to a list of tools the agent was explicitly granted permission to call, for a window the
human reviewer approved, signed by the jit-approver that orchestrates the approval flow.
Holding it does not expose a downstream service to the agent — it permits the agent to prove
its approval to the gateway layer (Kyverno).  The invariant is intact.

### 5. Vault policy fix (N2)

`platform/vault/config/jit-approver.hcl` now grants:

```hcl
path "secret/data/jit/*" {
  capabilities = ["create", "update", "read", "delete"]
}

path "secret/metadata/jit/*" {
  capabilities = ["delete"]
}
```

The previous `["read"]`-only grant prevented KV writes from completing (403), causing
issuance to roll back.  The comment now correctly identifies jit-approver (not ext-proc-
delegation) as the writer of these paths.

### 6. Ephemeral Vault role reaper (N3)

jit-approver's background reaper task, on session expiry, must:

1. Call `vault delete kubernetes/roles/jit-<session>` to remove the ephemeral role.
2. Call `vault delete secret/data/jit/<session>` (soft delete).
3. Call `vault delete secret/metadata/jit/<session>` (hard delete — ensures secret
   is unrecoverable after the window).

The jit-approver Vault policy already grants `delete` on both `kubernetes/roles/jit-*`
and `secret/data/jit/*` / `secret/metadata/jit/*`, so the capability exists.

## Consequences

### Positive

- **Stateless gate:** Kyverno verifies the session JWT cryptographically at each request
  with no live dependency on jit-approver.  A jit-approver pod restart or transient
  unavailability does not affect in-flight approved sessions (as long as the JWT is valid).

- **No injector bootstrapping problem:** Dynamic sessions do not require pod restarts or
  static annotations.  Credentials arrive in the first `/status` response that returns
  `state == issued`.

- **Invariant intact:** The session JWT is the agent's own scoped capability.  No downstream
  service credentials (pfSense, Kube API credentials from UC1) are held by agent pods.

- **Expiry is cryptographic:** A session JWT past its `exp` claim is rejected by the gate
  without any state lookup.  The gate cannot be confused by stale in-memory session data.

- **Least-privilege Vault policy:** `jit-approver.hcl` grants exactly the capabilities
  needed for the full session lifecycle — no broader KV or Kubernetes engine access.

### Neutral

- The jit-approver JWKS endpoint (`/jwks`) must be reachable from Kyverno within the
  cluster.  This is already within the same `mcp-gateway` namespace; a NetworkPolicy
  egress rule from `kyverno` to `mcp-gateway:8080` is required.

- The jit-approver RS256 signing keypair must be persisted across pod restarts (stored in
  Vault or as a Kubernetes Secret, not ephemeral in-process memory), so that JWTs issued
  before a restart remain verifiable after it.

### Negative / trade-offs

- Adds signing key management to jit-approver's responsibilities.  Key rotation requires
  updating the JWKS endpoint and allowing a brief overlap window for in-flight JWTs.

- If the reaper fails to delete `kubernetes/roles/jit-<session>`, the role accumulates
  (N3).  The Kyverno cleanup backstop (`ClusterCleanupPolicy`) only deletes K8s objects,
  not Vault roles — a gap that existed before this ADR and is not fully resolved here
  (the reaper implementation is in services/jit-approver, owned by the jit-approver agent).
  Monitoring on stale `kubernetes/roles/jit-*` entries is recommended.
