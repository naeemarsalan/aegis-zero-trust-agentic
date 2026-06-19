# ADR-0012: Real per-user split identity for pfSense MCP (two-token model)

## Status

Proposed

## Date

2026-06-18

## Context

The user requires a delegated-identity design where:

1. The agent/shell "impersonates my identity" but holds ZERO credentials.
2. A "real per-user token must flow" downstream — the downstream must see the user as a distinct principal, not a generic service account.
3. **Read and write identity must be split** — baseline grants read; write requires a distinct, separately-approved elevation. The downstream/audit should reflect this distinction.
4. The design must be reliable and testable by hand on the live spoke.
5. pfSense is the ONLY target for now.

### Key technical facts grounding this decision

**pfSense-MCP does not validate JWTs.** The upstream `gensecaihq/pfsense-mcp-server` validates an opaque bearer token against a comma-separated `MCP_API_KEY` list loaded from Vault (`secret/data/mcp-tools/mcp-tokens`). A Keycloak-minted JWT is meaningless to pfSense — the per-user opaque token is what makes pfSense attribute calls to the user.

**ext-proc already injects the per-user pfSense token** keyed by username from Vault on the SVID/sandbox path (`server.go:750-765`). The Keycloak RFC 8693 `ExchangeOnBehalf` result is audit-only on this path (non-fatal when it fails).

**Keycloak naked-impersonation is a confirmed dead end.** The live RHBK 26.6.3 NPE (`UserPermissionsV2.canImpersonate`, `keycloak#40328`, closed WONTFIX) blocks naked impersonation (`requested_subject` without `subject_token`). Standard RFC 8693 v2 token-exchange **requires** a real user `subject_token`, which the agent never holds. A newer Keycloak removes naked impersonation rather than fixing it.

**ext-proc already enforces JIT write-elevation in-process** (`server.go:639-687`). When a jit-approver session JWT is present, ext-proc verifies it against the jit-approver JWKS, asserts `sandbox_uid == svid.sandbox_uid` (the session is cryptographically bound to THIS sandbox), and requires the tool be listed in `tool_scope`. This is fail-closed.

**The Kyverno `dangerous-tools-admins-only` gate is redundant and broken.** Its NetworkPolicy lacks egress to jit-approver:8080, so the JWKS fetch is dropped and JIT-elevated writes are permanently 403 at the Kyverno layer. Since ext-proc already does the identical JIT check, removing the Kyverno gate simplifies the stack without reducing security.

### The no-credential-passing invariant

The platform invariant is: **no credential (token, password, API key, SVID) may flow from one component to another through memory, environment variables, RPC arguments, or agent context.** Permitted flows are:

- Vault Agent Injector writing to tmpfs (consumed by that pod only).
- Kubernetes projected SA tokens (consumed by that pod only).
- RFC 8693 token exchange at the gateway (original credential never forwarded; new scoped token issued).
- SPIRE Workload API SVIDs (consumed by the workload that requested them).

Any design that routes a credential through an agent's context window, an MCP tool argument, or a message queue violates this invariant.

## Decision

### Recommended design: Two per-user pfSense tokens (read and write)

Provision **two opaque pfSense tokens per user** in Vault:

| Vault path | Key | Purpose |
|------------|-----|---------|
| `secret/data/mcp-tools/mcp-tokens` | `<username>` | Read-only baseline token |
| `secret/data/mcp-tools/mcp-tokens-write` | `<username>` | Write-capable token |

**ext-proc selects the token based on JIT elevation status:**

- **No JIT session JWT or invalid session:** inject the read-only token (`mcp-tokens/<user>`).
- **Valid, sandbox-bound, tool-scoped JIT session JWT:** inject the write token (`mcp-tokens-write/<user>`).

pfSense sees **different tokens for read vs write** — the split is real and visible in pfSense's audit log (different principal/scope). This is the cleanest way to satisfy "split identity" when the downstream consumes opaque tokens.

### Why not one token + ext-proc scope enforcement only?

A single-token design relies entirely on ext-proc to block writes. If ext-proc is bypassed (misconfiguration, bug, or future refactor), a read-scoped agent could issue writes. With two tokens, pfSense itself enforces the split — defense in depth. The downstream audit unambiguously shows which scope was active.

### Why drop Keycloak from the pfSense path?

For pfSense, the Keycloak RFC 8693 exchange buys **nothing**: pfSense ignores JWTs and validates only its opaque bearer list. Fixing the Keycloak NPE would restore the audit-only exchange (useful for proving the pattern works), but it does not change the actual downstream credential. Keycloak is already non-fatal/audit-only on the static-auth path; this ADR formalizes that as the intended design, not a fallback.

**Optional:** demonstrate genuine RFC 8693 v2 exchange against a JWT-aware target (echo-mcp already exists and echoes the principal) to prove the OIDC pattern works — without blocking the pfSense loop. This is secondary and does not affect the pfSense identity flow.

### Remove the redundant Kyverno gate

Delete the `dangerous-tools-admins-only` ValidatingPolicy and its NetworkPolicy egress rule. ext-proc's in-process JIT verification is the single source of truth for dangerous-tool authorization. This eliminates a broken redundant gate (JWKS fetch dropped by NetworkPolicy) and simplifies the auth chain.

## READ flow (baseline)

1. Agent calls gateway with its **SPIRE JWT-SVID only** (no downstream credential in agent env/args).
2. Gateway routes to ext-proc.
3. ext-proc verifies SVID (SPIRE OIDC JWKS, iss=spire-oidc, aud=mcp-gateway).
4. ext-proc reads Vault grant at `secret/data/sandbox-grants/<svid.sandbox_uid>`.
5. ext-proc validates: TTL, sandbox_uid match, scope (read-only permits read tools).
6. ext-proc fetches read-only token from `secret/data/mcp-tools/mcp-tokens` keyed by `grant.user`.
7. ext-proc injects `Authorization: Bearer <read-token>` into downstream request.
8. pfSense validates token, attributes call to `grant.user`, returns result.
9. Audit emits: `caller_username=<user>, grant_result=valid, jit_elevated=false, decision=allow`.

## WRITE flow (JIT-elevated)

1. Agent requests write tool (e.g., `create_firewall_rule_advanced`) — denied 403 (`grant_scope_denied`).
2. jit-approver creates Gitea PR (branch `jit/<session-id>`, label `jit-approval`).
3. Human merges PR. Gitea webhook fires; jit-approver mints sandbox-bound session JWT with `sandbox_uid=<svid.sandbox_uid>`, `tool_scope=["create_firewall_rule_advanced"]`.
4. Agent retries with `X-JIT-Session-JWT: <jwt>` header.
5. ext-proc verifies session JWT (jit-approver JWKS, iss, aud, exp, sandbox_uid match, tool in scope).
6. ext-proc fetches **write token** from `secret/data/mcp-tools/mcp-tokens-write` keyed by `grant.user`.
7. ext-proc injects `Authorization: Bearer <write-token>` into downstream request.
8. pfSense validates token, attributes call to `grant.user` (write scope), returns result.
9. Audit emits: `caller_username=<user>, grant_result=valid, jit_elevated=true, jit_session_id=<id>, decision=allow`.

## No-credential-passing analysis

| Credential | Where it lives | Lifetime | Who consumes it | Agent access |
|------------|----------------|----------|-----------------|--------------|
| SPIRE SVID | `/spiffe-workload-api` socket in pod | 60 min (SPIRE TTL) | ext-proc (for verification) | Agent presents it; cannot extract it from sandbox |
| Vault grant | Vault KV-v2 | 3600 s (platform cap) | ext-proc reads; never forwarded | None |
| pfSense read token | Vault KV-v2, loaded into ext-proc memory on demand | ext-proc caches per-request | ext-proc injects to pfSense | None |
| pfSense write token | Vault KV-v2, loaded into ext-proc memory on demand | ext-proc caches per-request | ext-proc injects to pfSense only when JIT-elevated | None |
| JIT session JWT | jit-approver mints; agent presents | 60 min (session TTL) | ext-proc verifies; agent holds | Agent holds this (by design) — it is the agent's own approved capability, not a downstream credential |

**Invariant satisfied:** The agent never holds a pfSense token, Vault token, or Keycloak credential. The only token the agent holds is the JIT session JWT, which is the agent's own approved capability (scoped, signed, short-lived) — not a downstream service credential. The pfSense tokens transit only from Vault to ext-proc memory to the downstream request; they never enter the agent's context window.

## Consequences

### Positive

- **Real per-user identity downstream:** pfSense sees the user's token (not a generic service account) — each user is auditable as a distinct principal.
- **Real read/write split downstream:** pfSense sees different tokens for read vs write — the scope distinction is visible in pfSense's own audit, not just in ext-proc.
- **Defense in depth:** Even if ext-proc scope enforcement is bypassed, pfSense itself enforces the read/write split (a read token cannot issue writes if pfSense is configured to recognize read-vs-write tokens).
- **Keycloak failure is non-fatal:** The pfSense path does not depend on Keycloak token exchange. The exchange can be restored later for audit enrichment without blocking the critical path.
- **Simpler auth chain:** Removing the broken Kyverno gate eliminates a source of permanent 403s and reduces moving parts.
- **Testable by hand:** The journey is sit-down-drivable with `mcp-call` from the harness pod and the jit-approver Gitea PR flow.

### Negative / trade-offs

- **Two tokens per user:** Provisioning overhead (Vault bootstrap must create both tokens per user). Acceptable for the PoC scope.
- **pfSense must recognize the split:** If pfSense is configured with a single combined token list, the split is only ext-proc-enforced. To get defense-in-depth, pfSense must be configured to accept read tokens for read calls and write tokens for write calls. (For PoC, ext-proc enforcement is sufficient; the split is still visible in audit.)
- **Keycloak exchange not exercised on pfSense path:** Demonstrating genuine RFC 8693 requires a JWT-aware target (echo-mcp). This is secondary.

### Security implications

- **No-credential-passing invariant:** Satisfied. The agent never holds a pfSense credential. The JIT session JWT is explicitly permitted (it is the agent's own capability, not a downstream credential).
- **Kyverno gate removal:** Safe because ext-proc's in-process JIT verification is identical in logic (same JWKS, same iss/aud, same sandbox_uid binding, same tool_scope check). The Kyverno gate was a redundant second gate that was broken by NetworkPolicy; removing it does not widen access.
- **Keycloak exchange audit-only:** The live audit records `keycloak_result=exchange_5xx` when the exchange fails, preserving visibility. This is an audit gap (no exchanged JWT to inspect), not an authorization gap.

## Alternatives considered

| Option | Rejected because |
|--------|------------------|
| **Single pfSense token per user + ext-proc scope enforcement only** | No defense in depth; downstream audit cannot distinguish read vs write; relies entirely on ext-proc correctness. |
| **Fix Keycloak naked-impersonation for pfSense** | pfSense does not validate JWTs; the exchange buys nothing for pfSense. The Keycloak NPE is a known bug (keycloak#40328, WONTFIX); newer Keycloak removes naked impersonation rather than fixing it. |
| **Use Keycloak standard RFC 8693 v2 (with subject_token)** | Requires the agent to hold a real user JWT as subject_token — violates no-credential-passing. |
| **Keep the Kyverno dangerous-tools-admins-only gate** | It is broken (NetworkPolicy blocks JWKS fetch); it is redundant (ext-proc does the same check); it adds latency and failure modes. |
| **Wait for OpenShell native provider_spiffe** | Blocked by OCP/CRI-O setns EPERM (ADR-0011 disproof); Variant-B + ext-proc is the standing decision. |

## Code and manifest changes required

### ext-proc-delegation (`services/ext-proc-delegation/`)

1. **`internal/config/config.go`:** Add `StaticTokenSecretWrite string` (default `"mcp-tokens-write"`).
2. **`internal/extproc/server.go` (~line 752):** When `jitElevatesTool == true`, fetch from `s.cfg.StaticTokenSecretWrite` instead of `s.cfg.StaticTokenSecret`.
3. **Unit tests:** Update `extproc_stream_test.go` to cover the two-token selection logic.

### Kyverno (`platform/kyverno/`)

1. **Delete `platform/kyverno/authz/base/dangerous-tools-admins-only.yaml`.**
2. **Update `platform/kyverno/authz/base/kustomization.yaml`:** Remove the resource reference.
3. **Delete or update `platform/networkpolicies/base/np-kyverno.yaml`:** Remove the `allow-egress-jit-approver-jwks` NetworkPolicy (no longer needed).

### Vault bootstrap (`environment/` or operator docs)

1. **Provision `secret/data/mcp-tools/mcp-tokens-write` with per-user write tokens** (same structure as `mcp-tokens`, but these tokens grant write scope in pfSense).
2. **Document the two-token convention** in `services/pfsense-mcp-server/README.md`.

### Optional (secondary target)

- **echo-mcp:** No changes needed; it already echoes the JWT principal. Use it to demonstrate genuine RFC 8693 v2 exchange once Keycloak is fixed or a different IdP is added.

## Open questions

1. **pfSense server-side scope enforcement:** Does pfSense's `MCP_API_KEY` validation support distinguishing read-vs-write tokens, or must the upstream server be patched to recognize two token lists? For PoC, ext-proc enforcement is sufficient; defense-in-depth can be deferred.
2. **Keycloak audit-only exchange:** Should the failing exchange be disabled entirely (save latency) or kept (preserve audit visibility for future JWT-aware targets)? Current recommendation: keep it audit-only.
