# ADR-0014 — Operation-shaped JIT capability TTLs via session-JWT/SA-token decoupling

> **Part of:** [Master Plan — OpenShell Agentic Platform](../plans/openshell-agentic-platform-master-plan.md) → **Phase B (JIT/token system)**, Loop B1.

**Status:** Proposed — design agreed 2026-06-20; implementation pending

## Context

The JIT plane currently couples two unrelated TTLs:

1. **Capability TTL** — how long the human-approved authorization is valid (the window within which the agent may invoke the approved tool).
2. **Kubernetes SA-token TTL** — how long the Vault-issued ServiceAccount token lives (set via Vault kubernetes engine `token_default_ttl`).

Both derive from the same `EscalationRequest.duration_minutes` value (`models.py:86`, Annotated `ge=10`). The floor of 10 minutes exists because Kubernetes TokenRequest hard-rejects any `expirationSeconds < 600` (validation.go `MinTokenAgeSec`, KEP-1205). This floor is industry-universal: AWS STS rejects sub-900s; Entra PIM is hour-granular; k8s SA tokens cannot be individually revoked.

**Problem:** a one-shot mutating write (scale a deployment, create a firewall rule) should NOT carry a 10-minute reuse window. A 5-minute capability is appropriate for interactive troubleshooting; a one-shot write should be single-use. The 10-minute floor is an artifact of k8s token plumbing, not a security requirement for the capability itself.

**Existing enforcement guarantees this is safe to decouple:**
- jit-gate decodes the session JWT with `require: ['exp']` and checks `tool_scope` (`gate.py:52-74`); it never reads the SA-token TTL.
- `mcp-call` presents only the session JWT (`X-JIT-Session-JWT` header, `mcp-call:159`); it never uses `sa_token` for the gated MCP path — the Vault SA token is vestigial on the Kagenti/jit-gate path.
- The k8s-mcp-edit backend's sole ingress is jit-gate-k8s — NetworkPolicy `allow-ingress-edit-from-gate` (`services/jit-gate/deploy/jit-gate-k8s.yaml`): `podSelector app=k8s-mcp-edit` ⇐ ingress `from app=jit-gate-k8s` only; the namespace default-deny is Kyverno-auto-injected (`platform/k8s-mcp/base/networkpolicies.yaml` header). The SA token cannot be used to bypass the gate. (Verified live: `k8s-mcp-edit` ingress is from `app=jit-gate-k8s` only.)

**External grounding:**
- Kubernetes TokenRequest hard-rejects `expirationSeconds < 600` — not a silent clamp-up (KEP-1205, `pkg/apis/authentication/validation/validation.go`, PR #63999). The extend-to-1-year path applies only to kube-apiserver-audience tokens; Vault's non-apiserver audience hits only the 600s floor.
- The canonical fix is DECOUPLE: Teleport/SPIFFE issue 5-min JWT-SVIDs; Red Hat's agentic zero-trust design uses short JWTs at the app layer + longer X.509 SVIDs at transport (https://next.redhat.com/2026/06/10/wiring-zero-trust-identity-for-ai-agents-spiffe-token-exchange-and-kagenti/).
- True single-use = jti consume-on-use at the gate (DPoP RFC 9449 section 11.1: "a single-use check provides very strong protection against replay"). A 5-min reuse window permits N writes.
- Per-operation capability tokens 60-300s, authz enforced at the tool server/sidecar, never in the prompt (SuperTokens agent-auth guidance, OWASP LLM Top 10 2025).

## Decision

### 1. Introduce a per-operation capability TTL (drives session-JWT `exp` only)

`signing.mint_session_jwt` (`signing.py:275-321`) sets `exp = issued_at + duration_minutes * 60` (`signing.py:300`). The capability TTL is derived SERVER-SIDE from the operation class (never from a client-supplied duration):

| Operation class | Capability TTL | Reuse policy |
|-----------------|---------------|--------------|
| One-shot mutating writes (`resources_scale`, `resources_create_or_update`, `create_firewall_rule_advanced`, `add_firewall_rule`) | 5 minutes | Single-use (jti consumed) |
| Interactive session (`pods_exec`, `pods_run`) | 30 minutes | Reuse-window (jti not consumed) |

The operation class is derived from the (verb, resource) or `tool_scope` already computed in `signing.tool_scope_for` (`signing.py:231-251`).

The Vault SA-token mint is clamped to `max(10min, capability_ttl)` to satisfy the k8s 600s floor. Relax the session-JWT duration validation floor in `models.py:86` from `ge=10` to `ge=1` (or remove the floor entirely from the JWT path); keep a separate `>= 10min` clamp ONLY on the SA mint path (`vault.py:175, 189-211`).

`expires_at` returned to the agent in `/requests/{id}/status` = the session-JWT `exp` (the real capability window), not the SA-token lease.

### 2. jti consume-on-use for single-use class

The session JWT already carries `jti = session_id` (`signing.py:305`). For single-use-class tools, jit-gate atomically consumes the jti before authorizing:

```sql
INSERT INTO consumed_jti (jti, tool, consumed_at)
VALUES ($1, $2, now())
ON CONFLICT DO NOTHING;
```

If `rowcount == 0`, the proof was already used: deny with JSON-RPC error code `-32001` and reason `capability already consumed`.

**CNPG-backed from the start:** RFC 9449 notes that single-use checks are multi-server-unsafe if state is in-process. jit-gate may run multi-replica; the consumed-jti table MUST be CNPG (same cluster as the L0/L1 mint-gate work, `platform/jit-approver-db/`). Reuse the mint-gate branch's CNPG connection/migration pattern (`docs/plans/jit-approval-replacement-implementation.md:107-108`).

**Migration:** add table `consumed_jti(jti TEXT PRIMARY KEY, tool TEXT NOT NULL, consumed_at TIMESTAMPTZ NOT NULL DEFAULT now())` via the same `postInitApplicationSQLRefs` schema ConfigMap pattern. Periodic reaper (or TTL-based auto-expiry) prunes rows older than the max capability TTL (30 min) to bound table size.

### 3. SA-token remains a coarse outer backstop

The Vault SA token lease is clamped to `max(10min, capability_ttl)`. A consumed-but-unexpired SA token stays live-but-gate-unusable until the lease/reaper expires. This is safe ONLY because jit-gate-k8s is the SOLE NetworkPolicy-enforced ingress to k8s-mcp-edit (`allow-ingress-edit-from-gate` in `services/jit-gate/deploy/jit-gate-k8s.yaml`). No component holding an SA token can reach the k8s-edit backend without passing jit-gate.

**Residual:** the SA token cannot be individually revoked (k8s TokenRequest limitation). Optionally clamp the SA lease to the 10-min floor always (the capability TTL already limits real reuse); or rely on the Vault reaper (`vault.py:405-429`) + role deletion.

### 4. Implementation touch-points

| File | Change |
|------|--------|
| `models.py:86` | Relax `duration_minutes` floor to `ge=1` for session-JWT; add separate SA-token-floor clamp |
| `signing.py` | Add `operation_class_for(tool_scope) -> "single_use" | "reuse_window"`; set `exp` per class |
| `vault.py:175,189-211` | Clamp SA-token TTL to `max(600, capability_ttl_seconds)` |
| `gate.py` | Before allowing a single-use-class tool, atomic INSERT to `consumed_jti`; deny on rowcount 0 |
| `mcp-call` | No change (already uses session_jwt only) |
| `platform/jit-approver-db/` | Migration: `consumed_jti` table |
| NetworkPolicy | jit-gate egress to CNPG (new) |
| jit-gate deployment | `DATABASE_URL` secretKeyRef (same pattern as mint-gate L0) |

**Security review required:** before merging, a security-review pass must verify the consume-on-use path, the NetworkPolicy change, and the CNPG credential injection.

## Consequences

### Positive

- **Operation-shaped capability windows:** one-shot writes get 5-min single-use; interactive sessions get 30-min reuse — matches the operation's risk profile.
- **True single-use for mutating writes:** jti consume-on-use blocks replay even within the 5-min window (industry-standard, per RFC 9449).
- **No-credential-passing invariant PRESERVED:** the agent still holds only its SVID + the short capability JWT; it never holds the SA token. The JWT is the agent's own approved capability (explicitly permitted by the invariant), not a downstream credential. Verified: `mcp-call` reads only `session_jwt` (`mcp-call:159,256`) and never uses `sa_token`.
- **Multi-replica safe:** CNPG-backed consume-check is atomic across jit-gate replicas.
- **Defense in depth:** the SA-token NetworkPolicy isolation (jit-gate-k8s sole ingress) contains a leaked/replayed SA token; the capability JWT is the real authz gate.

### Negative / trade-offs

- **CNPG dependency for jit-gate:** jit-gate now requires DB access (connection + credentials + NetworkPolicy egress). Adds an init-time failure mode if CNPG is unreachable (fail-closed).
- **Standing SA-token window:** a consumed capability leaves the SA token live-but-gate-unusable for up to 10 minutes. This is contained by NetworkPolicy; document the residual.
- **Table growth:** `consumed_jti` grows with each single-use invocation. Mitigate with TTL-based pruning (rows older than 30 min are safe to delete).

### Security implications

- **No-credential-passing invariant:** PRESERVED. The agent never holds the SA token; it presents only the session JWT. This is unchanged from the current design.
- **Replay protection:** single-use jti consume-on-use closes the N-writes-in-5-min gap for one-shot operations.
- **NetworkPolicy containment:** the k8s-mcp-edit upstream is unreachable without passing jit-gate; a consumed-but-unexpired SA token cannot bypass the gate.
- **CNPG credential handling:** `DATABASE_URL` arrives via CNPG-generated `secretKeyRef` (same pattern as keycloak-db-app, mint-gate L0); no DSN in git.

## Alternatives considered

| Option | Rejected because |
|--------|------------------|
| Lower `duration_minutes` to 5 globally | Kubernetes TokenRequest hard-rejects `expirationSeconds < 600`; the SA mint fails. |
| Flat 10-min floor for everything (no decouple) | Too loose for one-shot writes; no true single-use; a 10-min window permits N replays. |
| 5-min reuse window without jti consume | Industry treats a reuse window as a deliberate weakness (RFC 9449); permits N writes within the window. |
| In-process consume-set (no CNPG) | Multi-replica unsafe; a replayed request hitting a different replica bypasses the check. |

## References

- KEP-1205 Bound Service Account Tokens: https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/1205-bound-service-account-tokens/README.md
- Kubernetes CSI TokenRequest (documents 600s floor): https://kubernetes-csi.github.io/docs/token-requests.html
- AWS STS AssumeRole (900s floor): https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- RFC 9449 DPoP section 11.1 (single-use check): https://www.rfc-editor.org/rfc/rfc9449.html
- Red Hat agentic zero-trust (SVID + short JWT split): https://next.redhat.com/2026/06/10/wiring-zero-trust-identity-for-ai-agents-spiffe-token-exchange-and-kagenti/
- Teleport JWT-SVIDs (5-min TTL pattern): https://goteleport.com/docs/machine-workload-identity/workload-identity/jwt-svids/
- Macaroons (seconds-scale time caveats): https://theory.stanford.edu/~ataly/Papers/macaroons.pdf
- SuperTokens agent auth: https://supertokens.com/blog/auth-for-ai-agents
- OWASP LLM Top 10 2025 (per-operation capability tokens)
- Code refs: `gate.py:52-74`, `signing.py:275-321,300,305`, `vault.py:175,189-211`, `models.py:86`, `mcp-call:159`; edit-isolation NP `allow-ingress-edit-from-gate` in `services/jit-gate/deploy/jit-gate-k8s.yaml` (view ingress is `platform/k8s-mcp/base/networkpolicies.yaml:33-39`)
- Mint-gate L0/L1 CNPG pattern: `docs/plans/jit-approval-replacement-implementation.md:107-108`
- Full prior-art research + cited evidence: `docs/research/2026-06-20-jit-short-lived-capability-ttl-prior-art.md`
