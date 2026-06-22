# ADR-0007: Console-side Mint Gate replaces PR-merge approval (closes M5)

**Status:** Accepted  
**Date:** 2026-06-19  
**Loop:** L1 (feat/jit-mint-gate-L0-L1)  
**Supersedes:** the approval-decision portion of ADR-0005 (no-slack-gitea-pr-approval)

---

## Context

ADR-0005 moved approval from Slack to a Gitea PR merge triggered by the
approval-console.  The approver identity (`merged_by`) was captured from the
Gitea webhook payload but was **never compared to the requester's identity**
(`requester_sub`), leaving the M5 self-approval gap: a requester could approve
their own JIT session by triggering the Gitea PR merge themselves.

Additionally, the approval path relied on a shared `GITEA_TOKEN` to merge PRs
— a service-level credential that does not carry individual approver identity.

## Decision

Introduce a new authenticated endpoint `POST /requests/{id}/mint` in
jit-approver that:

1. Authenticates the caller as the **approval-console service** (not an agent),
   using mTLS SPIFFE SVID (production) or Kubernetes SA TokenReview (interim).
2. Accepts `{approver_sub, scope_hash}` in the request body.
3. Enforces `approver_sub != requester_sub` **before any state change or Vault
   call** (fail-closed, closes M5).
4. Verifies `scope_hash == canonical_scope_hash(stored_req)` to prevent TOCTOU
   scope substitution.
5. Performs the once-only `pending -> issued` flip via the shared
   `mint_core._atomic_issue()` path.
6. Calls the unchanged `vault.issue_credentials()` path.

The approval-console's `approve()` handler is rewritten to POST to `/mint`
instead of merging the Gitea PR, carrying the Keycloak identity resolved by
`_actor()` (from oauth2-proxy X-Forwarded-Preferred-Username) as `approver_sub`.

**The Gitea PR + webhook stay live in parallel** as a diffable audit mirror.
The webhook path is also routed through `mint_core._atomic_issue()` and the M5
SoD check, so both paths share a single issuance code path and cannot drift.

## Caller Authentication (SPIFFE/mTLS vs Interim TokenReview)

**Decision (locked):** `/mint` authenticates the caller as the console service
via mTLS using its SPIFFE SVID.  The jit-approver extracts the peer SPIFFE ID
from the verified client cert and checks it against
`JIT_MINT_ALLOWED_SPIFFE_IDS`.

**Interim (current PoC, `JIT_MINT_REQUIRE_MTLS=false`):** The
console and jit-approver pods on this hop do not yet have SPIRE-issued SVIDs
wired for client-cert mTLS termination.  As an interim enforced caller-check
(so `/mint` is **never open** to unauthenticated callers), the console sends its
projected Kubernetes ServiceAccount token in `X-Console-SA-Token` and the
jit-approver validates it via the Kubernetes TokenReview API.  Agent-sandbox
pods do not have the console SA token and are rejected.

**Live mTLS items (explicit on-cluster verify tasks):**
- Register the `approval-console` workload in SPIRE (SpiffeID
  `spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/approval-console`).
- Configure envoy/SPIRE proxy on both pods to perform mutual TLS with the SVID
  and pass `X-Peer-Spiffe-Id` to the jit-approver handler.
- Set `JIT_MINT_REQUIRE_MTLS=true` and
  `JIT_MINT_ALLOWED_SPIFFE_IDS=spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/approval-console`
  once the SPIRE registrations are live.

## Feature Flags

| Service          | Flag                    | Default | Effect when off                         |
|------------------|-------------------------|---------|-----------------------------------------|
| jit-approver     | `JIT_MINT_GATE_ENABLED` | `true`  | `/mint` returns 503                     |
| approval-console | `JIT_APPROVE_VIA_MINT`  | `true`  | `approve()` reverts to Gitea PR merge   |

Both flags default on once the test suites are green.  Setting either to
`false` is a one-flag rollback to the legacy PR-merge path (which remains live
as the webhook git mirror throughout L1).

## Approver Identity Trust

`approver_sub` is populated from `_actor(request)` in the console, which reads
`X-Forwarded-Preferred-Username` injected by oauth2-proxy (server-trusted
Keycloak claim).  It is **never** accepted from a field the requesting agent or
browser controls.

## Scope Hash / TOCTOU

`canonical_scope_hash(req)` serialises the ceiling-relevant fields
(`namespace`, sorted verbs, sorted resources, `duration_minutes`, `sandbox`,
sorted `host:port` policy_delta) as canonical JSON and SHA-256 hexes them.
The console computes the same hash over the detail it fetched; the mint handler
recomputes from the stored `EscalationRequest` and rejects on mismatch (409).
This prevents a scope mutation between the approver's view and the issuance.

Both implementations (`jit_approver.models.canonical_scope_hash` and
`approval_console.app._canonical_scope_hash`) are cross-checked in the test
suite to guarantee identical output.

## Audit

`audit.emit_approved(session_id, approver_sub, pr_number)` is emitted from
`mint_core._atomic_issue()` for both the `/mint` path and the webhook path.
The `merged_by` field in the audit log carries `approver_sub` for both paths.
A `jit_denied` event is emitted on any SoD violation.

## Consequences

- **Closes M5:** a requester can no longer approve their own request.
- **Removes GITEA_TOKEN from the approval path:** the console no longer needs
  the shared Gitea service token to approve; it is still needed for PR creation
  (POST /requests → `create_approval_pr`).
- **Single issuance code path:** `mint_core._atomic_issue()` is called by both
  the console (`/mint`) and the webhook, so the M5 check lives in one place.
- **Once-only guarantee preserved:** both paths contend on the same
  `store_lock + _TERMINAL_STATES` atomic flip.
- **Vault/signing/ext-proc unchanged:** the Vault lease, RS256 session JWT,
  JWKS, and ext-proc per-call enforcement are downstream of `issue_credentials()`
  and are not touched by this change.
- **Rollback is a flag flip:** set `JIT_APPROVE_VIA_MINT=false` and
  `JIT_MINT_GATE_ENABLED=false`; the legacy webhook path is always live.

## Deferred

- Live mTLS handshake + SPIRE registration for the console→jit-approver hop
  (recorded as on-cluster verify items above).
- Hash-chained WORM ledger entries for mint decisions (L2).
- Dual-control (two distinct approver_subs for dangerous tier) (L3).
- Fast-lane auto-approval (L4).
