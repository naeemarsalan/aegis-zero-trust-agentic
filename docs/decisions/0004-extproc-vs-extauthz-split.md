# ADR 0004 — extProc vs extAuthz responsibility split

## Status

Accepted.

## Context

The agentgateway data path has two distinct extension points that could each, in principle,
"see" a request and influence it:

- **`extAuthz`** — Envoy external authorization. A boolean **allow/deny** decision made
  *before* the request proceeds. Designed to gate access.
- **`extProc`** — Envoy external processing. A bidirectional stream that can **read and mutate**
  headers/body. Designed to transform requests/responses.

If the same component did both authorization and mutation, a mutation filter could
inadvertently (or maliciously) become an access-granting path, and the policy decision would be
entangled with credential injection — bad for both auditability and least privilege.

We have two distinct needs: (1) **tool RBAC** — decide whether *this identity* may call *this
tool* (allow/deny); (2) **credential delegation** — swap the agent identity for the user's
downstream credential (mutation). These must not be conflated.

## Decision

Split the two responsibilities across the two extension points:

- **Kyverno** runs as the **`extAuthz`** server (Envoy-mode `ValidatingPolicy`, CEL tool RBAC)
  at `kyverno-authz-server.kyverno.svc.cluster.local:9081`. It owns **allow/deny only**. It
  cannot mutate the request.
- **`ext-proc-delegation`** runs as the **`extProc`** filter at
  `ext-proc-delegation.mcp-gateway.svc.cluster.local:9000`. It owns **mutation only** (token
  exchange, secret fetch, header inject, response strip). It makes **no** access decision.

Ordering: `extAuthz` (Kyverno) runs **before** `extProc` (delegation) — access is decided
before any credential is minted, so the delegation service never exchanges a token for a call
that policy would deny. Both filters are **required** and **fail closed**.

## Consequences

- **Clean separation of concerns / least privilege:** the mutation path cannot grant access;
  the authz path cannot leak or mint credentials. Neither can substitute for the other.
- **Auditability:** policy decisions (Kyverno PolicyReports) and delegation events
  (ext_proc audit) are separately attributable.
- **Defense in depth:** an attacker who compromises the mutation filter still cannot bypass
  Kyverno's allow/deny, and vice versa.
- The gateway config must wire **both** filters in the correct order; tests must prove that a
  Kyverno DENY short-circuits *before* any Keycloak/Vault call happens (no token minted on a
  denied request).
- Kyverno policy is authored/maintained as Envoy-mode `ValidatingPolicy` CEL (opus-reviewed);
  delegation logic stays in the Go service (ADR 0001).
