# ADR 0002 — JIT grants via Vault Kubernetes secrets engine

**Status:** Accepted

---

## Context

UC2 requires just-in-time, time-boxed, least-privilege Kubernetes access that is granted only after a human approval and **removed automatically** when its window ends, with every action attributable to the grant. Revocation must be reliable even if a controller crashes — a missed cron or reconcile must not leave standing elevated access.

Options considered:

- (a) A custom operator that creates SA/Role/RoleBinding and a TTL controller that deletes them
- (b) cert-manager-style short-lived certificates
- (c) **Vault Kubernetes secrets engine** issuing the identity with a lease whose expiry deletes the objects

---

## Decision

Use the **Vault Kubernetes secrets engine** with a role `jit-scoped`. Reading `kubernetes/creds/jit-scoped` makes Vault create a `jit-<agent>-<session>` ServiceAccount + namespaced Role (`generated_role_rules` = approved scope) + RoleBinding, scoped to `allowed_kubernetes_namespaces`, with token TTL = the approved window. **Lease expiry deletes all three objects** — revocation is structural, owned by Vault, with no cron on the critical path.

Only the `jit-approver` service identity may call the creds endpoint (Vault policy); the agent can never self-issue. Kyverno cleanup is a backstop for orphaned leases only.

---

## Consequences

- **Auto-revoke is a property of the lease**, not of a controller we have to keep healthy — provable via Kube audit (sign-off gate 3).
- No custom JIT operator to build or maintain; the engine is OSS-Vault-available.
- Per-grant Role generation means least privilege is exact, not approximated by pre-baked roles.
- **OSS-Vault constraints** (no namespaces, no native SPIFFE auth) are handled by `auth/jwt` bound to SPIRE OIDC + per-path policy isolation.
- Vault becomes a hard dependency on the UC2 critical path; a Vault outage stops new JIT grants (fail-closed). HA documented for production; single-replica raft on SNO for the PoC.
- The Kyverno cleanup backstop must alert when it fires (a firing indicates a Vault revoke miss), and must never be the sole revocation path.
