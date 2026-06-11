# JIT Sub-Identity — Design of Record (UC2)

This is the authoritative design for the just-in-time (JIT) scoped-access mechanism. It
realizes the approved plan's "JIT grant mechanism" section and ADR 0002. Companion docs:
[architecture.md](./architecture.md) (UC2 sequence), [threat-model.md](./threat-model.md)
(TB-E, abuse cases 1/2/4/5), [decisions/0002-jit-grant-vault-k8s-engine.md](./decisions/0002-jit-grant-vault-k8s-engine.md),
[decisions/0005-no-slack-gitea-pr-approval.md](./decisions/0005-no-slack-gitea-pr-approval.md).

---

## 1. Goal and principles

When an agent hits a denial for a privileged action, it must be able to obtain **exactly the
access it needs, for exactly as long as it needs it, only after a human approves** — with
every action attributable to a session and an approval, and the access removed automatically
at the window's end. Riskier follow-on actions are a **new request**, never a silent
in-place escalation.

Principles:

1. **Structural revocation, not procedural.** The grant's lifetime is a Vault lease TTL.
   Lease expiry *is* the revocation; there is no cron, no reconciler, no human cleanup step
   on the critical path. Kyverno cleanup is a backstop only.
2. **Approver-only issuance.** The agent can never mint its own access. Only the
   `jit-approver` service identity may call the Vault creds endpoint.
3. **Human-in-the-loop via Gitea PR.** The approval *is* a git merge. No Slack (ADR 0005).
4. **Least privilege by construction.** The ephemeral identity gets only the approved
   verbs/resources in the approved namespace(s), nothing else.
5. **Full attribution.** A uniquely named ephemeral SA flows into Kube audit; an OTel span
   ties request → approval → action → revoke.

---

## 2. Vault Kubernetes secrets-engine role `jit-scoped`

The grant is issued by Vault's **Kubernetes secrets engine** (`kubernetes/`). The role
`jit-scoped` is configured so that **reading credentials creates a namespaced, rule-scoped,
lease-bound Kubernetes identity** and **lease expiry deletes it**.

| Role field | Value / behavior | Why |
|---|---|---|
| `allowed_kubernetes_namespaces` | the approved namespace(s) only (from the merged grant manifest) | hard ceiling on blast radius — Vault refuses to mint into any other ns |
| `generated_role_rules` | the approved `verbs`/`resources`/`apiGroups` from the request scope | least privilege; the Role is generated per-grant, not pre-baked |
| `kubernetes_role_type` | `Role` (namespaced) — never `ClusterRole` in the PoC | keeps grants namespace-bounded |
| `service_account_name` (omitted) → engine generates one | engine creates `jit-<agent>-<session>` SA + Role + RoleBinding | unique, attributable identity per session |
| `token_default_ttl` / `token_max_ttl` | = the approved **window** | window expiry = lease expiry = auto-revoke |

**Auto-revoke mechanics.** When `jit-approver` reads `kubernetes/creds/jit-scoped`, Vault:
(a) creates SA `jit-<agent>-<session>`, a namespaced `Role` carrying `generated_role_rules`,
and a `RoleBinding` linking them; (b) returns a short-lived SA token; (c) tracks all three as
**lease-owned objects**. On lease expiry (or explicit revoke), Vault **deletes the SA, Role,
and RoleBinding** — the token stops working and the identity disappears. No external timer.

> OSS-Vault note (from plan / SWOT Weaknesses): OSS Vault has no namespaces and no native
> SPIFFE auth. We use `auth/jwt` bound to SPIRE OIDC + per-path policy isolation; the
> Kubernetes secrets engine is OSS-available. This is the documented OSS-compatible design.

---

## 3. Approver-only issuance (Vault policy)

```hcl
# vault policy: jit-approver  (attached to the approver's auth/jwt role)
path "kubernetes/creds/jit-scoped" {
  capabilities = ["create", "update"]   # read-to-generate
}
# The agent's auth/jwt role gets NO path to kubernetes/creds/* — it cannot self-issue.
```

- The **agent** SVID authenticates to Vault only for UC1 per-tool secrets (separate, narrow
  policy). It has **no** capability on `kubernetes/creds/*`. (Abuse case 2.)
- The **jit-approver** SVID is the *only* identity with `create`/`update` on
  `kubernetes/creds/jit-scoped`, and it only exercises it after webhook verification.

---

## 4. Gitea-PR-as-approval flow

The approval channel is a Gitea pull request; **merging the PR is the human approval act**
(ADR 0005). Notifications/audit ride PR comments (no Slack). The webhook that signals the
merge is **HMAC-mandatory**.

- jit-approver opens a PR whose committed manifest carries the **requested scope** (the
  source of truth for what will be granted — not the webhook body, which is untrusted).
- Arsalan reviews and **merges**. The merge commit's author + PR are the immutable approval
  record (non-repudiation, threat-model TB-E).
- Gitea fires a **merge webhook** (HMAC-signed) to `jit-approver :8080`.
- jit-approver **verifies HMAC + repo allowlist (`anaeem/nvidia-ida`) + merged-PR event
  type**, then **re-reads the approved scope from the committed manifest** and
  **re-validates it against the ceiling** before calling Vault. A merged-but-over-ceiling
  grant is still rejected (abuse case 4).

---

## 5. The 9-step sequence

| # | Step | Actor | Notes |
|---|---|---|---|
| 1 | **Denial** | gateway / Kyverno | Agent's privileged action is denied (fail closed) |
| 2 | **Estimate scope** | agent (SKILL.md) | `{namespace(s), verbs, resources, duration, justification}`; **scope ceiling enforced** locally before sending |
| 3 | **Request** | agent → jit-approver `/request` | jit-approver validates against ceiling; over-ceiling rejected immediately |
| 4 | **Open PR** | jit-approver → Gitea | PR carries the scoped grant manifest + estimate + paper trail |
| 5 | **Human approval** | Arsalan merges PR | the merge *is* the approval; PR/commit author recorded |
| 6 | **Webhook (HMAC)** | Gitea → jit-approver | verify HMAC + repo allowlist + merged-PR event; re-read scope from committed manifest; re-validate ceiling |
| 7 | **Mint ephemeral identity** | jit-approver → Vault `creds/jit-scoped` | Vault creates SA `jit-<agent>-<session>` + Role + RoleBinding, TTL = window; returns lease-bound token |
| 8 | **Agent acts** | agent (token via injector / tmpfs) | every Kube API call **attributed to `jit-<agent>-<session>` SA** in Kube audit |
| 9 | **Auto-revoke + summary** | Vault lease expiry; jit-approver | lease TTL deletes SA+Role+RoleBinding; jit-approver posts a **summary comment** on the PR (actions, audit refs, revoke confirmed) + audit/OTel |

---

## 6. Kyverno cleanup backstop

Structural revocation (step 9) is primary. The Kyverno cleanup policy is a **defense-in-depth
backstop** for the rare case where a Vault lease leaks (e.g., Vault crash mid-lease):

- A Kyverno `CleanupPolicy` (or TTL/label-driven cleanup) targets objects labeled
  `app.kubernetes.io/managed-by=jit` (SA/Role/RoleBinding) whose grant window has elapsed,
  and removes any that Vault failed to delete.
- It must **never** be the only path that revokes a grant — it exists solely to catch
  orphans. Any backstop deletion should raise an alert (it indicates a Vault revoke miss).

---

## 7. Promotion path — recurring grant → standing policy

When the same scoped grant recurs for the same identity, repeatedly minting JIT grants is
both noisy and a signal that the access is no longer "just in time." The promotion path:

1. jit-approver (or the audit review) detects a **recurring grant** pattern (same identity,
   same scope, N times within a window).
2. It opens a **standing-policy PR** that proposes the access as a **committed, GitOps-managed
   Role/RoleBinding** (or a Kyverno policy / Keycloak role) under `platform/` — reviewed and
   merged through the normal change process.
3. Once merged and reconciled by ArgoCD, that access is **standing** (still least-privilege,
   still attributable, but no longer per-session JIT). The JIT path stops firing for it.

This keeps JIT for genuinely exceptional access and routes durable needs through the standard,
reviewable GitOps change control — avoiding "JIT churn" masquerading as least privilege.

---

## 8. What this design proves (maps to PoC sign-off gate)

- **Gate 3 — auto-revoke proven by Kube audit:** lease expiry deletes SA+Role+RoleBinding;
  post-TTL Kube calls denied.
- **Gate 4 — attribution to session + approval:** `jit-<agent>-<session>` SA in Kube audit +
  the merged PR as the approval record + OTel span tying request→approval→action→revoke.
- **Abuse case 2 (self-issue):** Vault policy denies the agent the creds endpoint.
- **Abuse case 4 (scope creep):** ceiling + new-request rule + post-merge ceiling re-check.
- **Abuse case 1 (forged webhook):** HMAC + repo allowlist + scope read from committed manifest.
- **Abuse case 5 (stale grant):** structural revoke + Kyverno backstop.
