# SWOT & PoC Sign-Off Gate

## SWOT

### Strengths

- Exactly **one custom component** (`ext_proc` service); everything else is a supported vendor stack (Red Hat operators, HashiCorp, Linux Foundation agentgateway) — strong supportability story for a regulated bank context.
- Attribution everywhere: SPIFFE ID per workload, user identity downstream, ephemeral `jit-<agent>-<session>` SA in Kube audit, structured audit events in Loki, OTel trace tying request → approval → action.
- Auto-revoke is **structural** (Vault lease TTL deletes SA+RoleBinding+token), not procedural — no cron in the revocation path; Kyverno cleanup is only a backstop.
- Defense in depth: identity (SPIRE) → policy (Kyverno authz + admission) → isolation (Kata → CoCo roadmap) → network (default-deny) → human gate (Gitea PR merge).
- No credentials in etcd, git, or agent pods at any point.

### Weaknesses

- Critical path rides on immature pieces: agentgateway v1.3.0-**alpha** CRDs; RHBK RFC 7523 JWT grant is **preview**; ZTWIM is newly GA/TP depending on OCP level.
- `ext_proc` buffers MCP request bodies → per-call latency; fail-closed design means delegation-service outage halts MCP traffic.
- Large operational surface for a PoC: 6+ operators, multi-cluster GitOps.
- OSS Vault: no namespaces, no native SPIFFE auth (Enterprise-only) — JWT auth + path/policy isolation instead.
- In-memory approval state in `jit-approver` — pod restart loses pending approvals.

### Opportunities

- The JIT sub-identity + delegation mechanic is genuinely novel — reusable as the reference pattern for agentic access at Wells Fargo scale.
- CoCo manifests give a hardware-attestation roadmap with no redesign.
- Red Hat's Kagenti/AgentRuntime (H2 2026 preview) may productize parts of this — PoC positions ahead of it.
- EDA loop generalizes to any alert-driven remediation.

### Threats

- agentgateway alpha CRD churn between scaffold and demo — mitigated by pinning chart version and vendoring CRDs.
- Keycloak preview-feature instability on the RFC 7523 leg — mitigated by `mode: standard|legacy` fallback flag (ADR 0003).
- Forged webhook approvals = silent escalation — mitigated by HMAC-verified webhooks, repo allowlist, scope-from-committed-manifest, post-merge ceiling re-check.
- Credential leak via MCP response — mitigated by response-header stripping + cred-echo tests; fail-closed.

> **Note on scope drift:** The approved plan predates the decision to drop Slack. Wherever the SWOT above says "Slack/PR" or "Slack", the realized design uses **Gitea PR merge** as the sole approval channel with a mandatory HMAC-verified webhook (ADR 0005). The threat and its mitigation carry over unchanged.

---

## PoC sign-off gate

> **Must prove for PoC sign-off:** (1) no-credential-passing proven by pod inspection; (2) downstream identity = user, proven by logs; (3) JIT grant auto-revokes, proven by Kube audit; (4) every privileged action attributable to session + approval; (5) guardrails enforced (Kata, default-deny, no SA-token automount); (6) self-healing loop closes to a PR.

| # | Gate item | Status | What makes it provable |
|---|---|---|---|
| 1 | No-credential-passing proven by **pod inspection** | Designed; not yet provable at PoC stage | Proof needs deployed agent pod + pod-inspection + git/etcd scan. Blocked on full deployment. |
| 2 | Downstream identity = user, proven by **logs** | Designed; not yet provable | Proof needs pfsense-mcp deployed + upstream-log assertion showing user subject. |
| 3 | JIT grant **auto-revokes**, proven by Kube audit | Designed; not yet provable | Proof needs Vault kubernetes engine configured + Kube audit policy on + UC2 demo run. |
| 4 | Every privileged action **attributable to session + approval** | Designed; not yet provable | Proof needs full UC2 chain (Gitea PR → webhook → Vault → Kube audit) running. |
| 5 | Guardrails enforced (**Kata, default-deny, no SA-token automount**) | **Partially provable** | Static guardrail manifests + `make validate` enforce these statically. Kata scheduling requires runtime verification (nested virt already CONFIRMED on `anaeem`). |
| 6 | Self-healing loop closes to a **PR** | Designed; not yet provable | Proof needs EDA Event Stream wired + a forced denial triggering the full loop. |

### Provability roadmap

| Gate item | Unblocked by |
|---|---|
| 5 (guardrails — static portion) | Now (`make validate` + kustomize build) |
| 1 (no-cred pod inspection) | Identity core + gateway + sandbox deployed |
| 2 (downstream = user) | Gateway + pfsense-mcp deployed + upstream-log assertion |
| 3 (auto-revoke) | Vault kubernetes engine configured + UC2 demo |
| 4 (session+approval attribution) | Full UC2 chain (EDA + jit-approver + Kube audit) |
| 6 (self-healing to PR) | Observability + EDA Event Stream wired + forced denial |
