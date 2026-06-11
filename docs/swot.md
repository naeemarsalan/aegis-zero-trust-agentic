# SWOT & PoC Sign-Off Gate

The SWOT and the six-point sign-off gate below are copied **verbatim** from the approved plan
(`/home/anaeem/.claude/plans/binary-petting-marble.md`, "Step 0 — SWOT"). The only addition is
the **Status** column on the sign-off gate, tracking what is provable today (2026-06-11, at
the architecture/design stage — before any platform component is deployed).

---

## SWOT (verbatim from approved plan)

**Strengths**
- Exactly **one custom component** (ext_proc service); everything else is supported vendor stack (RH operators, HashiCorp, LF agentgateway) — strong supportability story for a bank.
- Attribution everywhere: SPIFFE ID per workload, user identity downstream, ephemeral `jit-<agent>-<session>` SA in Kube audit, structured audit events in Loki, OTel trace tying request→approval→action.
- Auto-revoke is **structural** (Vault lease TTL deletes SA+RoleBinding+token), not procedural — no cron in the revocation path; Kyverno cleanup is only a backstop.
- Defense in depth: identity (SPIRE) → policy (Kyverno authz + admission) → isolation (Kata→CoCo) → network (default-deny) → human gate (Slack/PR).
- No credentials in etcd, git, or agent pods at any point.

**Weaknesses**
- Critical path rides on immature pieces: agentgateway v1.3.0-**alpha** CRDs; RHBK RFC 7523 JWT grant is **preview**; ZTWIM is newly GA/TP depending on OCP level.
- ext_proc buffers MCP request bodies → per-call latency; fail-closed design means delegation-service outage halts MCP traffic.
- Large operational surface for a PoC: 6+ operators, multi-cluster GitOps.
- OSS Vault: no namespaces, no native SPIFFE auth (Enterprise-only) — JWT auth + path/policy isolation instead.

**Opportunities**
- The JIT sub-identity + delegation mechanic is genuinely novel — reusable as the reference pattern for agentic access at Wells Fargo scale.
- CoCo manifests give a hardware-attestation roadmap with no redesign.
- Red Hat's Kagenti/AgentRuntime (H2 2026 preview) may productize parts of this — PoC positions you ahead of it.
- EDA loop generalizes to any alert-driven remediation.

**Threats**
- agentgateway alpha CRD churn between scaffold and demo (mitigate: pin chart, vendor CRDs).
- Keycloak preview-feature instability on the impersonation leg (mitigate: `mode: standard|legacy` fallback flag in the service — ADR 0003).
- Forged Slack approvals = silent escalation (mitigate: HMAC-verified callbacks, security-reviewer gate).
- Credential leak via MCP response (mitigate: response-header stripping + tests; fail closed).

> **Note (scope drift since approval):** the approved plan predates the user's decision to drop
> Slack. Wherever the SWOT above says "Slack/PR" or "Slack", the realized design uses the
> **Gitea PR merge** as the sole approval channel with a **mandatory HMAC-verified webhook**
> (ADR 0005). The threat ("Forged Slack approvals = silent escalation") and its mitigation
> ("HMAC-verified callbacks") carry over unchanged to the Gitea webhook — see
> [threat-model.md](./threat-model.md) abuse case 1.

---

## PoC sign-off gate (verbatim) + Status

> **Must prove for PoC sign-off:** (1) no-credential-passing proven by pod inspection; (2) downstream identity = user, proven by logs; (3) JIT grant auto-revokes, proven by Kube audit; (4) every privileged action attributable to session + approval; (5) guardrails enforced (Kata, default-deny, no SA-token automount); (6) self-healing loop closes to a PR.

| # | Gate item (verbatim) | Status (2026-06-11) | What makes it provable |
|---|---|---|---|
| 1 | no-credential-passing proven by **pod inspection** | **Designed, not yet provable** | Invariant + per-boundary preservation documented (threat-model §3). Proof needs the deployed agent pod + `make validate` pod-inspection + git/etcd scan. Blocked on Phase 2–5 deploy. |
| 2 | downstream identity = user, proven by **logs** | **Designed, not yet provable** | UC1 sequence (architecture §3) ends in RFC 8693 user-audience token + agent-SVID clear. Proof needs pfsense-mcp deployed + upstream-log assertion. Blocked on Phase 3–5. |
| 3 | JIT grant **auto-revokes**, proven by Kube audit | **Designed, not yet provable** | Structural lease-TTL revoke specified (jit-sub-identity.md, ADR 0002). Proof needs Vault kubernetes engine configured + Kube audit policy on. Blocked on Phase 2 (Vault) + UC2 demo. |
| 4 | every privileged action **attributable to session + approval** | **Designed, not yet provable** | `jit-<agent>-<session>` SA + OTel request→approval→action span specified. Proof needs the full UC2 chain (Gitea PR → webhook → Vault → Kube audit) running. Blocked on Phase 7–8. |
| 5 | guardrails enforced (**Kata, default-deny, no SA-token automount**) | **Partially provable at scaffold time** | Kata runtimeClass, default-deny NetworkPolicies, and `automountServiceAccountToken: false` are static manifest facts → enforceable now via `kustomize build` + kyverno-json/chainsaw guardrail tests. Runtime enforcement (Kata actually scheduling, nested-virt confirmed) is provable on cluster — nested virt already CONFIRMED on anaeem. |
| 6 | self-healing loop closes to a **PR** | **Designed, not yet provable** | EDA path (denial → AlertManager → Event Stream HMAC → rulebook → job template → Gitea PR) specified across architecture/threat-model. Proof needs AAP Event Stream wired + a forced denial. Blocked on Phase 6–7. |

**Summary.** At the architecture stage, item **5** is the only gate item with any scaffold-time
provability (static guardrail manifests + kyverno-json/chainsaw tests, and nested-virt already
confirmed for Kata). Items 1–4 and 6 are fully **designed** with explicit proof hooks but
require deployment of the identity core, gateway, and EDA loop before they move from "designed"
to "provable." No gate item is unaccounted for or unmitigated.

**Provability roadmap (which phase unblocks each item):**

| Gate item | Unblocked by phase (from plan) |
|---|---|
| 5 (guardrails — static portion) | Now (Phase 0 manifests + tests) |
| 1 (no-cred pod inspection) | Phase 2–5 (identity core + gateway + sandbox) |
| 2 (downstream = user) | Phase 3–5 (gateway + RHOAI MCP) |
| 3 (auto-revoke) | Phase 2 + UC2 (Vault k8s engine + demo) |
| 4 (session+approval attribution) | Phase 7–8 (EDA + UC2 verification) |
| 6 (self-healing to PR) | Phase 6–7 (observability + EDA) |
