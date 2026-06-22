# Master Plan Review — OpenShell Agentic Platform

**Date:** 2026-06-20
**Reviewer:** Claude (Architect role)
**Document under review:** `/home/anaeem/nvidia-ida/docs/plans/openshell-agentic-platform-master-plan.md`
**Status:** The master plan requires significant corrections following the Phase A root-cause resolution.

---

## Executive Summary

The master plan is architecturally sound in its vision and sequencing, but **substantial portions are now stale** after the 2026-06-20 root-cause correction that identified `CAP_SYS_CHROOT` (not SELinux) as the setns-EPERM cause. The plan references a custom SELinux domain `openshell_sandbox_t` and Security Profiles Operator delivery that were never needed and have been deleted. Additionally, there is critical **git-vs-live drift** (kata vs runc runtimeClass, provider_spiffe on in git but off live) that must be resolved before Phase A can complete. The "block on OpenShell-native first" sequencing remains correct, but Phase B work (JIT TTL, mint-gate) is legitimately parallelizable and should not be held back.

**Key findings:**
1. **15+ stale references** to SELinux domains/SPO/MachineConfig that no longer exist
2. **Live helm drift:** rev6 = `kata` + no `providerTokenGrants`, git = `runc` + `spiffe.enabled: true`
3. **Gate-2 label mismatch confirmed:** ClusterSPIFFEID selects `openshell.ai/managed-by`, pods carry `agents.x-k8s.io/sandbox-name-hash` only
4. **CAP_SYS_CHROOT granted but not yet effective:** existing pods lack it (predating the Kyverno mutate); new pods post-enablement will have it
5. **Missing egress NetworkPolicy on `openshell` namespace** creates lateral-movement risk
6. **Phase B/C have false dependencies** on Phase A completion; code authoring should proceed in parallel

---

## 1. Alignment: Stale References After the Phase-A Root-Cause Correction

The master plan still describes the Phase A fix as requiring a custom SELinux domain. This is incorrect after ADR-0017's rewrite. The actual fix is a single Kyverno mutate that appends `CAP_SYS_CHROOT`.

### Stale text in the master plan (exact edits needed)

| Location | Current (stale) text | Correction |
|----------|---------------------|------------|
| Line 20 (vision) | "all under a custom **confined** SELinux domain" | DELETE "custom confined SELinux domain" -> "under `container_t` SELinux confinement (MCS intact)" |
| Line 33 (Identity runtime) | "`openshell_sandbox_t` SELinux domain" | DELETE `openshell_sandbox_t` -> "`container_t`" |
| Line 40-41 (Composition rule) | "reaffirmed by ADR-0017" | ADD clarification that ADR-0017 was REWRITTEN after initial SELinux conclusion was overturned |
| Line 49 (Thread table) | "Root cause PROVEN (SELinux `container_t`)" | REPLACE with "Root cause PROVEN (`CAP_SYS_CHROOT` missing - NOT SELinux); fix = Kyverno mutate" |
| Line 68-69 (Phase A goal) | "runs end-to-end on a **confined** custom SELinux domain" | REPLACE with "runs on `container_t` (confined, MCS intact) with `CAP_SYS_CHROOT` granted" |
| Lines 70-72 (Loop A1) | Entire A1 describes SELinux domain build, SPO, Kyverno SELinux mutate | DELETE A1 entirely; REPLACE with single step: "Apply Kyverno `mutate-openshell-sandbox-syschroot.yaml` (DONE 2026-06-20)" |
| Line 82 (Phase A exit) | "in an OpenShell `openshell_sandbox_t` sandbox" | REPLACE with "in an OpenShell sandbox (`container_t`, `CAP_SYS_CHROOT` granted)" |
| Line 109-111 (touch-points) | `selinux/openshell-sandbox.cil`, SPO SelinuxProfile/raw-CIL CR, `mutate-openshell-sandbox-selinux.yaml` | DELETE SELinux refs; REPLACE with "Kyverno `mutate-openshell-sandbox-syschroot.yaml` (appends `SYS_CHROOT`)" |
| Line 143-144 (DoD) | "`openshell_sandbox_t`" | REPLACE with "`container_t` + `SYS_CHROOT`" |

### Stale/contradictory text in phase-A-openshell-native-loops.md

The Phase A loops doc has an accurate CORRECTED banner (lines 1-10) but still contains the full obsolete Loop A1 body (lines 27-60) describing SELinux module installation. This is confusing.

| Location | Issue | Fix |
|----------|-------|-----|
| Lines 17-24 (authored artifacts table) | Lists `.cil`, MachineConfig, SPO, SELinux mutate files | DELETE entire table; these artifacts were deleted |
| Lines 27-60 (Loop A1 body) | Full SELinux module workflow | DELETE or collapse to "OBSOLETE - see CORRECTED banner" |
| Line 13 (goal) | Still says "confined `openshell_sandbox_t` domain" | UPDATE to "`container_t` (confined, MCS) with `CAP_SYS_CHROOT`" |

### Stale text in ADR-0011 superseded banner

| Location | Issue | Fix |
|----------|-------|-----|
| Lines 5-9 (ADR-0011 banner) | Says fix is "custom confined SELinux domain `openshell_sandbox_t`, delivered via SPO + Kyverno" | UPDATE to "fix is Kyverno mutate granting `CAP_SYS_CHROOT` (ADR-0017); sandbox remains `container_t`" |

### Runbook (phaseA-userns-cap-diagnostic.md)

The RESOLVED banner at line 3 is correct. The historical SELinux/userns framing (lines 15-60) is labeled correctly as "historical" and "DISPROVED". No change needed.

---

## 2. Soundness of Sequencing: False Dependencies Identified

The master plan states (line 60): "Code for B can be *written* during A, but B integration/test and all of C are gated on Phase A being green."

### What genuinely depends on Phase A

- **Loop B3 (short-lived token minting integrated):** Requires native `provider_spiffe` for the agent to receive an SVID, so the token-exchange flow works. TRUE dependency.
- **Loop A4 (hybrid acceptance):** The whole test. TRUE dependency.
- **Loop C1-C5:** Agent/session model, webshell attachment, etc. require working sandboxes. TRUE dependency.

### What does NOT depend on Phase A (parallelizable)

| Item | Why it is independent |
|------|----------------------|
| **ADR-0014 implementation (operation-shaped TTL)** | Purely jit-approver/jit-gate code. The `consumed_jti` table, JWT exp derivation, and CNPG migration are internal to the JIT service. Can be written, tested, and deployed on the existing ext-proc path WITHOUT native `provider_spiffe`. |
| **Mint-gate L0/L1 deployment (branch feat/jit-mint-gate-L0-L1)** | The console->jit-approver `/mint` flow uses existing session infrastructure. The blockers listed in the handoff (cluster context, system:auth-delegator RBAC) are deployment prereqs, NOT Phase A dependencies. |
| **L2 LEDGER, L3 DUAL-CONTROL, L5 DECOMMISSION** | Pure audit/policy work in jit-approver. |
| **Skills repo creation (C3 partial)** | Creating the Gitea `skills` repo, seeding it from existing `.claude/skills`, and building the UI picker can proceed. The loading mechanism (clone into sandbox) depends on working sandboxes, but the repo/UI does not. |

### Recommendation

Update the plan to explicitly list Phase B loops that can proceed in parallel:
- B1 (operation-shaped TTL implementation)
- B2 (mint-gate deployment) minus L4/FAST-LANE which depends on Kyverno-envoy-plugin
- L2/L3/L5 of the mint-gate roadmap

Revise line 60 to: "B1, B2 (L0-L3, L5), and partial C3 (skills repo/UI) may proceed in parallel with A. B3 and full C integration are gated on Phase A green."

---

## 3. Security Posture: CAP_SYS_CHROOT Grant and Compensating Controls

### Analysis of the CAP_SYS_CHROOT grant

ADR-0017 correctly identifies `CAP_SYS_CHROOT` as a narrow, well-understood capability. The sandbox already runs as root with `CAP_SYS_ADMIN`, so the marginal increase is small.

**Residual risks:**
1. `chroot(2)` escape: with `SYS_ADMIN` the sandbox can already `pivot_root`/`unshare(CLONE_NEWNS)`, so `SYS_CHROOT` adds no meaningful new capability. ACCEPTABLE.
2. Abuse by malicious agent code: the agent runs as a non-root user inside the sandbox (the supervisor is root); the agent cannot invoke `chroot()` without root. ACCEPTABLE.

**No-credential-passing invariant:** PRESERVED. The capability grant affects syscall permissions, not credential flows. The supervisor fetches the SVID in its original mount namespace, hides it, returns; the agent never touches the socket. Env-strip and tmpfs hide are unchanged.

### Missing compensating controls (CRITICAL GAPS)

| Gap | Severity | Current state | Required |
|-----|----------|---------------|----------|
| **Egress NetworkPolicy on `openshell` namespace** | HIGH | Only ingress NP exists (`openshell-sandbox-ssh`). No egress restrictions. | Add a deny-all-egress + allow-only-required baseline. Agent sandboxes should only reach `kube-dns`, the MCP gateway, and possibly the LiteLLM proxy. |
| **Existing sandboxes lack SYS_CHROOT** | MEDIUM | Kyverno mutate applied 2026-06-20T01:50:12Z but existing pods (created 4-6 days ago) were not mutated. Verified live: `agent-arsalan-04ba52` has `[SYS_ADMIN,NET_ADMIN,SYS_PTRACE,SYSLOG]` only. | After helm upgrade with provider_spiffe enabled, sandboxes will restart and pick up the mutate. Explicitly confirm this in the verify step. |
| **CAP_NET_ADMIN grant on sandboxes** | LOW | Listed in ADR-0017 "compensating controls" as "consider dropping". | Evaluate whether the supervisor/agent actually needs `NET_ADMIN`. If not, add a Kyverno drop-cap rule. |

### kata -> runc switch implications

The git values file specifies `runtimeClassName: ""` (runc); live helm rev6 uses `kata`. Implications:

| Factor | kata (live) | runc (git) | Security delta |
|--------|-------------|------------|----------------|
| Isolation | Micro-VM boundary | Linux namespaces only | runc weaker isolation; compensate with tighter NP + PSA |
| SPIFFE socket access | CSI volume cannot cross VM boundary; native delegation broken | CSI volume works; native delegation viable | Required for Phase A |
| Performance | Higher overhead | Lower overhead | N/A to security |
| Node impact | kata-containers runtime required | Default CRI-O | N/A |

**Verdict:** The switch to runc is mandatory for native `provider_spiffe` (the whole point of Phase A). Compensate with:
1. Egress NetworkPolicy (missing)
2. Ensure Pod Security Admission at `restricted` level for the namespace (verify)
3. Seccomp profile remains `RuntimeDefault` (verify)

---

## 4. Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|------------|--------|------------|
| R1 | **Gateway-wide provider_spiffe restart** disrupts all sandboxes | HIGH (100% on enable) | MEDIUM (brief outage) | Pre-communicate; teardown non-essential sandboxes; etcd already defragged (728MB). Documented in plan. |
| R2 | **Gate-2 SVID label mismatch** - ClusterSPIFFEID selects `openshell.ai/managed-by` but pods have `agents.x-k8s.io/sandbox-name-hash` only | HIGH (confirmed live) | HIGH (sandboxes get no SVID; entire delegation broken) | OpenShell stamps `openshell.ai/*` only when provider_spiffe enabled. Verify after helm upgrade; if not stamped, either (a) realign ClusterSPIFFEID to `agents.x-k8s.io/*` and use Kyverno to stamp `openshell.ai/sandbox-id`, or (b) configure OpenShell to stamp regardless. |
| R3 | **Git-vs-live drift** (kata+no-spiffe live vs runc+spiffe git) | HIGH (observed now) | HIGH (helm upgrade is multi-change; risk of partial apply) | Run `helm diff upgrade` before apply; verify all changes; consider staged approach (runtimeClass first, then provider_spiffe). |
| R4 | **Branch sprawl** - `feat/jit-mint-gate-L0-L1` (uncommitted), `backup/e2e-delegated-zero-trust`, plus 20+ `jit/*` branches | MEDIUM | MEDIUM (merge conflicts, stale code) | Converge: commit mint-gate branch, merge into main or a unified feature branch; prune stale `jit/*` remotes. |
| R5 | **Mint-gate missing system:auth-delegator RBAC** | HIGH (documented in handoff) | HIGH (all `/mint` calls fail on-cluster) | Add `ClusterRoleBinding` before deploying mint-gate. |
| R6 | **Existing sandboxes lack SYS_CHROOT** - mutate only fires at CREATE | MEDIUM | MEDIUM (helm upgrade restarts will fix) | Document expected behavior; verify post-upgrade. |
| R7 | **Missing egress NetworkPolicy in openshell namespace** | HIGH (none exists) | HIGH (agent could exfiltrate to arbitrary destinations) | Create before production use. |
| R8 | **L4 FAST-LANE blocked on kyverno-envoy-plugin upgrade** | HIGH (documented) | LOW (ext-proc remains sole enforcer) | Keep ext-proc as authoritative; do not fast-lane until plugin upgrade. |
| R9 | **Kyverno at 0 replicas (parked)** | MEDIUM (per memory) | HIGH (no mutates/validates fire) | Re-enable before any policy-dependent work. Verify etcd can handle. |

---

## 5. Gaps and Missing Pieces

### Not addressed in the master plan

| Gap | Severity | Notes |
|-----|----------|-------|
| **Per-agent Gitea repo lifecycle** | MEDIUM | Plan says "Open decision: repo cleanup policy." No concrete design. Suggest: soft-delete on agent archive (rename + make private); hard-delete 30 days after archive; access via per-agent deploy key. |
| **Skills load mechanism** | MEDIUM | Plan says "init-container `git clone` into writable `.claude/skills` emptyDir" as one option. Recommend this approach (simplest, GitOps-aligned). Document the volume mounts needed. |
| **Webshell tech choice** | LOW | Plan lists "OpenShell's own webshell vs ttyd/wetty". Recommend ttyd (lightweight, proven, Keycloak-gatable via oauth2-proxy). |
| **Observability** | HIGH | No mention of metrics, tracing, or alerting. Sandboxes should emit metrics (agent tool invocations, approval latency); JIT flows should be traced (correlation ID from approval-console to jit-approver to jit-gate to upstream). Use existing Loki for logs; add Tempo spans. |
| **Testing strategy** | HIGH | Only mentions `hack/test-openshell-native-hybrid.sh`. Need: unit test coverage gates; integration test suite for JIT flows; chaos testing (revoke mid-session, network partition). |
| **Disaster recovery** | MEDIUM | CNPG WORM audit is mentioned, but no DR export procedure. CNPG barman backup + offsite sync recommended. |
| **Multi-cluster** | LOW | Plan is SNO-centric. Multi-cluster SPIFFE federation (already referenced in ADR-0013) should be called out as Phase D/E. |

### Artifacts referenced but not present in repo

| Artifact | Referenced in | Status |
|----------|---------------|--------|
| `platform/openshell/selinux/openshell-sandbox.cil` | master-plan line 109, phase-A line 18 | DELETED (correct - was never needed) |
| `platform/openshell/selinux/99-master-openshell-sandbox-selinux.yaml` | phase-A line 19 | DELETED |
| `platform/openshell/selinux/spo-rawselinuxprofile.yaml` | phase-A line 20 | DELETED |
| `platform/kyverno/guardrails/base/mutate-openshell-sandbox-selinux.yaml` | phase-A line 21 | DELETED (different from `-syschroot.yaml` which exists) |
| `hack/test-openshell-native-hybrid.sh` | master-plan line 81, phase-A line 114 | NOT YET CREATED |

---

## 6. Recommended Document Adjustments (Prioritized Checklist)

### Immediate (before proceeding with Phase A enablement)

- [ ] **master-plan.md:** Remove all `openshell_sandbox_t` references (lines 20, 33, 68, 82, 143); replace with `container_t + SYS_CHROOT`
- [ ] **master-plan.md:** Delete Loop A1 SELinux domain content (lines 70-72); replace with single completed step
- [ ] **master-plan.md:** Update Thread table (line 49) to reflect correct root cause
- [ ] **master-plan.md:** Delete SELinux touch-points (lines 109-111); add `mutate-openshell-sandbox-syschroot.yaml`
- [ ] **master-plan.md:** Update Composition rule (lines 40-41) to note ADR-0017 rewrite
- [ ] **phase-A-openshell-native-loops.md:** Delete obsolete artifacts table (lines 17-24)
- [ ] **phase-A-openshell-native-loops.md:** Delete or collapse Loop A1 body (lines 27-60)
- [ ] **ADR-0011 banner (lines 5-9):** Correct the superseded text to reference SYS_CHROOT, not SELinux

### Before helm upgrade (Phase A enablement)

- [ ] **Run and capture `helm diff upgrade`:** document the full delta before applying
- [ ] **Create egress NetworkPolicy** for `openshell` namespace (deny-all + allow kube-dns, mcp-gateway, LiteLLM)
- [ ] **Verify Kyverno is running** (currently parked at 0 replicas per memory)
- [ ] **Pre-tear-down** non-essential sandboxes to reduce blast radius

### Before Phase B deployment

- [ ] **Add system:auth-delegator ClusterRoleBinding** for jit-approver SA
- [ ] **Commit mint-gate branch** (`feat/jit-mint-gate-L0-L1`)
- [ ] **Fix cluster context** in local kubeconfig for live e2e test
- [ ] **Create ADR for parallel work decision** (B1/B2/partial-C3 can proceed during A)

### Documentation debt (can be addressed during execution)

- [ ] **Create observability section** in master plan (metrics, tracing, alerting)
- [ ] **Create testing strategy section** in master plan
- [ ] **Resolve open decision #1** (Gate-2 label fix shape) - recommend realign ClusterSPIFFEID to `agents.x-k8s.io/*`
- [ ] **Resolve open decision #3** (skills load) - recommend init-container git clone to emptyDir
- [ ] **Resolve open decision #4** (webshell tech) - recommend ttyd
- [ ] **Document per-agent repo lifecycle** (retention, cleanup, access scoping)

---

## Appendix: Live Cluster State Snapshot (2026-06-20)

```
# Helm release
NAME       REVISION  STATUS    CHART              runtimeClassName (LIVE)
openshell  6         deployed  helm-chart-0.0.62  kata

# Git values-openshift.yaml
sandbox.runtimeClassName: ""  (runc)
providerTokenGrants.spiffe.enabled: true

# Kyverno mutate applied
mutate-openshell-sandbox-syschroot: 2026-06-20T01:50:12Z

# Sample sandbox pod capabilities (created before mutate)
agent-arsalan-04ba52: [SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYSLOG]  # NO SYS_CHROOT

# Sample sandbox pod labels
agent-arsalan-04ba52: agents.x-k8s.io/sandbox-name-hash=39bc7d52  # NO openshell.ai/*

# ClusterSPIFFEID selector
openshell-sandbox-workloads: matchLabels: openshell.ai/managed-by=openshell  # MISMATCH

# NetworkPolicies in openshell
openshell-sandbox-ssh (ingress only) - NO EGRESS POLICY
```

---

## Resolution status (appended 2026-06-22)

This review is a point-in-time snapshot (2026-06-20). Findings below were acted on; status reflects the
canonical worklog `phaseA-delegation-worklog-and-issues-2026-06-20.md` and ADR-0017/0018.

| # | Finding (review) | Status | What happened |
|---|---|---|---|
| 1 | 15+ stale SELinux / `openshell_sandbox_t` references | ✅ RESOLVED | Master plan, Phase-A loop doc, ADR-0017, runbook all corrected. Real root cause = missing `CAP_SYS_CHROOT` (not SELinux); the custom-domain plan was dropped. |
| 2 | git↔live drift (live kata + provider_spiffe off; git runc + on) | ✅ RESOLVED | `helm upgrade` → rev 7: runc + `provider_spiffe` ENABLED live; gateway healthy. |
| 3 | Gate-2 SVID label mismatch (CSID vs pod labels) | ✅ RESOLVED (ADR-0018) | Two defects fixed in `cluster-spiffe-ids.yaml`: (a) CSID had **no `className`** → the class-gated controller ignored it; (b) 0.0.62 stamps the UUID as the **`openshell.io/sandbox-id` annotation**, not `openshell.ai/*` labels. Now selects on `agents.x-k8s.io/sandbox-name-hash` + templates off the annotation; later split into **two CSIDs** (SA-shaped for the Kagenti plane, UUID-shaped for ext-proc). 7/7 entries; proven. |
| 4 | Missing egress NetworkPolicy in `openshell` | ✅ RESOLVED | Egress NP applied. The earlier "DNS broke" was **my wrong rule** — OVN-K CoreDNS listens on **:5353** (Service maps 53→5353); fixed to allow **:53 AND :5353** to `openshift-dns`, plus keycloak `:8080` + agentic-mcp `:8000`. Verified DNS + reachability + disallowed-IP block. |
| 5 | Phase B false dependencies | ✅ ADDRESSED | Parallelism noted in the master plan dependency graph; with Phase-A core journey PROVEN (2026-06-22), B/C are unblockable. |
| 6 | "Kyverno parked at 0 replicas" | ⚠️ STALE/INCORRECT | Verified live: kyverno-admission-controller **1/1** with webhooks present (that's why the SYS_CHROOT mutate fired). The "parked at 0" note was outdated memory. |

**Net since this review:** Phase-A's core zero-trust journey is PROVEN — a credential-less LLM agent in a
native OpenShell sandbox does the real pfSense read-delegated(200)→write(403)→approve→write(200) loop. The
review's blocking findings are closed; what remains are last-mile *seams* in the worklog (unattended-SVID
file-handoff, ACM image reverter [hub], real per-user OBO [proven viable, not applied]).
