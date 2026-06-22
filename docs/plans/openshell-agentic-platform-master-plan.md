# Master Plan — OpenShell Agentic Platform (the whole solution)

- **Status:** Plan of record. Created 2026-06-20. **Phase A (the gate) executed + its core journey PROVEN 2026-06-22** — a credential-less LLM agent in a native OpenShell sandbox does the real pfSense read-delegated→write-403→approve→write-200 loop; last-mile seams remain (unattended-SVID file-handoff, ACM image reverter [hub], real OBO [proven, not applied]). Phases B/C now unblockable. Canonical detail: `docs/reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md`.
- **Owner decisions locked (2026-06-20):** UI = extend `approval-console`; agent model = **persistent agents that spawn sessions**; v1 features = **webshell + per-agent Gitea repo + skills repo & selectable loading + in-console JIT/token**; sequencing = **block on OpenShell-native first** (foundation before product).
- **This doc is the apex.** It unifies the three in-flight threads and the new product vision into one sequenced plan. Sub-decisions live in their ADRs/handoffs (linked inline); this doc is what a master agent picks up to drive the whole thing.

---

## 1. The final product (vision)

A single **OpenShell-backed console** (the extended `approval-console`, Keycloak-authenticated) where a human:

1. **Launches a living agent** — a *persistent* OpenShell sandbox with its own SPIFFE identity, workspace, and Gitea repo. The agent endures; you revisit it.
2. **Runs sessions under it** — each task is a child session (streamed transcript), so one living agent accumulates history/workspace across many runs.
3. **Picks skills at launch** — selects from a central **skills Git repo**; chosen skills are loaded into the agent (`.claude/skills`).
4. **Gets a per-agent Git repo** — auto-created in Gitea at launch for the agent's workspace/state/output.
5. **Reads freely, writes by approval** — reads run under a scoped view identity; dangerous tools/writes are **denied until a human approves in-console**, which **mints a short-lived, minimally-scoped token** the agent then wields (JIT). Approver ≠ requester. Everything is audited (WORM).
6. **Drops into a webshell** — a browser terminal to spin up a new agent and interact live.

**Runtime = OpenShell** (policy-driven, "secure"): per-agent sandboxes, native `provider_spiffe` credential mint, floor+elevator network policy, all in a **confined `container_t`** sandbox (MCS intact) granted only the one extra capability the supervisor needs (`CAP_SYS_CHROOT`).

### The hard invariant (non-negotiable, applies to every phase)
> The agent holds only its SPIFFE SVID. No long-lived, broadly-scoped credential is ever stored in or forwarded by the agent. Every privileged action is read-only via a scoped identity, **or** human-approved + just-in-time + short-lived + attributed to a real human. No phase may end with the agent holding a standing edit/write credential.

---

## 2. Architecture of the whole solution

| Plane | Component | Role |
|-------|-----------|------|
| **Identity (workloads)** | SPIRE / SPIFFE (ZTWIM operator), per-agent `ClusterSPIFFEID` | Each agent sandbox gets a unique SVID via `csi.spiffe.io`. |
| **Identity (humans)** | Keycloak (realm `agentic`) + oauth2-proxy | Human auth for the console; identity forwarded into JIT `requester_sub` / audit. |
| **Runtime** | **OpenShell** sandboxes, `provider_spiffe` native, confined `container_t` + `CAP_SYS_CHROOT` (Kyverno mutate) | Per-agent policy-driven sandbox; native credential mint. |
| **Authz — network floor/elevator** | OpenShell policy API (`UpdateConfig` merge-ops, `jit-` rules, auto-reverting) | Time-boxed egress elevation on approval (Boundary #1). |
| **Authz — per-tool scope** | `ext-proc-delegation` + `jit-gate` (STRICT tool-scope) | Read-only baseline; dangerous tool lifted for exactly one tool on a bound JIT session JWT (Boundary #2). Rich per-call audit. |
| **JIT / token** | `jit-approver` (mint-gate), console approve, k8s `TokenRequest` short-lived creds, operation-shaped TTL | Approver≠requester; short-lived minimally-scoped credential; SoD enforced. |
| **Persistence** | CNPG (WORM audit), Gitea (per-agent repos + skills repo), PVC (agent workspace) | Durable audit + code + state. |
| **UI** | **`approval-console`** extended (Keycloak, SSE, session launch already proven) | Launch agents, sessions, skills picker, webshell, JIT/token panels. |

### Composition rule (carried from ADR-0011, reaffirmed by ADR-0017)
Native OpenShell `provider_spiffe` supplies the **credential mint only**. **ext-proc stays in front** as the per-tool tool-scope gate + audit emitter. jit-approver's network elevator stays native. Native delegation must never displace the ext-proc per-tool JIT loop or the receipt/audit surface.

---

## 3. In-flight threads being unified (current state)

| Thread | Artifacts | State | Folds into |
|--------|-----------|-------|------------|
| **OpenShell setns (CAP_SYS_CHROOT)** | [ADR-0017](../adr/0017-provider-spiffe-setns-selinux-confinement.md), [runbook](../runbooks/phaseA-userns-cap-diagnostic.md), memory `project-openshell-setns-rootcause` | Root cause = missing `CAP_SYS_CHROOT` (NOT SELinux). FIXED (Kyverno) + `provider_spiffe` ENABLED (helm rev7); real supervisor passes setns. **2026-06-22: full agent-run via gateway PROVEN** — a native LLM agent does the real pfSense read-delegated→write-403→approve→write-200 journey. Remaining: unattended-SVID file-handoff + ACM image durability (hub). See `docs/reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md`. | **Phase A** |
| **JIT operation-shaped TTL** | [ADR-0014](../adr/0014-operation-shaped-jit-ttl-decouple.md), `docs/research/2026-06-20-jit-short-lived-capability-ttl-prior-art.md` | Decision recorded (k8s 600s floor); 5 touch-points + CNPG migration queued. | **Phase B** |
| **Console mint-gate L0/L1** | `docs/plans/jit-mint-gate-L0-L1-HANDOFF.md` (branch `feat/jit-mint-gate-L0-L1`), `docs/decisions/0007-console-mint-gate-replaces-pr-merge-approval.md`, memory `project-console-mint-gate` | L0+L1 built (uncommitted); approver≠requester, CNPG WORM, TokenReview interim. Live-e2e blockers flagged (cluster ctx, RBAC `system:auth-delegator`, not deployed). | **Phase B** |
| **Product console + agent platform** | this plan | New. | **Phase C** |

**Branch/commit posture:** OpenShell setns docs (this session) are uncommitted on `backup/e2e-delegated-zero-trust`; mint-gate L0/L1 on `feat/jit-mint-gate-L0-L1`; ADR-0014 + research doc uncommitted in working tree. A commit/durability step is built into Phase 0.

---

## 3b. Detailed phase plans + execution spine (2026-06-22)

Each phase now has a detailed, loop-structured plan (authored by the parallel planning workflow `w3o0a1r3g`):
- **Phase A-tail** → [`phase-A-tail-detailed-plan.md`](phase-A-tail-detailed-plan.md) (8 loops; core PROVEN, seams remain)
- **Phase B** → [`phase-B-jit-token-detailed-plan.md`](phase-B-jit-token-detailed-plan.md)
- **Phase C** → [`phase-C-product-console-detailed-plan.md`](phase-C-product-console-detailed-plan.md)
- **Phase D** → [`phase-D-productionize-detailed-plan.md`](phase-D-productionize-detailed-plan.md)

**Sequencing is RELAXED (the strict A→B→C→D in §4 is now too conservative).** Phase A *core* is done/proven;
only the **product (Phase C live)** truly gates on **AT-1** (unattended file-SVID handoff green) made durable by
**AT-3** (hub image pin). ALL code authoring across A-tail/B/C/D is mutually independent and runs in parallel NOW
(file-only). The single **gated-mutation spine** is:

> **[AT-3 hub pin ≡ D1]** → **[AT-1 re-verify]** → **[B2 mint-gate live: CNPG + `system:auth-delegator` CRB + `JIT_STORE_BACKEND=postgres`]** → **[B1 jit-gate `DATABASE_URL` flip]** → **[B3 narrow-SA manifests]** → **[C live integration G-C1..G-C5]** → **[D2/D5 tightening + reaper]**.
> Housekeeping floats off the critical path (AT-6 dead-policy reap, AT-7 pfSense rule 50, AT-4 KC v1 OBO — static-token fallback keeps the journey green).

**AT-3 == D1 are the SAME hub `ManifestWork ida-launcher-componenta` edit — do it once, early; it is the single
highest-leverage durability action (closes SEAM #2 / issue #28).**

**Code authored 2026-06-22 (file-only, uncommitted, NOT applied; tests green):** B touch-points in `jit-approver`
(144 passed, 1 pre-existing unrelated fail) + `platform/jit-approver-db/`, `platform/jit-token-sas/`; C modules
`approval-console/{agents,gitea,skills,ui,webshell}` + tests (**69 passed**, incl. the original 42) +
`platform/gitea/`, `mutate-openshell-sandbox-skills-loader.yaml`; D `hack/test-openshell-native-hybrid.sh`.

**Pinned golden tags:** launcher `sandbox-launcher:svidfile-20260622-010033`; sandbox `sandbox-agent:brain-gw403retry5-20260622-142214`; `SVID_JWT_PATH=/tmp/svid-out/mcp-gateway-svid.jwt`; `SVID_REQUIRE_PATH_SUBSTR=/sandbox/`.

**Resolved open decisions (§6):** C3 skills load = init-container git-clone into a writable `.claude/skills`;
C4 webshell = FastAPI WS bridge v1 (ttyd sidecar v2); C2 lifecycle = per-agent deploy key + soft-archive→30d hard-delete.
**Hard note:** Phase-B **L4 fast-lane is PERMANENTLY BLOCKED** on a kyverno-envoy-plugin `mcp.Parse` upgrade — do NOT
wire it (auto-approve would violate approver≠requester; ext-proc stays sole enforcer). **OBO posture:** AT-4 (KC v1
fine-grained perms) is a near-term reversible milestone behind static-token fallback; AT-5 (v2 `subject_token`, RFC 8693)
is the durable target since KC v1 token-exchange is deprecated.

---

## 4. The plan as workflow loops (original strict sequencing — see §3b for the relaxed, current spine)

Each loop is **goal → steps → verify/exit**. (Historical note: this section's strict **A → B → C → D** gate has been
**superseded by §3b** — code authoring parallelizes now; only Phase-C *live* gates on the A-tail/B-live spine.)

### PHASE 0 — Consolidate & make durable (no cluster change)
- **Loop 0.1 — Commit the doc bundles.** Land ADR-0017 + runbook/ADR banners (this session); ADR-0014 + research doc; confirm mint-gate handoff committed on its branch. Scope commits per thread; nothing cross-contaminated.
- **Loop 0.2 — Adopt this master plan** as the tracking doc; link it from `MEMORY.md` and the three thread docs.
- **Exit:** every thread is pickable from git; this plan is the single entry point.

### PHASE A — OpenShell-native foundation *(the blocking gate)*
Goal: a native OpenShell agent runs end-to-end in a **confined `container_t` (MCS-intact)** sandbox, delivering an SVID and minting credentials, with ext-proc in front. Ref: rewritten [ADR-0017](../adr/0017-provider-spiffe-setns-selinux-confinement.md). **NOTE: the root cause was a missing `CAP_SYS_CHROOT`, NOT SELinux** — the earlier custom-SELinux-domain plan was wrong and is dropped.

- **Loop A1 — Grant `CAP_SYS_CHROOT` (✅ DONE).** The supervisor's setns-back re-roots into the original mount ns → needs `SYS_CHROOT` on top of `SYS_ADMIN`. Fix = **Kyverno mutate** `platform/kyverno/guardrails/base/mutate-openshell-sandbox-syschroot.yaml` (APPENDS `SYS_CHROOT` at Pod CREATE; matched by `agents.x-k8s.io/sandbox-name-hash`). APPLIED + verified; sandbox stays `container_t`+MCS. No SELinux module / SPO / MachineConfig / privileged. (Kyverno admission-controller is 1/1 — the old "parked at 0" note is stale.)
- **Loop A2 — Gate-2 SVID registration (✅ DONE 2026-06-20 — [ADR-0018](../adr/0018-openshell-native-svid-grant-key-binding.md)).** Two defects fixed in `platform/spire/base/cluster-spiffe-ids.yaml`: (1) the CSID had **no `spec.className`** so the class-gated `spire-controller-manager` ignored it (empty `.status`); added `className: zero-trust-workload-identity-manager-spire`. (2) OpenShell 0.0.62 does **not** stamp `openshell.ai/*` as pod labels — the sandbox UUID arrives as the **annotation** `openshell.io/sandbox-id`; so the CSID now selects on `agents.x-k8s.io/sandbox-name-hash` (Exists) and templates the SVID path off that annotation. That UUID == `resp.sandbox.metadata.id` == the Vault grant key (the ADR-0018 binding). **PROVEN:** `podsSelected:7, renderFailures:0`; a freshly-launched sandbox gets a `…/sandbox/<uuid>` SVID entry; `…-spire-default`(135)+harness CSID unregressed.
- **Loop A3 — Enable `provider_spiffe` (✅ DONE).** `helm upgrade openshell oci://ghcr.io/nvidia/openshell/helm-chart --version 0.0.62 -n openshell -f platform/openshell/values-openshift.yaml` → **rev 7 deployed** (kata→runc + provider_spiffe enabled), gateway healthy, config carries the socket path. etcd defragged 1.2GB→728MB. **PROVEN:** the real supervisor passes the identity-mount/setns stage with **0 setns/EPERM** (old crash signature gone).
- **Loop A4 — Hybrid acceptance (SUBSTRATE ✅ 2026-06-20; agent-driven ⏳ REMAINING).** Captured as `hack/test-openshell-native-hybrid.sh` (loop-until-green on the substrate). On a gateway-launched sandbox it PROVES green: launcher **wrote the Vault grant** (Loop 2 — fixed the stale launcher image + the missing `sandbox-launcher` Vault policy/role, `platform/vault/config/sandbox-launcher.hcl`+`vault-bootstrap.sh`); CSID **issued the SVID**; **binding holds** (metadata.id==annotation==SVID-path==grant-key); socket mounted + `SYS_CHROOT` + confined `container_t` + 0 setns/EPERM; **SVID-only** (no stored credential). `test-openshift-jit.sh` stayed 4/4; etcd defragged 1.0GB→787MB. **Remaining:** the in-sandbox agent must drive an MCP read **through ext-proc with its SVID** (SVID-only→`403`; JIT→`200`+audit; post-TTL→`403`) — needs the agent-brain reachable from ns `openshell` (the egress NP below) + confirming the supervisor routes MCP via ext-proc (ADR-0011 hybrid wiring). A fresh sandbox is substrate-ready but the agent session did not autonomously call a tool (ext-proc saw no native traffic).
- **Compensating control (from review):** add an **egress NetworkPolicy** to ns `openshell` (only an SSH ingress NP exists today) before Phase A closes — `SYS_CHROOT`+`SYS_ADMIN` sandboxes should not egress arbitrarily.
- **Phase A exit (the gate for B/C):** a credential-less Claude agent in a confined `container_t` OpenShell sandbox reads via SVID, writes via JIT, on native `provider_spiffe`, with ext-proc audit intact.

### PHASE B — JIT / token system (on the native runtime)
Goal: in-console JIT approve → mint a short-lived, minimally-scoped, operation-shaped-TTL token → agent writes; approver≠requester; WORM-audited.

- **Loop B1 — Operation-shaped JIT TTL.** Implement ADR-0014's 5 touch-points + the CNPG migration (k8s 600s floor honored). Verify per the ADR's criteria.
- **Loop B2 — Console mint-gate L0/L1 → live.** Land branch `feat/jit-mint-gate-L0-L1`; resolve the handoff's live-e2e blockers (correct platform cluster, grant `system:auth-delegator` RBAC, deploy via GitOps/ArgoCD). Then drive the L2–L5 roadmap loops.
- **Loop B3 — Short-lived token minting integrated.** k8s `TokenRequest` for a per-capability narrow SA (not the standing broad `edit` binding); gate injects it per-call; replay-after-TTL → 401; `oc auth can-i` proves minimal scope. (This is roadmap-#4 Loop B from `docs/research/04-real-isolation-and-delegation.md`, now on the OpenShell runtime.)
- **Phase B exit:** approve-in-console → mint → write, SoD enforced, audited; no standing write credential anywhere.

### PHASE C — Product console (extend `approval-console`) + agent platform
Goal: the full UI/product on the native+JIT foundation.

- **Loop C1 — Persistent-agent + session model.** Introduce an **Agent** object (CRD or backed table) = {OpenShell sandbox + SPIFFE id + workspace PVC + Gitea repo + loaded skills}. Sessions are children of an Agent (reuse the proven session-launch + SSE path). Lifecycle: create / list / attach / archive / delete (+ reaping).
- **Loop C2 — Per-agent Gitea repo.** At agent launch, create a Gitea repo via API; wire it as the agent's workspace remote; scope access to the agent. (Open decision: repo cleanup policy.)
- **Loop C3 — Skills repo + selectable loading.** Create a dedicated Gitea **`skills`** repo (seed from `services/agent-sandbox/agent-harness/.claude/skills`); UI skill-picker; load selected skills into the agent at launch (clone via init container into a writable `.claude/skills` — the harness image's is read-only). (Open decision: load mechanism.)
- **Loop C4 — Webshell.** Browser terminal in the console to spin up / attach to an agent (tech choice open — OpenShell's own webshell vs ttyd/wetty; Keycloak-gated; SSE/websocket through the router with the heartbeat+timeout already solved).
- **Loop C5 — JIT/token panels in-console.** Surface the approve/mint/token + receipt flow directly in the product UI (unifies Phase B into the UX).
- **Phase C exit:** from the console — launch a living agent, pick skills, get a repo, webshell in, run sessions, approve writes in-place.

### PHASE D — Productionize
- GitOps durability (base manifests carry real values; mounts over env where ArgoCD reverts; `apply -k` non-destructive), NetworkPolicies (incl. the missing egress NP on ns `openshell`), secrets out of git, loop-until-green tests per surface, operator docs, and the compensating controls from ADR-0017 (egress NP, consider dropping `CAP_NET_ADMIN`).

---

## 5. Implementation touch-points (by component)

- **`platform/openshell/`** — `selinux/openshell-sandbox.cil` (new), `values-openshift.yaml` (provider_spiffe toggle), SandboxTemplate/labels for Gate-2.
- **Security Profiles Operator** — new GitOps Application + `SelinuxProfile`/raw-CIL CR.
- **`platform/kyverno/guardrails/`** — `mutate-openshell-sandbox-selinux.yaml` (+ kustomization); plus the existing guardrail set.
- **SPIRE** — `openshell-sandbox-workloads` ClusterSPIFFEID selector/template (Gate-2).
- **`services/jit-approver/`** — operation-shaped TTL (ADR-0014), TokenRequest minting, mint-gate (L-series).
- **`services/ext-proc-delegation/`, `services/jit-gate/`** — kept in front; per-tool gate + audit; token injection.
- **`services/approval-console/`** — Agent model + session children, Gitea repo creation, skills picker + loader, webshell, JIT/token panels.
- **Gitea** — per-agent repos + the new `skills` repo.
- **CNPG** — WORM audit (mint-gate) + ADR-0014 migration.

---

## 6. Open decisions (need owner input before/within the relevant loop)

1. **Gate-2 label fix shape (A2):** realign the ClusterSPIFFEID selector to the `agents.x-k8s.io` labels the pods actually carry, **vs** make OpenShell stamp `openshell.ai/*` labels (may need an OpenShell config/version change).
2. **`provider_spiffe` cutover (A3):** accept the brief gateway-wide all-sandbox disruption for enablement, **vs** request a per-sandbox toggle upstream.
3. **Skills load mechanism (C3):** init-container `git clone` into a writable `.claude/skills` emptyDir, **vs** a projected volume, **vs** rebuilding the harness image per skill-set. (Image `.claude/skills` is read-only.)
4. **Webshell tech (C4):** reuse OpenShell's own webshell **vs** ttyd/wetty embedded in the console.
5. **Per-agent repo lifecycle (C2):** retention/cleanup when an agent is archived/deleted; access scoping (per-agent deploy key vs SVID-brokered).
6. **Commit/branch strategy (Phase 0):** whether to converge `feat/jit-mint-gate-L0-L1` and `backup/e2e-delegated-zero-trust` or keep thread branches until each phase merges.

---

## 7. Dependency graph (why this order)

```
PHASE 0 (docs/commit) ──► PHASE A (OpenShell-native) ──► PHASE B (JIT/token) ──► PHASE C (product UI) ──► PHASE D (prod)
                                  │  A1 SYS_CHROOT ✅ ─┐
                                  │  A2 Gate-2 (verify)├─► A3 enable ✅ ─► A4 full-run+hybrid  (GATE before C)
                                  └────────────────────┘
```
**Parallelism (review 2026-06-20):** "block on OpenShell-native first" gates the **product (C)**, not all code. ADR-0014 (operation-shaped TTL), mint-gate L0–L3, and the skills-repo seed (C3 groundwork) have **no hard dependency on native OpenShell** and may proceed in parallel with the Phase-A tail. Only B *integration on the live native runtime* and the product UI wait on A4.

## 8. Definition of done (final product)

From the console, a Keycloak-authed human launches a **living agent** that: runs in a confined `container_t` OpenShell sandbox (with `CAP_SYS_CHROOT`) with its own SVID; has an auto-created Gitea repo + selected skills loaded; can be entered via webshell; spawns task sessions with streamed transcripts; reads freely; and on any write, **pauses for in-console human approval that mints a short-lived minimally-scoped token** (approver≠requester, operation-shaped TTL, WORM-audited) — with the no-stored-credential invariant holding throughout, ext-proc per-tool audit intact, and the whole thing GitOps-durable.
