# Phase A — OpenShell-native foundation: executable workflow loops

> **⚠️ CORRECTED 2026-06-20 — Loop A1 below (SELinux domain) is OBSOLETE.** Live testing proved the
> setns blocker is a **missing `CAP_SYS_CHROOT`**, not SELinux (see rewritten [ADR-0017](../adr/0017-provider-spiffe-setns-selinux-confinement.md)).
> **A1 is now a single step:** apply the Kyverno mutate
> `platform/kyverno/guardrails/base/mutate-openshell-sandbox-syschroot.yaml` (APPLIED + proven —
> appends `SYS_CHROOT`, sandbox stays `container_t`+MCS confined). The SELinux CIL/MachineConfig/SPO
> artifacts were DELETED. Loops A2 (Gate-2), A3 (enable provider_spiffe — note live drift: rev6 = kata
> + provider_spiffe off; git = runc + enabled, so A3 is a multi-change `helm upgrade`), and A4 (hybrid
> acceptance) below remain valid. The 🔴/🟢 apply order still applies, minus the SELinux steps.

- **Parent:** [Master Plan](openshell-agentic-platform-master-plan.md) · **Decision record:** [ADR-0017](../adr/0017-provider-spiffe-setns-selinux-confinement.md) · **Diagnostic:** [runbook](../runbooks/phaseA-userns-cap-diagnostic.md)
- **Goal of Phase A (the gate):** a credential-less agent in an OpenShell sandbox (confined `container_t`+MCS, granted only `CAP_SYS_CHROOT` — the custom-SELinux-domain idea was dropped, ADR-0017) reads via its SVID and writes via JIT, with ext-proc in front. Phase B/C are blocked until this is green.
- **Status (2026-06-22): CORE journey PROVEN.** A credential-less LLM agent in a native OpenShell sandbox does the real pfSense read-delegated→write-403→human-approve→write-200 loop. Substrate (ADR-0018 binding), Kagenti enrollment + chain, and OpenShell-operational (native sandbox boots a real LLM agent: `agent-harness` image + `ExecSandbox` detached boot + `PYTHONPATH=/app/src`) are all DONE; `hack/test-openshift-jit.sh` held 4/4. **Remaining seams:** unattended-SVID file-handoff (spiffe-helper→file, in progress); ACM image reverter (hub ManifestWork, no hub access from this cluster); real per-user OBO (PROVEN viable via per-client config on the agentic mcp-gateway, not applied — static-token fallback is the PoC answer). **Canonical detail:** `docs/reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md`.
- **Convention:** each loop = Goal → Gate → Steps → Verify → Rollback. `🟢` = safe/read-only or file-only. `🔴` = cluster mutation (needs explicit go). `KUBECONFIG=/home/anaeem/.kube/anaeem-sno.kubeconfig`, `NODE=anaeem-sno.na-launch.com`.

## Authored artifacts (ready to apply)
| File | Purpose |
|------|---------|
| `platform/openshell/selinux/openshell-sandbox.cil` | The custom domain module (container_t + `capability sys_admin`). |
| `platform/openshell/selinux/99-master-openshell-sandbox-selinux.yaml` | **MachineConfig** delivery (PRIMARY, 1-node). Embeds the CIL; `semodule -i` oneshot. |
| `platform/openshell/selinux/spo-rawselinuxprofile.yaml` | **SPO** delivery (ALT, multi-node/scale). |
| `platform/kyverno/guardrails/base/mutate-openshell-sandbox-selinux.yaml` | Kyverno mutate: set `seLinuxOptions.type` on sandbox pods at CREATE. |

---

## Loop A1 — `openshell_sandbox_t` confined domain

**Goal:** the custom domain is installed on the node and assigned to sandbox pods, replacing the EPERM with a permitted setns-back, while keeping confinement.

**A1.1 — AVC-validate the exact perm 🔴 (small, reversible; on the node).**
Confirm the denial is `class=capability perm=sys_admin` (not `cap_userns`) before trusting the CIL.
```sh
# On a disposable container_t sandbox (or the relabeled test pod), capture the real denial:
oc debug node/$NODE -- chroot /host sh -c 'semodule -DB && setenforce 0'   # remove dontaudit + permissive
# re-trigger setns in a container_t pod (see runbook §CONFIRMED PROCEDURE step 1), then:
oc debug node/$NODE -- chroot /host sh -c 'ausearch -m AVC -ts recent | grep -i setns; audit2allow -a'
# RESTORE IMMEDIATELY:
oc debug node/$NODE -- chroot /host sh -c 'setenforce 1 && semodule -B'
```
**Verify:** the AVC shows `tclass=capability ... { sys_admin }` and `audit2allow` yields exactly `allow <type> self:capability sys_admin`. If it shows anything else (e.g. `cap_userns`), correct `openshell-sandbox.cil` before proceeding.
**Rollback:** `setenforce 1 && semodule -B` (already in the step). Nothing persistent.

**A1.2 — Install the module 🔴 (MachineConfig = one SNO reboot).**
```sh
oc apply -f platform/openshell/selinux/99-master-openshell-sandbox-selinux.yaml   # via GitOps in practice
oc get mcp master -w     # wait UPDATED=True; SNO drains+reboots ONCE
```
*(Alt, no reboot: install SPO instead — `oc apply -f platform/openshell/selinux/spo-rawselinuxprofile.yaml`; pick ONE.)*
**Verify:** `oc debug node/$NODE -- chroot /host semodule -l | grep openshell-sandbox` → present.
**Rollback:** delete the MachineConfig (triggers a revert reboot) or `semodule -r openshell-sandbox`.

**A1.3 — Assign the domain via Kyverno 🔴 (no reboot).**
```sh
oc apply -k platform/kyverno/guardrails/base    # includes mutate-openshell-sandbox-selinux
```
**Verify (deferred to A3, when a sandbox actually carries the matching label):** a new sandbox shows `cat /proc/self/attr/current` → `openshell_sandbox_t:s0:cX,cY` (MCS categories present).
**Rollback:** `oc delete clusterpolicy mutate-openshell-sandbox-selinux`.

> **Dependency note (ties to A2):** the Kyverno match selector (`openshell.ai/managed-by=openshell`) and the ClusterSPIFFEID selector are the SAME label. If A2 shows OpenShell does NOT stamp `openshell.ai/*`, switch BOTH selectors to the label the pods actually carry (`agents.x-k8s.io/sandbox-name-hash`) and have Kyverno additionally stamp `openshell.ai/sandbox-id` for the SVID path.

---

## Loop A2 — Gate-2: SVID registration (✅ RESOLVED 2026-06-20 — see [ADR-0018](../adr/0018-openshell-native-svid-grant-key-binding.md))

> **RESOLVED.** Two defects, both fixed in `platform/spire/base/cluster-spiffe-ids.yaml` (GitOps-durable, applied + proven):
> 1. **className gate.** The `openshell-sandbox-workloads` CSID had **no `spec.className`**, so the class-gated `spire-controller-manager` (`className: zero-trust-workload-identity-manager-spire`) silently ignored it (empty `.status`, 0 entries). Added the className.
> 2. **Label reality (option (a) from A2.2 below).** OpenShell 0.0.62 does **not** stamp `openshell.ai/*` as pod labels. A sandbox pod carries `agents.x-k8s.io/sandbox-name-hash` (label) + `openshell.io/sandbox-id=<uuid>` (**annotation**, propagated from the Sandbox CR). So the CSID now **selects** on `agents.x-k8s.io/sandbox-name-hash` (Exists) and **templates** the SVID path off the `openshell.io/sandbox-id` **annotation** (`.PodMeta.Annotations` is readable in `spiffeIDTemplate`). That annotation value equals `resp.sandbox.metadata.id` = the Vault grant key, so SVID-path == grant-key (the ADR-0018 binding).
>
> **Proven:** `.status.stats` = `podsSelected:7, entriesToSet:7, podEntryRenderFailures:0`; 7 `…/ns/openshell/sandbox/<uuid>` entries; a freshly-launched sandbox gets its SVID entry + matching annotation; `…-spire-default` (135) and the harness CSID unregressed; `test-openshift-jit.sh` stayed 4/4. We did **not** extend the Kyverno mutate to stamp `openshell.ai/sandbox-id` (option (a)'s second half) — templating off the existing annotation needs no Kyverno change and decouples SVID issuance from the admission webhook.

**Original goal (kept for provenance):** sandbox pods actually receive an SVID. The earlier note ("OpenShell stamps `openshell.ai/*` only when `provider_spiffe` is enabled") was **wrong for 0.0.62** — it never stamps those as pod labels; the UUID arrives as the `openshell.io/sandbox-id` annotation.

**A2.1 — After A3 enables provider_spiffe, check stamping 🟢.**
```sh
oc -n openshell get pod <new-sandbox> --show-labels | tr ',' '\n' | grep openshell.ai
oc get clusterspiffeid openshell-sandbox-workloads -o jsonpath='{.status.stats}{"\n"}'
oc -n zero-trust-workload-identity-manager exec spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show | grep -c openshell
```
**Verify:** pods carry `openshell.ai/managed-by` + `openshell.ai/sandbox-id`; ClusterSPIFFEID `podsSelected>=1`; an entry exists; the agent reads a valid SVID from `/spiffe-workload-api/spire-agent.sock`.

**A2.2 — Fix ONLY if not stamped 🔴.** Two options (see A1.3 dependency note):
- (a) Realign `cluster-spiffe-ids.yaml` `openshell-sandbox-workloads` podSelector + template to the `agents.x-k8s.io/*` labels the pods carry; **and** extend the Kyverno mutate to stamp `openshell.ai/sandbox-id`.
- (b) Configure/upgrade OpenShell to stamp the `openshell.ai/*` labels (chart/values).
**Decision required** (master plan §6 open decision #1).

---

## Loop A3 — Enable native `provider_spiffe` (gated cutover)

**Goal:** native provider_spiffe live; setns reconciles under the new domain; socket hidden; SVID delivered.

**Gate (all must be green) 🔴:**
- Supervisor image pre-refactor `ghcr.io/nvidia/openshell/supervisor:0.0.62` ✅ (verified).
- etcd defragged ✅ (done 1.2GB→728MB; re-check `etcdctl endpoint status` < ~800MB).
- A1 module installed + Kyverno live.
- **Window:** `provider_spiffe` enable is gateway-wide (Helm TOML) → it restarts ALL sandboxes. Tear down / accept disruption of other `openshell` sandboxes for the window (master plan §6 open decision #2).

**Steps:**
```sh
# enable in values (GitOps), then helm/ArgoCD sync:
#   platform/openshell/values-openshift.yaml: providerTokenGrants.spiffe.enabled: true
```
**Verify (per restarted sandbox):**
```sh
oc -n openshell exec <sandbox> -- cat /proc/self/attr/current            # openshell_sandbox_t:s0:cX,cY
oc -n openshell exec <sandbox> -- env | grep PROVIDER_SPIFFE              # socket path set
oc debug node/$NODE -- chroot /host sh -c 'pid=$(crictl inspect $(crictl ps -q --name <sandbox>) | jq -r .info.pid); strace -f -tt -e trace=setns,unshare,mount -p $pid 2>&1 | head -40'   # setns(... )=0
oc -n openshell exec <sandbox> -c agent -- stat /spiffe-workload-api/spire-agent.sock   # ENOENT from the AGENT child (socket hidden) -> FAIL-STOP if reachable
```
**Rollback:** set `spiffe.enabled: false`, resync; sandboxes revert to the working (non-native) state.

---

## Loop A4 — Hybrid acceptance (ext-proc stays in front)

**Goal:** native mint composes with the per-tool JIT gate + audit (ADR-0011/0017 hybrid); nothing regresses.

> **Status 2026-06-20 — SUBSTRATE ✅ PROVEN, agent-driven acceptance ⏳ REMAINING.** Authored
> `hack/test-openshell-native-hybrid.sh` (loop-until-green on the substrate). On a freshly
> gateway-launched sandbox it verifies, end-to-end and green: the launcher **wrote the Vault grant**
> (`secret/data/sandbox-grants/<id>`, was absent pre-fix — Loop 2: stale image + missing
> `sandbox-launcher` Vault policy/role, both fixed); the CSID **issued the per-sandbox SVID** (Loop 1 /
> ADR-0018); the **binding holds** (`metadata.id` == `openshell.io/sandbox-id` annotation == SVID path ==
> grant key); the **workload-API socket is mounted**, **`SYS_CHROOT` present**, **confined `container_t`**,
> **0 setns/EPERM**; and **only the SVID** is present in the sandbox (no stored broad credential).
> `test-openshift-jit.sh` stayed **4/4** throughout. etcd defragged 1.0GB→787MB before the spawns.
>
> **Remaining (the agent-driven hybrid, steps 1–3 below):** the in-sandbox agent must drive an MCP call
> **through ext-proc carrying its raw SVID** so ext-proc resolves the grant and exchanges on-behalf-of
> (ADR-0011's retained-hybrid posture). Observed: a fresh sandbox is substrate-ready, but the in-sandbox
> agent session did **not** autonomously call a tool (ext-proc saw zero native traffic). Closing this needs:
> (i) the **agent-brain reachable from ns `openshell`** (LiteLLM is "live-only"; today only an SSH NP exists —
> apply `platform/openshell/networkpolicy-sandbox-egress.yaml`, the §A4 compensating control); and (ii)
> confirming the **supervisor routes MCP through ext-proc with the SVID** rather than doing its own Keycloak
> exchange (the ADR-0011 hybrid-wiring question). Run with `REQUIRE_AGENT_READ=1` to make the delegated read
> a hard gate once (i)+(ii) land.

**Steps/Verify (`hack/test-openshell-native-hybrid.sh`, loop-until-green):**
0. *(substrate, ✅ green)* launch → grant written → SVID entry → binding consistent → socket+`SYS_CHROOT`+confined+0 setns → SVID-only invariant.
1. SVID-only call + a dangerous tool → `403 grant_scope_denied`.  *(⏳ needs agent-driven path)*
2. JIT-elevate (jit-approver bound session JWT, `jwt.sandbox_uid==svid.sandbox_uid`) → retry exactly that tool → `200`; audit shows `jit_elevated=true` / `jit_session_id` / `caller_username`.  *(⏳)*
3. Post-TTL `revert_network` → same tool → `403`.  *(⏳)*
**Exit (Phase A done):** substrate green (done) **+** the agent-driven steps 1–3 green → unblock Phase B/C.

---

## Apply order (the gated sequence, for the go)

1. 🟢 commit the authored artifacts (Phase 0).
2. 🔴 **A1.1** AVC-validate (reversible) → confirm the CIL perm.
3. 🔴 **A1.2** install module (MachineConfig → 1 SNO reboot, or SPO → no reboot).
4. 🔴 **A1.3** apply Kyverno mutate.
5. 🔴 **A3** enable provider_spiffe (window) → **A2** verify SVID stamping (fix iff needed).
6. 🟢/🔴 **A4** run hybrid acceptance.

Each 🔴 step is an explicit stop-and-confirm on this fragile SNO. Open decisions that surface inside loops: #1 (Gate-2 label fix shape), #2 (provider_spiffe cutover window) — both in master plan §6.
