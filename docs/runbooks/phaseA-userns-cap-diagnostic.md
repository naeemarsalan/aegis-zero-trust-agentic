# Runbook — pin the native `provider_spiffe` setns-EPERM cause (READ-ONLY first)

> **✅ RESOLVED 2026-06-20 — the cause is a missing `CAP_SYS_CHROOT`; see [ADR-0017](../adr/0017-provider-spiffe-setns-selinux-confinement.md).**
> The supervisor's `setns`-back re-roots into the original mount ns, which the kernel gates on
> `CAP_SYS_CHROOT` (on top of `CAP_SYS_ADMIN`). The sandbox has `SYS_ADMIN` but not `SYS_CHROOT` →
> EPERM. Proven: `container_t` (confined, MCS intact) + `[SYS_ADMIN, SYS_CHROOT]` → setns OK. It is
> **NOT** SELinux, seccomp, userns, or propagation (all ruled out live — an earlier same-day SELinux
> conclusion was a `privileged`-confounded misdiagnosis, since `privileged:true` grants all caps incl.
> SYS_CHROOT). Fix = Kyverno mutate appends `SYS_CHROOT`. The procedure below remains a valid
> read-only repro; the userns/SELinux framing is historical.
>
> ---
>
> (historical SELinux/userns framing follows)
> It was thought to be **SELinux `container_t` confinement**, NOT userns and NOT propagation. The Tier-1 userns
> hypothesis below was DISPROVED live (the sandbox runs in the **init userns** — `uid_map "0 0
> 4294967295"`, `NS_GET_USERNS` of the mnt-ns → 4026531837 — with a working `CAP_SYS_ADMIN`). The
> "CONFIRMED PROCEDURE" section immediately below is what actually pinned and proved it; the original
> Tier-1/Tier-2 sections are retained for provenance only.
>
> ## CONFIRMED PROCEDURE (what pinned + proved the SELinux cause, mostly READ-ONLY)
>
> Set `export KUBECONFIG=/home/anaeem/.kube/anaeem-sno.kubeconfig`. `POD` = a running
> `openshell/agent-arsalan-*` sandbox.
>
> **1. Reproduce the EPERM (read-only, process-local).** In the confined sandbox, replay the
> supervisor sequence in a throwaway forked child — it EPERMs in EVERY variant (no-mount;
> `MS_REC|MS_PRIVATE /`; non-recursive `MS_PRIVATE`; `MS_SLAVE`; and a pure no-op `setns`), via both
> python `ctypes` and the stock CLI: `oc -n openshell exec "$POD" -- sh -c 'unshare -m sh -c "nsenter
> --mount=/proc/1/ns/mnt true"'` → `Operation not permitted`. → Rules out propagation (no-mount fails)
> and the ADR-0011 scoped-remount fork-patch (`MS_PRIVATE`/`MS_SLAVE` fail identically).
>
> **2. Rule out userns (read-only).** `oc -n openshell exec "$POD" -- sh -c 'cat /proc/1/uid_map;
> readlink /proc/1/ns/user'` → `0 0 4294967295` + `user:[4026531837]` (init userns); `CAP_SYS_ADMIN`
> is effective AND functional (`unshare`/`mount` succeed). So the cap triple should pass → an LSM veto.
>
> **3. Pin SELinux (read-only).** Sandbox domain = `container_t:s0:cX,cY` (confined); the comparison
> privileged pod `spire-agent` = `spc_t:s0` (unconfined): `oc ... exec ... -- cat
> /proc/self/attr/current`. Node `getenforce` = Enforcing; no AVC (dontaudit-masked). Policy delta
> (from the node's `container-selinux-2.237.0` policy.33): `container_t` has `cap_userns{sys_admin}`
> unconditionally but `capability{sys_admin}` only behind `virt_sandbox_use_sys_admin` (OFF); `spc_t`
> has `capability{sys_admin}` unconditionally. The kernel selects class `capability` (not `cap_userns`)
> because `mnt_ns->user_ns == init_user_ns`.
>
> **4. Positive control (ONE throwaway pod — minimal mutation, auto-torn-down).** Create a pod with
> the **real `csi.spiffe.io` volume** + `securityContext.seLinuxOptions.type: spc_t` + `privileged`
> (throwaway SA granted the `privileged` SCC). Run the FULL supervisor sequence: `unshare(CLONE_NEWNS)`
> → `mount(MS_REC|MS_PRIVATE,/)` → tmpfs overlay on `/spiffe-workload-api` → `setns`-back. Under
> `spc_t` ALL succeed (vs EPERM under `container_t`) → SELinux domain is the SOLE cause; **no
> compounding CSI-propagation blocker.** Tear down pod + SA + SCC grant immediately. *(This replaced
> the heavier gateway-wide `provider_spiffe` Helm flip + sandbox teardown — same proof, far smaller
> blast radius.)*
>
> **Pre-gates carried forward for the live cutover** (enabling `provider_spiffe` for real): confirm
> supervisor image is pre-refactor `ghcr.io/nvidia/openshell/supervisor:0.0.62`; **etcd defrag** if
> `dbSize` > ~800MB (`oc -n openshift-etcd exec etcd-<node> -c etcdctl -- etcdctl defrag
> --command-timeout=120s`; done 2026-06-20, 1.2GB→728MB); fix the Gate-2 SVID registration
> (`openshell-sandbox-workloads` ClusterSPIFFEID selects 0 pods — labels mismatch). `provider_spiffe`
> enable is gateway-wide (Helm TOML) → tear down other sandboxes for that window. Remediation +
> remaining work: ADR-0017.

---

## (ORIGINAL — retained for provenance; the userns hypothesis below was DISPROVED, see above)

**Why:** ADR-0011's off-cluster disproof (`experiments/phaseA-epmm-fixture/FINDINGS.md`) showed
`setns(CLONE_NEWNS)` back to the original mount namespace EPERMs **only** on the capability triple
in `fs/namespace.c::mntns_install` — it has **no** mount-propagation reconciliation. So the live
EPERM is a **user-namespace / capability ownership** problem, not the propagation problem ADR-0009
assumed. This runbook pins it on the real cluster **without** the propagation guesswork.

**Hard guardrails (carried from ADR-0011 / the session guardrails):**
- Tier 1 is **pure read-only**. Run it first. It does **not** re-enable `provider_spiffe` and does
  **not** touch the crashing path.
- Tier 2 re-enables `provider_spiffe` on **one disposable test sandbox** — that is the crashing
  path and a live mutation. **Do NOT run Tier 2** until: (a) Tier 1 is captured, (b) the user
  explicitly approves, (c) the control plane is healthy (the flapping etcd member at `172.16.1.3`
  is settled; consider an etcd defrag first), and (d) it is scoped to a single throwaway sandbox.

Prereqs: OpenShell deployed (the `sandboxes` CRD present and at least one sandbox supervisor pod
running) — as of 2026-06-16 **none of this is deployed** (the PoC namespaces are torn down), so
this runbook is staged for when the stack is back. Set:
```sh
KC=~/.config/ida/anaeem-admin.kubeconfig      # cluster-admin (ida-admin SA)
NS=openshell                                   # sandbox namespace (per ida config sandbox_namespace)
oc() { command oc --kubeconfig "$KC" "$@"; }
```

## Tier 1 — READ-ONLY userns/cap topology of the supervisor (no provider_spiffe needed)

The decisive variable: does the sandbox pod run in a **non-init user namespace**, and is the
supervisor's *original* mount namespace owned by a **different** user_ns than the one the
supervisor process holds CAP_SYS_ADMIN in? If yes, the setns-back EPERM is fully explained by
`mntns_install` and the scoped-remount fix is irrelevant.

```sh
# 1. Find a running sandbox supervisor pod + its node and the supervisor PID's container.
oc -n "$NS" get pods -o wide
POD=<sandbox-pod>
oc -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}{"\n"}'
# Is a userns requested at the pod level? (OCP user-namespace support)
oc -n "$NS" get pod "$POD" -o jsonpath='hostUsers={.spec.hostUsers}{"\n"}'   # false => pod userns ON
oc -n "$NS" get pod "$POD" -o jsonpath='{range .spec.containers[*]}{.name} scc-uid={.securityContext.runAsUser}{"\n"}{end}'
oc -n "$NS" get pod "$POD" -o jsonpath='scc={.metadata.annotations.openshift\.io/scc}{"\n"}'

# 2. From INSIDE the supervisor container (read-only): the supervisor's own userns/mnt-ns + caps.
#    (the supervisor is pid 1 or the openshell-supervisor process)
oc -n "$NS" exec "$POD" -- sh -c '
  echo "== pid1 ns =="; ls -l /proc/1/ns/user /proc/1/ns/mnt
  echo "== uid_map =="; cat /proc/1/uid_map; echo "== gid_map =="; cat /proc/1/gid_map
  echo "== caps =="; grep -E "Cap(Eff|Bnd|Prm)" /proc/1/status
  echo "== self ns (the shell, for comparison) =="; ls -l /proc/self/ns/user /proc/self/ns/mnt
'
#    Interpretation:
#    - /proc/1/ns/user a NON-init userns (uid_map maps a sub-range, NOT "0 0 4294967295")
#      => the pod runs in a user namespace. CAP_SYS_ADMIN in /proc/1/status is then caps over
#      THAT userns only.
#    - If the supervisor captures its "original" mnt-ns while in that pod userns but the runtime
#      created the mnt-ns under init_user_ns, mntns_install's ns_capable(mnt_ns->user_ns,...)
#      check fails on setns-back => the observed EPERM, propagation-independent.

# 3. Node-level (READ-ONLY): is CRI-O running this pod in a user namespace, and who owns the
#    pod's mount namespace? Use an oc debug node shell (read-only commands only).
oc debug node/<node> -- chroot /host sh -c '
  echo "== crio userns config =="; crio config 2>/dev/null | grep -iE "userns|uid_mappings|gid_mappings|annotations" | head
  echo "== crio version =="; crio --version | head -1
'
#    Map the supervisor PID on the node and inspect its ns owners (read-only):
#    crictl ps | grep <sandbox>; crictl inspect <id> | jq .info.pid ; then
#    readlink /proc/<pid>/ns/user ; readlink /proc/<pid>/ns/mnt ; cat /proc/<pid>/uid_map

# 4. mustFix #6 (deployed-image caller path) — confirm the patched function is the one exercised.
#    Read-only: inspect the deployed supervisor binary + its env wiring.
oc -n "$NS" get pod "$POD" -o jsonpath='{range .spec.containers[*]}{.image}{"\n"}{end}'
oc -n "$NS" exec "$POD" -- sh -c '
  # SUPERVISOR_IDENTITY_MOUNT_NS is set only if prepare_..._from_env ran and found the socket env.
  env | grep -iE "PROVIDER_SPIFFE_WORKLOAD_API_SOCKET|SUPERVISOR_IDENTITY_MOUNT_NS|OPENSHELL_" | sort
  # presence of the symbol in the shipped binary:
  (command -v strings >/dev/null && strings -a /proc/1/exe 2>/dev/null | \
     grep -iE "prepare_supervisor_identity_mount_namespace_from_env|supervisor identity mount" | head) || true
'
```

**Tier 1 verdict to record:** (a) pod-userns ON/OFF; (b) supervisor uid_map (init vs sub-range);
(c) owner userns of `/proc/1/ns/mnt` vs the userns holding caps; (d) whether
`SUPERVISOR_IDENTITY_MOUNT_NS` is populated in a normal (non-provider_spiffe) sandbox. If (a)=ON
and (c) mismatched, the cause is pinned to userns/cap and the ADR-0011 native-unblock work item
must be re-authored around userns alignment (e.g. ensure the supervisor captures/restores within
a single userns, or run the pod with `hostUsers: true`), NOT around mount-propagation flags.

## Tier 2 — confirm with the live failing syscall (MUTATION; explicit approval only)

Only after Tier 1 + approval + a healthy control plane. Enable `provider_spiffe` on **one**
disposable test sandbox and capture the exact failing call:
```sh
# (scoped enable per platform/openshell/values-openshift.yaml on a single test sandbox)
# Then, on the node, strace the supervisor through the identity-mount sequence:
oc debug node/<node> -- chroot /host sh -c '
  pid=$(crictl inspect $(crictl ps -q --name <test-sandbox>) | jq -r .info.pid)
  strace -f -tt -e trace=setns,unshare,mount,umount2 -p "$pid" 2>&1 | head -40
'
# Expect: unshare(CLONE_NEWNS)=0, mount(...MS_*...)=0, setns(<original_fd>, CLONE_NEWNS)=-1 EPERM.
# Confirm errno==EPERM (not EINVAL) and that it persists regardless of the propagation flag.
```
Tear the test sandbox down immediately after; revert `provider_spiffe`.
```
