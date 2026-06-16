# Runbook — pin the native `provider_spiffe` setns-EPERM cause (READ-ONLY first)

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
