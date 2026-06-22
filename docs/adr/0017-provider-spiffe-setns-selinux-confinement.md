# ADR-0017: provider_spiffe setns-EPERM is a missing CAP_SYS_CHROOT — fix by granting the sandbox that one capability

- **Status:** Accepted — root cause CONFIRMED LIVE and the fix PROVEN on a confined (`container_t`, MCS-intact) sandbox (2026-06-20). Delivery (Kyverno) authored; provider_spiffe enablement pending.
- **Date:** 2026-06-20
- **Supersedes:** ADR-0011's "Chosen unblock path" (the scoped remount fork-patch) and Next-steps #3/#5; ADR-0009's mount-propagation root cause. **Retains** ADR-0011's hybrid decision (ext-proc in front as tool-scope gate + audit; jit-approver `UpdateConfig` network elevator native; native supplies the credential mint only).
- **Part of:** [Master Plan](../plans/openshell-agentic-platform-master-plan.md) → Phase A. **Diagnostic:** [runbook](../runbooks/phaseA-userns-cap-diagnostic.md).

> **⚠️ This ADR was rewritten 2026-06-20 after live testing overturned an earlier (same-day) SELinux
> conclusion.** The first draft blamed SELinux `container_t` confinement, based on a `spc_t` positive
> control that turned out to be **confounded**: every working `spc_t` test was also `privileged: true`,
> which grants the *full capability set* — including the one that actually mattered. Granular testing
> isolated the true cause. The ruled-out theories are recorded below precisely so this isn't
> re-litigated.

## Context

The user wants the native OpenShell delegated-agent journey, which needs `provider_spiffe`. Enabling it
crashes every sandbox on OCP with `failed to restore original mount namespace ... setns: EPERM`. The
supervisor (`create_supervisor_identity_mount_namespace`, `process.rs:283-311`) hides the SPIFFE socket
from agent children via `unshare(CLONE_NEWNS)` → recursive private remount → tmpfs overlay → **`setns`
back to the original mount namespace**. The `setns`-back is what EPERMs.

## Root cause (CONFIRMED LIVE, read-only + minimal disposable pods)

**The supervisor's sandbox lacks `CAP_SYS_CHROOT`.** The `setns`-back into the original mount namespace
**re-roots** the process into that namespace's root, which the kernel gates on `CAP_SYS_CHROOT` *in
addition to* `CAP_SYS_ADMIN`. OpenShell grants the sandbox `SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYSLOG`
but **not `SYS_CHROOT`** — so `unshare` and `mount` (which need only `SYS_ADMIN`) succeed, while the
`setns`-back EPERMs.

**Proof (all on a single live sandbox node, RHEL 9.6 / kernel 5.14, SELinux Enforcing):**

| Pod config | SELinux ctx | setns-back |
|---|---|---|
| caps `[SYS_ADMIN]` (and `+NET_ADMIN,SYS_PTRACE,SYSLOG`) | `container_t:s0:cX,cY` | **EPERM** |
| **caps `[SYS_ADMIN, SYS_CHROOT]`** | `container_t:s0:cX,cY` (confined, MCS intact) | **OK** ✅ |
| caps `[SYS_ADMIN, SYS_RESOURCE]` / `+DAC_OVERRIDE` / `+DAC_READ_SEARCH` | `container_t` | EPERM |
| `privileged: true` | `spc_t:s0` | OK (because privileged grants ALL caps, incl. SYS_CHROOT) |

The fix works **with MCS categories present and SELinux Enforcing** — confinement is fully preserved.

### Ruled out (each tested live, do not revisit)
- **Mount propagation** (ADR-0009/0011): the no-mount variant and scoped `MS_PRIVATE`/`MS_SLAVE` all EPERM identically; kernel `mntns_install` has no propagation logic.
- **User-namespace mismatch** (ADR-0011 re-scope): pod is in the **init userns** (`uid_map "0 0 4294967295"`, mnt-ns owner = init); `CAP_SYS_ADMIN` effective and functional.
- **SELinux type / domain:** byte-identical `spc_t:s0` context EPERMs when non-privileged but works when privileged → the label is not the cause. Granting `container_t` `capability sys_admin` (module) did NOT help. The `virt_sandbox_use_sys_admin` boolean is **ineffective** for `container_t` (targets legacy `sandbox_t`). A custom `openshell_sandbox_t` domain's transition worked but kubelet couldn't manage it — moot, since SELinux was never the cause.
- **Seccomp:** EPERM persists with `Seccomp: 0` (unconfined) → not seccomp.
- **no_new_privs:** EPERM persists with `NoNewPrivs: 0` → not it.

## Decision

**Grant the OpenShell sandbox `CAP_SYS_CHROOT` (added to its existing `SYS_ADMIN, NET_ADMIN, SYS_PTRACE,
SYSLOG`).** No SELinux policy, no custom domain, no MachineConfig/SPO, no `privileged: true`, no seccomp
change. The sandbox stays `container_t` with MCS categories — fully confined; we add exactly one
capability that the supervisor's own code path requires.

- **Delivery:** a Kyverno mutate `ClusterPolicy`
  (`platform/kyverno/guardrails/base/mutate-openshell-sandbox-syschroot.yaml`) adds `SYS_CHROOT` to every
  container in `openshell` sandbox pods at CREATE (matched by `openshell.ai/managed-by=openshell`).
  Admission-time mutation is durable and revert-immune — the OpenShell chart/SandboxTemplate don't expose
  sandbox capabilities, and ArgoCD/the driver revert CR-level edits.
- **Upstream:** the cleaner long-term fix is OpenShell granting `SYS_CHROOT` to the sandbox itself when
  `provider_spiffe` is enabled (its supervisor needs it). File this as an OpenShell bug; the Kyverno mutate
  is the durable workaround until then.
- **Hybrid retained:** native supplies the credential mint only; ext-proc stays in front (per ADR-0011).

## Consequences

- **POSITIVE:** minimal, surgical, **confinement-preserving** (container_t + MCS + seccomp all intact);
  no node-level SELinux change, no reboot, no new operator; GitOps-durable via the existing Kyverno
  guardrails kustomize. The no-stored-credential invariant is untouched (the supervisor still fetches the
  SVID live in its original ns; env-strip + tmpfs hide unchanged; the capability only lets it return).
- **NEGATIVE / caveats:** `CAP_SYS_CHROOT` is a real capability grant, but narrow and well-understood
  (it permits `chroot(2)`; the sandbox is already root with `SYS_ADMIN`, so this is a small marginal
  increase). The Kyverno match label `openshell.ai/managed-by=openshell` is stamped by OpenShell only when
  `provider_spiffe` is enabled — so the mutate fires exactly when needed (see Gate-2 in the loop doc if the
  label isn't stamped). Removed artifacts: the earlier SELinux CIL/MachineConfig/SPO/SELinux-mutate (wrong
  root cause) were deleted.

## Remaining work (ordered)
1. Apply the Kyverno mutate (`platform/kyverno/guardrails/base`).
2. Enable `provider_spiffe` (`platform/openshell/values-openshift.yaml` — already `true` in git, rolled back live; sync). Gateway-wide → restarts sandboxes; pre-gate etcd (defragged 2026-06-20, 1.2GB→728MB).
3. Verify a real sandbox: `setns` reconciles (no crash), socket hidden from the agent child, SVID delivered; sandbox stays `container_t` with `SYS_CHROOT` present.
4. Gate-2: confirm OpenShell stamps `openshell.ai/*` labels on enable (so both the Kyverno mutate and the `openshell-sandbox-workloads` ClusterSPIFFEID match); fix selector iff not.
5. Hybrid acceptance (`hack/test-openshell-native-hybrid.sh`): SVID-only→403; JIT-elevate→200+audit; post-TTL→403.
