# Phase A findings — the scoped-remount fix premise does NOT hold off-cluster

**Date:** 2026-06-16  **Status:** mustFix #1 (ADR-0011) returned `holds=false` — as the
adversarial review predicted (medium confidence). Do NOT proceed to a live `provider_spiffe`
re-enable on this basis.

## What was built
- `fixture.c` — mirrors `process.rs::create_supervisor_identity_mount_namespace`
  syscall-for-syscall (open original mnt-ns fd → `unshare(CLONE_NEWNS)` → propagation step →
  RDONLY tmpfs overlay at the CSI mountpoint → open sanitized fd → `setns(original)`), under
  the faithful CRI-O topology: a shared peer-group MASTER held in a "host" ns (kept alive by an
  open fd), with the `csi.spiffe.io` mount delivered into a "pod" ns as a propagated member
  (`TOPO=external`). Structural correction honored: `target` IS the `/spiffe-workload-api`
  mountpoint itself (shared), and the tmpfs overlays that same mountpoint.
- `fixture_caps.c` — control isolating the actual EPERM source.
- `run.sh` — sweeps `TOPO={external,local} × MODE={buggy,private,slave,none}` in privileged
  containers (real CAP_SYS_ADMIN, host user namespace = faithful OCP privileged-SCC posture).

## Results
| fixture | topology | mode (propagation) | setns-back | socket hidden | re-leak |
|---|---|---|---|---|---|
| fixture.c | external & local | buggy (`MS_REC\|MS_PRIVATE /`) | **OK (no EPERM)** | hidden | none |
| fixture.c | external & local | private (`MS_PRIVATE` on CSI mountpoint) | OK | hidden | none |
| fixture.c | external & local | slave (`MS_SLAVE` on CSI mountpoint) | OK | hidden | none |
| fixture.c | external & local | none (control) | OK | hidden | none |
| fixture_caps.c | userns cap-mismatch | buggy | **EPERM** | — | — |
| fixture_caps.c | userns cap-mismatch | private | **EPERM** | — | — |

## Conclusion (load-bearing)
1. **The documented root cause is mechanically wrong.** `setns(CLONE_NEWNS)` into a mount
   namespace EPERMs **only** on the capability triple in `fs/namespace.c::mntns_install`
   (`ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)` × target-cred-userns × `current_user_ns()`).
   There is **no mount-propagation reconciliation** on the setns path. So a recursive
   `MS_REC|MS_PRIVATE` over `/` cannot, by itself, cause a setns-back EPERM — confirmed across
   8 fixture runs (every mode/topology succeeds in a privileged host-userns container).
2. **The real EPERM is a user-namespace capability mismatch.** `fixture_caps.c` reproduces the
   exact EPERM when the process holds CAP_SYS_ADMIN only over its own (child) user namespace
   while the original mount namespace is owned by a different (parent/init) user namespace —
   **and it EPERMs identically for `buggy` and `private`**, i.e. the propagation flag is
   irrelevant to it.
3. **Therefore the ADR-0011 rank-1 fix (scope the remount to the CSI mountpoint) likely does
   NOT clear the live EPERM.** It changes a flag the EPERM does not depend on. If the live
   cause is userns/cap ownership (the only kernel-supported EPERM source here), scoping the
   remount is a no-op on the failure.

## What this does NOT settle (needs a READ-ONLY live diagnostic on the SNO)
Why the deployed supervisor hits a userns/cap mismatch at setns-back on OCP 4.20/CRI-O. The
mechanism is now narrowed to capabilities, not propagation. The decisive evidence must come
from the actual node, READ-ONLY (no mutation):
- The real errno + call site: `strace -f -e trace=setns,unshare,mount` (or the supervisor's
  own error) on a sandbox pod with `provider_spiffe` enabled.
- The userns topology at setns time: ownership of the supervisor's original mnt-ns vs the
  process's `current_user_ns` (`/proc/<pid>/ns/{user,mnt}`, `/proc/<pid>/uid_map`), and whether
  CRI-O is running the pod with user namespaces (`runAsUser`/userns annotations, `crio` config).
- Whether OpenShell drops privileges / changes creds between `unshare` and `setns` in the
  DEPLOYED image (ties to ADR-0011 mustFix #5/#6 — child-entry ordering and the actual caller
  of `prepare_supervisor_identity_mount_namespace_from_env`).

## Recommendation
Do NOT author or ship the scoped-remount patch as the unblock until the live cause is pinned
to propagation (it almost certainly isn't). Treat this as strengthening ADR-0011's standing
decision: **stay on Variant-B + ext-proc** (per-tool JIT + rich audit), and re-scope the
"native provider_spiffe unblock" investigation around user-namespace/capability ownership, not
mount propagation. The single-pane UX stays the ida TUI hybrid (ADR-0010), unaffected.
