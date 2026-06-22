# ADR-0011: E2E delegated-agent journey — OpenShell-native vs Variant-B + ext-proc (and the hybrid target)

> **⚠️ "Chosen unblock path" SUPERSEDED 2026-06-20 by [ADR-0017](0017-provider-spiffe-setns-selinux-confinement.md).**
> The scoped `MS_SLAVE`/`MS_PRIVATE` remount **fork-patch below is DEAD — do not build it.** The native
> `provider_spiffe` setns-EPERM was CONFIRMED LIVE to be **SELinux `container_t` confinement** (class
> `capability` perm `sys_admin`), proven by a `spc_t` positive control that succeeds *with the real CSI
> mount + tmpfs hide present* — so it is neither mount propagation nor a userns mismatch (both ruled out
> three ways). The fix is a custom confined SELinux domain `openshell_sandbox_t`, delivered via SPO +
> Kyverno (ADR-0017). This ADR's **standing hybrid decision is RETAINED**: ext-proc stays in front as
> the per-tool tool-scope gate + audit emitter; jit-approver's `UpdateConfig` network elevator stays
> native; native supplies the credential mint only.

- **Status:** Proposed — *standing decision (stay on Variant-B + ext-proc) REINFORCED 2026-06-16 by an off-cluster disproof of the native-unblock premise (see "UPDATE" below); native-unblock CAUSE+FIX resolved 2026-06-20 in ADR-0017.*
- **Date:** 2026-06-16
- **Related:** ADR-0008 (SVID into launched sandbox), ADR-0009 (native delegation + OCP/CRI-O blocker; provider-spiffe EPMM mount-propagation), ADR-0010 (ida TUI hybrid compose over OpenShell)

## UPDATE 2026-06-16 — off-cluster disproof of the setns-EPERM propagation premise (mustFix #1 → `holds=false`)

The rank-1 unblock below assumed the live `setns`-back EPERM is a **mount-propagation
reconciliation** conflict, fixable by scoping the private remount to the CSI mountpoint. An
off-cluster fixture built to mustFix #1's spec (`experiments/phaseA-epmm-fixture/`,
`FINDINGS.md`) **disproves that premise**:

- **Faithful CRI-O fixture, every mode passes.** `fixture.c` mirrors
  `create_supervisor_identity_mount_namespace` syscall-for-syscall under the exact topology
  (shared peer-group master held in a "host" ns via an open fd; the `/spiffe-workload-api` CSI
  mountpoint delivered into a "pod" ns as a propagated member; tmpfs overlay on that same
  mountpoint). Swept `TOPO={external,local} × MODE={buggy(`MS_REC|MS_PRIVATE /`),private,slave,none}`
  in privileged containers (real CAP_SYS_ADMIN, host user namespace = OCP privileged-SCC posture).
  **All 8 runs: `setns` back succeeds, socket hidden, no re-leak.** The recursive remount the ADR
  blamed does **not** cause a setns EPERM here — so the fixture cannot even distinguish the "fix"
  from the "bug."
- **Kernel source confirms why.** `fs/namespace.c::mntns_install` has **no mount-propagation
  logic**; `setns(CLONE_NEWNS)` EPERMs **only** on the capability triple
  (`ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)` × target-cred-userns × `current_user_ns()`).
- **The real EPERM is a user-namespace capability mismatch.** `fixture_caps.c` reproduces the
  exact EPERM when the process holds CAP_SYS_ADMIN only over its *own* (child) user namespace
  while the original mount namespace is owned by a *different* (parent/init) user namespace — and
  it EPERMs **identically for the recursive `buggy` and the scoped `private` modes**, i.e. the
  propagation flag is irrelevant to the failure.

**Consequence for the decision below.** "Scope the supervisor identity private remount" almost
certainly **does not unblock native `provider_spiffe`** — it changes a flag the EPERM does not
depend on. This **strengthens** the standing decision (stay on Variant-B + ext-proc) and
**re-scopes** the native-unblock investigation away from mount propagation and onto
**user-namespace / capability ownership** of the supervisor's mount namespace on OCP/CRI-O. The
remaining open question — *why* the deployed supervisor's process lacks CAP_SYS_ADMIN over the
user_ns that owns its original mnt-ns at setns-back time — is now a **READ-ONLY live diagnostic**
(see `docs/runbooks/phaseA-userns-cap-diagnostic.md`), not an off-cluster modeling exercise. The
"Chosen unblock path" and "Next steps #3/#5" below are therefore **superseded**: do **not**
author or ship the scoped-remount patch as the unblock until a live diagnostic pins the cause to
propagation (it almost certainly will not).

## Context

The user wants to run the full end-to-end delegated-agent journey **natively** via the OpenShell TUI
(`openshell term`) — using OpenShell's own remote sandboxes plus native provider token-grant delegation —
instead of the proven "Variant-B" stand-in (a separate agent-sandbox harness pod plus our ext-proc
Vault-grant / SVID bolt-on).

**What is proven today (Variant-B + ext-proc, live on runc).** The agent calls the gateway with its own SVID;
ext-proc `handleSandboxAgentPath` verifies the SVID, reads the Vault grant by `sandbox_uid`, checks nonce/TTL/scope
fail-closed, performs the RFC 8693 exchange to `sub=user`, and emits a rich per-call audit event
(`services/ext-proc-delegation/internal/audit/audit.go:80-105,162-177,200-225`:
`caller_username`/`grant_result`/`grant_scope`/`jit_elevated`/`jit_session_id`/`decision`/`mcp_tool`/`args_hash`).
The per-tool JIT loop is proven end-to-end (commit `e720e09`: `403 grant_scope_denied` → Gitea PR #9 merge →
sandbox-bound session JWT → elevated retry of exactly `create_firewall_rule_advanced`,
`services/ext-proc-delegation/internal/extproc/server.go:639-687`).

**The blocker for going native (ADR-0009).** Enabling OpenShell native `provider_spiffe` crashes every sandbox on
OCP/CRI-O with `failed to restore original mount namespace ... setns: EPERM`. Confirmed in source: the supervisor's
`create_supervisor_identity_mount_namespace(target: &Path)` (`OpenShell/.../process.rs:283-311`) opens the original
mnt-ns, calls `private_mount_namespace()` (`:320-348`) = `unshare(CLONE_NEWNS)` (`:322`) **then**
`mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)` (`:330-340`), overlays a read-only tmpfs at the SPIFFE socket parent
(`mount_empty_tmpfs`, `:364-384` — the actual hide), then `set_mount_namespace(original)` (`setns`, `:351-361`).
The EPERM fires at the **setns back to the original namespace** (surfaced at `:299`), not on unshare or MS_PRIVATE
(the SA is `scc=privileged` with `SYS_ADMIN`, so both succeed). Root cause is host-side: the
`spire-spiffe-csi-driver` DaemonSet mounts `/var/lib/kubelet/pods` `Bidirectional` (rshared, confirmed live), so
CRI-O delivers the `csi.spiffe.io` Workload-API socket into the pod as a **shared peer-group** member. The recursive
`MS_REC|MS_PRIVATE` over `/` severs that peer-group membership for the whole subtree, and the kernel's
`mntns_install`/`commit_tree` reconciliation then refuses the switch back → EPERM. OpenShell's reference runtime
(k3d/containerd) lands the same CSI mount **private**, so the recursive remount is a no-op there and setns always
reconciles — which is why native works upstream but not on OCP.

Critically, the same env var (`PROVIDER_SPIFFE_WORKLOAD_API_SOCKET`) is **both** the SVID source for token-grant and
the trigger for the mount isolation (`process.rs:217-227`), and the native flow **explicitly drops the ext-proc hot
path** where our per-tool JIT and rich audit live (ADR-0009 Decision 1).

## Decision

**Stay on Variant-B + ext-proc now; target a hybrid, not pure native.**

- **Now (the delegated-credential + per-tool-JIT spine):** keep the proven Variant-B + ext-proc path. It works live
  on runc, gives per-tool JIT and receipts, and is the only path with no in-session blocker.
- **Single-pane UX:** deliver the operator experience through the **ida TUI hybrid** (ADR-0010) — Approvals / Receipt
  / Logs tabs over the proven path — rather than raw `openshell term`. The user's single-pane desire is a UX/TUI
  delta, not a requirement to mint the delegated credential natively.
- **Target (future):** bring OpenShell native `provider_spiffe` in **only as the credential-mint leg**, behind a
  **retained ext-proc tool-scope gate + audit emitter** — a hybrid mirroring ADR-0010's TUI posture. Native is the
  best call **only after** the mount-fix lands **and** ext-proc is kept in front for per-tool JIT + audit.

This is decisive on three grounds: (1) native is hard-blocked on OCP/CRI-O by the setns EPERM with **no** no-patch,
in-session fix; (2) native authorizes only at `(endpoint, audience, scope)` grain and has no per-MCP-tool deny to
elevate, collapsing JIT from a per-tool exception into a coarse scope/network bump; (3) audit parity fails outright —
the native injection site emits only `tracing::warn!` on error
(`OpenShell/.../l7/token_grant_injection.rs`), with no structured per-call event. The one genuine native win
(zero-fork once unblocked + credential minted in-supervisor with a smaller exposure window) does **not** offset the
blocker + JIT regression + audit loss.

## Chosen unblock path for `provider_spiffe`

> **⚠️ SUPERSEDED 2026-06-16 (see "UPDATE" at top).** The off-cluster disproof shows the
> setns-back EPERM is capability/user-namespace driven, **not** propagation driven. The
> scoped-remount path below changes a flag the EPERM does not depend on and almost certainly does
> not unblock native `provider_spiffe`. Retained for provenance; do not implement until a
> READ-ONLY live diagnostic pins the cause to propagation.

**Scope the supervisor identity private remount to the SPIFFE socket mount only — drop the recursive
`MS_REC|MS_PRIVATE` over `/`.** (Synthesis rank 1; the only path that genuinely unblocks native `provider_spiffe`
while preserving the no-credential-passing invariant.)

**Exact change.** In `OpenShell/crates/openshell-supervisor-process/src/process.rs`:
- `private_mount_namespace()` (`:319-348`) currently does `unshare(CLONE_NEWNS)` (`:322`) then
  `mount(NULL, c"/", NULL, MS_REC|MS_PRIVATE, NULL)` (`:330-340`).
- Keep `unshare(CLONE_NEWNS)`. **Replace** the recursive `/` remount with a **non-recursive**
  `mount(NULL, <socket-parent>, NULL, MS_SLAVE, NULL)` (no `MS_REC`). Try `MS_SLAVE` first; fall back to a
  **non-recursive** `MS_PRIVATE` on the same target if the socket still leaks into children.
- This is purely additive plumbing: `create_supervisor_identity_mount_namespace` (`:283`) already receives the exact
  `target: &Path` (computed by `supervisor_identity_mount_target`, `~:229-269`) and currently passes it only to
  `mount_empty_tmpfs` (`:292`). Thread that same `target` into `private_mount_namespace` (currently zero-arg at
  `:320`). No new path logic.
- Leave `mount_empty_tmpfs` (`:364-384`, the real hide) and the setns restore (`:299`) byte-for-byte unchanged.

**Why it clears EPERM.** The EPERM is propagation reconciliation on setns-restore, not a capability gap. By **not**
recursing over `/` and applying `MS_SLAVE` to only the socket-parent mount, the CSI peer group is left intact for the
rest of the tree, and `MS_SLAVE` keeps the **inbound** propagation edge the kernel checks on restore (slave still
RECEIVES from the master peer, it just stops SENDing), so setns reconciles cleanly. The socket stays hidden from the
agent's children by the unchanged tmpfs overlay. This is exactly why k3d/containerd never broke: there the CSI mount
already lands private, so the recursive MS_PRIVATE was already a no-op.

**Structural correction (must carry into the patch/PR).** `target` is **not** a directory that merely *contains* the
CSI mount — it **is** the `csi.spiffe.io` mountpoint itself: `spiffe_socket_mount_path()` =
`supervisor_identity_mount_target` = `/spiffe-workload-api` (driver.rs:1429; process.rs:268). So the remount acts
directly on the shared CSI mount (shared→slave), and the tmpfs overlays that same mountpoint. Any test fixture or
upstream PR description must reflect this topology or it will exercise the wrong mounts.

### Adversarial verdicts (folded in as conditions)

Three lenses reviewed the fix. **`no-credential-passing` holds** (the fix is a propagation-flag change only; env-strip
+ topmost tmpfs overlay, neither altered, govern the agent's view of the socket). **`svid-delivery-and-binding`
holds** (the **supervisor** fetches the SVID in the original namespace via `token_grant.rs:255-276`; the throwaway
child ns is discarded after setns-restore, so identity/audience binding is byte-identical pre/post fix).
**`mount-ns-correctness` does NOT hold as written** — `holds=false`, medium confidence — because the load-bearing
claim "clears the setns EPERM" is mechanically plausible but **unverified and unverifiable in this environment**
(provider_spiffe is rolled back live, the SNO is READ-ONLY, and OpenShell has zero runtime tests for the
mount/setns path; `MS_SLAVE` appears nowhere in the tree). The fix therefore lands **conditional on** these mustFix
gates:

1. **Off-cluster CRI-O-shaped fixture (load-bearing):** in a fixture with `/var/lib/kubelet/pods` rshared → per-pod
   bind-mount in a shared peer group + tmpfs overlay at the CSI mountpoint, prove non-recursive `MS_SLAVE` on
   `/spiffe-workload-api` lets setns back to the original ns reconcile **without EPERM**, AND that the real
   `spire-agent.sock` is **not** statable/connectable from inside the entered snapshot ns. The whole fix stands or
   falls on this; do **not** trust it from reasoning alone.
2. **Resolve `MS_SLAVE`-vs-`MS_PRIVATE` explicitly, not as a mere fallback.** `MS_SLAVE` keeps an inbound edge, so a
   post-overlay host CSI mount/unmount under `/spiffe-workload-api` could propagate a child mount into the agent ns
   and re-expose the socket beneath/over the tmpfs. Prefer **non-recursive `MS_PRIVATE`** for the hide guarantee and
   prove **that** reconciles setns; only fall back to `MS_SLAVE` if `MS_PRIVATE` still EPERMs, and if so add a test
   that no host-side propagation can surface the socket post-snapshot. Validate the `MS_PRIVATE` fallback is itself
   non-recursive and scoped to the socket-parent (NOT `MS_REC`, NOT over `/`), else the fallback silently reintroduces
   the original blocker.
3. **Propagation re-leak test:** after `MS_SLAVE`+tmpfs setup, trigger a CSI-style mount **and** unmount on the master
   peer group and assert the real socket does not reappear at the in-container mountpoint.
4. **Correct-mount / correct-order assertions:** slave the **existing** socket-parent mount **before** stacking the
   tmpfs; assert the `target` threaded into `private_mount_namespace` is byte-identical to the one
   `mount_empty_tmpfs` receives (reuse the single `supervisor_identity_mount_target` result; do not recompute). A
   wrong-target or wrong-order slave is the only way the hide regresses.
5. **Additive-only regression guard:** assert `SUPERVISOR_ONLY_ENV_VARS` still strips
   `OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET` (`process.rs:31-46,472`) and that child-entry (`ssh.rs:1196-1198`)
   still runs **before** drop_privileges/Landlock/seccomp. The fix must not reorder these.
6. **Confirm the deployed call path.** `prepare_supervisor_identity_mount_namespace_from_env` (`process.rs:189`) — the
   sole populator of `SUPERVISOR_IDENTITY_MOUNT_NS` consumed by the agent pre_exec (`:524`) — has zero callers in the
   tracked tree at `ed65bfd`. Validate against the **actual deployed supervisor image**, not just this checkout, so the
   patched function is provably the one exercised live.
7. **Off-cluster only until green:** do **not** re-enable `provider_spiffe` on the live SNO to test (READ-ONLY/fragile,
   provider_spiffe rolled back, etcd ~1.1GB, kyverno parked at 0). Prove the fix in a CRI-O-or-equivalent
   shared-peer-group fixture or a disposable node first.

The fix **patches OpenShell** (violates the user's no-fork intent), so carry it as a fork-built supervisor image
(image-maintenance burden) until/unless upstreamed to NVIDIA/OpenShell (origin `NVIDIA/OpenShell`, head `ed65bfd`;
DCO/RFC/vouch timeline per ADR-0010, may not land before a demo deadline).

## Alternatives considered

1. **K8s mount-propagation fix (host-side spiffe-csi rslave/rprivate) — rank 2, NOT viable.** Does not patch
   OpenShell, but the lever is wrong. The OpenShell k8s driver already emits the CSI volumeMount with no propagation
   field (`driver.rs:1426-1432`), i.e. kubelet-default None/rprivate, and EPERM still fires — proving pod-side
   propagation is not the cause. The real source is host-side `Bidirectional`/rshared on `/var/lib/kubelet/pods`,
   structurally required for any CSI node driver to publish. The `ZeroTrustWorkloadIdentityManager` operator reconciles
   that DaemonSet and the `SpiffeCSIDriver` CR exposes no propagation knob (manual edits revert); forcing rslave risks
   breaking CSI publish for all pods, and a node MachineConfig is high-blast-radius on a fragile READ-ONLY SNO.

2. **Sidecar-file SVID delivery (`svid-vault-fetch` `WRITE_SVID_PATH` writes JWT-SVID to a file) — rank 3, NOT
   viable.** `fetch_jwt_svid_for_token_grant` (`token_grant.rs:255-276`) is **socket-only**; there is no file/env SVID
   reader anywhere in the tree. The same env var is also the EPERM trigger (`process.rs:217`), and
   `supervisor_identity_mount_target` hard-rejects `tcp:`. Making this work natively requires a **larger** fork than
   rank 1 (~3 sites: token_grant fetch path + process.rs identity-mount gating + driver.rs env/CSI wiring) and
   re-opens RFC7523-against-Keycloak re-testing. The file-write path **is** the right primitive for the Variant-B
   bolt-on (it already feeds jit-approver `vault.py` via `SVID_JWT_PATH`) — just not for native `provider_spiffe`.

3. **Runtime change (runc ↔ Kata `runtimeClassName` flip) — rank 4, clears nothing.** runc is already the live/correct
   choice for native (every supervised sandbox in ns `openshell` runs `runtimeClassName=<none>`/runc, `scc=privileged`,
   caps `SYS_ADMIN/NET_ADMIN/SYS_PTRACE/SYSLOG`) and still EPERMs, because the cause is host-side rshared CSI
   propagation, not runc-vs-Kata. Kata cannot use `csi.spiffe.io` at all (the host unix Workload-API socket cannot
   cross the micro-VM boundary), so Kata sandboxes carry no CSI volume and must use the nested-in-VM SPIRE-agent +
   join_token design — independently blocked per ADR-0008 (join_token NodeAttestor not durable, ZTWIM reverts,
   SandboxTemplate exposes no sidecar/volume/join_token fields) and proven live by `openshell-agent-kata` in
   Failed/exit-2. Kata is a trap, not an unblock.

## Consequences

- **Native drops the ext-proc hot path (ADR-0009 Decision 1).** The per-tool, sandbox-bound, fail-closed JIT elevator
  (`server.go:639-687`) and the rich per-call audit (`audit.go`) have **no** native equivalent — native authorizes at
  `(endpoint, audience, scope)` grain with error-only tracing. The hybrid must therefore **explicitly keep ext-proc on
  the request path as the tool-scope gate + audit emitter**, even after the supervisor mints the Bearer natively
  post-L7/OPA. If native delegation displaces ext-proc, the proven `403 → approve → retry-this-exact-tool` loop and the
  Receipt surface are lost.

- **JIT spans two independent authorization boundaries, wired differently:**
  - **Boundary #1 — OpenShell POLICY (network-egress floor+elevator):** jit-approver already drives this **natively**
    via the gateway `UpdateConfig` RPC with `AddNetworkRule`/`RemoveNetworkRule` merge-ops
    (`services/jit-approver/.../openshell.py:180-215,291-317`, `RULE_PREFIX 'jit-'`, time-boxed + auto-reverting onto
    `baseline.yaml`). It is **model-independent** — it gates the supervisor's network floor, not the credential mint —
    and is **kept native in Variant-B, native, and hybrid**.
  - **Boundary #2 — MCP TOOL-SCOPE (read-only baseline → dangerous-tool elevation):** lives **entirely** in ext-proc
    `handleSandboxAgentPath` (`server.go:639-687`). A sandbox-bound jit-approver session JWT, cryptographically bound
    (`jwt.sandbox_uid == svid.sandbox_uid`) + `containsTool(tool_scope, tool)`, lifts the baseline for **one** tool,
    fail-closed, emitting `jit_elevated`/`jit_session_id`. This boundary has **no home** in pure native and **stays in
    ext-proc** in the hybrid.

- **Approvals / Receipt integration (ida TUI, ADR-0010):** Approvals tab → Gitea PR approve → jit-approver mints the
  bound session JWT for boundary #2 **and** fires `UpdateConfig` for boundary #1; Receipt tab reads the per-call audit
  that **only ext-proc produces**.

- **Operator UX shift:** the single-pane experience is delivered via the **ida TUI hybrid** over the proven path, not
  raw `openshell term`. `openshell term`-native becomes the best UX only **after** the mount-fix lands **and** ext-proc
  is retained in front.

- **What we keep from Variant-B (always):** the ext-proc per-tool tool-scope gate, the rich per-call audit, and
  jit-approver's native OpenShell-policy network elevator. Native (once unblocked) supplies the credential **mint**
  only.

- **Keycloak/JIT caveat for native:** scope-bump as the only native JIT lever is coarse and may require re-minting
  against a different audience/scope cache key (`token_grant.rs:494`) controlled by the supervisor profile, not
  jit-approver — confirm the native path can even express a JIT scope-widen without a supervisor-profile change before
  claiming any native JIT story.

## Next steps (ordered)

1. **Keep running E2E on Variant-B + ext-proc** as the delegated-credential + per-tool-JIT spine. No cluster change.
2. **Deliver the single-pane operator experience via the ida TUI hybrid** (ADR-0010): Approvals → Gitea PR →
   jit-approver (boundary #1 `UpdateConfig` + boundary #2 bound session JWT); Receipt → ext-proc per-call audit.
3. **Prototype the rank-1 mount-fix off-cluster** in a CRI-O-shaped shared-peer-group fixture: thread `target` into
   `private_mount_namespace`, replace `MS_REC|MS_PRIVATE` over `/` with non-recursive `MS_PRIVATE` (preferred) /
   `MS_SLAVE` (fallback) on `/spiffe-workload-api`. Gate on mustFix #1–#4 (setns reconciles **and** socket hidden from
   children **and** no propagation re-leak **and** correct-mount/correct-order).
4. **Validate against the deployed supervisor image** (mustFix #6): confirm the live call path that populates
   `SUPERVISOR_IDENTITY_MOUNT_NS` so the patched function is the one exercised, before trusting any on-cluster result.
5. **Decide fork-build vs upstream PR** to NVIDIA/OpenShell (head `ed65bfd`); if forking, stand up supervisor-image
   maintenance. Frame the PR as a genuine OCP/CRI-O compat fix that weakens no other deployment, with the structural
   correction (target == the CSI mountpoint) in the description.
6. **CAREFUL live test — only after off-cluster green.** Re-enabling `provider_spiffe` on the SNO reintroduces the
   crashing path. The cluster is READ-ONLY/fragile: provider_spiffe is rolled back, etcd is ~1.1GB (defrag first),
   kyverno is parked at 0. Do **not** re-enable for a live test until the fix is validated off-cluster and an etcd
   defrag window exists; coordinate explicitly before any create/apply/scale on the SNO.
7. **When native lands, wire it as the hybrid:** supervisor mints the credential natively (RFC7523/8693) post-L7/OPA;
   **retain ext-proc in front** as the tool-scope gate + audit emitter; keep jit-approver's `UpdateConfig` network
   elevator native. Do **not** let native delegation displace the ext-proc per-tool gate.
