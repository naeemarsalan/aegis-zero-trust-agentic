# ADR-0009: Make OpenShell native provider_spiffe work on anaeem (mount-ns EPERM)

## Status
Proposed
[SECURITY-OPEN] Keycloak must be configured to accept JWT-SVID client assertions
(jwt-bearer) bound to the SPIRE issuer before delegated credentials can flow.

## Date
2026-06-16

Related: ADR-0008 (SVID into launched sandbox — BLOCKED via template), ADR-0003
(token-exchange), docs/design/agent-harness.md, platform/spire, platform/openshell,
services/ext-proc-delegation.

## Context

The user directive: run OpenShell as designed and change cluster infra around it —
do NOT patch OpenShell. We enabled native `provider_spiffe`
(`server.providerTokenGrants.spiffe.enabled=true`,
`platform/openshell/values-openshift.yaml`) and the sandbox **supervisor crashed**:

> failed to restore original mount namespace after supervisor identity isolation
> setup: failed to enter mount namespace: Operation not permitted (EPERM)

Sandboxes WITHOUT the `csi.spiffe.io` volume boot fine. The crash only appears when
the SPIFFE Workload API CSI volume is mounted.

### What the supervisor actually does (verified)
`crates/openshell-supervisor-process/src/process.rs:283-311`
(`create_supervisor_identity_mount_namespace`):

1. open `/proc/thread-self/ns/mnt` (original ns fd)
2. `unshare(CLONE_NEWNS)` then `mount(MS_REC|MS_PRIVATE, "/")` — recursively private
3. overlay an empty read-only tmpfs at the SPIFFE socket parent dir to hide it from
   child processes
4. `setns(original_ns_fd, CLONE_NEWNS)` to return — **this is where EPERM fires**

The Kubernetes driver already grants the supervisor everything it needs to do the
mount work itself: `runAsUser: 0` (`driver.rs:980`) and capabilities
`SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYSLOG` (`driver.rs:1397`). So `unshare` and the
recursive `MS_PRIVATE` succeed. **The EPERM is NOT a missing capability.**

### Root cause (precise)
`setns(CLONE_NEWNS)` back to the original namespace fails because of a **mount
propagation reconciliation conflict** introduced by the CSI socket mount:

- The upstream SPIFFE reference (k3d / vanilla kubelet) lands the `csi.spiffe.io`
  Workload API socket directory in the pod such that the recursive `MS_PRIVATE`
  inside the child namespace is a no-op on restore.
- On anaeem (OCP 4.20 SNO, **CRI-O**), the `csi.spiffe.io` socket dir is propagated
  into the pod mount namespace as part of a **shared/peer-group** mount. After the
  supervisor flips everything `MS_REC|MS_PRIVATE` in the child namespace, the kernel
  cannot reconcile the now-divergent propagation state of `/spiffe-workload-api`
  between the child and the original peer group when `setns` tries to re-enter →
  EPERM.

This is the OpenShift-specific delta the upstream reference never had to handle.
There is a SECOND OpenShift-specific delta layered on top: anaeem's default SCC
(`restricted-v2`) would strip `SYS_ADMIN`, force `runAsNonRoot`, and pin seccomp
`RuntimeDefault` — which alone would block the whole isolation sequence. The chart's
sandbox posture (runAsUser:0, the 4 caps above, AppArmor `Unconfined`) requires an
SCC that actually admits it. The `openshell` sandbox SA does not yet have one.

## Decision

Fix this entirely on the infrastructure side. No OpenShell code change.

1. **SCC for the sandbox SA.** Bind a dedicated SCC (clone of `privileged` minus
   what we don't need, or `privileged` itself for the PoC) to the ServiceAccount that
   runs sandbox pods in namespace `openshell`, mirroring the existing
   `platform/agentgateway/base/scc-rolebinding.yaml` pattern. The SCC must permit:
   `runAsUser: 0` (RunAsAny / 0 allowed), `allowedCapabilities` including
   `SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYSLOG`, `seccompProfiles: ['*']` (so the chart
   may set/omit and AppArmor `Unconfined` is allowed), `allowPrivilegeEscalation:
   true`, `allowHostDirVolumePlugin: false`, and `volumes` including `csi` and
   `projected`. This is what the upstream "it just works on k3d" cluster effectively
   already permits.

2. **Fix CSI mount propagation so setns can reconcile.** Make the `csi.spiffe.io`
   Workload API socket land in the pod as a **non-shared (rprivate / rslave)** peer so
   the supervisor's recursive `MS_PRIVATE` is reconcilable on restore. Order of
   preference:
   - (a) Set the ZTWIM `SpiffeCSIDriver` / spiffe-csi-driver Daemonset socket
     directory propagation to private (`rprivate`) at the host, OR
   - (b) Ensure CRI-O on the SNO node mounts the CSI volume into the pod with
     `mountPropagation: None` (Kubernetes default → `rprivate` at the container
     boundary). The OpenShell driver already does NOT set `mountPropagation` on the
     volumeMount (`driver.rs:1426-1432`), so the kubelet default applies; the conflict
     comes from the HOST-side spiffe-csi mount being `rshared`. The durable fix is the
     host-side daemonset propagation.

3. **Run sandboxes on `runc`, not Kata, for the native path.** Native `provider_spiffe`
   delivers the Workload API via a host unix socket through `csi.spiffe.io`, which
   cannot cross the Kata micro-VM boundary (already recorded in ADR-0008 and pinned in
   `values-openshift.yaml: runtimeClassName: ""`). Keep `runtimeClassName: ""` (runc)
   for the native delegated-credential path. Kata hardening is a separate track
   (nested in-VM SPIRE agent, ADR-0008).

4. **Adopt OpenShell native provider token-grant for the delegated credential.**
   Replace our bolt-on ext-proc Vault-grant + SVID-path delegation with the native
   `ProviderCredentialTokenGrant` flow (RFC 7523 JWT-SVID client assertion → OAuth2
   token at Keycloak → Authorization header injected by the supervisor L7 relay,
   `crates/openshell-supervisor-network/src/token_grant.rs`). This keeps the credential
   inside the sandbox/supervisor and never forwards it — it satisfies the
   no-credential-passing invariant by construction.

## Consequences

### Positive
- OpenShell runs as designed; zero fork/patch maintenance burden.
- Delegated credential is obtained at request time by the supervisor, per-endpoint,
  and cached in-process — smaller exposure window than the centralized Vault grant.
- Drops the ext-proc-delegation sidecar + Vault grant plumbing from the hot path
  (Vault may remain only for static provider secret storage, if any).
- Standard protocols end-to-end (SPIFFE Workload API + RFC 7523 + OIDC).

### Negative / trade-offs
- The sandbox SA gets an elevated SCC (SYS_ADMIN etc.). This is the supervisor's
  requirement for mount/network-namespace isolation; the untrusted agent process is
  dropped to an unprivileged UID by the supervisor inside the pod. Net posture is
  acceptable but must be documented and network-fenced (sandbox egress policy stays).
- runc (not Kata) for the native path — weaker isolation than a micro-VM. Mitigated by
  SCC scoping + NetworkPolicy + the supervisor's per-sandbox identity isolation.
- Keycloak must trust the SPIRE issuer for jwt-bearer client assertions — new config.

### Security implications
- **No-credential-passing invariant: UPHELD and strengthened.** The user credential
  never enters the sandbox. The agent authenticates with its OWN JWT-SVID (SPIRE
  Workload API, permitted flow #4). The SVID is exchanged for a scoped OAuth2 token at
  Keycloak (RFC 8693 / RFC 7523 token-grant at the boundary, permitted flow #3). The
  scoped token is injected by the supervisor AFTER L7/OPA policy evaluation, so it
  cannot bypass policy and is never placed in agent context, env passed across a
  boundary, an MCP tool argument, or a log line.
- **Authorization at receiver:** Keycloak validates the JWT-SVID assertion (iss=SPIRE,
  aud=realm, sub=spiffe id); the MCP gateway/OPA validates the resulting token. Deny
  path is fail-closed: if SPIRE is unavailable or the token-grant fails, the supervisor
  denies the outbound request (no degraded-but-allowed path).
- **Sandbox network boundary:** unchanged — sandbox egress NetworkPolicy
  (`platform/networkpolicies/base/np-agent-sandbox.yaml`) still applies; the SVID
  socket is read-only and hidden from agent child processes by the supervisor.

## Alternatives considered

| Option | Rejected because |
|--------|-----------------|
| Patch supervisor to skip MS_PRIVATE when CSI mount present | Violates "do not patch OpenShell"; weakens the supervisor's identity isolation. |
| Add only CAP_SYS_ADMIN to the sandbox | Cap is already present (driver.rs:1397); EPERM is propagation, not capability. Necessary-but-insufficient. |
| Keep ext-proc Vault-grant + SVID-path scheme | Bolt-on; centralizes the credential, larger exposure window, extra moving parts; native flow is simpler and equally invariant-safe. |
| Run native path on Kata | csi.spiffe.io host socket cannot cross the Kata VM boundary (ADR-0008). |
| Set mountPropagation: Bidirectional on the volumeMount | Requires privileged + bidirectional is the wrong direction (it would re-share into host); the fix is to make the pod-side mount private/slave. |
