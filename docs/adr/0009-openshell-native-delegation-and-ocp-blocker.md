# ADR-0009: OpenShell-native delegation; and the OCP/CRI-O provider_spiffe blocker

> **⚠️ ROOT CAUSE SUPERSEDED 2026-06-20 by [ADR-0017](0017-provider-spiffe-setns-selinux-confinement.md).**
> This ADR's `provider_spiffe` blocker diagnosis (mount-propagation / rshared CSI) is **WRONG**. The
> setns-EPERM was CONFIRMED LIVE to be **SELinux `container_t` confinement** denying the `setns`-back
> (class `capability` perm `sys_admin`) — proven by a `spc_t` positive control that succeeds with the
> real CSI mount present. It is NOT propagation and NOT a userns mismatch. Do not act on the
> mount-propagation analysis below; see ADR-0017 for the cause, proof, and remediation. The
> Decision-1 native-delegation design is otherwise retained.

Status: **Proposed** (supersedes the delegation approach in agent-harness.md; records a hard OCP blocker)
Date: 2026-06-16
Related: ADR-0008, ADR-0017, docs/design/agent-harness.md

## Decision 1 — Use OpenShell's NATIVE provider token-grant; retire our bolt-on

Run OpenShell the way it's designed. Its **provider token-grant** flow IS the delegated-credential
mechanism we were re-implementing:
- Supervisor (`crates/openshell-supervisor-network/src/token_grant.rs`) fetches a **JWT-SVID** from the
  local SPIRE agent (audience = the token endpoint, e.g. the Keycloak realm), performs an **RFC 7523
  jwt-bearer** client assertion to Keycloak, gets a scoped OAuth2 access token, caches it per
  (endpoint, audience, scopes), and injects `Authorization: Bearer` **after** L7/OPA policy.
- This upholds no-credential-passing **by construction**: the agent uses its own SVID; no user
  credential enters the sandbox; the scoped token never hits agent context/logs; fail-closed if SPIRE
  or Keycloak is down.

**Consequence:** the bolt-on **ext-proc Vault-grant + SVID-path delegation is dropped from the hot
path.** Keep Vault only for static provider-secret storage if needed. Still required for native:
(a) Keycloak trusts the SPIRE issuer for jwt-bearer assertions (iss/JWKS, aud, sub=spiffe-id) +
audience mapper to the MCP resource — `[SECURITY-OPEN]`; (b) an OpenShell **provider profile** with a
`token_grant` block + endpoints for the MCP gateway, attached to the sandbox at create.

## Decision 2 — `provider_spiffe` is BLOCKED on OCP/CRI-O (runtime incompatibility)

Enabling `provider_spiffe` on anaeem (OCP 4.20 SNO) crashes every sandbox:
`failed to restore original mount namespace after supervisor identity isolation setup: setns:
Operation not permitted (EPERM)`.

Root cause (verified): the supervisor's identity isolation
(`crates/openshell-supervisor-process/src/process.rs:283-311`) does
`unshare(CLONE_NEWNS)` → `mount(MS_REC|MS_PRIVATE,"/")` (hide the SVID socket from the agent) →
`setns(original_ns)`. The `csi.spiffe.io` socket is delivered via the spiffe-csi DaemonSet's
`/var/lib/kubelet/pods` **Bidirectional** mount, and **CRI-O lands it in the pod as a SHARED
peer-group mount**; the recursive `MS_PRIVATE` then can't reconcile on `setns` → EPERM. OpenShell's
reference runtime (k3d/containerd) lands the same CSI mount **private**, so the operation is a no-op
on restore and it works there.

What is NOT the cause / NOT a fix: caps (the sandbox SA already runs `scc=privileged`, runAsUser 0,
SYS_ADMIN/NET_ADMIN/SYS_PTRACE/SYSLOG, AppArmor Unconfined); there is **no OpenShell config flag** to
skip the isolation (it is unconditional + intentional). CSI ephemeral volumes **require**
Bidirectional propagation, so the DaemonSet mount can't simply be made private; ZTWIM also reverts raw
DaemonSet edits.

**This is an OpenShell-on-OpenShift compatibility gap.** Resolution options, none landable in-session
without one of:
1. **Upstream OpenShell fix (recommended):** make the supervisor identity isolation
   CRI-O-compatible — e.g. make only the SPIFFE socket mount private (`mount MS_PRIVATE
   /spiffe-workload-api`) instead of a broad `MS_REC|MS_PRIVATE "/"`, or detect a shared CSI mount and
   adapt — so `setns` reconciles. A real, scoped upstream contribution (the "fix it properly" path).
2. **Node/CRI-O runtime change:** alter how CRI-O propagates the CSI mount — node-level, risky on a
   production SNO.
3. **Kata + nested in-VM SPIRE agent** (ADR-0008 track): no host CSI socket crosses the boundary, so
   the propagation conflict doesn't arise; larger effort.

## Status of the e2e

- Architecture/design: settled and correct (native provider token-grant).
- Code: ext-proc binding + launcher grant built/reviewed (now superseded for delegation by native flow).
- Negative half of the zero-trust invariant: **proven live** (no-credential/forged → 401 from inside a
  sandbox).
- Positive delegated e2e: **blocked** on Decision-2's OCP/CRI-O runtime gap. Platform is healthy
  (provider_spiffe rolled back).
