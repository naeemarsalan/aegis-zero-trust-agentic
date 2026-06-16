# ADR-0008: Delivering a SPIFFE SVID into a launcher-created sandbox

Status: **Proposed** (records a BLOCKER + the durable design)
Date: 2026-06-15
Related: docs/design/agent-harness.md (§2, §7), ADR-0003 (token-exchange), kata-svid/

## Context

The agent-harness design (Option D, on-behalf-of) requires the in-sandbox agent to
authenticate to the MCP gateway with **its own SPIFFE JWT-SVID**, with the
**sandbox UID + nonce** bound into that identity (so ext-proc derives the sandbox
from the cryptographic SVID, never a spoofable `X-Sandbox-UID` header — see
agent-harness.md §7 `[OPEN]`). The grant in Vault is keyed by the Sandbox CR
`metadata.uid`.

## Decision / Finding

**Delivering an SVID into a *launcher-created OpenShell sandbox* is BLOCKED today.**

Verified against the vendored proto (`services/jit-approver/proto/openshell.proto`
`SandboxTemplate`, fields 333–361) and `services/sandbox-launcher/.../openshell.py`:

- `SandboxTemplate` exposes only `image`, `runtime_class_name`, `agent_socket`
  (inert string), `labels`, `annotations`, `environment`, `resources`,
  `volume_claim_templates` (**PVC-only** Struct), `user_namespaces`, `driver_config`.
  There is **no** field for an inline `csi.spiffe.io` volume, configMap/emptyDir,
  init/sidecar container, `shareProcessNamespace`, or per-sandbox serviceAccount.
- The provider mechanism (`GetSandboxProviderEnvironment`) returns **env vars only**
  — not sockets or files — so it cannot deliver the workload-API socket or bootstrap
  a nested SPIRE agent.
- Launched sandboxes default to **Kata** (`SANDBOX_RUNTIME_CLASS=kata`); the
  `csi.spiffe.io` host unix socket **cannot traverse the Kata VM boundary**. The only
  proven in-Kata SVID path is a **nested in-VM SPIRE agent + join_token**
  (`kata-svid/`), which needs exactly the pod primitives OpenShell does not expose.
- The ZTWIM operator hardcodes `psat` config and **reverts** ConfigMap edits within
  ~25s; `join_token` NodeAttestor is not enabled and the `SpireServer` CR exposes no
  field for it — so per-sandbox `join_token` registration is not GitOps-reconciled and
  does not survive a pod restart.

## Durable design (gated on a platform change)

Per-sandbox **nested-SPIRE-agent + join_token**, with `sandbox_uid` encoded in the
SPIFFE ID path:
1. Sandbox runs (Kata) with the nested-spire-agent init container.
2. At launch, the launcher (using its OWN identity) generates a `join_token` bound to
   `spiffe://anaeem.na-launch.com/nested-agent/<sandbox_uid>` and creates a workload
   entry `spiffe://.../ns/agent-sandbox/sa/openshell-agent/sandbox/<sandbox_uid>`
   stamping claims `{sandbox_uid, sandbox_nonce == grant.nonce}`.
3. ext-proc derives `sandbox_uid` **from the SVID** (path tail or stamped claim),
   reads the grant at `secret/data/sandbox-grants/<sandbox_uid>`, validates
   nonce/TTL/scope (fail-closed), and performs the RFC 8693 exchange → `sub=user`.
4. **no-credential-passing:** the `join_token` is a node-attestation credential and
   MUST reach the sandbox only as a **tmpfs-mounted file** (Vault-Injector class),
   never via env/provider/agent-context.

**Gating platform tasks (NOT landable in this repo):**
- Prove `SandboxTemplate.driver_config` can express a pod-spec patch (volumes +
  sidecars + shareProcessNamespace) the k8s compute driver honors — **OR** add
  first-class sidecar/volume fields to OpenShell.
- Make `join_token` NodeAttestor durably enabled (a `SpireServer` CR field, or
  un-manage SPIRE).

## Consequence / interim

Until the platform change lands, the keystone **credential loop** is proven via the
**stopgap (FIX #2)**: run the harness in the existing statically-deployed
`openshell-agent` pod (agent-sandbox ns) **without** `runtimeClassName: kata` — which
already gets a real SVID over `csi.spiffe.io` (~1.6s, proven) — plus ONE manually
created SPIRE entry stamping a FIXED demo `sandbox_uid`+`nonce` and a matching Vault
grant. This exercises SVID → ext-proc verify → grant read → CheckNonce → RFC 8693
(`sub=user`) → downstream `search_firewall_rules` → JSONL → TUI.

**Honest caveats of the stopgap:** not launcher-created and not per-sandbox (one fixed
UID reused → no per-sandbox isolation, no launcher→SPIRE registration); not
hardware-isolated (Kata dropped); the SPIRE entry is hand-created, not GitOps-managed.
The stopgap proves the credential machinery is **correct**; #1 is what makes it
per-sandbox, isolated, and launch-driven.

## `[SECURITY-OPEN]`

ext-proc MUST read `sandbox_uid` from the SVID, never from a request header. Do not
move this ADR to Accepted until that is enforced in code (it is, today, in
`internal/spire/spire.go` + `server.go`; keep it that way).
