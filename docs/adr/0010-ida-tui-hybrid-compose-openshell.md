# ADR-0010: ida TUI/CLI is a hybrid layer — defer sandbox lifecycle to OpenShell, keep only the zero-trust delta

## Status
Proposed

## Date
2026-06-16

## Context
ida (our Go/Bubble Tea TUI + CLI at `services/ida-cli`) re-implements a large slice of
OpenShell's own CLI/TUI: sandbox listing, pod exec/shell, log streaming. The user asks
whether we should extend OpenShell to add our approval/JIT/zero-trust features instead of
maintaining a parallel TUI.

Two facts in the current codebase make this concrete:

1. **The launcher already composes with OpenShell natively.** `services/sandbox-launcher`
   owns the OpenShell gRPC protobuf stubs (`osh/openshell_pb2_grpc.py`) and calls
   `CreateSandbox` directly with the launcher's OWN client-credentials token — the
   caller's Backstage/Keycloak JWT is discarded after entity-ref extraction. jit-approver
   does the same for policy mutation. So nvidia-ida already treats OpenShell's gateway as
   the system of record for sandboxes.

2. **The ida TUI does NOT.** It bypasses the gateway and reads `Sandbox` CRs through the
   Kubernetes dynamic client (`internal/kube/kube.go`, GVR `agents.x-k8s.io/v1alpha1`) and
   does pod exec/logs natively (`internal/kube/exec.go`, `logs.go`). This is the
   duplication: lifecycle/exec/logs that OpenShell's CLI/TUI already deliver over the
   gateway gRPC API, re-built against raw CRDs.

This is the same pattern ADR-0009 already ruled on for delegation: "Run OpenShell the way
it's designed; retire our bolt-on." That decision retired the ext-proc Vault-grant in
favour of OpenShell's native provider token-grant. The TUI is the next bolt-on of the same
shape.

The genuinely nvidia-ida-specific surface is small and orthogonal to OpenShell: the
**Gitea-PR-as-JIT-approval** flow (jit-approver), the **Approvals/Receipt** tabs that
visualise our zero-trust grant + ext-proc/Kyverno decisions, the **MCP-capability** launch
framing, and our **Keycloak `agentic` realm / ROPC** specifics. OpenShell has no JIT
escalation concept, no Gitea integration, and no realm boundary enforcement.

Relevant invariants: no-credential-passing (the launcher already enforces it structurally;
any TUI redesign must not regress it), authorization-at-receiver (ownership/scope checks
must remain server-side), and the agent-sandbox network boundary.

## Decision
Adopt a **hybrid** model:

1. **ida stops re-implementing sandbox lifecycle.** Sandbox create/list/get/delete, exec,
   shell, logs, port-forward are delegated to OpenShell — via the gateway gRPC API
   (preferred, identity-asserted at the gateway) rather than raw CRD reads. The ida TUI
   either shells out to `openshell` for these, or calls the same gateway gRPC the launcher
   already uses. The `internal/kube` direct-CRD path is retired from the hot path.

2. **ida keeps ONLY the zero-trust delta as its own thin layer**: the Approvals tab
   (Gitea-PR merge as JIT approval), the Receipt tab (ext-proc/Kyverno outcome audit), the
   MCP-capability launch wizard, and Keycloak-`agentic`-realm login. These compose on top
   of OpenShell, they do not replace any OpenShell screen.

3. **We contribute a generic approval/gating hook upstream to OpenShell** so external
   approvers (our jit-approver) are a first-class, supported integration point rather than
   a side-channel — see "what goes upstream" below.

## Consequences
### Positive
- One system of record for sandboxes (the gateway), removing CR-schema drift risk already
  visible in `kube.go` (phase derived by hand from `status.conditions`, selector parsing).
- ~3 of ida's 5 tabs (Overview/Logs/Shell) shrink to thin views over OpenShell, cutting
  client-go/SPDY/vt10x maintenance we currently carry alone.
- Our differentiated UX (approval queue, receipts, capability framing) stays sharp and
  ours; it is what justifies a separate product surface at all.
- An upstream approval hook makes jit-approver a supported extension, not a fork.

### Negative / trade-offs
- Short-term work to re-point ida's lifecycle calls at the gateway and delete the
  direct-CRD path; some UX (e.g. embedded shell) must be re-wired through OpenShell's SSH
  relay instead of native exec.
- An upstream contribution has its own review/merge latency (DCO, RFC, vouch); until it
  lands, jit-approver keeps using the existing gateway RPCs as it does today.
- Two auth surfaces (OpenShell gateway OIDC + our Keycloak realm) must be kept coherent.

### Security implications
- **No-credential-passing is improved, not regressed.** Today the TUI uses the operator's
  kubeconfig directly for CR/exec; routing through the gateway means the receiver (gateway)
  asserts identity and authorizes per-RPC. The launcher's existing rule — caller token
  discarded after entity-ref extraction, launcher uses its OWN token — is the template.
  The upstream approval hook must pass only an opaque proposal/grant **reference**, never a
  credential; the credential (Vault dynamic secret / scoped OAuth token) continues to be
  resolved at the sandbox via SVID, never handed to the approver or the TUI.
- **Authorization-at-receiver** is strengthened: ownership checks move from ida's
  client-side `CheckSandboxOwnership` to the gateway's per-method AuthzPolicy.
- The agent-sandbox network boundary is unchanged; the TUI is an operator-plane client and
  must not gain a path into the sandbox network.
- `[SECURITY-OPEN]` The upstream approval hook's authentication of the external approver
  (jit-approver) to the gateway must be a Keycloak service-account or SVID identity, scoped
  to approve-only. This must be resolved before the ADR is Accepted.

## Alternatives considered
| Option | Rejected because |
|--------|-----------------|
| extend-openshell (fold all JIT/approval/receipt UX into OpenShell's TUI) | Gitea-PR JIT, our Keycloak realm, RHDH parity, and ext-proc/Kyverno receipts are nvidia-ida threat-model specifics with no OpenShell concept; upstreaming them is a poor fit and would fork OpenShell's product direction. Loses our consumption-UX control. |
| keep-ida (maintain the parallel TUI as-is) | Perpetuates duplicated, drift-prone lifecycle/exec/log code against raw CRDs; contradicts ADR-0009's "run OpenShell as designed"; the launcher already composes natively, so the TUI is the outlier. |
