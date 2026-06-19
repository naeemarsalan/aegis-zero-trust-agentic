# Security Review: Variant-B GitOps Stage 1 (ext-proc delegation + JIT + SPIRE harness) — 2026-06-16

## Summary
Reviewed the uncommitted Stage-1 manifests that make the proven Variant-B delegated zero-trust
stack GitOps-durable: the ext-proc deployment patch that activates the SPIRE sandbox-agent path,
the `agent-sandbox-e2e-harness` ClusterSPIFFEID, image-tag bumps, the e2e-harness Pod patch, two
new ArgoCD apps, and two Kyverno guardrail relaxations. The core no-credential-passing invariant
holds: the agent presents only its SPIRE JWT-SVID, the downstream credential is selected
server-side from the Vault grant keyed by the SVID sandbox_uid, and every leg fails closed
(verified in `internal/extproc/server.go` and `internal/config/config.go`). However, two
load-bearing identity-trust weaknesses are activated by this change set: (A) the SPIRE OIDC JWKS
is fetched with TLS verification disabled, and (B) the SVID sandbox_uid is bound from an
attacker-settable pod label with no SA/image/uid scoping. Both undermine invariant 6 (SPIFFE
trust) and must be fixed before this is treated as production-durable.

Verdict: **PASS-WITH-CONDITIONS** (PoC/demo merge OK; the two CRITICALs below are must-fix before
this is relied on as a production trust boundary, and should be tracked as committed follow-ups
even for the demo since these manifests are now GitOps-durable and will be reused).

## Findings

### [CRITICAL] SPIRE OIDC JWKS fetched with TLS verification disabled — JWKS-spoofing enables SVID forgery
- **File**: `services/ext-proc-delegation/deploy/overlays/anaeem/deployment-patch.yaml:31` (`SPIRE_TLS_INSECURE=true`); sink at `services/ext-proc-delegation/cmd/server/main.go:117-122`
- **Invariant violated**: 6 (SPIFFE trust domain / SVID validation), 9 (mTLS on inter-service paths)
- **Description**: When `SPIRE_TLS_INSECURE=true`, the SPIRE verifier's HTTP client is built with
  `tls.Config{InsecureSkipVerify: true}` (`main.go:120`). The JWKS document fetched over that
  connection is the *sole* trust anchor for SVID signature verification (`jwks.go:307-336` →
  `keyForKIDAlg` → `tok.Claims(key,...)`). The deployment-patch comment ("The JWKS content is
  still trust-anchored by the SVID signature") is circular and false: the SVID is verified
  *against* the keys in this JWKS, so there is no independent anchor. An attacker who can
  intercept or redirect the connection to `spire-oidc.apps.anaeem.na-launch.com/keys` substitutes
  their own public keys; ext-proc then accepts SVIDs signed by the attacker's private key. Because
  the trust-domain check (`spire.go:105`) only inspects the *sub string* of an already
  signature-verified token, a forged SVID with `sub=spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/<any-uuid>`
  passes every downstream check and unlocks the Vault grant for that uuid.
- **Attack scenario**: An attacker who has compromised one pod (or any on-path position between
  the ext-proc pod and the OpenShift router serving the spire-oidc route — same node, hostNetwork
  router, ARP/DNS spoofing on the SDN, or a malicious egress proxy) MITMs the JWKS fetch, serves
  attacker-controlled keys, mints a self-signed JWT with the target sandbox's SPIFFE sub and
  `aud=mcp-gateway`, and obtains the delegated pfSense credential for `user=arsalan` without ever
  possessing a real SVID. This is full bypass of the zero-trust identity boundary.
- **Remediation**: Mount the SPIRE/cluster CA that signs the spire-oidc route cert into the
  ext-proc pod (projected configmap or the SPIRE bundle the workload already receives via the
  csi.spiffe.io volume / `x509Source` already present at `main.go:75`) and configure the JWKS
  HTTP client with `RootCAs` set to that bundle instead of `InsecureSkipVerify`. Drop
  `SPIRE_TLS_INSECURE=true`. If a flag is retained for local dev, gate it so it can never be set
  in the anaeem overlay. Until fixed, this path must not be considered a real trust boundary.

### [CRITICAL] Sandbox identity bound from attacker-settable pod label — cross-sandbox grant impersonation
- **File**: `platform/spire/base/cluster-spiffe-ids.yaml:88-94` (`agent-sandbox-e2e-harness` ClusterSPIFFEID)
- **Invariant violated**: 6 (SVID/identity binding), 4 (downstream sees user identity — here the wrong user)
- **Description**: The new ClusterSPIFFEID templates the SVID path directly from a pod label:
  `spiffeIDTemplate: spiffe://anaeem.na-launch.com/ns/{{.PodMeta.Namespace}}/sandbox/{{ index .PodMeta.Labels "nvidia-ida/sandbox-id" }}`,
  selected solely by `podSelector: nvidia-ida/e2e-harness="true"` in namespace `agent-sandbox`.
  Both the selector label and the uuid label are free-form pod metadata that the pod author
  chooses. There is no binding to a specific ServiceAccount, image digest, or the Kubernetes pod
  UID. SPIRE will therefore mint a `sandbox/<uuid>` SVID for **any** pod in agent-sandbox carrying
  those two labels, with whatever uuid the author writes. ext-proc reads the Vault grant at
  `secret/data/sandbox-grants/<uuid>` purely from that uuid (`server.go:586-595`), and the grant
  resolves to `user=arsalan`. The grant.sandbox_uid binding check (`server.go:621`) only confirms
  the grant document's own field matches the SVID uuid — it does not constrain *which pod* may
  hold that uuid.
- **Attack scenario**: Any principal who can create a Pod in the `agent-sandbox` namespace (or who
  has compromised a workload able to do so) launches a pod labelled
  `nvidia-ida/e2e-harness=true` and `nvidia-ida/sandbox-id=<a-victim-sandbox-uuid>`. SPIRE issues a
  valid SVID for that sandbox; the attacker calls the MCP gateway and receives the victim
  sandbox's delegated downstream credential (the firewall token for that grant's user). This is
  lateral movement / privilege escalation across sandboxes via label spoofing. The read-only
  hard-pin (`grantScopeGroups`, `server.go:788`) limits this to read scope absent a JIT session,
  but it is still impersonation of another sandbox's delegated identity and exfiltration of a
  downstream credential the attacker was never granted.
- **Remediation**: (1) Tighten the binding so the SVID uuid cannot be self-asserted: bind the
  ClusterSPIFFEID to a dedicated ServiceAccount and (ideally) image, and derive the sandbox uuid
  from the pod UID or a sandbox-launcher-controlled, non-mutable field rather than a free label —
  matching how real sandboxes are provisioned. (2) Lock down `create pods` RBAC in `agent-sandbox`
  to the sandbox-launcher controller only; confirm no broad RoleBinding (e.g. RHDH/devhub readers
  or demo RBAC in `usecases/uc2-jit-escalation/manifests/demo-agent-rbac.yaml`) grants pod-create
  there. (3) Document that label-based binding is acceptable ONLY for the isolated single-tenant
  demo and is not safe for multi-sandbox/production.

### [HIGH] e2e-harness Pod omits `runtimeClassName: kata`, weakening sandbox isolation that backstops the SVID
- **File**: `services/agent-sandbox/e2e-harness/pod.yaml:25-27` (no `runtimeClassName`); guardrail at `platform/kyverno/guardrails/base/require-kata-runtimeclass.yaml:31-35`
- **Invariant violated**: defense-in-depth for invariant 6 (the Kata micro-VM is what prevents a
  compromised neighbour from reading/forging this pod's SVID material)
- **Description**: The require-kata-runtimeclass guardrail mandates `spec.runtimeClassName: kata`
  for pods in agent-sandbox; the harness pod sets none. The guardrail is currently
  `validationFailureAction: Audit`, so it is non-blocking, but the harness holds a live SVID via
  the csi.spiffe.io volume and runs as an ordinary container sharing the node kernel. Combined with
  Finding B (label-spoofable identity) and Finding A (forgeable JWKS), the loss of hardware
  isolation widens the blast radius of any node-local compromise.
- **Attack scenario**: A container-escape from a co-resident non-Kata pod reaches the harness SVID
  socket / node, then exercises Finding A or B from a trusted on-node position.
- **Remediation**: Add `runtimeClassName: kata` to the harness pod spec (matching the documented
  agent-pod model), or explicitly document and accept the exception in the manifest header. Flip
  the guardrail to Enforce before production.

### [MEDIUM] Kyverno `forceFailurePolicyIgnore=true` makes admission fail-open
- **File**: `platform/kyverno/install/base/values.yaml:42-43`
- **Invariant violated**: 2 (fail-closed posture) — note this is the admission/guardrail plane, not the runtime authz datapath
- **Description**: Setting `features.forceFailurePolicyIgnore.enabled: true` forces every Kyverno
  webhook to `failurePolicy: Ignore`, so when the admission controller is down/flapping all
  policy enforcement (image-registry restriction, kata requirement, default-SA-automount, etc.) is
  silently skipped instead of blocking the write. This is a deliberate availability tradeoff to
  prevent the 2026-06-16 cluster-wide cascade, and it is correctly documented, but it means an
  attacker who can briefly disrupt the Kyverno admission pods gets a window to create
  non-compliant pods (e.g. a non-Kata pod, or a pod from a disallowed registry) cluster-wide. The
  runtime zero-trust datapath (ext-proc/Vault/SPIRE) is unaffected and still fails closed.
- **Attack scenario**: Attacker DoSes or wedges the Kyverno admission controller, then creates
  guardrail-violating pods during the gap (compounds Findings B and the kata gap above).
- **Remediation**: Acceptable for PoC given the documented outage. For production, prefer scaling
  the admission controller for HA + tight `failurePolicy: Fail` on the small set of security-load-
  bearing policies, and keep Ignore only for non-security generate/report policies. Track as a
  pre-production item.

### [LOW] Compiled `__pycache__/*.pyc` artifacts committed/modified in the jit-approver diff
- **File**: `services/jit-approver/src/jit_approver/__pycache__/*.pyc`, `services/jit-approver/tests/__pycache__/*.pyc`
- **Invariant violated**: none directly; hygiene/supply-chain clarity
- **Description**: The working tree shows modified `.pyc` bytecode under version control. Committed
  bytecode can drift from source and obscures what actually changed in the e2e-jit image. Not a
  credential or authz issue.
- **Remediation**: gitignore `__pycache__/` and remove tracked `.pyc` files.

## Passed checks
- **Invariant 1 (no credentials in git)**: The activation manifests introduce no `kind: Secret`
  with a `data` block. `SPIRE_*` env vars are URLs/identifiers, not secrets. The `grants/*.yaml`
  files are JITGrant CRs (audit/metadata records) that explicitly state the credential is stored
  in Vault KV and "never returned over HTTP" — no embedded secret material.
- **Invariant 2 (fail-closed)**: Confirmed in code. SPIRE-routed tokens that fail `VerifySVID`
  return 401 deny and do NOT fall through to the Keycloak path (`server.go:194-202`). Empty body,
  oversized body, parse error, grant vault error, grant absent/malformed/expired/uid-mismatch, TTL
  cap exceeded, scope denied, empty downstream token all deny (`server.go:232-773`). `FAIL_MODE`
  is validated to be exactly `"closed"` at startup (`config.go:148-150`) and the patch keeps the
  base value.
- **Invariant 3 (default-deny NetworkPolicies)**: The require-networkpolicy `exclude` is scoped to
  `openshift-*`/`kube-*`/`default` and applies only to the *generate* rule for system/operator
  namespaces. Platform namespaces (agent-sandbox, mcp-gateway, vault, keycloak, etc.) still carry
  curated `default-deny` policies and remain in the validate rule's namespace list. agent-sandbox
  retains its committed default-deny-all (`platform/networkpolicies/base/np-agent-sandbox.yaml`).
- **Invariant 4 (downstream sees user identity, never agent identity)**: On the SPIRE path the
  agent's SVID is never forwarded downstream. ext-proc runs RFC 8693 Phase-1 impersonation with
  `requested_subject=grant.user` and injects the per-user static token selected by `grant.user`
  (`server.go:698-767`); the SVID is consumed only for verification.
- **Invariant 6 (trust domain locked)**: `spire.go:36,105` enforces `spiffe://anaeem.na-launch.com/`
  and rejects any other trust domain and any sub without a non-empty single-component
  `/sandbox/<uuid>` segment. alg=none and algorithm-confusion are rejected at parse
  (`jwks.go:148-156`). (The TLS-anchor weakness is Finding A; the binding weakness is Finding B —
  both are *how* this invariant is undermined despite the in-code checks being correct.)
- **Invariant 8 (no cluster-scoped JIT escalation)**: JIT elevation on this path is per-tool only,
  requires a verified jit-approver session JWT whose `sandbox_uid` equals the SVID's, and never
  widens the grant (`server.go:639-684`). Sample JITGrant CRs are namespace-scoped (agent-sandbox),
  <=15m, verbs get/list on pods only — within the 60-minute / no-RBAC-mutation bounds.

## Reviewer notes
- The two ArgoCD apps use `prune: true, selfHeal: false`. Blast radius (question E) is acceptable:
  each app is scoped to a single overlay path (`services/.../overlays/anaeem`) targeting the
  `mcp-gateway` namespace and owns only its own kustomize output, so prune removes only resources
  this app previously created. No shared/global resources are in scope. selfHeal:false is the safe
  choice (operator edits won't be stomped). The e2e-harness is deliberately NOT app-of-apps'd
  (Never-pod churn), which is correct.
- Image-tag pinning (question D): `grant-e2e-jit`, `e2e-jit`, `dev` are mutable, human-readable
  tags under auto-sync. This is a real supply-chain/reproducibility gap — a registry retag silently
  changes what ArgoCD deploys with no diff in git, and `dev`/`e2e-jit` carry no provenance. Not
  rated as a numbered-invariant finding (no checklist item covers image provenance), but flagging:
  before production, pin by immutable digest (`@sha256:...`) and ideally enforce with a Kyverno
  verifyImages/cosign policy. Acceptable for the live-proven demo as documented.
- Question C is answered in the Passed checks (invariants 2 and 4): activating the SPIRE path
  introduces no credential into the sandbox and does not weaken fail-closed — the injected
  credential remains grant-selected server-side and the agent only ever sends its SVID. The
  weaknesses are in *trusting* that SVID (Findings A and B), not in credential leakage into the
  sandbox.
- `SpireTLSInsecure` only takes effect because `SPIRE_JWKS_URL` is now set by this patch; before
  this change the insecure client was dead code. So this change set is what turns Finding A from
  latent to live — strengthening the case for fixing A as part of this Stage-1 work.

---

## Final pre-merge confirmation (2026-06-17, independent security-reviewer pass)

Independent verification of commit `c028188` on `backup/e2e-delegated-zero-trust` against the two
CRITICALs. Read every changed file (not relying on the self-verification doc). Findings below.

### Finding A (SVID forgery via JWKS spoofing) — **CLOSED**
- `cmd/server/main.go:202 buildSpireHTTPClient`, verified line-by-line:
  - (a) `InsecureSkipVerify` (case 1, line 206-209) is reachable **only** when `cfg.SpireTLSInsecure`
    is true, which `config.go:131` sets **only** on `SPIRE_TLS_INSECURE == "true"` (default `""` → false).
  - (b) Default path (case 3, line 223-241) builds `RootCAs` from the in-pod SPIFFE bundle:
    `src.GetX509SVID()` → `.ID.TrustDomain()` → `GetX509BundleForTrustDomain(td)` → `X509Authorities()`,
    with `MinVersion: tls.VersionTLS12`. No system-root or insecure fallback.
  - (c) Fail-closed: any error in case 3 returns; at the call site `main.go:120-123` a
    `buildSpireHTTPClient` error does `return fmt.Errorf(...)` and **aborts startup**. No degraded path.
  - (d) `SPIRE_CA_FILE` path (case 2, line 211-221) is fail-closed: returns error on unreadable file
    and on `AppendCertsFromPEM` parsing zero certs. `config.go:81/132` wires `SpireCAFile`.
- Overlay confirmed: `deployment-patch.yaml` sets SPIRE_JWKS_URL/ISSUER/AUDIENCE and **does not**
  set `SPIRE_TLS_INSECURE` (default-off secure path). `kustomization.yaml` pins the image by
  **digest** `sha256:0488968457c3a52a1592283d0e35ca0d07abb6068933806a2a337082e763d163` (closes the
  mutable-tag provenance note D). 5 new unit tests present in `cmd/server/main_test.go`
  (Insecure, CAFile happy/missing/invalid-PEM, InsecureTakesPrecedenceOverCAFile).
- **Residual (runtime, NOT a code defect):** Go validates the JWKS endpoint hostname against the
  served cert SAN. If the live `spire-oidc` route cert SAN omits `spire-oidc.apps.anaeem.na-launch.com`,
  the default path **fails closed** (verifier init warns, sandbox path disabled, calls deny — no
  forgery, no leak). Confirm the SAN on the live route; if mismatched, mount the right CA via
  `SPIRE_CA_FILE`. Safe-by-default. This is the only A item that cannot be settled from the diff.
- **Minor note:** insecure (case 1) is ordered before CA-file (case 2), so `SPIRE_TLS_INSECURE=true`
  wins over a set `SPIRE_CA_FILE`. Documented in `config.go:79` and asserted by a test. Acceptable
  because insecure is an explicit, default-off, never-set-in-overlay opt-in.

### Finding B (label-forgeable sandbox identity) — **PARTIALLY-CLOSED (adequate for PoC)**
- Confirmed: `serviceaccount.yaml` (`automountServiceAccountToken: false`), `pod.yaml`
  (`serviceAccountName: e2e-harness`), `rbac.yaml` (empty-rules Role + RoleBinding, with an explicit
  do-not-grant-pods:create incident note), and `require-e2e-harness-serviceaccount.yaml`
  (`validationFailureAction: Audit`, pattern pins SA on the labelled pods).
- **Precise residual:** the Kyverno policy is **Audit** (and per memory Kyverno is parked at
  replicas 0), so the SA-pin is **not enforced at admission**. The ClusterSPIFFEID
  (`cluster-spiffe-ids.yaml:88`) still derives the SVID `sandbox/<uuid>` from the attacker-settable
  `nvidia-ida/sandbox-id` pod label, selected only by the `nvidia-ida/e2e-harness=true` label —
  unchanged from the original finding. The **effective control today is RBAC on `pods:create` in
  `agent-sandbox`** (admin/launcher-only; rbac.yaml grants none and forbids adding any).
- **Verdict for PoC:** adequately mitigated for a single-tenant demo namespace. The bar is raised
  (dedicated tokenless SA + pin + committed Audit policy ready to flip to Enforce). Production must:
  flip the policy to Enforce with Kyverno running, and bind the uuid to a launcher-controlled
  non-mutable field (pod UID) rather than a free label.

### ArgoCD apps blast-radius (prune) — acceptable
- `ext-proc-delegation.yaml` / `jit-approver.yaml`: `prune: true, selfHeal: false`, each scoped to a
  single overlay path (`services/.../overlays/anaeem`) in namespace `mcp-gateway`, SSA + wave 5,
  added to `gitops/applications/kustomization.yaml`. Prune only removes resources each app itself
  created — no shared/global resources in scope. `selfHeal: false` means operator edits aren't
  stomped (safe). The forgeable-label `e2e-harness` Pod is deliberately **NOT** ArgoCD-managed
  (`e2e-harness/kustomization.yaml` header; applied on-demand), so auto-prune cannot recreate/churn
  it — correct. No blast-radius concern. Note: `targetRevision: main` means these apps only take
  effect once the commit reaches `main`; benign.

### Per-finding verdict
- Finding A: **CLOSED** (one runtime SAN check remains as a documented, fail-closed pre-journey gate).
- Finding B: **PARTIALLY-CLOSED** — adequately mitigated for the PoC; not production-safe until
  Enforce + non-mutable uuid binding.

### Overall: **MERGE-READY-FOR-POC: yes**
Both CRITICALs are remediated to PoC-adequate posture; no new credential-leak, fail-open, or
trust-domain-bypass path was introduced by this commit. Two pre-journey (not pre-merge-blocking)
items stand: (1) live `spire-oidc` cert-SAN verification for Finding A's default TLS path, and
(2) flip the Kyverno SA-pin policy to Enforce with Kyverno running before any multi-tenant use.
Not for production until Finding B's label binding is hardened.
