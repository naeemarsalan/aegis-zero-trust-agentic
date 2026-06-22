# Phase D - Productionize / Hardening - Detailed Plan

**Status:** Draft
**Date:** 2026-06-22
**Depends on:** Phase A DONE (core journey proven 2026-06-22); Phase B (JIT/token) and Phase C (product console) can proceed in parallel.
**Reference:** [Master Plan](./openshell-agentic-platform-master-plan.md), [Phase A Worklog](../reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md), [ADR-0017](../adr/0017-provider-spiffe-setns-selinux-confinement.md), [ADR-0018](../adr/0018-openshell-native-svid-grant-key-binding.md), [ADR-0014](../adr/0014-operation-shaped-jit-ttl-decouple.md)

---

## Executive Summary

Phase D addresses the durability, security hardening, testing, observability, and stability concerns that must be resolved before the platform is production-ready. The core zero-trust journey is PROVEN (2026-06-22); this phase ensures it STAYS proven under GitOps reversion, cluster maintenance, and real operational load.

**Hard invariant preserved throughout:** The agent holds only its SPIFFE SVID. No long-lived, broadly-scoped credential is stored in or forwarded by the agent. ext-proc stays in front as the per-tool scope gate and audit emitter.

---

## Loop D1 - GitOps Durability

### Goal
Every artifact that makes the proven journey work is durable under GitOps reversion: ArgoCD sync, ACM work-agent reconciliation, and `oc apply -k` are non-destructive to the running state.

### Background (Issues from Phase A Worklog)
- **Issue #4:** `oc apply -f cluster-spiffe-ids.yaml` (whole file) silently breaks the proven 4/4 harness because the committed `agent-sandbox-e2e-harness` CSID drifts from live (git=templated; live=hardcoded literal UUID + className).
- **Issue #25:** ACM `work-agent` (ManifestWork `ida-launcher-componenta`) keeps clobbering the launcher image back to `:dev`/`sh3` ~2min after any overlay apply. The ManifestWork lives on the **hub** (not the managed cluster).
- **Issue #28 (master-plan):** The ACM/work-agent hub-pin pattern needs resolution for all mutable images.

### Steps

1. **Audit every mutable artifact for git-vs-live drift.**
   - ClusterSPIFFEIDs: compare `platform/spire/base/cluster-spiffe-ids.yaml` against live (`oc get clusterspiffeid -o yaml`).
   - Deployments with image pins: sandbox-launcher, ext-proc-delegation, jit-approver, jit-gate, approval-console, agent-harness.
   - Kyverno ClusterPolicies: mutate-openshell-sandbox-syschroot, stamp-sandbox-cr.
   - NetworkPolicies: all per-namespace NPs vs live.

2. **Reconcile cluster-spiffe-ids.yaml per-doc apply rule.**
   - Add a header comment to `cluster-spiffe-ids.yaml` (already present) warning against whole-file apply.
   - Author a helper script `hack/apply-clusterspiffeid.sh <name>` that extracts a single CSID doc by name and applies only it.
   - Verify via `oc diff -f -` before any apply.

3. **Resolve ACM work-agent hub-pin (Issue #25).**
   - **GATED (hub action required):** Edit ManifestWork `ida-launcher-componenta` on the ACM hub to:
     - Pin the launcher image to the brain-boot tag (e.g., `llmgate-20260622-153517`).
     - Include `SANDBOX_IMAGE` env pointing to the native brain image.
     - Include `envFrom: agent-harness-inference` for the LiteLLM secret.
   - Alternatively: repoint the ManifestWork source at `services/sandbox-launcher/deploy/overlays/anaeem` (if the hub supports kustomize).
   - Until hub is fixed: document that managed-side `oc apply` only holds ~2min.

4. **Mounts-over-env pattern for ArgoCD revert-immunity.**
   - For secrets that ArgoCD reverts (e.g., inference API keys), use `envFrom` referencing a Secret managed outside ArgoCD's sync scope, OR use Vault Agent Injector writing to tmpfs.
   - Current pattern: `agent-harness-inference` Secret for LiteLLM keys (already used in deployment-patch.yaml).
   - Verify: ArgoCD sync does not revert the Secret (it is not in the GitOps source, only the `envFrom` reference is).

5. **Validate `apply -k` is non-destructive.**
   - Run `kustomize build platform/spire/overlays/anaeem | oc diff -f -` and verify no unexpected changes.
   - Run `kustomize build services/sandbox-launcher/deploy/overlays/anaeem | oc diff -f -` and verify.
   - Create a CI gate (optional): `hack/validate-gitops-drift.sh` that exits non-zero on unexpected diffs.

### Verify / Exit
- `oc apply -k platform/spire/overlays/anaeem` produces no changes to the working CSIDs.
- `oc apply -k services/sandbox-launcher/deploy/overlays/anaeem` produces no changes to the working launcher (after hub fix).
- `hack/test-openshift-jit.sh` remains 4/4 after a full GitOps sync.

### Files / Touch-Points
- `platform/spire/base/cluster-spiffe-ids.yaml` (per-doc apply warning, already present)
- `hack/apply-clusterspiffeid.sh` (new helper script)
- `hack/validate-gitops-drift.sh` (new validation script)
- Hub ManifestWork `ida-launcher-componenta` (GATED - hub mutation)
- `services/sandbox-launcher/deploy/overlays/anaeem/kustomization.yaml` (image pin, already correct)

### Gated?
**Yes** - the hub ManifestWork edit is a cluster mutation (on the hub, not managed cluster).

---

## Loop D2 - NetworkPolicies

### Goal
Complete the network security posture: default-deny per namespace, explicit allow-lists, compensating controls for `CAP_SYS_CHROOT` + `CAP_SYS_ADMIN` sandboxes.

### Background
- **ADR-0017 compensating control:** ns `openshell` had only an SSH ingress NP; sandboxes could egress anywhere.
- **Issue #6 (Phase A):** The egress NP broke DNS because OVN-K CoreDNS listens on :5353 (Service maps 53->5353); fixed by allowing BOTH :53 AND :5353.
- **CAP_NET_ADMIN:** Listed in ADR-0017 as "consider dropping" - sandboxes have it but may not need it.

### Steps

1. **Audit completeness of openshell egress NP.**
   - Current file: `platform/openshell/networkpolicy-sandbox-egress.yaml`
   - Already allows: DNS (:53+:5353), in-cluster planes (openshell, mcp-gateway, SPIRE), apps-VIP :443, LiteLLM :4000, Keycloak :8080 in-cluster, agentic-mcp :8000.
   - Verify no missing targets by testing a native sandbox: DNS, brain, ext-proc, Keycloak.
   - Add missing: telemetry/observability (Loki/OTel collector) if agents need to emit logs directly.

2. **Add jit-gate egress NP (already present).**
   - `openshell-jit-gate-egress` in the same file.
   - Verify: jit-gate can reach DNS, jit-approver /jwks (mcp-gateway:8080), upstream echo-mcp (agentic-mcp:8000).

3. **Default-deny posture per namespace.**
   - Verify existing: `platform/networkpolicies/base/` contains NPs for keycloak, vault, mcp-gateway, kyverno, agentic-mcp, agent-sandbox, agentic-observability.
   - Missing: ns `openshell` has no default-deny-ingress (only explicit sandbox-ssh + sandbox-egress + jit-gate-egress).
   - Add: `default-deny-ingress` to ns openshell (allow-lists for gateway SSH/HTTP already exist).

4. **Evaluate dropping CAP_NET_ADMIN from sandboxes.**
   - Current sandbox caps: `[SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYSLOG, SYS_CHROOT]`.
   - `NET_ADMIN` allows: modifying routing tables, firewall rules (iptables), network interfaces.
   - The supervisor/agent do not need `NET_ADMIN` (verified: no iptables/ip route calls in supervisor code).
   - Decision: author a Kyverno policy to DROP `NET_ADMIN` from sandbox pods (inverse of the SYS_CHROOT mutate).
   - **Risk:** If the supervisor or a future feature needs NET_ADMIN, this breaks. Test thoroughly.

5. **Add ingress NP for openshell gateway SSH from approval-console (webshell path).**
   - Currently: `openshell-sandbox-ssh` allows port 22 ingress. Verify the source selector is correct (oauth2-proxy/approval-console).

### Verify / Exit
- `hack/test-openshell-native-hybrid.sh` passes with all NPs applied.
- A sandbox pod cannot reach an arbitrary external IP (e.g., 1.1.1.1:443 times out).
- A sandbox pod CAN reach: DNS, LiteLLM brain, mcp-gateway, ext-proc, Keycloak, spire-oidc.
- `oc get networkpolicy -n openshell` shows default-deny + explicit allows.

### Files / Touch-Points
- `platform/openshell/networkpolicy-sandbox-egress.yaml` (audit, possibly extend)
- `platform/openshell/networkpolicy-default-deny-ingress.yaml` (new)
- `platform/kyverno/guardrails/base/mutate-openshell-sandbox-drop-netadmin.yaml` (new, optional)
- `platform/networkpolicies/base/kustomization.yaml` (add openshell NPs if not already)

### Gated?
**No** - NetworkPolicies are namespace-scoped and additive; they do not break existing traffic (only restrict it). Apply with caution but not cluster-mutation-gated.

---

## Loop D3 - Testing Strategy

### Goal
Establish a repeatable testing pyramid: the regression anchor (`test-openshift-jit.sh`), per-surface loop-until-green scripts, and acceptance criteria for each Phase B/C feature.

### Background
- `hack/test-openshift-jit.sh` is the proven 4/4 anchor for the OpenShift troubleshooting journey.
- `hack/test-openshell-native-hybrid.sh` tests the native OpenShell SVID-mint substrate.
- `hack/test-kagenti-jit.sh` tests the Kagenti AuthBridge JIT loop (echo-mcp).
- Missing: mint-gate tests, operation-shaped TTL tests, webshell attach tests, skills-load tests.

### Steps

1. **Protect the regression anchor.**
   - `hack/test-openshift-jit.sh` MUST NOT be edited by subagents (already in lane rules).
   - Add a CI/pre-commit hook: if `hack/test-openshift-jit.sh` is modified, require explicit approval.
   - Document the expected pass/fail behavior (4/4 = pass; any fail = block merge).

2. **Native-LLM-on-real-tools acceptance script.**
   - Current: `test-openshell-native-hybrid.sh` tests substrate (grant+SVID+binding) but the agent-driven hybrid acceptance is PENDING.
   - Extend or create `hack/test-openshell-native-llm-e2e.sh`:
     - Launch a native sandbox with a brain-enabled launcher image.
     - Wait for the brain to boot (probe SVID_JWT_PATH file exists).
     - Drive a read via the brain's MCP call -> verify ext-proc audit shows `decision=allow`.
     - Drive a write -> verify 403 `grant_scope_denied`.
     - Approve via jit-approver (or auto-merge Gitea PR).
     - Retry write -> verify 200 + `jit_elevated=true`.
     - Post-TTL (or jti-consumed for single-use) -> verify 403.
   - Exit: 6 assertions (read-allow, write-deny, approve, write-allow, audit-jit, post-ttl-deny).

3. **Mint-gate acceptance script (`hack/test-mint-gate.sh`).**
   - Prerequisites: jit-approver has mint-gate L0/L1 deployed, CNPG is up, `system:auth-delegator` RBAC granted.
   - Test: create a JIT request, verify pending; approve, verify approved + session_jwt minted; call /jwks, verify JWT validates; call jit-gate with JWT, verify pass; call with expired/consumed JWT, verify 401/403.

4. **Operation-shaped TTL tests (`hack/test-operation-ttl.sh`).**
   - Prerequisites: ADR-0014 implemented (single-use jti consume, class-based TTL).
   - Test: mint a single-use class JWT (5min, jti), call jit-gate with it -> 200; call again with same jti -> 403 `capability already consumed`.
   - Test: mint a reuse-window class JWT (30min), call jit-gate multiple times -> all 200 within TTL; after TTL -> 403.

5. **Webshell attach test (`hack/test-webshell.sh`).**
   - Prerequisites: Phase C webshell deployed.
   - Test: authenticate to approval-console as a user, spawn a sandbox, attach via webshell, run a command, verify output.

6. **Skills-load test (`hack/test-skills-load.sh`).**
   - Prerequisites: Phase C skills picker deployed.
   - Test: launch an agent with selected skills, verify skills are cloned into `/app/.claude/skills` (or the writable emptyDir), verify the agent can list/use them.

### Verify / Exit
- `hack/test-openshift-jit.sh` = 4/4.
- All per-surface scripts pass in a clean environment.
- CI runs all scripts on PR (gated merge).

### Files / Touch-Points
- `hack/test-openshift-jit.sh` (protected, no edit)
- `hack/test-openshell-native-hybrid.sh` (existing)
- `hack/test-openshell-native-llm-e2e.sh` (new)
- `hack/test-mint-gate.sh` (new)
- `hack/test-operation-ttl.sh` (new)
- `hack/test-webshell.sh` (new, Phase C)
- `hack/test-skills-load.sh` (new, Phase C)
- `.github/workflows/` or `gitea-actions/` CI config (new or extend)

### Gated?
**No** - test scripts are read-only against the cluster; they create/delete sandboxes but do not mutate platform state.

---

## Loop D4 - Observability

### Goal
Ensure every security-relevant action is auditable (WORM), ext-proc emits per-call receipts, SSE/agent transcripts are captured, and dashboards exist for operational visibility.

### Background
- ext-proc-delegation already emits structured JSON audit lines (worklog: `caller_username`, `grant_scope`, `decision`, `jit_elevated`).
- jit-approver emits JIT grant metrics (`agentic_agent_jit_grants_issued_total`).
- PrometheusRule `agentic-platform-alerts` defines `AgentPermissionDenied` and `JITGrantIssued` alerts.
- OTel collector is deployed (`platform/observability/otel-collector`).
- Grafana dashboards exist in `platform/observability/grafana-dashboards`.
- CNPG WORM audit is planned for mint-gate L0/L1 (ADR-0014).

### Steps

1. **Audit/WORM coverage verification.**
   - Verify ext-proc audit lines are forwarded to Loki (via OTel collector or direct).
   - Verify jit-approver audit (request create, approve, mint) is written to CNPG with append-only semantics.
   - CNPG WORM: ensure the `jit_requests` table has no UPDATE/DELETE permissions for the app user; only INSERT + SELECT.
   - Verify the `consumed_jti` table (ADR-0014) is CNPG-backed.

2. **ext-proc per-call receipts.**
   - Current: ext-proc logs `{"timestamp", "svid_sub", "tool", "decision", "grant_*", ...}`.
   - Extend: add a `receipt_id` (UUID) to every log line; return it in the gRPC response header so the caller can correlate.
   - Persist receipts to CNPG (optional, for compliance): `receipts` table with TTL-based pruning.

3. **SSE/agent transcripts.**
   - approval-console SSE path already streams agent transcripts to the browser.
   - Persist transcripts to CNPG or S3 (for compliance): `transcripts` table with `session_id`, `timestamp`, `content`.
   - Add a transcript replay endpoint: `/sessions/{id}/transcript`.

4. **Dashboards.**
   - Existing: `agentic-platform-dashboard-cm.yaml`, `jit-audit-dashboard-cm.yaml`.
   - Extend: add panels for:
     - Sandbox spawn rate (by user, by capability).
     - SVID issuance rate (SPIRE entries created).
     - ext-proc decisions (allow vs deny, by tool).
     - JIT approval latency (request -> approve).
     - Operation-shaped TTL: single-use consume vs reuse-window reuse.
   - Export dashboards as ConfigMaps (already done via kustomize).

5. **Alerting completeness.**
   - Existing: `AgentPermissionDenied`, `JITGrantIssued`, `OtelCollectorDown`.
   - Add: `SPIREServerUnhealthy` (spire-server pod not Ready for 5m).
   - Add: `EtcdFragmentationHigh` (fragmentation > 50% for 30m on SNO).
   - Add: `JITApprovalBacklogHigh` (pending requests > 10 for 10m).

### Verify / Exit
- `oc logs -n mcp-gateway deploy/ext-proc-delegation` shows structured JSON with `receipt_id`.
- Loki query `{namespace="mcp-gateway"} |= "decision"` returns ext-proc audit lines.
- CNPG `jit_requests` table is append-only (INSERT only; UPDATE/DELETE denied).
- Grafana dashboards load and show data.
- PrometheusRules are evaluated (check `oc get prometheusrule -n agentic-observability`).

### Files / Touch-Points
- `services/ext-proc-delegation/internal/authz/handler.go` (add receipt_id)
- `platform/jit-approver-db/` CNPG schema (append-only constraints)
- `services/approval-console/` (transcript persistence)
- `platform/observability/grafana-dashboards/base/*.yaml` (extend)
- `platform/observability/alerts/base/prometheus-rule.yaml` (extend)

### Gated?
**No** - observability changes are additive; they do not break existing functionality.

---

## Loop D5 - Stability

### Goal
Ensure the platform is stable under SNO constraints: etcd defrag cadence, SPIRE server restart mitigation, image-pin durability.

### Background
- **etcd (SNO):** Single-node etcd has no redundancy; fragmentation above ~800MB impacts performance. Defrag during quiet windows (worklog: 1.2GB->728MB).
- **SPIRE server restart:** Pods with pending SVID requests may time out if spire-server-0 restarts.
- **Image-pin durability:** ACM work-agent clobbers images (issue #25); without hub fix, managed-side applies are temporary.

### Steps

1. **etcd defrag cadence (SNO).**
   - Document the defrag runbook: `docs/runbooks/etcd-defrag-sno.md`.
   - Cadence: weekly or when fragmentation > 30% (check via `etcdctl endpoint status`).
   - Pre-defrag: take etcd snapshot (`etcdctl snapshot save`); verify no alarms.
   - Defrag: `etcdctl defrag` (single member on SNO).
   - Post-defrag: verify health, no alarms, API responsive.
   - Add a monitoring alert: `EtcdFragmentationHigh` (fragmentation > 50% for 30m).

2. **SPIRE server restart mitigation.**
   - SPIRE pods have `readinessProbe` and `livenessProbe`; verify they are tuned appropriately.
   - spire-agent daemonset should tolerate spire-server restarts (built-in retry logic).
   - Verify: after `oc delete pod spire-server-0 -n zero-trust-workload-identity-manager`, agent pods recover SVID fetch within 60s.
   - Document: if SVID fetch fails for a sandbox, the sandbox can be restarted (the Kyverno mutate + CSID will re-issue).

3. **Image-pin durability.**
   - Document the ACM work-agent issue and the hub-fix requirement (Loop D1).
   - Until hub-fixed: maintain a list of "golden" image tags in `docs/runbooks/golden-image-pins.md`.
   - Add a pre-flight check to `hack/validate.sh`: warn if a deployed image differs from the golden tag.

4. **CNPG stability (jit-approver-db).**
   - Verify CNPG cluster has backups enabled (`barmanObjectStore` or local PVC snapshots).
   - Document recovery procedure: `docs/runbooks/cnpg-recovery.md`.
   - Test: delete the primary pod, verify failover (on non-SNO) or recovery (on SNO with single instance).

5. **Sandbox reaping (garbage collection).**
   - Sandboxes have a TTL (`ttlMinutes`); verify the launcher/gateway reaps expired sandboxes.
   - If not automatic: add a CronJob `sandbox-reaper` that deletes Sandbox CRs where `metadata.creationTimestamp + ttl < now`.
   - Verify: after TTL, the sandbox pod is gone and the Vault grant can be cleaned up (optional; grants expire naturally).

### Verify / Exit
- etcd defrag runs without errors; post-defrag fragmentation < 10%.
- `oc delete pod spire-server-0 -n zero-trust-workload-identity-manager` does not break in-flight sandboxes (they recover).
- Image pins in overlays match golden tags.
- CNPG primary pod deletion triggers recovery; data is not lost.
- Expired sandboxes are reaped within 10min of TTL expiry.

### Files / Touch-Points
- `docs/runbooks/etcd-defrag-sno.md` (new)
- `docs/runbooks/golden-image-pins.md` (new)
- `docs/runbooks/cnpg-recovery.md` (new)
- `platform/observability/alerts/base/prometheus-rule.yaml` (add EtcdFragmentationHigh)
- `platform/sandbox-reaper/` (new CronJob, optional)

### Gated?
**No** - these are operational procedures and monitoring additions; no cluster mutation required for the runbooks. The sandbox-reaper CronJob is a new resource but is additive.

---

## Parallelism Analysis

| Loop | Can run in parallel with A/B/C? | Must come last? | Notes |
|------|--------------------------------|-----------------|-------|
| D1 (GitOps durability) | Yes (parallel with B/C) | No | Hub fix is gated but does not block other loops. |
| D2 (NetworkPolicies) | Yes (parallel with B/C) | No | NPs are additive; can apply now. |
| D3 (Testing strategy) | Partially (scripts for B/C features come after B/C) | No | Test scripts for existing features can be written now. |
| D4 (Observability) | Yes (parallel with B/C) | No | Dashboards/alerts can be extended now. |
| D5 (Stability) | Yes (parallel with B/C) | No | Runbooks and monitoring can be written now. |

**What must come last:** Full D3 (testing) depends on B/C features being deployed to write their acceptance tests. D4 (CNPG WORM for mint-gate) depends on B1/B2 being deployed.

---

## Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|------------|--------|------------|
| D-R1 | Hub ManifestWork edit breaks other components | LOW | HIGH | Test in staging; edit is additive (image pin only). |
| D-R2 | Dropping CAP_NET_ADMIN breaks supervisor | LOW | MEDIUM | Test on a disposable sandbox first; revert if needed. |
| D-R3 | etcd defrag causes brief API unavailability (SNO) | HIGH | MEDIUM | Schedule during quiet window; take snapshot first. |
| D-R4 | CNPG append-only constraints prevent emergency fixes | LOW | MEDIUM | Keep a privileged admin role for break-glass; audit its use. |
| D-R5 | Sandbox-reaper deletes an in-use sandbox | LOW | MEDIUM | Reaper checks TTL strictly; add a "keep" label exemption. |

---

## Open Questions

1. **Sandbox-reaper implementation:** Should this be a CronJob or an operator-style controller with watch on Sandbox CRs?
2. **Transcript retention:** How long should transcripts be kept (compliance requirement)?
3. **Receipt persistence:** Is CNPG receipt storage required for compliance, or is Loki sufficient?
4. **Hub access:** Who has access to edit the ACM ManifestWork on the hub cluster?

---

## Summary

Phase D makes the proven journey DURABLE and OBSERVABLE:
- **D1:** GitOps never reverts the working state (hub fix, per-doc apply, mounts-over-env).
- **D2:** Network security is complete (egress NP, default-deny, consider dropping NET_ADMIN).
- **D3:** Tests prevent regression (anchor protected, per-surface scripts, CI gates).
- **D4:** Every action is auditable (ext-proc receipts, CNPG WORM, dashboards, alerts).
- **D5:** The platform survives maintenance (etcd defrag, SPIRE restart, image pins, sandbox reaping).

All loops except D1 hub-fix and the Phase B/C-dependent tests can proceed NOW, in parallel with B/C development.
