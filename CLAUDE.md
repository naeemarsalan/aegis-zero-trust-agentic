# nvidia-ida — zero-trust agentic platform (orientation for the main agent)

Single-node OpenShift (SNO) homelab PoC proving a **credential-less agent** can **read delegated as a
human** and **write only via human-approved, just-in-time, short-lived** elevation — the agent holds
**only its SPIFFE SVID**, never a stored broad credential. Keep this invariant in every change.

- **Cluster:** `export KUBECONFIG=/home/anaeem/.kube/anaeem-sno.kubeconfig` · node `anaeem-sno.na-launch.com`.
- **FRAGILE.** etcd hovers ~1 GB (defrag if >~800 MB, snapshot first); spire-server has many restarts;
  transient API/`529` flaps happen — retry, don't panic. READ-ONLY first; gate every mutation.
- **Canonical state-of-the-world doc:** `docs/reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md`
  (the running work-log + every issue→resolution). Read it before reasoning about Phase A.
- **Per-session memory** (the real "context store"): `~/.claude/projects/-home-anaeem-nvidia-ida/memory/`
  (`MEMORY.md` is the index). Verify a memory's file/flag claims against live code before asserting them.

## The two identity planes (do not conflate)
1. **ext-proc / Variant-B — REAL tools (pfSense, k8s).** Agent SVID (UUID-shaped
   `…/ns/openshell/sandbox/<uuid>`) → `ext-proc-delegation` verifies it → reads the per-sandbox **Vault
   consent grant** (`secret/data/sandbox-grants/<uuid>`, written by the launcher) → RFC 8693 on-behalf-of
   (currently the **static per-user token fallback** from Vault `mcp-tools/mcp-tokens{,-write}`, because
   KC OBO needs a per-client config — see below) → injects the downstream token. JIT = the ext-proc gate
   / `jit-gate-k8s`. This is the path that reaches the **real** tools. Proven 4/4 (`hack/test-openshift-jit.sh`).
2. **Kagenti AuthBridge — the chosen identity plane (ADR-0013), reaches echo-mcp.** Agent SVID (SA-shaped
   `…/ns/openshell/sa/openshell-sandbox`) → injected `spiffe-helper` + `authbridge-proxy` sidecars →
   Keycloak **federated-jwt** (realm `kagenti`) → token-exchange → `jit-gate` → `echo-mcp`. JIT = `jit-gate`
   (capability JWT, `aud=kyverno-authz`). Proven green.

**SVID-shape mutual exclusion (key fact):** ext-proc needs the UUID path; Kagenti needs the SA path. One
SVID can't be both, so the openshell sandbox pod carries **TWO** SVIDs via two ClusterSPIFFEIDs
(`openshell-sandbox-workloads` = SA-shaped, `openshell-sandbox-extproc` = UUID-shaped). The agent's
`svid_bearer` selects the UUID one for ext-proc via `SVID_REQUIRE_PATH_SUBSTR=/sandbox/`.

## Current Phase-A status (gate for Phases B/C)
**PROVEN end-to-end:** a credential-less LLM agent in a native OpenShell sandbox does the real pfSense
journey — read-delegated `200` → write `403 grant_scope_denied` → human-approve (Gitea PR) → JIT-elevated
write `200` (real rule created). Substrate (SVID issuance, Vault grant, the metadata.id==annotation==SVID-path
binding per ADR-0018), Kagenti enrollment + chain, and OpenShell-operational (a native sandbox boots a real
LLM agent: `agent-harness` image + `ExecSandbox` detached boot + `PYTHONPATH=/app/src`) are all done.

**Open seams (last-mile, not the core loop):**
- **Unattended autonomy (in progress):** a launcher-booted brain runs in the gateway's confined setns/MCS
  namespace where the SPIRE Workload-API SVID fetch fails. Fix being wired: the `spiffe-helper` sidecar
  writes the UUID `mcp-gateway` SVID to a shared file → the brain reads it via `SVID_JWT_PATH` (the
  file-handoff was still broken at last check; workflow `wf_2594a3fe-73d` paused after a transient 529).
- **ACM image reverter:** an ACM klusterlet `work-agent` (hub ManifestWork `ida-launcher-componenta`)
  re-pins the launcher to `:dev`/`sandbox-agent:sh3` ~2 min after any apply. **No hub access from this
  cluster** → durable fix is a HUB edit (human). Managed-side `oc apply` holds ~2 min only.
- **Real per-user OBO:** PROVEN viable (NOT the old #40328 NPE — RHBK 26.6.3 just needs fine-grained
  impersonation perms on the agentic `mcp-gateway` client; verified in the isolated `kagenti` realm). Not
  applied (the static-token fallback is the PoC answer; v1 is deprecated, v2 `subject_token` is durable).

## Conventions & gotchas (save yourself the re-learning)
- **`oc delete` of CLUSTER-SCOPED resources is harness-DENIED** (clusterpolicy/clusterrole/clusterspiffeid).
  Namespaced deletes work. Hand cluster-scoped reaps to the human.
- **Never whole-file `oc apply platform/spire/base/cluster-spiffe-ids.yaml`** — the live
  `agent-sandbox-e2e-harness` CSID drifts from git (hardcoded UUID); a whole-file apply breaks the 4/4
  harness. Apply per-doc (python-extract the single CSID).
- **OVN-K DNS egress** needs `:53` AND `:5353` to `openshift-dns` (CoreDNS pods listen on 5353).
- **Webhook objectSelector ordering:** a label a *later* mutating webhook (Kyverno-on-pod) adds does NOT
  retroactively fire a selector-gated earlier webhook. Stamp selector labels on the **Sandbox CR**
  podTemplate (the agent-sandbox controller propagates them to the pod at creation).
- **Kyverno on a CRD:** use `patchesJson6902` (append), not `patchStrategicMerge`, on `containers`/`env`
  lists — strategic-merge clobbers the whole element on a CRD (no list-map-key honored).
- **The setns fix is CLOSED** (ADR-0017: missing `CAP_SYS_CHROOT`, delivered by Kyverno
  `mutate-openshell-sandbox-syschroot`). `provider_spiffe` is enabled live. Don't reopen it.
- **The agent-brain** is LiteLLM→OpenRouter (`172.16.2.251:4000`, `anthropic/claude-sonnet-4`); it is
  credit-gated (a `402` there, not a code bug, is why a journey may stall).

## Where things live
- `platform/spire/base/cluster-spiffe-ids.yaml` + `cluster-spiffe-id-openshell-sandbox-extproc.yaml` — SVIDs.
- `platform/openshell/kagenti-authbridge/` — the Kagenti enrollment (CMs, Kyverno-on-CR stamp, NPs).
- `platform/kagenti/operator-finalizer-rbac.yaml` — the operator `sandboxes/finalizers` RBAC.
- `platform/vault/config/{sandbox-launcher.hcl,vault-bootstrap.sh}` — launcher Vault policy/role.
- `services/sandbox-launcher/` — `/launch` + the brain-boot (`openshell.py`), Vault grant write.
- `services/ext-proc-delegation/` — SVID verify → grant → exchange/inject + audit.
- `services/jit-gate/` + `services/jit-approver/` — the JIT human-approval plane.
- `services/agent-sandbox/agent-harness/` — the brain-bearing agent image + `svid_bearer` + `mcp-call` + skills.
- `hack/test-openshift-jit.sh` (the proven 4/4 anchor — re-run after every change),
  `hack/test-openshell-native-hybrid.sh`, `hack/test-kagenti-{identity,jit}.sh`.
- ADRs: 0011 (ext-proc hybrid), 0012 (pfSense opaque tokens), 0013 (Kagenti adoption + OBO),
  0017 (setns/CAP_SYS_CHROOT), 0018 (SVID↔grant-key binding).

## Working state
Phase-A work is on branch **`feat/openshell-native-svid-grant`**, **uncommitted**, intermingled with a
separate **mint-gate L0/L1 WIP** (jit-approver/approval-console/mint_core/persistence — keep that diff
separate when committing).
