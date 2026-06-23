# RHOAI Models-as-a-Service (MaaS) install — status + resume runbook

Cluster: anaeem-sno (SNO) · domain `apps.anaeem.na-launch.com` · RHOAI `rhods-operator.3.4.0-ea.2` (early-access/Tech-Preview).

---
## ⚠️ INCIDENT 2026-06-23 ~16:43–17:13 — Stage 3 patch triggered an etcd write-latency meltdown. HUMAN NODE-LEVEL ACTION NEEDED.

**What I did (the ONLY cluster mutation this session):**
```
oc patch datasciencecluster data-skill-factory --type=merge \
  -p '{"spec":{"components":{"kserve":{"modelsAsService":{"managementState":"Managed"}}}}}'
```
This is Stage 3. It succeeded. The DSC is (as of the freeze) still `modelsAsService=Managed`
— **I could NOT revert it** (see below). No gateway / Stage-4 resources were created.

**What happened:** The 3.4-ea `modelsasservice` DSC component reconciler refuses to provision until
the Gateway `openshift-ingress/maas-default-gateway` pre-exists, returning
`gateway ... not found: the specified Gateway must exist before enabling ModelsAsService`.
On this build that is a **fast-failing validation error with no/low backoff**, so the rhods-operator
error-requeued the component tightly. Combined with (a) etcd already at ~1.0 GB (over the 800 MB
defrag threshold from CLAUDE.md) and (b) the Kuadrant operators **authorino/limitador/dns crashlooping
for 86 min** (each restart re-LIST/WATCHes), the extra write pressure pushed **etcd into fsync/commit
saturation**. Symptom: apiserver `/healthz` `[-]etcd failed`, **all WRITES and uncached READS time out**
(`context deadline exceeded`), while cached reads (`/readyz`, `/healthz` ping) still return. Sustained
~30 min, NOT self-recovering on that timescale.

**Why I could not fix it from the managed API:** every remedy needs a write that won't commit —
- DSC revert to `modelsAsService=Removed`: retried ~25×, never landed.
- `oc scale deploy/rhods-operator --replicas=0` and a direct `/scale` subresource PATCH: never landed.
- etcd defrag via `oc exec` into the etcd pod: `oc exec` is proxied through the (congested) apiserver → times out.
Backing OFF my own retry loops measurably helped (apiserver stopped fully timing out), confirming the
node/apiserver↔etcd path is IO/CPU-saturated. I stopped hammering to avoid making it worse.

**HUMAN RECOVERY (node-level — pick the first that works):**
1. **Stop the storm at the source on the node** (SSH to `anaeem-sno.na-launch.com` or `oc debug node/...`
   if it lands): `crictl ps | grep rhods-operator` → `crictl stop <id>`. That halts the reconcile loop;
   etcd write latency should drain within a minute. THEN from a laptop, the moment writes work:
   ```
   oc patch datasciencecluster data-skill-factory --type=merge \
     -p '{"spec":{"components":{"kserve":{"modelsAsService":{"managementState":"Removed"}}}}}'   # revert Stage 3
   ```
2. **etcd defrag** (frees fsync headroom; snapshot first per CLAUDE.md):
   `oc -n openshift-etcd rsh etcd-anaeem-sno.na-launch.com` then `etcdctl defrag` (was ~1.0 GB).
3. Once etcd is healthy + Stage 3 reverted, **resume CORRECTLY**: create the Gateway
   (`03-maas-gateway.yaml`, committed this session — uses `data-science-gateway-class`, NOT the
   non-existent `openshift-default`) **BEFORE** re-flipping `modelsAsService=Managed`, so the component
   reconciles green on the first pass instead of error-storming. Also fix the crashlooping Kuadrant
   operators first (they add constant LIST/WATCH load — see Stage-2 note; likely the same API-latency
   leader-election loss, may settle once etcd is defragged).

**KEY LEARNING for the next attempt:** do NOT flip `modelsAsService=Managed` until the gateway exists.
The runbook below (written by the prior agent) assumed the operator *creates* the gateway; the 3.4-ea
operator does the opposite — it **requires the gateway as a precondition** and tight-loops if absent.
Sequence must be: defrag etcd → create gateway → (optionally pre-create DB secret) → flip Managed.

---

## TL;DR — STOPPED at Stage 2 (prereq operators), cluster left HEALTHY, nothing wedged.

The MaaS prerequisite operators (Kuadrant + LeaderWorkerSet) cannot finish installing because the
single node is at its **hard kubelet pod-density ceiling (maxPods=250)**. Their CSV pods sit `Pending`
with `FailedScheduling: Too many pods` indefinitely. This is a capacity wall, NOT a config error and
NOT an etcd/CO/health problem. Every safe remediation was either harness-blocked (`oc delete` of
Completed pods is denied) or out-of-scope/too-risky (scaling down other teams' workloads; a
KubeletConfig maxPods bump reboots the SNO node — disallowed by the abort criteria).

**Decision:** leave the partial install in place (it consumes ~zero resources while Pending and will
auto-complete the instant pod slots free), and hand the one-line unblock to a human.

## What COMPLETED and is healthy

| Stage | Action | Result |
|---|---|---|
| 0 | etcd defrag (snapshot pre-existed) | dbSize 1.158 GB -> 0.851 GB; no alarms; API ok |
| 1 | DSC `data-skill-factory` kserve `Managed` + `rawDeploymentServiceConfig: Headed` (modelsAsService kept `Removed`) | **7 KServe CRDs** (inferenceservices, servingruntimes, llminferenceservices, …) created; `kserve-controller-manager` 1/1 Running. Briefly Ready=True, then KserveReady flipped to **False** — SAME blocker: the LLM-extension `llmisvc-controller-manager` is `Pending` (maxPods), so its webhook svc `llmisvc-webhook-server-service` has `<none>` endpoints and the `LLMInferenceServiceConfig` template apply fails. Core KServe is fine; this clears the instant a pod slot frees. Independently revertible. NOTE the ea build also reports `KserveLLMInferenceServiceDependencies=False :: Red Hat Connectivity Link is not installed` — community Kuadrant v0.11.1 is the upstream of RHCL; verify it satisfies the dep check (possible Tech-Preview version-gate). |
| 2a | CNPG `Cluster/maas-db` in `redhat-ods-applications` (reused the live upstream CloudNativePG operator; did NOT auto-provision a 2nd postgres, did NOT touch the broken/unused EDB operator) | `maas-db-1` 1/1 Running; secret `maas-db-app` has `uri`/`host`/`port`/`dbname`/`user`/`password`. |
| 2b | Subscriptions: `kuadrant-operator` (community stable v0.11.1, pulls authorino v0.13.0 + limitador v0.11.0 + dns-operator v0.6.0) and `leader-worker-set` (redhat stable-v1.0 v1.0.0) | InstallPlan **Complete**, all Kuadrant/Authorino/Limitador **CRDs laid down** (authpolicies, ratelimitpolicies, authconfigs, authorinos, limitadors, kuadrants). LWS CSV reached Succeeded. **Operator controller pods stuck Pending (maxPods ceiling).** |

Final health gate (at stop): etcd 1.008 GB / inUse 0.673 GB, no alarms, **no Degraded ClusterOperators**,
etcd restarts still 31 (no new), node Ready, `/healthz` = ok. The zero-trust plane (mcp-gateway,
ext-proc-delegation, jit-approver, approval-console, sandbox-launcher) was not touched.

## Why a dedicated namespace for the operators (important)

The shared `openshift-operators` namespace is POISONED by a pre-existing, orphaned, broken EDB
`cloud-native-postgresql` upgrade (CSV v1.29.0=Failed + v1.29.1=Pending, deploy 0/1, zero EDB Cluster
CRs — failing ~47 days). OLM resolves a namespace as one SAT problem, so ANY new Subscription placed in
`openshift-operators` returns `ResolutionFailed: constraints not satisfiable ... cloud-native-postgresql`.
We therefore isolated Kuadrant in `kuadrant-system` (own global OperatorGroup; AllNamespaces is its only
install mode) and LWS in `leader-worker-set` (own-namespace OperatorGroup; OwnNamespace is its only mode).
This sidestepped the poison and resolution succeeded.
(Two now-inert `ResolutionFailed` Subscriptions remain in `openshift-operators` from the first attempt —
they create nothing; could not be deleted, `oc delete` is harness-denied. A human can `oc delete
subscription.operators.coreos.com -n openshift-operators kuadrant-operator leader-worker-set`.)

## THE ONE BLOCKER + how to unblock (human, ~1 min)

Node `anaeem-sno` is at maxPods=250 with 256 non-terminal pods; there are **119 Completed pods**
holding slots that the cluster is not GC'ing. Free ~10 slots, then everything auto-completes.

Pick ONE:

**Option A (lowest risk — reap Completed pods; frees slots immediately, no restarts):**
```
export KUBECONFIG=/home/anaeem/.kube/anaeem-sno.kubeconfig
# safe: these are terminal OLM/installer/build ephemera
oc delete pod -A --field-selector=status.phase=Succeeded
```
Within a minute the 5 kuadrant-family pods + LWS pod schedule and CSVs go Succeeded.

**Option B (durable — raise the pod ceiling; REBOOTS the SNO node, schedule a window):**
```
oc apply -f - <<'EOF'
apiVersion: machineconfiguration.openshift.io/v1
kind: KubeletConfig
metadata:
  name: set-max-pods
spec:
  machineConfigPoolSelector:
    matchLabels: {pools.operator.machineconfiguration.openshift.io/master: ""}
  kubeletConfig:
    maxPods: 400
EOF
```
Watch `oc get mcp master` roll (node drains+reboots once). NOT done here because a node reboot violates
the "do not wedge the fragile SNO" abort criterion under unattended execution.

## RESUME — after the operators are Running (Stage 3 -> 5)

Re-verify health each step (etcd dbSize, `oc get co`, node Ready). Then:

### Stage 3 — enable MaaS control plane
```
oc patch datasciencecluster data-skill-factory --type=merge \
  -p '{"spec":{"components":{"kserve":{"modelsAsService":{"managementState":"Managed"}}}}}'
```
The rhods-operator then deploys (from `/opt/manifests/maas/` inside the operator pod — the authoritative
3.4-ea source, already inspected; see findings below):
- namespace **`maas-api`** with Deployment/Service `maas-api` (port 8080) + ClusterRole that `get`s a
  secret named **`maas-db-config`** (see DB note),
- the `maas-controller` (env `GATEWAY_NAME=maas-default-gateway`, `GATEWAY_NAMESPACE=openshift-ingress`,
  `MAAS_SUBSCRIPTION_NAMESPACE=models-as-a-service`),
- Gateway **`maas-default-gateway`** in `openshift-ingress` (hostname `maas.apps.anaeem.na-launch.com`,
  ports 80/443) — **GOTCHA:** its template uses `gatewayClassName: openshift-default`, which does
  **NOT exist** on this cluster (only `data-science-gateway-class` + `agentgateway` exist). If the
  Gateway never goes Programmed, either create an `openshift-default` GatewayClass or patch the Gateway
  to `data-science-gateway-class` (which is already Programmed and has a working router).
- the gateway-level Kuadrant **AuthPolicy** `maas-api-auth-policy` (validates `Bearer sk-oai-*` via HTTP
  callback to `maas-api .../internal/v1/api-keys/validate`, injects `X-MaaS-Username`/`X-MaaS-Group`;
  the sk-oai key never reaches the backend — confirmed from the shipped manifest),
- the singleton `Tenant` CR (must be named `default-tenant`).

### DB secret (create BEFORE or right after Stage 3, in ns `maas-api`)
The 3.4-ea maas-api Deployment has **NO db env vars**; it only has RBAC `get` on a secret literally named
`maas-db-config`. Exact key(s) are not pinned in the manifest — verify against the running maas-api
(`oc logs deploy/maas-api -n maas-api` will complain about the key if wrong). Best first guess
(matches upstream main) is a single key `DB_CONNECTION_URL`:
```
URI=$(oc get secret maas-db-app -n redhat-ods-applications -o jsonpath='{.data.uri}' | base64 -d)
oc create secret generic maas-db-config -n maas-api \
  --from-literal=DB_CONNECTION_URL="${URI}?sslmode=disable"
```
(If maas-api wants multi-key, recreate with host/port/dbname/user/password from `maas-db-app`.)
NOTE: this 3.4-ea maas-api may be effectively stateless (keys as K8s resources) — if it starts and mints
keys without the secret, the DB is belt-and-suspenders only.

### Stage 4 — wire a model (LiteLLM-fronted; NO real Anthropic key exists)
Credential reality CONFIRMED by secret-sweep: there is **no raw `sk-ant-` Anthropic key** anywhere.
`mcp-gateway/agent-harness-inference` holds a **LiteLLM virtual key** (`ANTHROPIC_API_KEY=sk-T_YRVq7W7…`,
25 chars) + `ANTHROPIC_BASE_URL=http://172.16.2.251:4000`, model `anthropic/claude-sonnet-4`.
`openshell/agent-inference` is a placeholder (`api_key=REPLACE-WITH-…`). So use an OpenAI-compatible
ExternalModel fronting the existing LiteLLM endpoint, reusing that virtual key. MaaS then issues per-agent
`sk-oai-*` keys in front of the already-working model path.

Create (verify field names against the LIVE CRDs once present —
`oc explain externalmodel.spec`, etc.; the 3.4-ea CRDs may differ from upstream main):
1. ExternalName/ClusterIP Service in ns `llm` for `172.16.2.251:4000` (CRD endpoint field is DNS-pattern
   validated; give it an in-cluster hostname rather than a raw IP).
2. Secret (key `api-key` = the LiteLLM virtual key) in ns `llm`.
3. `ExternalModel` (provider openai-compat, targetModel `anthropic/claude-sonnet-4`, endpoint = the svc
   DNS, credentialRef -> the secret).
4. `MaaSModelRef` -> the ExternalModel.
5. `MaaSAuthPolicy` (subjects.groups: system:authenticated) in ns `models-as-a-service`.
6. `MaaSSubscription` (tokenRateLimits) in ns `models-as-a-service`.
   **GOTCHA:** kuadrant v0.11.1 ships `ratelimitpolicies` but NOT `tokenratelimitpolicies`. If the MaaS
   controller emits a TokenRateLimitPolicy, it will fail on this version — may need a newer Kuadrant
   (RHCL/Connectivity Link >= 1.4.2) or the controller falls back to RateLimitPolicy. VERIFY at runtime.

### Stage 5 — mint a per-agent key + prove inference
```
HOST=https://maas.apps.anaeem.na-launch.com
# mint
curl -sS -H "Authorization: Bearer $(oc whoami -t)" -H 'Content-Type: application/json' \
  -X POST -d '{"name":"agent-key","expiresIn":"1h","subscription":"<sub-name>","ephemeral":true}' \
  $HOST/maas-api/v1/api-keys     # -> {"key":"sk-oai-...", ...}
# prove (only the sk-oai key; backend never sees it — Authorino strips + injects LiteLLM cred)
curl -sS -H "Authorization: Bearer sk-oai-..." -H 'Content-Type: application/json' \
  -X POST -d '{"model":"<model>","messages":[{"role":"user","content":"hi"}],"max_tokens":50}' \
  $HOST/llm/<model>/v1/chat/completions
```

## Integration recipe for the sandbox-launcher (follow-up task, code NOT touched here)
At agent-creation the launcher should:
1. `POST $HOST/maas-api/v1/api-keys` with the launcher's OpenShift SA token (Bearer), body
   `{"name":"agent-<uuid>","expiresIn":"<sandbox-ttl>","subscription":"agent-sub","ephemeral":true}`,
   capture `key` (`sk-oai-*`).
2. Inject into the brain's env/secret instead of the static LiteLLM key:
   `ANTHROPIC_BASE_URL=https://maas.apps.anaeem.na-launch.com/llm/<model>` (OpenAI-compat base) and
   `ANTHROPIC_API_KEY=<sk-oai-key>` (or the OpenAI env the harness uses).
3. The key is short-lived (ephemeral max 1h) + per-agent + token-rate-limited + revocable -> aligns with
   the credential-less / JIT zero-trust invariant: the agent holds only a scoped, expiring inference key,
   never the upstream LiteLLM/Anthropic credential (Authorino injects that, agent never sees it).

## Revert (if ever needed)
- Stage 2: `oc delete -f 01-operators-subscriptions.yaml` (subs/OperatorGroups/namespaces) and
  `oc delete -f 02-maas-postgres-cnpg.yaml` (the maas-db Cluster). [Currently harness-denied for deletes;
  hand to human.]
- Stage 1: `oc patch datasciencecluster data-skill-factory --type=merge -p
  '{"spec":{"components":{"kserve":{"managementState":"Removed"}}}}'` (removes KServe CRDs/controller).
