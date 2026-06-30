# Install Guide — Zero-Trust Agentic AI Platform

This guide brings the platform up on a fresh OpenShift cluster. The **proven** install path is
**imperative, per-component `oc apply`** (this is exactly how the reference cluster `ocp-dev` is
deployed today). A GitOps **app-of-apps** also exists and reconciles most of the base/tool-plane
components, but it is **aspirational** — it is *not* the path the live cluster runs on (see §4). A few
steps (Vault init/unseal + config, Keycloak realm + demo password) are **imperative bootstrap** and are
not yet automated.

> **Honesty up front (PoC, not a turnkey installer).** Every command below is verified against the live
> `ocp-dev` cluster, but a 100%-hands-off fresh-cluster rebuild is **not yet proven** end-to-end
> (PRD §P2). Expect to run the secret-bootstrap steps by hand and to hit the **gotchas in §9** — they
> are documented because we hit them. Reference cluster: `ocp-dev` (OCP 4.20.25, 3 control-plane +
> 2 worker), trust domain `anaeem.na-launch.com`, apps wildcard `*.apps.ocp-dev.na-launch.com`
> (ingress VIP `172.16.2.59`).

**At a glance — the order that works:**

```
§1 prereqs → §2 clone+retarget → §3 node/storage prep → §5 operators (OLM + Helm + CNPG)
→ §5 base/tool plane (spire, vault, keycloak, kyverno, agentgateway, ext-proc, jit-approver)
→ §6 Vault bootstrap → §7 Keycloak realm + demo password → §8 model plane + WORM DB
→ §10 verify (one turnkey script proves all four planes)
```

---

## 1. Prerequisites

**Cluster**
- OpenShift **4.20+**, 3 control-plane + **≥2 worker** nodes. The platform is CPU/memory-heavy (RHOAI,
  SPIRE, Vault, Keycloak, Kyverno, RHCL/Istio, CNPG). Workers ~16 vCPU / 64 GB each is the floor.
- A default **`local-path`** StorageClass. CNPG, the SPIRE datastore, and the Keycloak DB initdb all
  hang on NFS — use local-path (see §3 + §9). Manifests expect `storageClassName: local-path`.
- `cluster-admin`. etcd runs on the control plane and **flaps under load** (slow `oc exec`, transient
  5xx); this is expected on the reference cluster — retry, don't panic. **READ-ONLY first; gate every
  mutation.** SPIRE here uses a single-replica **sqlite3** datastore (not HA).
- **No GPU** is required for the two auth planes (tool + model via OpenRouter). A GPU is only needed
  for in-cluster large-LLM serving (roadmap M7).

**A container registry** the cluster can pull from. The repo references `oci.arsalan.io/nvidia-ida/…`;
point it at your own (see §2).

**DNS / hosts.** The routes (Keycloak, Vault, MaaS gateway, jit-approver, console) live on the apps
wildcard. Either have real DNS for `*.apps.<cluster-domain>`, **or** add `/etc/hosts` entries to the
ingress VIP — the verify step (§10) needs them:

```
172.16.2.59  keycloak.apps.ocp-dev.na-launch.com vault.apps.ocp-dev.na-launch.com \
             jit-approver-api.apps.ocp-dev.na-launch.com console.apps.ocp-dev.na-launch.com \
             maas.apps.ocp-dev.na-launch.com
```

**Local tools:** `oc`, `kustomize` (≥ v5), `helm` (kustomize renders Vault/Kyverno/agentgateway via
the Helm inflation generator — see §5), `vault` CLI (only for the §6 bootstrap, run via port-forward),
`podman` (image builds), `python3`, `openssl`, `curl`, `git`, optionally `gh`.

> **Kubeconfig:** keep a **break-glass cert kubeconfig** (`system:admin`, bypasses OAuth) handy —
> OAuth user tokens expire and the control plane flaps. On the reference cluster the working file is
> `~/.kube/ocp-dev-admin.kubeconfig`; the user-token `~/.kube/ocp-dev.kubeconfig` is **expired**. The
> verify scripts default to the cert file (override with `IDA_KUBECONFIG`).

---

## 2. Get the repo + set your cluster

```bash
git clone <this-repo> && cd nvidia-ida
export KUBECONFIG=~/.kube/<your-cluster>-admin.kubeconfig
oc whoami            # confirm cluster-admin / system:admin
```

The manifests are pinned to a cluster apps-domain and a SPIFFE **trust domain**. Retargeting the
apps-domain is a simple sed; **changing the trust domain is invasive** (it appears in every
ClusterSPIFFEID, every Vault `bound_subject`, and the SVID paths) — **keep `anaeem.na-launch.com`
unless you have a reason not to.**

```bash
# Retarget the routes/issuers to YOUR apps domain (scoped — do NOT run from repo root, it would
# recurse into .git/ and docs/):
grep -rl 'apps.ocp-dev.na-launch.com' platform/ services/ gitops/ \
  | xargs sed -i 's/apps\.ocp-dev\.na-launch\.com/apps.<your-cluster>.na-launch.com/g'

# Registry (scoped the same way):
grep -rl 'oci.arsalan.io/nvidia-ida' platform/ services/ gitops/ \
  | xargs sed -i 's#oci.arsalan.io/nvidia-ida#<your-registry>#g'
```

Create your secrets env (git-ignored — never commit it):

```bash
cp environment/.env.example environment/.env
# Fill in at least: PFSENSE_API_URL, PFSENSE_API_KEY, PFSENSE_USERNAME, PFSENSE_PASSWORD,
#                   MCP_API_TOKENS, OPENROUTER_API_KEY (model plane), GITEA_TOKEN, DEMO_PASSWORD.
# The §6 Vault bootstrap reads these. See §6 for the full list.
```

---

## 3. Node + storage prep (do this BEFORE workloads schedule)

The local-path provisioner's hostPath needs the right SELinux label + perms on **every** node, or PVC
binding fails with `mkdir: Permission denied`:

```bash
for n in $(oc get nodes -o name); do
  oc debug "$n" -- chroot /host sh -c \
    'mkdir -p /opt/local-path-provisioner && chmod 1777 /opt/local-path-provisioner && \
     chcon -t container_file_t /opt/local-path-provisioner' 2>/dev/null
done
```

PVCs are `WaitForFirstConsumer`, so they bind once a consuming pod schedules.

---

## 4. (Optional) GitOps engine — aspirational, not the proven path

> **The live `ocp-dev` cluster has ZERO ArgoCD Applications applied** — the whole platform is deployed
> imperatively (§5/§8). The app-of-apps is real and builds cleanly, but it covers only the 13
> base/tool-plane components (the **model plane and WORM DB are not in it**) and a hands-off reconcile
> is unproven. **If you just want the platform up, skip to §5.** Use this section only if you want to
> drive the base components via ArgoCD.

```bash
# 1. Operator (OLM):
oc apply -k platform/00-operators/openshift-gitops
# 2. The controller manages ClusterSPIFFEIDs/Routes/SCCs (needs cluster-admin) and Vault/Kyverno render
#    via Helm (needs --enable-helm):
oc -n openshift-gitops adm policy add-cluster-role-to-user cluster-admin \
  -z openshift-gitops-argocd-application-controller
oc -n openshift-gitops patch argocd openshift-gitops --type merge \
  -p '{"spec":{"repo":{"env":[{"name":"ARGOCD_EXEC_TIMEOUT","value":"300s"}]},"kustomizeBuildOptions":"--enable-helm"}}'
# 3. Retarget the GitOps source to YOUR repo/branch (the manifests pin git.arsalan.io + the
#    fix/jit-approver-mint-route branch) and create the repo credential if private:
grep -rl 'git.arsalan.io/anaeem/nvidia-ida' gitops/ \
  | xargs sed -i 's#https://git.arsalan.io/anaeem/nvidia-ida.git#<your-repo-url>#g'
# (then create a repo-<name> secret of type repository in openshift-gitops with a git token)
# 4. Bootstrap (self-managed; the default build now emits NO ACM-hub resources):
kustomize build gitops | oc apply -f -
oc get applications -n openshift-gitops -w
```

> The `gitops/acm-registration/` flow (managed-cluster secret on an ACM hub) is the **older** model.
> The default `kustomize build gitops` is **self-managed** (all child apps target
> `https://kubernetes.default.svc`). To deploy from a separate ACM hub, re-enable `acm-registration`
> in `gitops/kustomization.yaml` (or `kustomize build gitops/acm-registration` separately).

---

## 5. Operators, then the base + tool plane (imperative — the proven path)

### 5a. Operators

These install via **three** mechanisms (not all OLM — the guide used to claim wave-0 installed
everything; it does not):

| Mechanism | Operators | How |
|---|---|---|
| **OLM** (`platform/00-operators`) | SPIRE / ZTWIM, RHBK (Keycloak), sandboxed-containers, OpenShift GitOps | `oc apply -k platform/00-operators` |
| **Helm** (rendered by kustomize) | Vault, Kyverno, agentgateway | `kustomize build <path> --enable-helm \| oc apply -f -` (see 5b) |
| **Community manifest** | CloudNativePG (CNPG) | upstream release manifest (below) |
| **OLM, applied with the model plane (§8)** | RHCL (Connectivity Link → Authorino/Limitador), RHOAI 3.4 (rhods), leader-worker-set, Service Mesh 3 (Istio) | `oc apply -f platform/rhoai-maas/01-… 10-…` (§8) |

```bash
# OLM operators (SPIRE, Keycloak/RHBK, sandboxed-containers, GitOps):
oc apply -k platform/00-operators
# CloudNativePG community operator (the keycloak / jit-approver-db / maas CNPG Cluster CRs depend on it).
# Pick a current release from https://github.com/cloudnative-pg/cloudnative-pg/releases — the reference
# cluster runs 1.27.0:
oc apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.27/releases/cnpg-1.27.0.yaml
# Wait for the CSVs to reach Succeeded before applying the components that consume them:
oc get csv -A -w     # ctrl-C once ztwim / rhbk / sandboxed-containers / gitops are Succeeded
```

> **CNPG on OpenShift gotcha (§9):** strip the alpha-seccomp annotations + pin `runAsUser` and grant
> the SA `anyuid`, or the controller won't run.
> **EDB-poison gotcha (§9):** do **not** put the model-plane operators in `openshift-operators` — a
> pre-existing broken EDB postgres CSV there makes OLM fail to resolve *any* new subscription. The
> model-plane manifests deliberately use a dedicated `kuadrant-system` namespace (§8).

### 5b. Base + tool plane

Apply each component's `anaeem` overlay (rename/copy the overlay for your own cluster). **Helm-backed
components (vault, kyverno, agentgateway) cannot use `oc apply -k`** — render them with
`--enable-helm` first:

```bash
# Identity (SPIRE / ZTWIM):
oc apply -k platform/spire/overlays/anaeem

# Secrets (Vault — Helm):
kustomize build platform/vault/overlays/anaeem --enable-helm | oc apply -f -

# Keycloak (RHBK operator CR + its CNPG DB):
oc apply -k platform/keycloak/overlays/anaeem

# Policy engine (Kyverno — Helm):
kustomize build platform/kyverno/install/overlays/anaeem --enable-helm | oc apply -f -
oc apply -k platform/kyverno/overlays/anaeem          # the guardrail ClusterPolicies

# MCP data plane (agentgateway — Helm) + ext-proc + jit-approver:
kustomize build platform/agentgateway/overlays/anaeem --enable-helm | oc apply -f -
oc apply -k services/ext-proc-delegation/deploy/overlays/anaeem
oc apply -k services/jit-approver/deploy/overlays/anaeem
```

> **SVID CSIDs:** the sandbox carries TWO SVIDs (UUID-shaped for ext-proc, SA-shaped for Kagenti).
> Apply `platform/spire/base/cluster-spiffe-ids.yaml` **per-document**, never whole-file — the live
> `agent-sandbox-e2e-harness` CSID has a hardcoded UUID that drifts (§9).
> **`VAULT_ADDR` invariant:** ext-proc and jit-approver must point at **in-cluster**
> `http://vault.vault.svc:8200`, not the external route (the overlays already do; §9).

---

## 6. Vault bootstrap (secrets — imperative)

After the Vault pod is `Running`:

```bash
# Init + unseal. Record the root token + unseal key(s) into environment/.env (git-ignored!).
# (The reference cluster runs shamir 1/1; -key-shares=5 -key-threshold=3 is also fine — just record
#  whatever you choose. Store the root token as the vault-init secret's root_token field — the verify
#  scripts read `oc -n vault get secret vault-init -o jsonpath='{.data.root_token}'`.)
oc -n vault exec vault-0 -- vault operator init -key-shares=1 -key-threshold=1   # record output
oc -n vault exec vault-0 -- vault operator unseal <unseal-key>

# Configure auth/policies/engines + seed KV (declarative, idempotent). Run via port-forward so the
# local vault CLI + the repo's .hcl files are both reachable:
oc -n vault port-forward svc/vault 8200:8200 &
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root-token>
source environment/.env                       # PFSENSE_*, MCP_API_TOKENS, OPENROUTER_API_KEY, GITEA_TOKEN, DEMO_USER
# SPIRE-OIDC trust: write the ingress CA chain to a FILE and export its PATH (the script consumes it
# as oidc_discovery_ca_pem=@<file>; exporting the PEM *content* would make Vault try to open a file
# named by the cert text and fail):
oc -n openshift-config-managed get cm default-ingress-cert -o jsonpath='{.data.ca-bundle\.crt}' > /tmp/ingress-ca.pem
export OIDC_DISCOVERY_CA_PEM=/tmp/ingress-ca.pem
# k8s secrets engine (run from a workstation -> pass the SA token + CA explicitly):
export VAULT_K8S_SA_JWT="$(oc create token vault -n vault)"
export VAULT_K8S_CA_CERT="$(oc -n vault get cm kube-root-ca.crt -o jsonpath='{.data.ca\.crt}')"
# Keycloak client-secret fetch uses the ambient kubeconfig (NOT the dead anaeem-sno one):
export OC='oc --insecure-skip-tls-verify' KEYCLOAK_URL='https://keycloak.apps.<your-cluster>.na-launch.com'
bash platform/vault/config/vault-bootstrap.sh
```

The script creates `jwt` + `kubernetes` auth, `kv` + `kubernetes` engines, the per-service
policies/roles (`ext-proc`, `jit-approver`, `agent-deny`, `agent-sandbox`, `pfsense-mcp`,
`sandbox-launcher`, and `llm-proxy` for the model plane), **and seeds the KV** it can from your
`environment/.env`:

| KV path | Fields | Source env |
|---|---|---|
| `secret/mcp-tools/pfsense` | `api_url`, `api_key` | `PFSENSE_API_URL/KEY` |
| `secret/mcp-tools/mcp-tokens` | `tokens` (comma list) + `<user>` (read token) | `MCP_API_TOKENS`, `DEMO_USER` |
| `secret/mcp-tools/mcp-tokens-write` | `tokens` + `<user>` (elevated-write token) | `MCP_API_TOKENS_WRITE` (defaults to `MCP_API_TOKENS`) |
| `secret/mcp-tools/openrouter` | `token` | `OPENROUTER_API_KEY` |
| `secret/jit-approver/*` | gitea-token, signing key, webhook | `GITEA_TOKEN` (key auto-generated) |

> **Field-name matters:** `mcp-tokens`/`mcp-tokens-write` use the field **`tokens`** (a comma list) plus
> a per-user field keyed by username — **not** a singular `token`. The bootstrap writes these for you;
> only override with `vault kv put secret/mcp-tools/mcp-tokens tokens=<list> <user>=<read-token>` (a
> naive `token=…` would clobber the correct fields). `openrouter` is the one path that uses `token`.
> **After bootstrap:** rotate the root token; keep unseal keys in `environment/.env` only. **Services
> use in-cluster `http://vault.vault.svc:8200`** — the external route is degraded (§9).

---

## 7. Keycloak realm + demo user password

```bash
# Import the agentic realm (a KeycloakRealmImport CR the RHBK operator consumes — NOT raw realm JSON):
oc apply -f platform/keycloak/base/realm-import.yaml
oc -n keycloak get keycloakrealmimport agentic-realm -w     # wait for Done=True

# Set the demo user's password (the realm ships user `arsalan` with NO credential by design, so any
# password/ROPC grant — and the regression scripts — fail with "Account is not fully set up" until):
source environment/.env                                     # provides DEMO_PASSWORD
bash hack/setup-demo-user.sh
```

> The `platform/keycloak/overlays/anaeem` apply in §5b already includes the realm-import CR + the CNPG
> DB; the explicit `oc apply -f` above is the standalone form. Per-service secrets (jit-approver mTLS,
> the Vault-injected signing key, the approval-console OAuth2 cookie + Keycloak client) are carried by
> the component overlays and the §6 Vault bootstrap.

---

## 8. Model plane — RHOAI 3.4 / MaaS / Gen AI Studio + WORM DB

The model-plane root (`platform/rhoai-maas/`) is an **ordered sequence**, not a single kustomization —
apply the operator subscriptions first, wait for their CSVs, then the CRs (`oc apply -k` on the root
fails: there is no top-level kustomization there).

```bash
# 1. Operators (RHCL/Kuadrant + leader-worker-set in kuadrant-system; RHOAI 3.4 rhods):
oc apply -f platform/rhoai-maas/01-operators-subscriptions.yaml
oc apply -f platform/rhoai-maas/10-rhods-operator-3.4-subscription.yaml
oc get csv -A -w        # wait for rhcl-operator, leader-worker-set, rhods-operator Succeeded

# 2. MaaS postgres (CNPG) + gateway, then the RHOAI DSCInitialization/DSC + dashboard config:
oc apply -f platform/rhoai-maas/02-maas-postgres-cnpg.yaml
oc apply -f platform/rhoai-maas/03-maas-gateway.yaml
oc apply -f platform/rhoai-maas/11-dscinitialization-v2.yaml
oc apply -f platform/rhoai-maas/12-datasciencecluster-v2.yaml
oc apply -f platform/rhoai-maas/13-odhdashboardconfig-genai-studio.yaml
oc apply -f platform/rhoai-maas/allow-egress-maas-gateway-networkpolicy.yaml

# 3. SPIFFE-auth model gateway (Istio + Authorino AuthPolicy + llm-proxy + premium tier).
#    MUST be applied before genai-studio/ — it carries the openrouter-bridge SA authorization (06-authpolicy.yaml):
oc apply -k platform/rhoai-maas/spiffe-auth/

# 4. Register OpenRouter + the MCP server as native Gen AI Studio assets (SVID-callable bridge):
oc apply -k platform/rhoai-maas/genai-studio/
oc label ns maas opendatahub.io/dashboard=true --overwrite     # make maas a selectable DS project

# 5. Durable WORM audit DB for jit-approver (CNPG, append-only hash-chain ledger):
oc apply -k platform/jit-approver-db/base/
```

> The jit-approver `anaeem` overlay already sets `JIT_STORE_BACKEND=postgres` (so the WORM ledger is
> live). If you run a different overlay, set it explicitly or auditing stays in-memory.
> Model-plane detail + verification curls: `docs/design/maas-spiffe-auth.md`,
> `docs/demo/genai-studio-spiffe-zerotrust-runbook.md`.

---

## 9. Known gotchas (we hit all of these)

- **local-path SELinux/perms** on every node — §3, or PVCs never bind.
- **CNPG on OpenShift** — strip alpha-seccomp annotations + pin `runAsUser` + grant SA `anyuid`, or the
  controller won't run. The CNPG DB name is `jit_approver` (owner `app`), not `app` — `psql -d app` fails.
- **EDB-poisoned `openshift-operators`** — a pre-existing broken `cloud-native-postgresql` CSV makes OLM
  return `ResolutionFailed` for *any* new subscription placed there. Install the model-plane operators
  in their own namespace (`kuadrant-system`, as `01-operators-subscriptions.yaml` does).
- **Vault external route is degraded** — point `ext-proc-delegation` and `jit-approver` `VAULT_ADDR` at
  **in-cluster** `http://vault.vault.svc:8200`. On an **ACM-hub-managed** cluster a live `oc set env`
  **reverts within seconds** (the hub ManifestWork re-applies the external route AND re-pins images) —
  the durable fix is a **hub-side edit**. (PRD §7.) The verify scripts read Vault via `oc exec vault-0`,
  not the route, for this reason.
- **SPIRE OIDC `Ready=False` is cosmetic** — if a `spire-oidc-discovery-provider` Route pre-exists, the
  operand reports `RouteAvailable: route already exists` and the ZTWIM `cluster` CR never reaches Ready,
  **but OIDC serves fine**. Verify SPIRE via `curl https://spire-oidc.apps.<cluster>/.well-known/openid-configuration`
  and the 1/1 deployment, not the CR condition (or delete the orphan Route and let the operator own it).
- **agentgateway flaps** under control-plane churn (hundreds of restarts, then stable). If the tool
  journey fails with a connection/5xx, confirm the `agentgateway-…` pod is 1/1 + warm and re-run before
  treating it as a real failure (the §10 anchor already retries transient `oc exec` errors).
- **kyverno-authz only blocks unauthenticated calls today** — per-tool/per-group RBAC at the gateway is
  disabled (commented out in `platform/kyverno/authz/base/kustomization.yaml`) pending a
  kyverno-envoy-plugin build with `mcp.Parse` + agentgateway forwarding JWT claims to ext_authz.
- **`require-kata-runtimeclass`** Kyverno policy targets `agent-sandbox`; native runc sandboxes
  elsewhere need no kata runtimeClass.
- **`oc delete` of cluster-scoped resources** (ClusterPolicy/ClusterRole/ClusterSPIFFEID/SCC/CRD) may be
  denied by your harness — apply per-doc; hand cluster-scoped reaps to a human.
- **OVN-K DNS egress** needs `:53` AND `:5353` to `openshift-dns`.
- **`vault kv put -mount=secret <path> -`** (stdin JSON) preserves numeric types — ext-proc's grant
  validation requires numeric `version`/`ttl` (the vault pod has no `curl`).
- **Tokens expire / control plane flaps** — keep the break-glass cert kubeconfig; the verify scripts
  default to it (`IDA_KUBECONFIG`).

---

## 10. Verify — the full e2e suite

**One turnkey script proves all four planes** (tool + model + WORM + Gen AI Studio assets):

```bash
IDA_KUBECONFIG=~/.kube/<your-cluster>-admin.kubeconfig bash hack/test-full-e2e-ocp-dev.sh
# ... expect:  FULL_E2E_RESULT: PASS   (9 passed / 0 failed)
```

It runs, in order:

1. **TOOL plane** (`hack/test-pfsense-jit-ocp-dev.sh`, the regression anchor): credential-less SVID-only
   caller does **read 200** (delegated as the user) → **write 403** (`grant_scope_denied`, fail-closed)
   → **mint** a capability JWT (approver ≠ requester, SoD) → **elevated write 200** (a real pfSense rule).
2. **MODEL plane:** the openrouter-bridge SVID-driven completion returns **200** (positive), and a
   **credential-less call to the in-cluster maas-gateway returns 401** (negative — zero-trust holds).
3. **WORM ledger:** `jit_ledger` has rows, the hash chain links (`chain_ok=true`), and the `app` DB role
   **cannot UPDATE/DELETE** `jit_ledger` (`permission denied`; grants = `INSERT,SELECT` only).
4. **Assets:** the two Gen AI Studio ConfigMaps (`gen-ai-aa-mcp-servers`, `gen-ai-aa-custom-model-endpoints`).

**Prerequisites (the scripts assume these):** a **non-expired** kubeconfig (the cert file — the
user-token one is expired; override with `IDA_KUBECONFIG`); `/etc/hosts` (or DNS) resolving the apps
wildcard to the ingress VIP (§1). Vault reads/writes go via `oc exec vault-0` (**not** port-forward —
port-forward drops on a flapping control plane and yields false failures). `curl -k` against the routes
is intentional (the `*.apps` edge cert is self-signed); `http=000` means an SSL/`-k`/`/etc/hosts`
problem, not a route outage.

**Run the planes individually** if you prefer:

```bash
# Tool plane only:
IDA_KUBECONFIG=~/.kube/<cluster>-admin.kubeconfig bash hack/test-pfsense-jit-ocp-dev.sh

# Model positive (SVID 200):
oc exec -n maas deploy/openrouter-bridge -- python3 -c \
 'import urllib.request,json;b=json.dumps({"model":"anthropic/claude-sonnet-4","messages":[{"role":"user","content":"OK"}],"max_tokens":8}).encode();print(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8321/v1/chat/completions",b,{"Content-Type":"application/json"})).status)'
# Model negative (no-token 401) — MUST hit the in-cluster gateway WITH the Host header (the external
# route 503s; without the Host header the route doesn't match and you get 404):
oc exec -n maas deploy/openrouter-bridge -- curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST -H 'Host: maas.apps.ocp-dev.na-launch.com' -H 'Content-Type: application/json' \
  http://maas-gateway-istio.maas.svc:80/openrouter/v1/chat/completions \
  -d '{"model":"anthropic/claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"max_tokens":4}'

# WORM ledger (chain + append-only REVOKE):
oc exec -n mcp-gateway jit-approver-db-1 -c postgres -- psql -U postgres -d jit_approver -tA -c \
 "SELECT count(*) FROM jit_ledger;
  WITH c AS (SELECT seq,prev_hash,lag(entry_hash) OVER (ORDER BY seq) le FROM jit_ledger)
  SELECT bool_and(prev_hash=COALESCE(le,'')) chain_ok FROM c;"
oc exec -n mcp-gateway jit-approver-db-1 -c postgres -- psql -U postgres -d jit_approver -c \
 "SET ROLE app; UPDATE jit_ledger SET payload_json=payload_json WHERE seq=1;"   # expect: permission denied

# Gen AI Studio assets:
oc get cm gen-ai-aa-mcp-servers -n redhat-ods-applications
oc get cm gen-ai-aa-custom-model-endpoints -n maas
```

`FULL_E2E_RESULT: PASS` = the platform is up across all four planes.

---

## Where to go next
- **`docs/PRD.md`** — requirement-by-requirement status (Done / Partial / Roadmap) + the open seams.
- **`docs/architecture.md`** / **`docs/design/maas-spiffe-auth.md`** — the two planes in depth.
- **`docs/demo/genai-studio-spiffe-zerotrust-runbook.md`** — the live demo script.
- **`docs/adr/`** — the irreversible decisions and why.
- **`platform/<component>/`** + **`docs/components/`** — per-component manifests + reference.
