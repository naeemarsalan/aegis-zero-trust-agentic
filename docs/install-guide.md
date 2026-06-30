# Install Guide — Zero-Trust Agentic AI Platform

This guide brings the platform up on a fresh OpenShift cluster. It is **GitOps-first** (an ArgoCD
app-of-apps reconciles the supported components) with a few **imperative bootstrap steps** for
secrets (Vault init/unseal, Keycloak realm, KV population) that are not yet fully automated.

> **Honesty up front (PoC, not a turnkey installer).** The app-of-apps + per-component manifests are
> real and current, but a 100%-hands-off fresh-cluster rebuild is **not yet proven** (PRD §P2). Expect
> to run the secret-bootstrap steps by hand and to hit the **known gotchas in §9** — they are all
> documented here because we hit them. Reference cluster: `ocp-dev` (OCP 4.20.25, 3 control-plane + 2
> worker), trust domain `anaeem.na-launch.com`.

---

## 1. Prerequisites

**Cluster**
- OpenShift **4.20+**, 3 control-plane nodes + **≥2 worker** nodes (the platform is CPU-heavy:
  RHOAI, SPIRE, Vault, Keycloak, Kyverno, RHCL, CNPG). Workers ~16 vCPU / 64 GB each.
- A default **`local-path`** StorageClass (CNPG + SPIRE datastore + Keycloak DB initdb hang on NFS —
  use local-path, see §9). The repo expects `storageClass: local-path`.
- `cluster-admin` access. etcd is on the control plane and can be fragile under load — watch DB size.
- **No GPU is required** for the auth planes; a GPU is only needed for in-cluster large-LLM serving (M7).

**A container registry** you can push to and the cluster can pull from. The repo references
`oci.arsalan.io/nvidia-ida/…`; point it at your own (see §3).

**DNS** for the cluster's `*.apps.<cluster-domain>` wildcard (the routes — Keycloak, Vault, MaaS
gateway, jit-approver, console, showroom — all live there).

**Local tools:** `oc`, `kustomize`, `helm`, `vault` CLI, `podman` (image builds), `git`, optionally `gh`.

---

## 2. Get the repo + set your cluster

```bash
git clone <this-repo> && cd nvidia-ida
export KUBECONFIG=~/.kube/<your-cluster>.kubeconfig
oc whoami            # confirm cluster-admin
```

The manifests are pinned to a cluster domain and a SPIFFE trust domain. To target a different cluster,
retarget the apps-domain hostnames (the reference uses `apps.ocp-dev.na-launch.com`) and keep — or
change — the trust domain `anaeem.na-launch.com`:

```bash
# Example: retarget the routes/issuers from ocp-dev to YOUR cluster apps domain.
grep -rl 'apps.ocp-dev.na-launch.com' platform/ services/ gitops/ \
  | xargs sed -i 's/apps\.ocp-dev\.na-launch\.com/apps.<your-cluster>.na-launch.com/g'
# Registry (if not using oci.arsalan.io):
grep -rl 'oci.arsalan.io/nvidia-ida' . | xargs sed -i 's#oci.arsalan.io/nvidia-ida#<your-registry>#g'
```

Create your secrets env (git-ignored — never commit it):
```bash
cp environment/.env.example environment/.env     # then fill in PFSENSE_API_URL / PFSENSE_API_KEY etc.
```

---

## 3. Node + storage prep (do this BEFORE workloads schedule)

The local-path provisioner's hostPath needs the right SELinux label + perms on **every** node, or
PVC binding fails with `mkdir: Permission denied`:

```bash
for n in $(oc get nodes -o name); do
  oc debug "$n" -- chroot /host sh -c \
    'mkdir -p /opt/local-path-provisioner && chmod 1777 /opt/local-path-provisioner && \
     chcon -t container_file_t /opt/local-path-provisioner' 2>/dev/null
done
```
PVCs are `WaitForFirstConsumer`, so they bind once a pod schedules.

---

## 4. GitOps engine (OpenShift GitOps / ArgoCD)

Install the **OpenShift GitOps** operator, then configure ArgoCD for this repo:

```bash
# 1. Operator (OLM)
oc apply -f platform/operators/base/openshift-gitops-subscription.yaml   # or via wave-0 below
# 2. The controller needs broad rights (it manages ClusterSPIFFEIDs, Routes, SCCs) + Helm
#    (Vault renders via a helmCharts kustomize generator):
oc -n openshift-gitops adm policy add-cluster-role-to-user cluster-admin -z openshift-gitops-argocd-application-controller
oc -n openshift-gitops patch argocd openshift-gitops --type merge \
  -p '{"spec":{"repo":{"env":[{"name":"ARGOCD_EXEC_TIMEOUT","value":"300s"}]},"kustomizeBuildOptions":"--enable-helm"}}'
# 3. Repo credential (if private): a repo-<name> secret with a git token in openshift-gitops.
```

> **ocp-dev runs ArgoCD self-managed, in-cluster.** All apps target `https://kubernetes.default.svc`.
> The `gitops/README.md` ACM-hub flow (injecting a managed-cluster secret) is the **older** model — use
> the self-managed destination unless you are deploying from a separate ACM hub.

---

## 5. Operators, then the app-of-apps

The deploy is an **app-of-apps** that reconciles 13 child apps in **sync-waves**:

| Wave | Apps |
|---|---|
| 0 | `operators` — OLM Subscriptions (SPIRE/ZTWIM, RHBK, Vault-via-helm, Kyverno, CNPG, RHCL, RHOAI 3.4, sandboxed-containers, GitOps) |
| 1 | `spire` (SPIRE / Zero-Trust Workload Identity Manager) |
| 2 | `keycloak` (RHBK), `vault` |
| 3 | `kyverno` |
| 4 | `agentgateway` + `ext-proc-delegation` + `jit-approver` |
| 5 | `isolation`, `rhoai`, `observability`, `networkpolicies`, `showroom` |

```bash
# Apply the hub bootstrap (AppProject + the root app-of-apps):
kustomize build gitops | oc apply -f -
# Watch the apps reconcile:
oc get applications -n openshift-gitops -w
```

Wait for waves 0–3 to be `Synced/Healthy` before relying on Vault/Keycloak (the bootstrap below needs them).

> If you prefer to skip ArgoCD for a component, every app maps to a `platform/<component>` kustomize
> base you can `oc apply -k` directly.

---

## 6. Vault bootstrap (secrets — imperative)

After the Vault pods are `Running`:

```bash
# Init + unseal (SAVE the root token + 5 unseal keys to environment/.env — git-ignored!):
oc -n vault exec vault-0 -- vault operator init -key-shares=5 -key-threshold=3   # record output
oc -n vault exec vault-0 -- vault operator unseal <key1>   # x3

# Configure auth methods, policies, secrets engines (declarative, idempotent):
oc -n vault port-forward svc/vault 8200:8200 &
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root-token>
source environment/.env                                    # PFSENSE_API_URL / PFSENSE_API_KEY
# The SPIRE-OIDC trust + the k8s engine need these (the script expects an in-pod SA token):
export OIDC_DISCOVERY_CA_PEM="$(oc -n openshift-config-managed get cm default-ingress-cert -o jsonpath='{.data.ca-bundle\.crt}')"
export VAULT_K8S_SA_JWT="$(oc create token vault -n vault)"
export VAULT_K8S_CA_CERT="$(oc -n vault get cm kube-root-ca.crt -o jsonpath='{.data.ca\.crt}')"
bash platform/vault/config/vault-bootstrap.sh
```

This creates: `jwt` + `kubernetes` auth, `kv` + `kubernetes` secrets engines, and the per-service
policies/roles (`ext-proc`, `jit-approver`, `agent-deny`, `agent-sandbox`, `pfsense-mcp`,
`sandbox-launcher`). Then populate the KV secrets the tools/models need, e.g.:

```bash
vault kv put secret/mcp-tools/mcp-tokens        token=<per-user-read-token>
vault kv put secret/mcp-tools/mcp-tokens-write  token=<elevated-write-token>
vault kv put secret/mcp-tools/openrouter        token=<your-openrouter-key>   # for the MaaS model plane
```

> **Rotate the Vault root token after bootstrap.** Keep the unseal keys in `environment/.env` only
> (git-ignored). **Point services at in-cluster Vault** `http://vault.vault.svc:8200`, not the external
> route — the external route is the source of the `grant_vault_error`/mint-502 failures (§9).

---

## 7. Keycloak realm + per-service secrets

```bash
# Import the agentic realm (RHBK):
oc apply -f platform/keycloak/realm/agentic-realm.yaml      # or the realm import CR
# Per-service prereq secrets the apps expect:
#   - jit-approver: openshell-client-tls (mTLS), the Vault-injected signing key
#   - approval-console: oauth2 cookie secret + Keycloak client (per-human SoD)
#   - agent-harness: the SVID CSIDs (platform/spire/base/cluster-spiffe-ids.yaml — apply PER-DOC, never whole-file)
```

---

## 8. Model plane — RHOAI 3.4 / MaaS / Gen AI Studio

```bash
# RHOAI 3.4 + RHCL (Kuadrant 1.x) + the SPIFFE-auth model gateway:
oc apply -k platform/rhoai-maas/                                  # DSC v2, gateway, Authorino, OPA
oc apply -k platform/rhoai-maas/spiffe-auth/                      # SVID-auth AuthPolicy, llm-proxy, premium tier
# Register OpenRouter + the MCP server as native Gen AI Studio assets, SVID-driven:
oc apply -k platform/rhoai-maas/genai-studio/                     # asset CMs + openrouter-bridge + CSID
oc label ns maas opendatahub.io/dashboard=true --overwrite        # make maas a selectable DS project
# Durable WORM audit DB for jit-approver (CNPG, append-only hash-chain ledger):
oc apply -k platform/jit-approver-db/base/
```

See `docs/design/maas-spiffe-auth.md` and `docs/demo/genai-studio-spiffe-zerotrust-runbook.md` for the
model-plane detail and the verification curls.

---

## 9. Known gotchas (we hit all of these)

- **local-path SELinux/perms** on every node — see §3, or PVCs never bind.
- **CNPG controller on OpenShift** — strip the alpha-seccomp annotations + hardcode `runAsUser` and
  grant the SA `anyuid`, or the controller won't run.
- **Vault external route is degraded** — point `ext-proc-delegation` and `jit-approver` `VAULT_ADDR`
  at **in-cluster** `http://vault.vault.svc:8200`. On an **ACM-hub-managed** cluster, a live `oc set env`
  **reverts within seconds** (the hub ManifestWork re-applies the external route) — the durable fix is a
  **hub-side edit**. (PRD §7.)
- **`oc delete` of cluster-scoped resources** (ClusterPolicy/ClusterRole/ClusterSPIFFEID) may be denied
  by your harness — apply per-doc; never whole-file `oc apply` `cluster-spiffe-ids.yaml` (the
  hardcoded-UUID e2e CSID drifts).
- **OVN-K DNS egress** needs `:53` AND `:5353` to `openshift-dns`.
- **`require-kata-runtimeclass`** Kyverno policy is Audit-scoped to `agent-sandbox`; native runc
  sandboxes elsewhere need no kata runtimeClass.
- **jit-approver postgres WORM** — the CNPG schema must `GRANT` the `app` role *and* the egress
  NetworkPolicy must be applied (both are in `platform/jit-approver-db/`); without them the pod
  crashloops with "table not found" or hangs connecting.
- **kube:admin / user tokens expire** — keep a break-glass cert kubeconfig handy.

---

## 10. Verify

```bash
# Tool plane (the zero-trust journey): read 200 -> write 403 -> approve (SoD) -> elevated write 200
bash hack/test-pfsense-jit-ocp-dev.sh                              # the deterministic regression anchor

# Model plane (SVID is the model credential): no-token 401 / SVID 200
oc exec -n maas deploy/openrouter-bridge -- python3 -c \
 'import urllib.request,json;b=json.dumps({"model":"anthropic/claude-sonnet-4","messages":[{"role":"user","content":"OK"}],"max_tokens":8}).encode();print(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8321/v1/chat/completions",b,{"Content-Type":"application/json"})).status)'

# Gen AI Studio assets registered (via the dashboard BFF):
oc get cm gen-ai-aa-mcp-servers -n redhat-ods-applications
oc get cm gen-ai-aa-custom-model-endpoints -n maas
```

Green tool journey + a `200` model completion + the two asset ConfigMaps = the platform is up.

---

## Where to go next
- **`docs/PRD.md`** — requirement-by-requirement status (Done / Partial / Roadmap) + the open seams.
- **`docs/architecture.md`** / **`docs/design/maas-spiffe-auth.md`** — the two planes in depth.
- **`docs/demo/genai-studio-spiffe-zerotrust-runbook.md`** — the live demo script.
- **`docs/adr/`** — the irreversible decisions and why.
- **`platform/<component>/`** + **`docs/components/`** — per-component manifests + reference.
