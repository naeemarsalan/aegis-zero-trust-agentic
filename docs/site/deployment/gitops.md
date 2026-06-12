# GitOps & Bootstrap

## Overview

The platform is managed entirely through **ArgoCD on the `virt` ACM hub** using an app-of-apps pattern. Every platform component under `platform/` is a Kustomize overlay; ArgoCD reconciles them continuously from the `anaeem/nvidia-ida` Gitea repository. Sync waves enforce the correct apply order.

```
Gitea (git.arsalan.io/anaeem/nvidia-ida)
  │  Git source
  ▼
ArgoCD (openshift-gitops on virt hub)
  │  ACM GitOpsCluster injects anaeem cluster secret into ArgoCD
  │  app-of-apps Application → gitops/applications/ (one Application per component)
  ▼
anaeem SNO cluster — platform/ components applied in wave order
```

---

## Repository layout

```
nvidia-ida/
├── environment/
│   ├── clusters.yaml          # cluster inventory (endpoints, params)
│   └── .env.example           # credential template (never commit .env)
├── platform/
│   └── <component>/
│       ├── base/              # base Kustomize manifests
│       └── overlays/anaeem/   # anaeem-specific patches and ConfigMaps
├── services/
│   ├── ext-proc-delegation/   # Go service (cmd/, internal/, Dockerfile)
│   ├── jit-approver/          # Python service (src/, tests/, Dockerfile)
│   └── pfsense-mcp-server/    # Python MCP server
├── gitops/
│   ├── projects/              # ArgoCD AppProject
│   ├── acm-registration/      # ACM GitOpsCluster + Placement
│   ├── applications/          # one Application YAML per component
│   ├── app-of-apps.yaml       # root Application
│   └── kustomization.yaml
├── hack/
│   ├── validate.sh            # kustomize build + kubeconform all overlays
│   └── render.sh              # render overlays to rendered/<component>.yaml
└── Makefile
```

---

## Bootstrap sequence

### Prerequisites

- Access to the `virt` hub cluster (`oc login` with cluster-admin)
- ArgoCD (`openshift-gitops`) already installed on `virt`
- ACM 2.14 installed on `virt` with the `anaeem` cluster registered as a ManagedCluster

### Step 1 — Hub one-time setup

Apply the GitOps bootstrap manifests to the `virt` hub. This creates the AppProject, ACM registration, and the root app-of-apps Application:

```bash
kustomize build gitops | oc apply -f - --context virt-admin
```

This creates:
- The `nvidia-ida` AppProject in `openshift-gitops` (scopes sources + destinations)
- `ManagedClusterSetBinding` + `Placement` + `GitOpsCluster` so ACM injects the `anaeem` cluster secret into ArgoCD
- The root app-of-apps `Application` pointing at `gitops/applications/`

### Step 2 — ACM injects anaeem cluster

After the `GitOpsCluster` CR is reconciled, ACM automatically injects a cluster secret for `anaeem` into ArgoCD. This allows ArgoCD to apply manifests directly to `anaeem` without additional kubeconfig management.

### Step 3 — Watch rollout

```bash
watch argocd app list
```

ArgoCD will begin reconciling all Applications in wave order. Each wave must complete (`Synced`, `Healthy`) before the next starts.

### Step 4 — Validate locally (no cluster needed)

Before pushing changes, validate all overlays and service code:

```bash
make validate    # kustomize build + kubeconform all overlays + Python syntax
make render      # render all overlays to rendered/<component>.yaml for inspection
```

---

## Sync waves

| Wave | Applications | Notes |
|---|---|---|
| 0 | `operators.yaml` | OLM Subscriptions — ZTWIM, RHBK, CNPG, sandboxed-containers operators |
| 1 | `spire.yaml` | SPIRE/ZTWIM — workload identity root; must be healthy before wave 2 |
| 2 | `keycloak.yaml`, `vault.yaml` | RHBK instance + CNPG cluster; Vault Helm release; both depend on SPIRE OIDC |
| 3 | `kyverno.yaml` | Kyverno admission + authz server; must be running before any admission request |
| 4 | `agentgateway.yaml` | agentgateway + ext-proc-delegation + jit-approver |
| 5 | `isolation.yaml`, `rhoai.yaml`, `observability.yaml`, `networkpolicies.yaml` | Parallel — Kata sandbox, RHOAI project, OTel/AlertManager, default-deny NetworkPolicies |

---

## Making changes

All changes to platform components go through a Gitea PR on `anaeem/nvidia-ida`:

1. Create a branch and commit your changes to `platform/<component>/overlays/anaeem/`
2. Open a PR in Gitea — this also serves as the paper trail for the change
3. The security-reviewer gate applies to any PR touching RBAC, NetworkPolicy, Vault policies, token-exchange code, SPIFFE/OIDC configuration, Kyverno policies, or JIT escalation logic
4. Merge the PR — ArgoCD detects the commit and reconciles the affected Application(s)

---

## Service image build

Custom service images are built with Podman and pushed to `oci.arsalan.io/nvidia-ida/<name>:dev`:

```bash
make build-images
```

The Makefile iterates over `services/ext-proc-delegation`, `services/jit-approver`, and `services/pfsense-mcp`. Images are tagged `:dev` in the PoC. The `overlays/anaeem/` patch for each service references the `oci.arsalan.io` registry directly.

---

## Environment configuration

Cluster-specific parameters (endpoints, URLs, storage class names) live in `environment/clusters.yaml`. Credentials and tokens live in `environment/.env` (gitignored — never commit). See `environment/.env.example` for the required variables.

```bash
cp environment/.env.example environment/.env
$EDITOR environment/.env
```
