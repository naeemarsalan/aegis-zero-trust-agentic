# gitops/

Hub-side ArgoCD bootstrap for the nvidia-ida PoC.  Everything here runs on or
is applied to the **virt** ACM hub cluster (ArgoCD namespace `openshift-gitops`).

## Directory layout

```
gitops/
  projects/
    nvidia-ida-appproject.yaml   # ArgoCD AppProject scoping sources + destinations
  acm-registration/
    managedclustersetbinding.yaml
    placement.yaml
    gitopscluster.yaml           # Tells ACM to inject anaeem cluster secret into ArgoCD
    kustomization.yaml
    README.md                    # Apply on HUB
  app-of-apps.yaml               # Root Application — sources gitops/applications/
  applications/
    kustomization.yaml
    operators.yaml               # wave 0 — OLM subscriptions
    spire.yaml                   # wave 1 — SPIRE / ZTWIM
    keycloak.yaml                # wave 2 — RHBK instance
    vault.yaml                   # wave 2 — HashiCorp Vault
    kyverno.yaml                 # wave 3 — Kyverno policy engine
    agentgateway.yaml            # wave 4 — agentgateway + ext-proc + jit-approver
    isolation.yaml               # wave 5 — sandboxed-containers / Kata
    rhoai.yaml                   # wave 5 — RHOAI / agentic-mcp DS Project
    observability.yaml           # wave 5 — OTel + alerting
    networkpolicies.yaml         # wave 5 — default-deny NetworkPolicies
  kustomization.yaml             # renders hub bootstrap (project + acm-registration + aoa)
```

## Bootstrap sequence

### 1. Hub one-time setup (virt cluster)

```bash
# Ensure the AppProject and ACM registration exist before the app-of-apps
kustomize build gitops | oc apply -f -
```

This creates:
- The `nvidia-ida` AppProject in `openshift-gitops`
- ManagedClusterSetBinding + Placement + GitOpsCluster so ACM injects the
  `anaeem` cluster secret into ArgoCD
- The root app-of-apps Application

### 2. ACM injects anaeem cluster secret

Once the GitOpsCluster reconciles, verify:
```bash
oc get secret -n openshift-gitops | grep anaeem
```

### 3. App-of-apps drives everything else

ArgoCD will reconcile `gitops/applications/` and create all child Applications.
Sync waves enforce ordering (operators -> spire -> keycloak/vault -> kyverno ->
agentgateway -> rest).

## Sync wave reference

| Wave | Applications |
|------|-------------|
| 0 | operators (OLM Subscriptions) |
| 1 | spire |
| 2 | keycloak, vault |
| 3 | kyverno |
| 4 | agentgateway |
| 5 | isolation, rhoai, observability, networkpolicies |

## Design notes

- `selfHeal: false` — PoC mode; prevents accidental drift correction during
  active development.  Set to `true` for production.
- `prune: true` — resources removed from git are deleted from the cluster.
- All Applications use `ServerSideApply=true` to avoid last-applied-annotation
  conflicts with large CRDs (e.g., Kyverno ClusterPolicy).
- The app-of-apps destination is `https://kubernetes.default.svc` (hub in-cluster)
  because it only manages Application CRs, not workloads.
- All component Applications target `https://api.anaeem.na-launch.com:6443`,
  which becomes valid only after ACM injects the cluster secret (step 2 above).
