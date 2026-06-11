# acm-registration

**Apply this on the ACM HUB cluster (virt), not on anaeem.**

These manifests tell ACM to register the `anaeem` managed cluster as a
destination in the hub ArgoCD instance (`openshift-gitops` namespace).

## What / Why

| Resource | Purpose |
|----------|---------|
| ManagedClusterSetBinding | Binds the `default` ManagedClusterSet to the `openshift-gitops` namespace so Placement can resolve clusters there |
| Placement | Selects the cluster labelled `name: anaeem` from the default set |
| GitOpsCluster | Instructs ACM's GitOps integration to inject the `anaeem` cluster kubeconfig secret into ArgoCD, making it available as a destination server (`https://api.anaeem.na-launch.com:6443`) |

## Apply order

Apply once during initial hub bootstrap, before any ArgoCD Application that
targets `https://api.anaeem.na-launch.com:6443` is created.

```bash
# On the virt hub (kubeconfig pointing to api.virt.na-launch.com):
kustomize build gitops/acm-registration | oc apply -f -
```

## Verify

```bash
# Cluster secret should appear in openshift-gitops namespace:
oc get secret -n openshift-gitops | grep anaeem

# GitOpsCluster should reach Reconciled condition:
oc get gitopscluster nvidia-ida-gitops -n openshift-gitops -o jsonpath='{.status.conditions}'

# ArgoCD cluster list should show the anaeem server:
argocd cluster list | grep anaeem
```
