# 00-operators

Bootstraps the OLM operators that must exist before any platform component
manifests are applied.  Each subdirectory manages one operator: a Namespace,
an OperatorGroup (single-namespace scope unless noted), and a Subscription.

## Operators included

| Dir | Namespace | Package | Channel | CatalogSource |
|-----|-----------|---------|---------|---------------|
| zero-trust-workload-identity-manager | zero-trust-workload-identity-manager | openshift-zero-trust-workload-identity-manager | stable-v1 | redhat-operators |
| rhbk | keycloak | rhbk-operator | stable-v26 | redhat-operators |
| kyverno | kyverno | kyverno-operator | stable | community-operators |
| sandboxed-containers | openshift-sandboxed-containers-operator | sandboxed-containers-operator | stable | redhat-operators |

## Operators intentionally omitted

- **openshift-gitops** — already installed on the ACM hub (virt); not deployed on anaeem.
- **rhoai / rhods** — RHOAI 3.4.0-ea.2 with DataScienceCluster `data-skill-factory` already exists on anaeem; do not create another DSC or DSCInitialization.
- **cloud-native-postgresql (cnpg)** — operator already present on anaeem (stable-v1.29).
- **external-secrets** — already installed on anaeem.

## Notes

### RHBK / Keycloak (rhbk/)
MTA already runs `rhbk-operator` channel `stable-v26.4` in namespace `openshift-mta`
(namespace-scoped OperatorGroup, manages the `mta-rhbk` Keycloak CR).  Because
that OperatorGroup only watches `openshift-mta`, we install our **own**
Subscription + OperatorGroup in namespace `keycloak` to manage the `agentic`
realm Keycloak instance independently.  Both operators coexist with no conflict.

### Kyverno (kyverno/)
The `kyverno-operator` package is published to `community-operators` on
OperatorHub.  If it is unavailable on your disconnected mirror, install Kyverno
via the official Helm chart instead:

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm upgrade --install kyverno kyverno/kyverno \
  -n kyverno --create-namespace \
  --set admissionController.replicas=1 \
  --set backgroundController.replicas=1 \
  --set cleanupController.replicas=1 \
  --set reportsController.replicas=1
```

Adjust replica counts for SNO (single-node) accordingly.

## Apply order

This directory is sync-wave **0** — it must succeed before any component
overlay is applied (spire, keycloak, vault, etc.).

```bash
# Verify offline render:
kustomize build platform/00-operators

# Apply (hub ArgoCD handles this automatically; manual bootstrap):
kustomize build platform/00-operators | oc apply -f -
```

## Verify

```bash
oc get csv -n zero-trust-workload-identity-manager
oc get csv -n keycloak
oc get csv -n kyverno
oc get csv -n openshift-sandboxed-containers-operator
```

All CSVs should reach `Succeeded` phase before proceeding to wave 1.
