# platform/kyverno/guardrails

## What

Four admission `ClusterPolicy` resources that enforce platform-wide security invariants across all nvidia-ida namespaces on the anaeem cluster.

## Why

These guardrails enforce the zero-trust security posture at the admission layer — before workloads are scheduled.  They are a complementary defense layer to SPIRE identity, Vault credential management, and network policies.

## Policies

| File | Rule | Namespaces | Default action |
|---|---|---|---|
| `require-kata-runtimeclass.yaml` | Pods must set `runtimeClassName: kata` | `agent-sandbox` | Audit |
| `disallow-default-sa-automount.yaml` | Pods must not use default SA or set `automountServiceAccountToken: true` | All platform ns | Audit |
| `require-networkpolicy.yaml` | Auto-generate default-deny NetworkPolicy; validate it exists | All platform ns (generate rule) | Audit |
| `restrict-image-registries.yaml` | Container images must come from `oci.arsalan.io`, `registry.redhat.io`, or `quay.io` | All platform ns | Audit |

**All policies are set to `validationFailureAction: Audit` for the PoC.**

To flip to Enforce for a specific policy:
```bash
kubectl patch clusterpolicy require-kata-runtimeclass \
  --type=merge \
  -p '{"spec":{"validationFailureAction":"Enforce"}}'
```

Pre-conditions before flipping `restrict-image-registries` to Enforce:
1. Re-mirror `ghcr.io/kyverno/kyverno-envoy-plugin:v0.3.0` to `oci.arsalan.io/nvidia-ida/kyverno-envoy-plugin:v0.3.0`
2. Update `platform/kyverno/authz/base/deployment.yaml` image reference
3. Re-mirror any other external images used in the platform

## Apply order

Guardrails are cluster-scoped and can be applied independently.  Kyverno operator must be installed first.

```bash
kustomize build platform/kyverno/guardrails/overlays/anaeem | oc apply -f -
```

## Verify

```bash
# ClusterPolicies ready
oc get clusterpolicies \
  require-kata-runtimeclass \
  disallow-default-sa-automount \
  require-networkpolicy \
  restrict-image-registries

# Check audit events (PolicyReport)
oc get policyreport -A

# Verify generate rule created default-deny in a platform namespace
oc get networkpolicy default-deny -n agent-sandbox
oc get networkpolicy default-deny -n agentic-mcp
```
