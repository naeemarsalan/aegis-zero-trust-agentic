# platform/kyverno/cleanup

## What

A `ClusterCleanupPolicy` (Kyverno 1.11+) that periodically deletes JIT-scoped `ServiceAccount`, `Role`, and `RoleBinding` resources labeled `app.kubernetes.io/managed-by=vault-jit` once their `jit.nvidia-ida/expires-at` annotation timestamp has passed.

## Why

**This is a backstop only.  Vault lease expiry is the primary revocation mechanism.**

When jit-approver creates JIT-scoped Kubernetes credentials via the Vault Kubernetes secrets engine, it:
1. Sets a Vault lease TTL (typically 15–30 minutes)
2. Annotates the created resources with `jit.nvidia-ida/expires-at: <RFC3339>`

On normal operation, Vault automatically revokes the lease and jit-approver deletes the resources on lease expiry.  This CleanupPolicy fires as a safety net in edge cases:
- jit-approver crash after resource creation but before revocation
- Vault lease revoke race condition
- Manual debugging artifacts left in the cluster

Resources **without** the `app.kubernetes.io/managed-by=vault-jit` label are never touched by this policy.

## CronJob fallback

`jit-resource-cleanup-cronjob.yaml` contains a commented-out `CronJob` equivalent for clusters where `ClusterCleanupPolicy` is unavailable (Kyverno < 1.11).  On anaeem (Kyverno 1.16+) the `ClusterCleanupPolicy` is used.

## Apply order

Kyverno operator must be installed.

```bash
kustomize build platform/kyverno/cleanup/overlays/anaeem | oc apply -f -
```

## Verify

```bash
# ClusterCleanupPolicy installed
oc get clustercleanuppolicies cleanup-expired-jit-resources

# Inspect cleanup history (Kyverno generates Events)
oc get events -n kyverno --field-selector reason=CleanupCompleted

# Manually trigger a cleanup run (Kyverno will run on next schedule tick)
# Or check that an expired JIT resource is gone:
oc get serviceaccount -n mcp-gateway -l app.kubernetes.io/managed-by=vault-jit
```
