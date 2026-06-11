## Purpose

Kyverno serves two distinct roles in this platform. As a Kubernetes admission controller it enforces baseline security invariants across all namespaces (no privileged containers, required SPIFFE labels, mandatory `storageClassName: nfs-csi` on PVCs). As a gRPC Authorization Server (Kyverno Authz Server) it provides real-time per-tool-call policy decisions to agentgateway via the ext-proc-delegation path — enabling fine-grained, versioned, auditable MCP tool authorization without embedding policy logic in application code.

## Exists or create

CREATE on anaeem. Deploy the Kyverno operator and the Kyverno Authz Server in namespace `kyverno`. Neither is currently installed. The authz server exposes a gRPC endpoint consumed by ext-proc-delegation; the admission webhook is cluster-scoped.

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11)
- Namespace: `kyverno`
- Authz Server internal service: `kyverno-authz-server.kyverno.svc.cluster.local:9081` (gRPC, no Route — internal only)
- Admission webhook: cluster-scoped (webhook configurations in the cluster)
- No external hostname

## Security posture

- SPIFFE ID: `spiffe://anaeem.na-launch.com/ns/kyverno/sa/kyverno-authz-server`
- mTLS to ext-proc-delegation: SPIFFE X.509 SVIDs; no static certs
- Admission webhook TLS: managed by Kyverno's built-in cert rotation (caBundle auto-injection)
- ClusterPolicy resources defining MCP tool authorization rules are stored in git (`components/kyverno/policies/`) and applied via ArgoCD — policy-as-code, reviewed via Gitea PR
- NetworkPolicy: ingress on 9081 from `mcp-gateway` namespace only; admission webhook receives calls from the API server (port 443 → 9443); deny all other ingress
- Fail-mode: admission webhooks set `failurePolicy: Fail` — if Kyverno is unavailable, new pod/resource creation is blocked cluster-wide (intentional fail-closed for admission); authz server failure causes ext-proc to return DENY (see ext-proc-delegation.md)

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| Kubernetes API server | inbound | 9443 HTTPS | Admission webhook (ValidatingAdmissionWebhook) |
| ext-proc-delegation | inbound | 9081 gRPC | MCP tool authorization decisions |
| ArgoCD / kustomize | — | — | Policy CR reconciliation from git |

## Maturity flags

- Kyverno 1.12+ with Authz Server (gRPC authorization API) is GA upstream; Red Hat does not ship Kyverno as an operator — deploy from upstream Helm chart or static manifests
- `failurePolicy: Fail` on the admission webhook will block the cluster if Kyverno crashes on SNO — ensure PodDisruptionBudget and resource requests are set appropriately for the SNO resource envelope (31.5 CPU / 130Gi)

## Verify

```bash
# 1. Check Kyverno pods are Running
oc get pods -n kyverno

# 2. List ClusterPolicies and confirm MCP tool policies are present
oc get clusterpolicies | grep mcp

# 3. Confirm authz server is healthy (from ext-proc-delegation pod)
oc exec -n mcp-gateway deploy/ext-proc-delegation -- \
  grpc_health_probe -addr=kyverno-authz-server.kyverno.svc.cluster.local:9081
```
