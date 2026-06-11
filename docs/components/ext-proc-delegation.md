## Purpose

ext-proc-delegation is the gRPC External Processing (ext_proc) filter sidecar that runs alongside agentgateway. It intercepts each MCP tool-call request, extracts the tool name and caller identity, evaluates the applicable Kyverno policy via the Kyverno authz server, and can rewrite or block the request before it reaches the downstream MCP server. It is also responsible for injecting the verified downstream user identity header so that MCP servers receive the user's identity, not the agent's.

## Exists or create

CREATE on anaeem. Deploy as a Deployment in namespace `mcp-gateway`, co-located with agentgateway. The image is `oci.arsalan.io/nvidia-ida/ext-proc-delegation:dev`. It is wired to agentgateway via Envoy's `ext_proc` HTTP filter configuration.

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11)
- Namespace: `mcp-gateway`
- Internal service: `ext-proc-delegation.mcp-gateway.svc.cluster.local:9000` (gRPC, no Route — internal only)
- No external hostname; never exposed outside the cluster

## Security posture

- SPIFFE ID: `spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/ext-proc-delegation`
- mTLS to agentgateway: SPIFFE X.509 SVIDs used for mutual authentication on the gRPC channel; no static TLS certificates
- mTLS to Kyverno authz server: same SPIFFE mTLS pattern on port 9081
- Secrets (e.g., Vault token for policy-decision enrichment) injected via Vault Agent Injector (tmpfs); no environment variables carrying credentials
- Audit: logs every policy decision (ALLOW/DENY) with tool name and hashed arguments to Loki; raw arguments never logged
- NetworkPolicy: ingress on 9000 gRPC from `agentgateway` pod only; egress to `kyverno-authz-server.kyverno.svc.cluster.local:9081`; deny all other ingress/egress
- Fail-mode: if ext-proc-delegation is unavailable, the Envoy ext_proc filter is configured `failure_mode_deny: true` — all MCP traffic is blocked (fail-closed)

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| agentgateway | inbound | 9000 gRPC | Ext_proc request/response processing |
| kyverno-authz-server | outbound | 9081 gRPC | Policy evaluation for each tool call |
| jit-approver | outbound | 8080 HTTP | JIT hold: pause request pending approval |
| Loki | outbound | 3100 HTTP | Policy decision audit log |

## Maturity flags

- Envoy ext_proc (`ProcessingMode`) is stable in Envoy 1.29+; the Red Hat agentgateway alpha bundles its own Envoy — confirm the ext_proc filter version matches
- The delegation identity-header injection pattern (user identity propagation) is a custom implementation — not an upstream standard; review carefully before production use

## Verify

```bash
# 1. Check ext-proc-delegation pod is Running
oc get pods -n mcp-gateway -l app=ext-proc-delegation

# 2. Confirm the gRPC service is reachable from agentgateway (exec into agentgateway pod)
oc exec -n mcp-gateway deploy/agentgateway -- \
  grpc_health_probe -addr=ext-proc-delegation.mcp-gateway.svc.cluster.local:9000

# 3. Send a synthetic MCP tool call through the gateway and verify a policy-decision log entry appears in Loki
curl -s "http://172.16.2.252:3100/loki/api/v1/query" \
  --data-urlencode 'query={app="ext-proc-delegation"}' | jq '.data.result[0].values[-1]'
```
