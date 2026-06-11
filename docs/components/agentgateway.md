## Purpose

agentgateway is the MCP-protocol-aware ingress and policy enforcement plane. Every AI agent call to a downstream MCP server transits the gateway, which validates the bearer token (Keycloak JWT), invokes the ext-proc-delegation sidecar to enforce per-tool Kyverno policies, and proxies the request with the verified user identity in a forwarded header — ensuring downstream MCP servers see the user, not the agent. It is the single choke-point for rate-limiting, audit logging, and JIT approval gating.

## Exists or create

CREATE on anaeem. Deploy agentgateway (Red Hat / Envoy-based MCP gateway, alpha release) in namespace `mcp-gateway` alongside the `ext-proc-delegation` and `jit-approver` components. Gateway API CRDs are already present on the cluster (installed via servicemeshoperator3) — no additional CRD install needed.

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11)
- Namespace: `mcp-gateway`
- External hostname: `https://mcp-gateway.apps.anaeem.na-launch.com` (OCP Route or Gateway API `Gateway` + `HTTPRoute`)
- Internal service: `agentgateway.mcp-gateway.svc.cluster.local:8080` (HTTP/1.1 MCP transport)
- No additional DNS changes needed

## Security posture

- SPIFFE ID: `spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/agentgateway`
- Inbound token validation: Keycloak JWKS (`https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/certs`) — rejects unauthenticated requests at the gateway; no request reaches ext-proc or a downstream MCP server without a valid realm token
- API keys and TLS private keys injected via Vault Agent Injector (tmpfs); not stored in Secrets
- Audit: every MCP tool invocation is logged to Loki (`http://172.16.2.252:3100`) with tool arguments SHA-256 hashed — raw arguments are never written to the audit log
- NetworkPolicy: ingress on 8080/8443 from OCP router namespace only; egress to `ext-proc-delegation:9000` (gRPC), `kyverno-authz-server.kyverno.svc.cluster.local:9081` (gRPC ext_authz), `jit-approver:8080` (HTTP), downstream MCP servers in `agentic-mcp`; deny all other egress
- Fail-mode: if ext-proc or Kyverno authz is unreachable, agentgateway returns `503` to the agent — fail-closed; no policy bypass

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| AI agents / clients | inbound | 443 HTTPS (Route) | MCP StreamableHTTP calls |
| ext-proc-delegation | outbound | 9000 gRPC | Per-tool policy ext-proc filter |
| kyverno-authz-server | outbound | 9081 gRPC | Envoy ext_authz for admission decisions |
| jit-approver | outbound | 8080 HTTP | JIT approval gate polling |
| pfsense-mcp (agentic-mcp) | outbound | 8000 HTTP | Proxied MCP server calls |
| Keycloak | outbound | 443 HTTPS | JWKS token validation |
| Loki | outbound | 3100 HTTP | Audit log push |

## Maturity flags

- agentgateway is **alpha** — Red Hat has not committed to a stable API surface; field names, CRD schema, and default behaviors may change between builds
- MCP StreamableHTTP transport (replacing SSE) is the target; SSE fallback may be needed for older agent SDKs
- Gateway API `HTTPRoute` + Envoy ext_authz combination is stable upstream but the Red Hat packaging is new

## Verify

```bash
# 1. Check agentgateway pod is Running
oc get pods -n mcp-gateway -l app=agentgateway

# 2. Confirm the gateway rejects unauthenticated MCP requests
curl -sv https://mcp-gateway.apps.anaeem.na-launch.com/mcp 2>&1 | grep "< HTTP"

# 3. Confirm audit events reach Loki (substitute a real timestamp window)
curl -s "http://172.16.2.252:3100/loki/api/v1/query" \
  --data-urlencode 'query={app="agentgateway"}' | jq '.data.result[0].values[-1]'
```
