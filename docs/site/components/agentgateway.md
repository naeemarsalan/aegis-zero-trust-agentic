# agentgateway — MCP Protocol Gateway

## Purpose

agentgateway is the MCP-protocol-aware ingress and policy enforcement plane. Every AI agent call to a downstream MCP server transits the gateway, which:

1. **Validates** the bearer JWT-SVID against the Keycloak JWKS (authentication)
2. **Calls Kyverno** ext_authz for a per-tool allow/deny decision (authorization)
3. **Calls ext-proc-delegation** ext_proc to swap the agent identity for the user's credential (mutation)
4. **Proxies** the request with the verified user identity to the downstream MCP server
5. **Strips** credential headers from the response before returning it to the agent

It is the single choke-point for rate-limiting, audit-logging, and the JIT approval gate.

---

## Placement

| Property | Value |
|---|---|
| Cluster | `anaeem` (SNO, OCP 4.20.11) |
| Namespace | `mcp-gateway` |
| External hostname | `https://mcp-gateway.apps.anaeem.na-launch.com` |
| Internal service | `agentgateway.mcp-gateway.svc.cluster.local:8080` |
| MCP transport | StreamableHTTP (primary); SSE fallback for older agent SDKs |

---

## Filter pipeline

The gateway processes every incoming MCP request through two required filters, in order:

```
Inbound MCP request
    ↓
JWT authn — validate SVID against SPIRE OIDC JWKS
    ↓  (fail → 401)
extAuthz — Kyverno at :9081 (allow/deny)
    ↓  (deny → 403, no credential minted)
extProc — ext-proc-delegation at :9000 (header mutation)
    ↓  (error → 503, fail-closed)
Proxy to downstream MCP server (user identity injected)
    ↓
extProc response leg — strip credential headers
    ↓
Agent sees response with no credential headers
```

Both filters (`extAuthz` and `extProc`) are configured as **required**. If either is unreachable or returns an error, the gateway returns 503 to the agent. There is no fallback path that allows a request to proceed without both checks.

---

## Security posture

- **SPIFFE ID:** `spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/agentgateway`
- **Inbound token validation:** Keycloak JWKS at `https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/certs`
- **API keys / TLS keys:** injected via Vault Agent Injector (tmpfs); not stored in Kubernetes Secrets
- **Audit:** every MCP tool invocation logged to Loki with tool arguments SHA-256 hashed
- **Fail-mode:** ext_authz or ext_proc unreachable → 503, never pass-through

**NetworkPolicy:** ingress on 8080/8443 from OCP router namespace only; egress to ext-proc-delegation:9000, kyverno-authz-server:9081, jit-approver:8080, downstream MCP servers in `agentic-mcp`; deny all other egress.

---

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|---|---|---|---|
| AI agents / clients | inbound | 443 HTTPS (Route) | MCP StreamableHTTP calls |
| ext-proc-delegation | outbound | 9000 gRPC | ext_proc header mutation filter |
| kyverno-authz-server | outbound | 9081 gRPC | ext_authz allow/deny |
| jit-approver | outbound | 8080 HTTP | JIT approval gate polling |
| pfsense-mcp (agentic-mcp) | outbound | 8000 HTTP | Proxied MCP server calls |
| Keycloak | outbound | 443 HTTPS | JWKS token validation |
| Loki | outbound | 3100 HTTP | Audit log push |

---

## Verify

```bash
# 1. Check agentgateway pod is Running
oc get pods -n mcp-gateway -l app=agentgateway

# 2. Confirm the gateway rejects unauthenticated MCP requests (expect 401)
curl -sv https://mcp-gateway.apps.anaeem.na-launch.com/mcp 2>&1 | grep "< HTTP"

# 3. Confirm audit events reach Loki
curl -s "http://172.16.2.252:3100/loki/api/v1/query" \
  --data-urlencode 'query={app="agentgateway"}' | jq '.data.result[0].values[-1]'
```

---

## Maturity flags

!!! warning "Alpha software"
    agentgateway is at an **alpha** release stage — Red Hat has not committed to a stable API surface. Field names, CRD schema, and default behaviors may change between builds. The deployment pins the Helm chart version to guard against unexpected CRD churn.

- MCP StreamableHTTP transport (replacing SSE) is the target; SSE fallback may be needed for older agent SDKs
- Gateway API `HTTPRoute` + Envoy ext_authz combination is stable upstream but the Red Hat packaging is new
- Gateway API CRDs are already present on `anaeem` (installed via `servicemeshoperator3`) — no additional CRD install needed
