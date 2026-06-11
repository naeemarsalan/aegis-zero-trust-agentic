## Purpose

pfsense-mcp is the demo MCP server that exposes pfSense firewall operations (firewall rule management, IP blocking, DHCP lease queries) as MCP tools callable by AI agents. It demonstrates the end-to-end zero-trust tool-call path: agent → agentgateway → ext-proc-delegation (policy) → JIT approval (for destructive ops) → pfsense-mcp → pfSense API. It also serves as the reference implementation for how custom MCP servers are onboarded to the platform.

## Exists or create

CREATE on anaeem. Deploy as a Deployment in namespace `agentic-mcp` (the RHOAI Data Science Project namespace). The image is `oci.arsalan.io/nvidia-ida/pfsense-mcp:dev`. The pfSense API URL and API key are **TODO** pending Arsalan's input — the URL will be stored in a Vault `kv-v2` path and the API key as a Vault dynamic secret; neither is committed to git.

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11)
- Namespace: `agentic-mcp`
- Internal service: `pfsense-mcp.agentic-mcp.svc.cluster.local:8000` (StreamableHTTP `/mcp`, no Route — agentgateway proxies all access)
- Not directly reachable from agents; all calls transit agentgateway at `https://mcp-gateway.apps.anaeem.na-launch.com`
- pfSense API URL: TBD (external, outside the cluster network) — injected via Vault at runtime

## Security posture

- SPIFFE ID: `spiffe://anaeem.na-launch.com/ns/agentic-mcp/sa/pfsense-mcp`
- pfSense API key stored in Vault (`kv-v2/pfsense/api-key`); injected via Vault Agent Injector (tmpfs mount at `/run/secrets/pfsense/`); never in etcd, git, or environment variables
- pfsense-mcp validates the incoming `X-Forwarded-User` header (set by ext-proc-delegation) to log which human user authorized each tool call; rejects requests missing this header
- Destructive tool calls (`block_ip`, `delete_rule`, `flush_rules`) are tagged `jit-required: true` in the tool manifest — Kyverno policy causes ext-proc-delegation to route them through jit-approver before execution
- NetworkPolicy: ingress on 8000 from `agentgateway` pod in `mcp-gateway` namespace only; egress to pfSense API (external IP, port 443/TCP) and to Vault on 8200; deny all other ingress/egress
- Fail-mode: if Vault Agent cannot inject the API key, the pod does not reach Ready; if pfSense API is unreachable, pfsense-mcp returns `503` with a structured MCP error — agentgateway surfaces this to the agent

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| agentgateway | inbound | 8000 HTTP | MCP StreamableHTTP tool calls |
| pfSense API | outbound | 443 HTTPS | Firewall rule management |
| Vault Agent sidecar | inbound (localhost) | 8200 HTTPS | API key injection |
| OTel Collector | outbound | 4317 gRPC | Traces and structured tool-call logs |

## Maturity flags

- pfsense-mcp is a custom component at `dev` tag — no upstream project; behavior and tool schema may change
- pfSense API URL is currently empty (`pfsense.apiUrl: ""` in clusters.yaml) — this component cannot function until the URL is provided and the API key is seeded into Vault
- MCP StreamableHTTP transport (vs. SSE) is the target; confirm the agent SDK version supports it
- The `X-Forwarded-User` header injection for user identity propagation is a platform convention, not an MCP standard — document this for all future MCP server authors

## Verify

```bash
# 1. Check pfsense-mcp pod is Running
oc get pods -n agentic-mcp -l app=pfsense-mcp

# 2. Confirm the pfSense API key is Vault-injected (tmpfs) not a Kubernetes Secret
oc exec -n agentic-mcp deploy/pfsense-mcp -- ls /run/secrets/pfsense/

# 3. Call the MCP list-tools endpoint through agentgateway (requires a valid Keycloak token)
TOKEN=$(curl -s -X POST \
  https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/token \
  -d "client_id=agent-cli&grant_type=password&username=operator&password=<pw>" \
  | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" \
  https://mcp-gateway.apps.anaeem.na-launch.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq '.result.tools[].name'
```
