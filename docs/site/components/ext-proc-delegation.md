# ext-proc-delegation — The Custom Component

## Purpose

`ext-proc-delegation` is **the only custom-built component** in the platform. It is a Go service implementing Envoy's gRPC External Processing (`ext_proc`) protocol. It runs as a sidecar alongside agentgateway and intercepts every MCP tool-call request in the gateway pipeline.

For each request it:

1. Parses the agent's identity claims from gateway metadata (`dev.agentgateway.jwt`)
2. Extracts the tool name and arguments from the MCP JSON-RPC body
3. Executes a two-leg Keycloak token exchange (RFC 7523 → RFC 8693) to produce a user-scoped downstream token
4. Authenticates to Vault using its own SPIFFE SVID and reads the per-tool secret
5. Injects the user token and the per-tool secret into the forwarded request headers
6. Clears the agent's original credential from the request
7. On the response leg, strips all credential and authorization headers
8. Emits a SHA-256-hashed-args audit event and an OTel span

This is the mechanism that enforces the **no-credential-passing invariant** in UC1.

---

## Placement

| Property | Value |
|---|---|
| Cluster | `anaeem` (SNO, OCP 4.20.11) |
| Namespace | `mcp-gateway` |
| Image | `oci.arsalan.io/nvidia-ida/ext-proc-delegation:dev` |
| Internal service | `ext-proc-delegation.mcp-gateway.svc.cluster.local:9000` (gRPC) |
| External exposure | None — internal only; never exposed via Route |
| Language | Go |
| Source | `services/ext-proc-delegation/` |

---

## Service structure

```
services/ext-proc-delegation/
├── cmd/server/          # main entrypoint
├── internal/
│   ├── extproc/        # ext_proc gRPC handler (bidirectional stream)
│   ├── claims/         # parse SPIFFE claims from gateway metadata
│   ├── keycloak/       # RFC 7523 + RFC 8693 token exchange (mode: standard|legacy)
│   ├── vault/          # SVID login + per-tool secret fetch
│   ├── inject/         # header mutation (inject user token, strip agent SVID)
│   ├── audit/          # SHA-256-hashed args + OTel span emission
│   └── config/         # mode flag, maxRequestBytes, per-tool audience map
├── pkg/spiffe/         # SPIRE Workload API client for own SVID
└── Dockerfile          # distroless non-root image
```

---

## Security posture

- **SPIFFE ID:** `spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/ext-proc-delegation`
- **mTLS to agentgateway:** SPIFFE X.509 SVIDs on the gRPC channel; no static TLS certificates
- **mTLS to Kyverno authz server:** same SPIFFE mTLS on port 9081
- **Secrets:** injected via Vault Agent Injector (tmpfs); no environment variables carry credentials
- **Audit invariant:** tool arguments are SHA-256 hashed before logging; raw arguments never reach any log sink
- **Fail-mode:** if unavailable, agentgateway ext_proc filter returns 503 to the agent (fail-closed, `failure_mode_deny: true`)

**NetworkPolicy:** ingress on 9000 gRPC from `agentgateway` pod only; egress to kyverno-authz-server:9081; deny all other ingress/egress.

---

## The token exchange

The service implements a `mode` flag (ADR 0003) for resilience against RHBK preview-feature instability:

| Mode | Exchange path |
|---|---|
| `standard` | RFC 7523 jwt-bearer (SVID → Keycloak realm token, RHBK preview) → RFC 8693 exchange (→ downstream audience) |
| `legacy` | Fallback path that avoids the fragile RFC 7523 preview leg; uses a pre-provisioned federated-identity arrangement |

The active mode is selected per environment in the kustomize overlay config. Both modes emit an audit attribute recording which mode produced each token — observable per request in Loki.

---

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|---|---|---|---|
| agentgateway | inbound | 9000 gRPC | ext_proc request/response processing stream |
| kyverno-authz-server | outbound | 9081 gRPC | Policy evaluation for each tool call |
| Keycloak | outbound | 443 HTTPS | RFC 7523 + RFC 8693 token exchange |
| Vault | outbound | 8200 HTTPS | SVID login + per-tool secret read |
| jit-approver | outbound | 8080 HTTP | JIT hold: pause request pending UC2 approval |
| Loki / OTel Collector | outbound | 4317 gRPC | Hashed-args audit event + OTel span |

---

## Verify

```bash
# 1. Check ext-proc-delegation pod is Running
oc get pods -n mcp-gateway -l app=ext-proc-delegation

# 2. Confirm the gRPC service is reachable from agentgateway
oc exec -n mcp-gateway deploy/agentgateway -- \
  grpc_health_probe -addr=ext-proc-delegation.mcp-gateway.svc.cluster.local:9000

# 3. Send a synthetic MCP tool call and verify a policy-decision log entry in Loki
curl -s "http://172.16.2.252:3100/loki/api/v1/query" \
  --data-urlencode 'query={app="ext-proc-delegation"}' | jq '.data.result[0].values[-1]'

# 4. Run Go unit tests for the service
make test-extproc
```

---

## Maturity flags

- The delegation identity-header injection pattern (user identity propagation) is a custom implementation — not an upstream standard; review carefully before production use
- Envoy ext_proc (`ProcessingMode`) is stable in Envoy 1.29+; the Red Hat agentgateway alpha bundles its own Envoy — confirm the ext_proc filter version matches
- Response body processing is SKIP by default; enabling it adds latency and memory pressure
