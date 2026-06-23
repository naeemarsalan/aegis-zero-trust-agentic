# agentgateway — MCP Gateway Control Plane

## What

Deploys the [agentgateway](https://github.com/agentgateway/agentgateway) controller (v1.3.0-alpha.1)
and data-plane proxy into namespace `mcp-gateway` on the **anaeem** SNO cluster.  Agentgateway
implements the Kubernetes Gateway API (`gateway.networking.k8s.io`) with MCP-aware CRDs
(`agentgateway.dev/v1alpha1`).

> **Alpha-version warning** — `v1.3.0-alpha.1` is pre-GA.  CRDs are pinned under `crds/` (vendored
> from the upstream release for `kubeconform` offline validation).  Before upgrading, diff CRD
> schemas and re-validate all resources with `kustomize build | kubeconform -schema-location crds/`.

## Why

- Provides the MCP proxy (StreamableHTTP) that fronts downstream MCP servers (`pfsense-mcp`, future
  AAP servers).
- Enforces JWT authn (Keycloak `agentic` realm), ext_authz (Kyverno), ext_proc (delegation sidecar),
  and CEL RBAC at the gateway layer so downstream servers see the **user** identity, never the
  agent's.
- OpenShift Route terminates TLS and re-encrypts to the Gateway listener.

## CRD Pinning Note

Upstream CRDs live at:
```
https://github.com/agentgateway/agentgateway/releases/tag/v1.3.0-alpha.1
```
Vendor YAML files into `crds/` so `kustomize build` and `kubeconform` work offline:
```bash
VERSION=v1.3.0-alpha.1
BASE=https://raw.githubusercontent.com/agentgateway/agentgateway/${VERSION}/controller/install/helm/agentgateway/files
# download AgentgatewayBackend, AgentgatewayPolicy, AgentgatewayParameters CRDs
# (exact file names may differ — check the release assets)
curl -sL "${BASE}/crds.yaml" -o crds/agentgateway-crds.yaml
```

## Apply Order

1. **CRDs** — apply once, cluster-scoped:
   ```bash
   kubectl apply -f crds/
   ```
2. **Namespace + RBAC** (included in base):
   ```bash
   kustomize build platform/agentgateway/overlays/anaeem | kubectl apply -f -
   ```
3. **Helm controller** — render values then apply:
   ```bash
   helm install agentgateway-controller \
     oci://cr.agentgateway.dev/charts/agentgateway \
     --version 0.0.2 \
     --namespace mcp-gateway \
     --values platform/agentgateway/helm-values.yaml
   ```
4. **Kustomize overlay** (Gateway, Backend, Policy, Routes, NetworkPolicies):
   ```bash
   kustomize build platform/agentgateway/overlays/anaeem | kubectl apply -f -
   ```

## Verify

```bash
# OIDC discovery reachable through gateway
curl -k https://mcp-gateway.apps.ocp-dev.na-launch.com/.well-known/openid-configuration

# MCP inspector (install once: npm i -g @modelcontextprotocol/inspector)
MCP_BEARER=<token>
npx @modelcontextprotocol/inspector \
  --url https://mcp-gateway.apps.ocp-dev.na-launch.com/mcp \
  --header "Authorization: Bearer ${MCP_BEARER}"

# Check CRD status
kubectl get agentgatewaybackend,agentgatewaypolicy -n mcp-gateway

# Gateway programmed
kubectl get gateway mcp-gateway -n mcp-gateway -o jsonpath='{.status.conditions}'
```
