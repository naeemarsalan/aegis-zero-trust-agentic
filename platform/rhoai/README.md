# platform/rhoai

RHOAI Data Science Project namespace and MCP server workloads for the
agentic-mcp platform.

RHOAI 3.4.0-ea.2 with DataScienceCluster **data-skill-factory** already runs on
anaeem — this component creates NO operator, DSC, or DSCInitialization resources.
It only provisions the `agentic-mcp` namespace as a Data Science Project and
deploys the MCP server workloads into it.

## What is deployed

| Resource | Kind | Notes |
|---|---|---|
| agentic-mcp | Namespace | RHOAI Data Science Project (`opendatahub.io/dashboard: "true"`) |
| pfsense-mcp | ServiceAccount | Vault Kubernetes auth subject |
| echo-mcp | ServiceAccount | No Vault injection |
| pfsense-mcp | Deployment | Upstream gensecaihq server; streamable-http on container port 3000; Vault Agent Injector; image `oci.arsalan.io/nvidia-ida/pfsense-mcp:1.0.0` |
| pfsense-mcp | Service port 8000 -> 3000 | ClusterIP; gateway contract port 8000 preserved; `app.kubernetes.io/component=mcp-server` |
| echo-mcp | Deployment | UC1 golden-test identity-echo server; image `oci.arsalan.io/nvidia-ida/echo-mcp:dev` |
| echo-mcp | Service :8000 | ClusterIP; `app.kubernetes.io/component=mcp-server` discovery label |

## Upstream server

`pfsense-mcp` runs the **gensecaihq/pfsense-mcp-server** (327 tools, MCP 2025-11-25 spec).
Source: `/home/anaeem/pfsense-mcp-server`.
Build: `bash services/pfsense-mcp-server/build-and-push.sh`.

Key runtime parameters:
- Transport: streamable-http
- Container port: **3000**  (Service port 8000 -> targetPort 3000)
- Auth: MCP_API_KEY bearer token (per-user token list from Vault)
- pfSense backend: https://172.99.0.1, basic auth, CE_2_8_1
- Health/readiness: `GET /mcp` on port 3000

## How RHOAI 3.x discovers MCP servers for Llama Stack agents

RHOAI 3.x Llama Stack integration builds its MCP tool registry by scanning
every namespace that carries the label:

```
opendatahub.io/dashboard: "true"
```

Within those namespaces it looks for Services labelled:

```
app.kubernetes.io/component: mcp-server
```

The combination of namespace label + service label is sufficient for the
RHOAI Dashboard to list the tool endpoint in the Data Science Project view
and for the Llama Stack `mcpd` sidecar to register it as a tool provider.

Both `pfsense-mcp` and `echo-mcp` carry the discovery label on their Service
resources.  Adding a new MCP server to this project requires only:

1. A Deployment + Service in `agentic-mcp` with
   `app.kubernetes.io/component: mcp-server` on the Service.
2. A corresponding `AgentgatewayBackend` in `platform/agentgateway/base/`
   pointing to `<name>.agentic-mcp.svc.cluster.local:8000`.
3. A NetworkPolicy update in `platform/networkpolicies/base/np-agentic-mcp.yaml`
   opening port 8000 ingress from `mcp-gateway`.

## Credential flow and identity delegation

### pfSense backend credentials

The Vault Agent Injector renders two files to a tmpfs at `/vault/secrets/` inside
the pfsense-mcp pod:

```
/vault/secrets/pfsense     — PFSENSE_USERNAME + PFSENSE_PASSWORD (basic auth to pfSense)
/vault/secrets/mcp-tokens  — comma-separated per-user MCP_API_KEY token list
```

Neither file touches etcd, container env at build time, or the container image.

### ext-proc delegation — UC1 proof

The delegation flow that proves "downstream MCP sees the USER identity, never the agent":

```
User request
  └── agentgateway + ext-proc-delegation (ns mcp-gateway)
        ├── validates user's SPIFFE SVID / OIDC token
        ├── exchanges for delegated user token at Keycloak
        └── fetches THIS user's pfSense MCP token from Vault
              (path: secret/data/mcp-tools/mcp-tokens, keyed by user sub)
        └── injects Authorization: Bearer <user-mcp-token>
  └── pfsense-mcp (ns agentic-mcp, port 8000 -> 3000)
        ├── BearerAuthMiddleware validates token against MCP_API_KEY list
        │   (loaded from /vault/secrets/mcp-tokens at startup)
        ├── routes tool call with user's identity visible in auth context
        └── pfSense REST API call attributed to that user in audit log
```

Each user has a **unique** token in the `mcp-tokens` Vault secret.
ext-proc injects the token belonging to the *requesting user*, not the agent.
The upstream server sees only that user's token — it can never observe another
user's token or the agent's service-account identity.

This is the **UC1 proof**: the pfSense server's own audit attributes every
action to the real user, and the agent's identity is recorded separately by
ext-proc in the OTel/Loki audit stream.

### Vault bootstrap (run once after Vault is initialized)

```bash
# Store pfSense basic-auth credentials
vault kv put secret/pfsense/credentials username=admin password=<value-from-arsalan>

# Store per-user MCP token list (comma-separated)
vault kv put secret/mcp-tools/mcp-tokens tokens=<user1-token>,<user2-token>

# Create Vault policy
vault policy write pfsense-mcp - <<'EOF'
path "secret/data/pfsense/credentials" {
  capabilities = ["read"]
}
path "secret/data/mcp-tools/mcp-tokens" {
  capabilities = ["read"]
}
EOF

# Create Kubernetes auth role
vault write auth/kubernetes/role/pfsense-mcp \
  bound_service_account_names=pfsense-mcp \
  bound_service_account_namespaces=agentic-mcp \
  policies=pfsense-mcp \
  ttl=1h
```

## Apply order

1. `platform/vault` — Vault must be initialized, unsealed, and the `pfsense-mcp`
   role must exist (see bootstrap above).
2. `platform/rhoai/overlays/anaeem` (this component).
3. `platform/networkpolicies/overlays/anaeem` — default-deny + gateway allowlist.

```bash
# Dry-run (offline)
kustomize build platform/rhoai/overlays/anaeem

# Apply
kustomize build platform/rhoai/overlays/anaeem | oc apply -f -
```

## Verify

```bash
# Namespace carries the RHOAI Data Science Project label
oc get ns agentic-mcp -o jsonpath='{.metadata.labels.opendatahub\.io/dashboard}'
# -> true

# Services carry the RHOAI discovery label
oc -n agentic-mcp get svc -l app.kubernetes.io/component=mcp-server
# NAME          TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)    AGE
# echo-mcp      ClusterIP   ...          <none>        8000/TCP   ...
# pfsense-mcp   ClusterIP   ...          <none>        8000/TCP   ...

# pfsense-mcp container port is 3000 (Service 8000 -> targetPort 3000)
oc -n agentic-mcp get svc pfsense-mcp -o jsonpath='{.spec.ports[0]}'
# -> {"name":"http-mcp","port":8000,"protocol":"TCP","targetPort":3000}

# Vault Agent Injector wrote the secrets to tmpfs
oc -n agentic-mcp exec deploy/pfsense-mcp -c pfsense-mcp -- ls -la /vault/secrets/

# pfsense-mcp healthz via MCP endpoint (port 3000 inside pod)
oc -n agentic-mcp exec deploy/pfsense-mcp -c pfsense-mcp -- \
  curl -sf -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $(cat /vault/secrets/mcp-tokens | cut -d, -f1)" \
  http://localhost:3000/mcp
# -> 200 or 405 (endpoint alive)

# echo-mcp healthz
oc -n agentic-mcp exec deploy/echo-mcp -- \
  curl -s http://localhost:8000/healthz

# UC1 golden test — call echo_identity via the mcp-gateway with a real user token
# (replace <USER_TOKEN> with a token issued by Keycloak realm agentic)
curl -s -X POST https://mcp-gateway.apps.anaeem.na-launch.com/mcp \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_identity","arguments":{}}}' \
  | jq '.result.content[0].text'
# Expected: the "sub" and "azp" claims from the delegated user token,
# confirming that the MCP server sees the USER identity, not the agent's.
```

## echo-mcp (identity-echo golden test)

`echo-mcp` is kept as-is for the UC1 identity-echo golden test.

The image must implement:

- StreamableHTTP MCP server on port 8000 (path `/mcp`)
- `GET /healthz` returning HTTP 200
- One MCP tool `echo_identity` that reads the `Authorization` request header,
  decodes the JWT without verification (the gateway has already validated it),
  extracts `sub`, `azp`, and `iss` claims, and returns them as a JSON string.

Build target: `oci.arsalan.io/nvidia-ida/echo-mcp:dev`.
A minimal Containerfile should be placed at `images/echo-mcp/Containerfile`.
