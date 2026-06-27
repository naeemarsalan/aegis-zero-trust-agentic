## Purpose

Red Hat OpenShift AI (RHOAI) provides the model serving and Gen AI catalog infrastructure for the platform. In this PoC it serves the inference plane that AI agents call, and it surfaces those models — plus the MCP gateway (real tools) — as **native Gen AI Studio assets**. The defining truth of this plane: an agent does **not** authenticate to a model with a stored key or a Keycloak token — the agent's **SPIFFE JWT-SVID is the model credential**, validated by Authorino on the Istio `maas-gateway` against SPIRE-OIDC.

## Exists or create

**RHOAI EXISTS** — RHOAI **3.4.1 GA** (fresh install) on cluster `ocp-dev`. The DataScienceCluster has native MaaS reconciled (`ModelsAsServiceReady=True`), KServe in **RawDeployment** mode, **Gen AI Studio**, and **LlamaStack** (`llamastackoperator=Managed`). Do **not** create a second `DataScienceCluster` or `DSCInitialization` CR — there is exactly one per cluster. Interact with RHOAI through its user-facing APIs and the Gen AI Studio catalog ConfigMaps (see Interfaces).

## Placement

- Cluster: **ocp-dev** (OCP 4.20.25)
- RHOAI dashboard: `https://rh-ai.apps.ocp-dev.na-launch.com` (Route `rhods-dashboard`; the gen-ai dashboard BFF is a compiled Go `/bff` binary in the `rhods-dashboard` pod, container `gen-ai-ui`)
- Dashboard namespace: `redhat-ods-applications` (the `dashboardNamespace` — Gen AI Studio MCP-server catalog lives here, NOT in the project ns)
- Project namespace: **`maas`** (must carry label `opendatahub.io/dashboard=true` to be a selectable Data Science project; holds the model-endpoint catalog ConfigMap and the SPIFFE plumbing)
- Edge domain: `*.apps.ocp-dev.na-launch.com` (self-signed edge cert — `curl` needs `-k`)

## Security posture

- **The SVID is the model credential.** Agents reach a registered model through the Istio `maas-gateway`, where the `maas-spiffe-auth` AuthPolicy (Authorino) validates the agent's JWT-SVID against SPIRE-OIDC. **No stored model key exists anywhere** — the OpenRouter custom AI Asset Endpoint is registered with an **empty** `custom_gen_ai.api_key.secretRef`; the real OpenRouter key stays in Vault and is injected **server-side** by the MaaS `llm-proxy`, never reaching the agent or the bridge.
- **openrouter-bridge** is the SPIFFE execution backend that makes the registered OpenRouter asset SVID-callable. It runs as a standalone Deployment in ns `maas` (the proven in-sandbox `maas_brain_proxy.Handler`, command-overridden to bind `0.0.0.0:8321`, reusing the existing `agent-harness:maas-brain` image — no code change, no rebuild). It mounts its own SPIRE CSI Workload-API volume and receives the SA-shaped SVID **`spiffe://anaeem.na-launch.com/ns/maas/sa/openrouter-bridge`**. Per request it fetches a fresh SVID, strips any inbound throwaway credential, rewrites `/v1/*` → `/openrouter/*`, sets `Host: maas.apps.ocp-dev.na-launch.com`, and forwards to `maas-gateway-istio.maas.svc:80` where Authorino validates the SVID.
- **Least-privilege AuthPolicy.** The keystone OPA gate on `maas-spiffe-auth` adds a second exact-match branch (`sub == "spiffe://…/ns/maas/sa/openrouter-bridge"`) — an EXACT equality, not a regex widening; the existing sandbox-regex branch is untouched. AuthPolicy `Enforced=True`. Fail-closed and verified: no-token `401`, garbage `401`, existing sandbox SVID still `200`, bridge SVID `200` (before the OPA edit the same bridge call was `403`).
- **Fail-mode:** fail-closed everywhere. An unauthenticated / unrecognized SVID is rejected at the gateway (`401`); a missing or denied capability never yields a partial response.

## Interfaces

**Gen AI Studio catalog** is driven by ConfigMaps the BFF reads **by exact name**. GET endpoints make no live backend call (safe to hand-author); only `POST /gen-ai/api/v1/models/external/verify` calls a model base_url.

| Asset | Surface | Backing ConfigMap (ns) | Notes |
|-------|---------|------------------------|-------|
| MCP gateway (`pfsense-k8s-tools`) | MCP Servers tab | `gen-ai-aa-mcp-servers` (`redhat-ods-applications`) | each `.data` key = server label; value JSON `{url, transport(sse\|streamable-http), description}`; **no auth field**; needs an all-users (`system:authenticated`) reader Role/RoleBinding |
| OpenRouter Claude Sonnet 4 (SPIFFE-gated) | AI Asset Endpoints | `gen-ai-aa-custom-model-endpoints` (`maas`) | single key `config.yaml`; `providers.inference[].provider_type = remote::openai` (LLM); `base_url = http://openrouter-bridge.maas.svc.cluster.local:8321/v1`; `api_key.secretRef` **empty** (SVID is the credential) |
| `style-onnx` (in-cluster CPU OVMS) | InferenceService | (project ns) | KServe RawDeployment OVMS serving runtime |

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| openrouter-bridge → `maas-gateway-istio.maas.svc` | outbound | `:80` HTTP | SVID-authenticated frontier completions (Authorino validates) |
| agent → openrouter-bridge | inbound | `:8321` HTTP (`/v1/*`) | the asset's `base_url`; bridge rewrites to `/openrouter/*` |
| MaaS `llm-proxy` → Vault | server-side | — | server-side injection of the OpenRouter key (never reaches agent/bridge) |
| Authorino → SPIRE-OIDC | internal | — | JWT-SVID validation for the model gateway |

## Files

- `platform/rhoai-maas/genai-studio/01-gen-ai-mcp-servers.yaml` — MCP Servers catalog ConfigMap + reader RBAC
- `platform/rhoai-maas/genai-studio/02-gen-ai-custom-endpoint-openrouter.yaml` — OpenRouter AI Asset Endpoint ConfigMap
- `platform/rhoai-maas/genai-studio/04-openrouter-bridge.yaml` — the standalone SPIFFE bridge Deployment
- `platform/rhoai-maas/genai-studio/05-clusterspiffeid-openrouter-bridge.yaml` — the `openrouter-bridge` SA-shaped ClusterSPIFFEID
- `platform/rhoai-maas/spiffe-auth/06-authpolicy.yaml` — durable copy of the `maas-spiffe-auth` AuthPolicy (with the bridge exact-match branch)
- `platform/rhoai-maas/genai-studio/06-llamastackdistribution.yaml` — **authored, NOT applied** (a LlamaStackDistribution registering OpenRouter as a remote provider + the MCP gateway as a toolgroup; redundant with the proven direct agent path, and the browser playground cannot mint an SVID, so it is not browser-usable; `userConfig` key `run.yaml` UNVERIFIED)
- `docs/demo/genai-studio-spiffe-zerotrust-runbook.md` — canonical step-by-step demo (Acts 1–4 + Troubleshooting)

## Verify

```bash
export KUBECONFIG=~/.kube/ocp-dev.kubeconfig

# 1. RHOAI components reconciled (MaaS, LlamaStack)
oc get datasciencecluster -o jsonpath='{.items[0].status.conditions}' | jq '.[] | select(.type=="ModelsAsServiceReady")'

# 2. Gen AI Studio catalog (BFF GET — no live backend call)
#    MCP Servers tab -> pfsense-k8s-tools, status healthy
#    GET /gen-ai/api/v1/aaa/mcps?namespace=maas
#    AI Asset Endpoints -> "OpenRouter Claude Sonnet 4 (SPIFFE-gated)", model_source_type custom_endpoint
#    GET /gen-ai/api/v1/aaa/models?sources=custom_endpoint

# 3. The catalog ConfigMaps exist by exact name
oc get cm gen-ai-aa-mcp-servers -n redhat-ods-applications
oc get cm gen-ai-aa-custom-model-endpoints -n maas

# 4. The SPIFFE bridge is up and SVID-authenticated end-to-end
oc get deploy openrouter-bridge -n maas
#    bridge -> maas-gateway with its SA SVID = HTTP 200, real anthropic/claude-4-sonnet completion
#    (before the OPA edit the same call = 403, fail-closed)

# 5. AuthPolicy enforced
oc get authpolicy maas-spiffe-auth -n maas -o jsonpath='{.status.conditions[?(@.type=="Enforced")].status}'
```

> **Status (honest):** the **model plane is fully green** — `401`/`200` at the gateway, the bridge's real OpenRouter completion, and the living OpenShell agent's brain still reasoning purely via SVID (in-pod `maas_brain_proxy` → `/openrouter` → `200`, content `BRAIN-OK`; the pod holds no model key). The OVMS `style-onnx` InferenceService and the `style-onnx` browser playground are in-cluster CPU serving.
