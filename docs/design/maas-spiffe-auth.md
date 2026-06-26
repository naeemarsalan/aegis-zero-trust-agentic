# MaaS with SPIFFE auth — the SVID *is* the model credential (no tokens)

## Goal
Agents call RHOAI-served models authenticating **only with their SPIFFE JWT-SVID** —
the same identity they already hold for the MCP gateway. No per-agent model bearer
token to mint, store, rotate, or leak. MaaS inherits the platform invariant:
*the agent has nothing to steal.*

## Architecture (flavor B — JWT-SVID at the gateway, Authorino-validated)
```
agent (JWT-SVID only)
   │  Authorization: Bearer <JWT-SVID>   (iss = SPIRE OIDC)
   ▼
Istio MaaS Gateway (Gateway API, gatewayClassName = istio)
   │  ext-authz → Authorino
   ▼
Authorino AuthPolicy:
   • authentication: JWT, issuerUrl = https://spire-oidc.apps.ocp-dev.na-launch.com
     (JWKS validated; trust the cluster ingress CA — same CA Vault needed)
   • authorization: allow when identity.sub matches
       ^spiffe://anaeem\.na-launch\.com/ns/(openshell|agent-sandbox)/sandbox/.+$
   ▼
HTTPRoute → KServe InferenceService (RawDeployment, CPU)
```
Downstream model sees a request authorized by the agent's cryptographic identity.
mTLS-SPIFFE (Istio⇄SPIRE federation, X.509-SVID, sidecar in-mesh) is the hardening
roadmap; flavor B needs **no sidecar in the sandbox** and reuses the SPIRE-OIDC trust
Vault + Keycloak already consume.

## Components
| Piece | Choice | Notes |
|---|---|---|
| Istio | Sail operator / OSSM 3 (`Istio` CR, ns istio-system) | provides GatewayClass `istio` (controller `istio.io/gateway-controller`) that Authorino enforces against. NOT agentgateway (Authorino can't enforce there). |
| Gateway | Gateway API `Gateway`, class `istio`, host `maas.apps.ocp-dev.na-launch.com` | HTTP listener is fine for the PoC; add TLS later. |
| Model | KServe `InferenceService`, RawDeployment, **CPU** | small/CPU model (e.g. sklearn-iris sample) or a mock predictor — the deliverable is the AUTH plane, not model size. GPU only for large LLM serving. |
| AuthN/Z | Kuadrant `AuthPolicy` (Authorino) on the Gateway/HTTPRoute | JWT issuer = SPIRE OIDC + ingress-CA; authz on the SPIFFE `sub`. |

## Reuse (already deployed)
- SPIRE issuing SVIDs; **SPIRE OIDC discovery already trusted** (Vault `auth/jwt`, Keycloak).
- Agent already fetches/presents a JWT-SVID (`svid_bearer`, `mcp-call`). Audience: SVID `aud` may be `mcp-gateway`; Authorino JWT check validates `iss`+signature and does NOT require `aud` (leave aud-check off, or mint a model-aud SVID later).
- Kuadrant/**Authorino installed**; KServe (RawDeployment) Ready (DSC default-dsc).

## To build
1. Install Istio (Sail/OSSM) → GatewayClass `istio` Accepted.
2. MaaS Gateway on `istio` class → Programmed.
3. Serve a CPU model (KServe) behind an HTTPRoute → Ready.
4. Kuadrant `AuthPolicy`: SPIRE-OIDC JWT identity + SPIFFE-sub authorization, attached to the Gateway.
5. Test from the e2e-harness pod: **no token → 401/403; valid JWT-SVID → 200 (model responds)**; unauthorized sub → 403.

## Authorization roadmap (bonus)
Model tiers collapse into the existing read-delegated / write-approved model:
- cheap model = delegated by SVID;
- **premium model = requires a JIT capability** (console mint-gate) — an Authorino
  rule additionally checking the capability JWT (`aud=kyverno-authz`/model-scope).

## e2e result — PROVEN (2026-06-26)
Tested from the `agent-sandbox` `e2e-harness` pod (its own SPIFFE JWT-SVID, no
other credential) against `maas-gateway-istio.maas.svc:80` (Host
`maas.apps.ocp-dev.na-launch.com`):

| Case | Result |
|---|---|
| no `Authorization` header | **401** (Authorino denies) |
| garbage `Bearer not.a.jwt` | **401** |
| valid JWT-SVID (`sub=spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/…`, `aud=mcp-gateway`) | **200**, model body returned (`/v1/models` → `mock-cpu-standin`) |

The SVID is the *only* credential presented; Authorino validates `iss`=SPIRE-OIDC
+ signature and the OPA `sub`-regex authorizes the sandbox identity. No model
bearer token exists anywhere. **Persisted under `platform/rhoai-maas/spiffe-auth/`.**

## Constraints on ocp-dev
- No GPU → serve CPU/small model (or mock) to prove auth; large-LLM serving is the GPU follow-up.
- `kube:admin` token TTL is short + API flaps (TLS timeouts) → every step must re-login + retry.
- Authorino must trust SPIRE-OIDC's serving cert → supply the ingress CA bundle (`oc -n openshift-config-managed get cm default-ingress-cert -o jsonpath='{.data.ca-bundle\.crt}'`).
