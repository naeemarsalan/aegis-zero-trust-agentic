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

## Real model (2026-06-26) — NOT a mock
The auth plane now fronts a **real KServe `InferenceService`**, not the mock:

- **`kserve-ovms`** ServingRuntime — Red Hat OpenVINO Model Server (OVMS),
  `protocolVersions: [v2, grpc-v2]`.
- **`style-onnx`** InferenceService — `RawDeployment`, **CPU-only**, pulling the
  public ONNX *style* model from `gs://kfserving-examples/models/onnx/style`.
  Status `Ready=True`, `modelStatus.activeModelState: Loaded`.
- Backend Service `style-onnx-predictor:80`. Both the standard route (`/`) and
  the premium route (`/premium/*`) backend onto it.
- Proof it is real inference (not canned): `GET /v2/models/style-onnx` returns the
  model's true metadata — `platform=OpenVINO`, FP32 tensors `[1,3,224,224]`.

The mock (`03-mock-model.yaml`) is kept deployed as a harmless fallback but is no
longer in the request path. Large-LLM serving (vLLM on GPU) is the hardware
follow-up; OVMS/ONNX runs the proof on a GPU-less cluster.

Manifest: `platform/rhoai-maas/spiffe-auth/09-real-model.yaml`.

## JIT-gated premium tier — approve-to-elevate
Model tiers map onto the platform's read-delegated / write-approved model:

- **STANDARD** (`/…`): a valid SPIFFE JWT-SVID is sufficient (delegated identity).
- **PREMIUM** (`/premium/…`): the SVID **AND** a valid **jit-approver JIT
  *capability* JWT** in the `X-JIT-Capability` header (approve-to-elevate).

Both tiers live in ONE AuthConfig (Authorino indexes one AuthConfig per host; a
second route-level policy on the same host collides — "host already taken"), so
the premium requirement is discriminated **in OPA** on the request path
(`06-authpolicy.yaml`). The capability JWT issuer
(`https://jit-approver.mcp-gateway.svc.cluster.local:8080`) is **not** OIDC-
discoverable, so OPA verifies it with `io.jwt.decode_verify` against the embedded
jit-approver JWKS (RS256, `kid=jit-approver-key-1`, `aud=kyverno-authz`) — the
**same** key jit-approver signs with (Vault-mounted PEM, `JIT_SIGNING_KEY_PATH`).
The `/premium` prefix is URL-rewritten away so the model sees its native v2 paths.

### e2e result — PROVEN against the REAL model (2026-06-26)
From the `agent-sandbox` `e2e-harness` pod, presenting **only** its SPIFFE
JWT-SVID (`sub=spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/…`,
`aud=mcp-gateway`) against `maas-gateway-istio.maas.svc:80` (Host
`maas.apps.ocp-dev.na-launch.com`):

| Tier | Credentials presented | Result |
|---|---|---|
| STANDARD | none | **401** |
| STANDARD | valid JWT-SVID | **200** (real model metadata) |
| PREMIUM `/premium/…` | valid JWT-SVID only | **403** (no capability) |
| PREMIUM `/premium/…` | valid JWT-SVID **+** valid JIT capability JWT | **200** (real model) |
| PREMIUM `/premium/…` | valid JWT-SVID + garbage capability | **403** |

No model bearer token exists anywhere; the SVID is the only standing credential,
and premium access requires a short-lived, approver-signed capability on top.

## Constraints on ocp-dev
- No GPU → serve a CPU model (real OVMS/ONNX above, or the mock) to prove auth;
  large-LLM (vLLM/GPU) serving is the hardware follow-up.
- `kube:admin` token TTL is short + API flaps (TLS timeouts) → every step must re-login + retry.
- Authorino must trust SPIRE-OIDC's serving cert → supply the ingress CA bundle (`oc -n openshift-config-managed get cm default-ingress-cert -o jsonpath='{.data.ca-bundle\.crt}'`).
