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

## OpenRouter (external LLM) behind MaaS — key injected server-side
The same SPIFFE-auth gateway now fronts a **real external LLM** (OpenRouter,
`anthropic/claude-sonnet-4` / `claude-opus-4`), not just the CPU ONNX model. The
agent still presents **only** its JWT-SVID; the **upstream OpenRouter API key
never exists in the agent** — it is injected **server-side** by the MaaS
`llm-proxy` from Vault (`secret/data/mcp-tools/openrouter`, key `token`).

- `llm-proxy` forwards **directly** to `https://openrouter.ai/api/v1/chat/completions`
  (LiteLLM removed from the path); `UPSTREAM_BASE_URL=https://openrouter.ai/api`
  with OpenRouter attribution headers.
- Routes: `/openrouter` (STANDARD) and `/premium/openrouter` (PREMIUM) — the same
  two-tier model as the CPU model, discriminated in OPA.
- Two infra seams fixed: the `maas` ns was missing from Vault's default-deny
  ingress allowlist (Vault Agent init timed out → added NetworkPolicy
  `vault/allow-ingress-from-maas` on `:8200`); plus an Istio `ServiceEntry`
  +`DestinationRule` for `openrouter.ai` (mesh-correctness / future injection).

### e2e result — PROVEN (2026-06-26), from the e2e-harness pod (SVID only)
| Case | Result |
|---|---|
| `/openrouter` no token | **401** |
| `/openrouter` + SVID | **200** — `claude-sonnet-4`: "HELLO" |
| `/premium/openrouter` + SVID only | **403** |
| `/premium/openrouter` + SVID + JIT capability | **200** — `claude-opus-4`: "PREMIUM" |
| `/premium/openrouter` + SVID + garbage capability | **403** |

Regression unchanged: style-onnx STANDARD 200 / PREMIUM SVID-only 403 / SVID+cap 200.
Manifests: `platform/rhoai-maas/spiffe-auth/{10-llm-proxy.yaml,11-llm-route.yaml,12-egress-openrouter.yaml,13-vault-ingress-from-maas.yaml}`.

## Agent brain calls models via MaaS (SVID auth)
The OpenShell agent's **Claude brain itself** now reasons credential-less through
the MaaS gateway, authenticating with its own JWT-SVID. The agent holds **no model
key**.

The system `claude` CLI speaks Anthropic `/v1/messages` with a *static* bearer, but
the SVID is short-lived and must be fresh per call. A tiny stdlib **SVID-injecting
loopback proxy** (`maas_brain_proxy.py`) sits in front: the CLI points at
`ANTHROPIC_BASE_URL=http://127.0.0.1:8787`, and per request the proxy strips the
CLI's throwaway token, fetches a **fresh SVID** via `svid_bearer` (same shape-guard
as the MCP path), rewrites `/v1/messages` → MaaS `/openrouter/messages`
(gateway URLRewrite `/openrouter`→`/v1` → OpenRouter's Anthropic-native
`/api/v1/messages`), and forwards with `Authorization: Bearer <SVID>`.

### Evidence — PROVEN (2026-06-26), e2e-harness pod
- Agent run output: `{"type":"assistant","text":"hello from the SVID-authed brain"}`
  → `{"type":"result","status":"success",...}` (EXIT=0) — the real `claude` CLI via
  the SDK, `max_turns=2`.
- llm-proxy log: `"POST /v1/messages?beta=true HTTP/1.1" 200` (the `?beta=true` is
  the SDK/CLI signature) — reached only **after** Authorino validated the SVID.
- No-key proof: `env | grep ANTHROPIC_API_KEY|sk-or|sk-ant` in the pod → none. The
  agent's placeholder token sent straight at MaaS → **401**; only the proxy's SVID
  turns it into **200**.

Wiring (LIVE — `agent-harness:maas-brain` image is the default boot):
`services/agent-sandbox/agent-harness/src/agent_harness/maas_brain_proxy.py`,
`bin/brain-entrypoint` (starts proxy, points CLI at it; `MAAS_BRAIN=1` default),
`Dockerfile`/`Dockerfile.native-brain`. The e2e-harness Deployment
(`services/agent-sandbox/e2e-harness/deployment.yaml`) no longer runs `sleep
infinity` — it auto-starts `agent_harness.maas_brain_proxy` on boot and keeps the
pod alive, so the standing brain serves every reasoning call. Verified live: boot
log `maas_brain_proxy started (credential-less MaaS brain)`; `agent_runner`
goal "17 times 3" → answer `51`, `status: success`; the only key in the pod env is
the placeholder `ANTHROPIC_API_KEY=svid-injected-by-local-proxy` (no real `sk-`).

## RHOAI 3.4 GA — native MaaS + Gen AI Studio (2026-06-26)

We did a **fresh install** of Red Hat OpenShift AI 3.4 (2.25 → 3.4 is not a
supported in-place upgrade): Subscription `rhods-operator` channel **stable-3.x**
from the standard **redhat-operators** catalog → CSV **rhods-operator.3.4.1
Succeeded**. The operator auto-created **DSCInitialization v2** (`default-dsci`,
Ready) and the native MaaS gateway **`data-science-gateway`** (GatewayClass
`data-science-gateway-class`, controller `openshift.io/gateway-controller`,
Programmed=True, fronting the dashboard at `rh-ai.apps.ocp-dev.na-launch.com`).

**DataScienceCluster v2** (`default-dsc`) created with the breaking-change shape
(`/v2`; `datasciencepipelines`→`aipipelines`; ModelMesh removed; KServe
RawDeployment; `kueue: Removed`). `kserve.modelsAsService=Managed` was flipped
**after** gateway+kserve were up. All components Ready **except**
`ModelsAsServiceReady`. **LlamaStack** ships inside rhods-operator 3.4 (DSC
`llamastackoperator=Managed`, Ready) — no separate subscription.

**Gen AI Studio** enabled via `OdhDashboardConfig.spec.dashboardConfig`:
`genAiStudio=true`, `modelAsService=true`, `aiAssetCustomEndpoints=true` (live).
Dashboard reachable (rhods-dashboard 9/9, `rh-ai…` 302→OIDC login).

### The Kuadrant single-plane blocker (human-gated) — RESOLVED 2026-06-26 (see "RHCL cutover" below)
`ModelsAsServiceReady=False` — maas-controller CrashLoops needing Kuadrant 1.x
CRDs the cluster does not serve: **AuthConfig `authorino.kuadrant.io/v1beta3`**
and **`kuadrant.io/v1alpha1` TokenRateLimitPolicy** (RHCL). The cluster runs the
**community** Authorino v0.13 (AuthConfig v1beta1/v1beta2 only). So **maas-api
never deploys** and **no `InferenceService` exists** → the Gen AI Studio "AI asset
endpoints" page is empty and nothing can carry the `opendatahub.io/genai-asset=true`
label yet. We deliberately did **NOT** install RHCL in parallel: both planes own the
cluster-scoped `kuadrant.io`/`authorino.kuadrant.io` CRDs and a second control plane
would fight the community Kuadrant our live SPIFFE/Istio MaaS depends on. The fix is
a deliberate **single-plane cutover** (uninstall community → install RHCL adopting
the same CRDs), migrating `maas-spiffe-auth` in lockstep — not a parallel install.

### Which auth path: neither `defaults` nor `overrides`
There is **no RHOAI-native AuthPolicy to reconcile with** — maas-controller never
generated one (maas-api never deployed), and the native `data-science-gateway`
(controller `openshift.io/gateway-controller`) is **not Kuadrant-enforced** anyway.
Our SPIFFE auth therefore lives on the **Istio `maas-gateway` (ns `maas`)**, which
Kuadrant *does* enforce, via a single gateway-attached `AuthPolicy/maas-spiffe-auth`
(Kuadrant **v1beta2**, plain `spec.rules` — gateway-default semantics, route-level
override permitted; not `overrides`). When the RHCL cutover lands, this same SPIFFE
AuthPolicy pattern re-attaches to whichever Kuadrant-enforced gateway hosts the
labeled AI-asset model.

### Native-endpoint SPIFFE proof — PASS (2026-06-26), e2e-harness pod
SVID-only (fresh `aud=maas` JWT-SVID via the workload API; sub
`…/ns/agent-sandbox/sandbox/e2e0a1b2-…`), against
`maas-gateway-istio.maas.svc` with `Host: maas.apps.ocp-dev.na-launch.com`:
- `/openrouter/models` **no token → 401**
- `/openrouter/models` **SVID → 200** (real OpenRouter model list, server-side key)
- `/premium/openrouter/models` **SVID only → 403** (`is_premium`, no cap)
- `/premium/openrouter/models` **SVID + JIT capability → 200** (real model body)

The capability was minted by the **live** `jit-approver` signing key
(`signing.mint_session_jwt`, kid `jit-approver-key-1`, iss
`https://jit-approver.mcp-gateway.svc.cluster.local:8080`, aud `kyverno-authz`); its
`/jwks` matches the rego-embedded JWKS exactly, so OPA `cap_ok` is genuinely
exercised. etcd healthy throughout (3/3, ~280 MB balanced, no MaaS-induced growth).
Manifests: `platform/rhoai-maas/{10-rhods-operator-3.4-subscription,11-dscinitialization-v2,12-datasciencecluster-v2,13-odhdashboardconfig-genai-studio}.yaml`.

## RHCL cutover + native AI Asset Endpoints — DONE (2026-06-26)
The single-plane cutover above is **complete and live**. State now:

**Community → RHCL cutover (no parallel install).** The cluster now runs **Red Hat
Connectivity Link** (`rhcl-operator` v1.4.0, redhat-operators) bringing
authorino-operator + limitador-operator **v1.4.0**, adopting the same
`kuadrant.io`/`authorino.kuadrant.io` CRDs (now serving **AuthConfig v1beta3** +
**AuthPolicy kuadrant.io/v1**). The Subscription change is in
`platform/rhoai-maas/01-operators-subscriptions.yaml` (kuadrant-operator/community →
rhcl-operator/redhat-operators). `maas-spiffe-auth` was migrated in lockstep:
`06-authpolicy.yaml` apiVersion **v1beta2 → v1** (rego/OPA byte-for-byte unchanged).

**Ext-authz wiring = wasm-shim, NOT the Istio extensionProvider.** RHCL 1.4.0 does
ext-authz via the **wasm-shim** (`EnvoyFilter kuadrant-maas-gateway`, scope-based),
so the Istio CR meshConfig `extensionProviders[kuadrant-authorization]` needed **no
change** (already correct/unused). The cutover blocker was a leftover community-era
**Istio CUSTOM `AuthorizationPolicy maas/on-maas-gateway`** that injected a raw
host-based ext_authz filter, shadowing the wasm-shim → Authorino 404 "Service not
found" (AuthConfig hosts are scope-hashes). **Deleted** it (not recreated); GitOps
must NOT re-create a CUSTOM AuthorizationPolicy for the maas gateway.
**CRITICAL durable gotcha:** the shared Authorino **listener TLS must stay DISABLED**
— the wasm-shim calls Authorino over **plaintext gRPC :50051** and the operator never
adds TLS there; enabling it 500s BOTH gateways. maas-controller needs listener TLS
only as a one-time reconcile precondition; revert it once maas-api is up.

**Native MaaS up.** `maas-controller` was unblocked by two prereqs (NOT an AuthConfig
version block — RHCL serves v1beta3): Secret `maas-db-config` (`DB_CONNECTION_URL`
from the CNPG `maas-db-app` secret) in `redhat-ods-applications`, and a one-time
Authorino listener serving cert. **`ModelsAsServiceReady=True`, `maas-api` 1/1**
(DB connected, schema applied).

**AI Asset Endpoints + Gen AI Studio.** A real **style-onnx OVMS `InferenceService`**
(ns `maas`, ServingRuntime `kserve-ovms`, OpenVINO backend, READY=True) labeled
`opendatahub.io/genai-asset=true` + `opendatahub.io/dashboard=true` now surfaces on the
**Gen AI Studio → AI asset endpoints** page (`genAiStudio` + `aiAssetCustomEndpoints`
true on OdhDashboardConfig). Manifest: `spiffe-auth/14-genai-asset-model.yaml`.

**SPIFFE on the NATIVE endpoint — PASS.** The maas-controller gateway AuthPolicy uses
the `defaults` strategy, so we attached a **ROUTE-level** SPIFFE `AuthPolicy`
(`maas-native-asset-spiffe-auth`, SPIRE-OIDC issuer + the same sub regex) to a new
`HTTPRoute` (`/native-asset` → `style-onnx-predictor`, prefix-rewritten) on the native
`maas-default-gateway` (ns `openshift-ingress`), plus a harness egress NetworkPolicy.
Manifests: `spiffe-auth/{15-native-asset-route-spiffe,16-egress-native-gateway-networkpolicy}.yaml`.
Proof from the e2e-harness pod (JWT-SVID only), via
`maas-default-gateway-data-science-gateway-class.openshift-ingress.svc`,
`Host: maas.apps.ocp-dev.na-launch.com`:
- `/native-asset/v2/health/ready` **no token → 401**
- `/native-asset/v2/models/style-onnx` **SVID → 200** — real OpenVINO metadata
  (`platform:OpenVINO`, FP32 `[1,3,224,224]`).

**Re-verified green after cutover (same run):** the istio SPIFFE matrix still holds
401 / 200 / 403 / 200 (the last with a freshly minted live `jit-approver` capability).

## Constraints on ocp-dev
- No GPU → serve a CPU model (real OVMS/ONNX above, or the mock) to prove auth;
  large-LLM (vLLM/GPU) serving is the hardware follow-up.
- `kube:admin` token TTL is short + API flaps (TLS timeouts) → every step must re-login + retry.
- Authorino must trust SPIRE-OIDC's serving cert → supply the ingress CA bundle (`oc -n openshift-config-managed get cm default-ingress-cert -o jsonpath='{.data.ca-bundle\.crt}'`).
