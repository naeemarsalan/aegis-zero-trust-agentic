# Architecture — Zero-Trust Agentic AI Platform (ocp-dev)

> Current as of 2026-06-26. Product requirements + status: [`docs/PRD.md`](PRD.md).
> Model-plane deep dive: [`docs/design/maas-spiffe-auth.md`](design/maas-spiffe-auth.md).
> Demo walkthrough: [`docs/demo/zero-trust-platform-demo.md`](demo/zero-trust-platform-demo.md).

## 1. System overview
An AI agent holds **no stored credential — only a SPIFFE SVID**. It can **read/act as the human** it works for, can
only **change anything (tools) or use premium models after a human approves it**, and uses **that same identity to call
AI models** (no model token). Tools and models share **one control plane**: identity to read, a human-approved
short-lived capability to elevate. Exactly **one** custom component (`ext-proc-delegation`, Go) sits on the tool path;
everything else is a supported product — the core supportability argument for a regulated context.

## 2. The two planes

### Tool plane (read delegated / write approved)
```
agent (JWT-SVID only) → gateway → Kyverno authz (allow/deny) → ext-proc-delegation
   → swap agent identity for the USER (Keycloak; static-token fallback today, real OBO viable)
   → inject downstream secret from Vault (in-memory, one request)
   → MCP tool (pfSense / k8s) sees the USER, not the agent
```
A **write** is denied (403) until a human approves in the **approval console** (mint-gate, **approver ≠ requester**,
Keycloak-authenticated). Approval mints a **short-lived, scoped capability JWT** (write = 5 min single-use; exec = 30 min)
that the agent then wields; it auto-expires (no cron). Every step is WORM-audited.

### Model plane (MaaS — the SVID is the credential)
```
agent (JWT-SVID only) → Istio / data-science gateway → Authorino (RHCL/Kuadrant)
   → authN: JWT, issuer = SPIRE OIDC (ingress CA trusted)
   → authZ: OPA — sub matches ^spiffe://anaeem.na-launch.com/ns/(openshell|agent-sandbox)/sandbox/.+$
   → HTTPRoute → model:
        • in-cluster KServe (OVMS/OpenVINO style-onnx, CPU)
        • OpenRouter (key injected server-side from Vault; LiteLLM removed)
```
**Premium** models require the SVID **and** a JIT capability (the same mint-gate as tool writes) — *approve-to-elevate*
for models. The agent's **brain** also reasons through this plane (a loopback SVID-injecting proxy), so even the LLM call
is credential-less. Models are published as **AI Asset Endpoints** (label `opendatahub.io/genai-asset=true`) and surface
in **Gen AI Studio** (RHOAI 3.4).

The model plane also registers as **native OpenShift AI Gen AI Studio assets**, with the SVID still the only credential:
- **AI Asset Endpoints page** — OpenRouter (Claude Sonnet 4) via ConfigMap `gen-ai-aa-custom-model-endpoints` in the
  `maas` project (labeled `opendatahub.io/dashboard=true`). Its `api_key.secretRef` is left **empty** — no stored model
  key; the SVID is the credential.
- **MCP Servers tab** — the MCP gateway (real tools) via ConfigMap `gen-ai-aa-mcp-servers` in `redhat-ods-applications`
  (the dashboard namespace) + an all-users reader RBAC.

The registered OpenRouter asset is made **SVID-callable** by the standalone **openrouter-bridge** (ns `maas`): it reuses
the agent-harness image, carries its **own SA-shaped SVID** (`…/ns/maas/sa/openrouter-bridge`), and per request fetches
a fresh SVID and forwards `/v1/*` → the MaaS model gateway, where Authorino validates it. An **OPA equality branch** on
`AuthPolicy maas-spiffe-auth` (exact-match, alongside the sandbox-regex branch) admits the bridge's SVID. The OpenRouter
key stays in Vault, injected server-side — it never reaches the bridge (proven: bridge → gateway = HTTP 200 real
completion; 403 fail-closed before the OPA edit).

## 3. Components (current)
| Layer | Component | Role |
|---|---|---|
| Workload identity | **SPIRE / Red Hat ZTWIM** | issues JWT-SVIDs; OIDC discovery (trusted by Vault, Keycloak, Authorino) |
| Federated identity | **Keycloak / RHBK** | token exchange (tools); OIDC for the console (per-human SoD) |
| Secrets | **Vault** | per-agent consent grants, per-tool secrets, OpenRouter key, JIT signing key; Agent Injector |
| Tool authz | **Kyverno** | per-tool allow/deny (ext_authz) |
| Tool delegation | **ext-proc-delegation** (custom Go) | identity swap + downstream secret inject (the one custom component) |
| JIT / approval | **jit-approver** + **approval-console** | capability minting; browser mint-gate UI (four-eyes) + webshell |
| Mesh / gateway | **OSSM / Istio**, **data-science-gateway** | Gateway API data planes |
| AI authn/z + rate-limit | **RHCL** (Kuadrant 1.x: Authorino + Limitador) | SPIFFE JWT validation, OPA authz, token-rate limits |
| Model serving / MaaS | **OpenShift AI 3.4** (KServe, modelsAsService, Gen AI Studio) | serves models; native AI Asset Endpoints + MCP Servers tab |
| Model SVID bridge | **openrouter-bridge** (reuses agent-harness image; own SA SVID) | makes the registered OpenRouter asset SVID-callable (fresh-SVID forward → MaaS gateway) |
| External model | **OpenRouter** (direct) | external LLM backend; key stays server-side |
| GitOps | **OpenShift GitOps** (ArgoCD) | app-of-apps deploy |
| Runtime | **OpenShell** sandbox (Kata/CoCo = hardening roadmap) | per-agent sandbox; SVID via SPIRE Workload API |

## 4. Design invariants (non-negotiable)
- **No credential in the agent** — only its SVID (auto-rotating).
- **Identity is the auth** — downstream tools see the user; models authenticate the SVID directly. No model token.
- **Fail closed** — any gate (Kyverno, ext-proc, Authorino) error → deny, never pass-through.
- **Elevation = human-approved, short-lived capability** — for tool writes *and* premium models; **approver ≠ requester**.
- **Structural auto-revoke** — short-lived capability + Vault lease TTL; no cron in the revoke path.
- **Attribution everywhere** — WORM audit: who requested, who approved, scope, TTL, single-use jti.
- **Default-deny network** — explicit allows only.

## 5. Deployment & status
Live on **ocp-dev** (OCP 4.20.25, 3 control-plane + 2 worker). RHOAI **3.4.1 GA**, **RHCL v1.4.0**. See
[`docs/PRD.md`](PRD.md) §5 for the requirement-by-requirement status (Done / Partial / Roadmap + verification) and §7
for open incidents (currently: `master-1` NotReady).

## 6. History / decisions
Decision records: [`docs/decisions/`](decisions/) (0001–0007) and [`docs/adr/`](adr/) (0008–0018). The Gitea-PR approval
gate (ADR 0005) was **superseded** by the console mint-gate (decision 0007). Canonical Phase-A worklog:
[`docs/reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md`](reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md).
