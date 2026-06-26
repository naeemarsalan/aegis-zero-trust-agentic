# PRD — Zero-Trust Agentic AI Platform (ocp-dev)

**Status:** Living document · last updated 2026-06-26 · cluster **ocp-dev** (OCP 4.20.25, 3 control-plane + 2 worker)
**One-liner:** An AI agent that holds **no stored credential — only a SPIFFE identity** — can *read/act as the human*,
can only *change anything (tools) or use premium models after a human approves it*, and uses that **same identity to
call AI models** (no model token). Tools and models share **one control plane**: identity to read, a human-approved
short-lived capability to elevate.

---

## 1. Problem & opportunity
Enterprises want AI agents that *act* on real systems, but the standard way to give software access is a stored
credential — unacceptable for a non-deterministic process in a regulated environment (credential sprawl, standing
privilege, attribution loss, procedural revocation, prompt-injection inheriting privilege). The platform makes the agent
have **nothing to steal** and makes elevation **impossible to forget to revoke**, for *both* tool calls and AI-model
calls — on a supported OpenShift stack.

## 2. Goals / non-goals
**Goals:** credential-less agent identity; delegated read; human-approved, short-lived, scoped write; the SVID as the
model credential; approve-to-elevate for premium models; a browser approval console (four-eyes) + webshell; native
RHOAI MaaS (AI Asset Endpoints) + Gen AI Studio with SPIFFE auth; one custom component, everything else supported;
GitOps-reproducible; tamper-evident audit.
**Non-goals (now):** multi-cluster/HA productionization; large-LLM serving without a GPU; replacing the model provider
(OpenRouter is the external backend); a polished end-user product UX beyond the PoC console.

## 3. Personas
- **AI agent** — holds only its SPIFFE SVID; reads/requests; reasons via the in-cluster MaaS brain.
- **Requesting engineer** — asks the agent in plain language.
- **Approver** — a *different* human; approves in the console UI (per-human SoD).
- **Security/compliance reviewer** — reads the WORM audit.
- **Platform team** — owns the GitOps deploy.

## 4. Architecture (summary)
One custom Go service (`ext-proc-delegation`) on the tool path; everything else supported: **SPIRE** (Red Hat ZTWIM),
**Keycloak** (RHBK), **Vault**, **Kyverno**, **OSSM/Istio**, **RHCL** (Kuadrant 1.x: Authorino + Limitador),
**OpenShift AI 3.4** (KServe + MaaS + Gen AI Studio), **OpenShift GitOps**. Tool plane: agent SVID → gateway →
Kyverno authz → ext-proc (identity swap + inject) → MCP tool. Model plane: agent SVID → Istio/MaaS gateway → Authorino
(validate JWT-SVID vs **SPIRE OIDC**, OPA authorize on the `spiffe://…/sandbox/<uuid>` sub) → KServe model / OpenRouter
(key injected server-side). Elevation (tool write, premium model) = a **jit-approver capability JWT** minted only after a
human approves in the console (approver ≠ requester). Detail: `docs/architecture.md`, `docs/design/maas-spiffe-auth.md`.

### Invariants (non-negotiable)
No credential in the agent (SVID only) · downstream sees the user (tools) / the SVID is the auth (models) · fail-closed
(any gate error = deny) · structural auto-revoke (short-lived capability + lease TTL; no cron) · attribution everywhere
(WORM) · approver ≠ requester · default-deny network.

---

## 5. Requirements & status

**Legend** — Status: ✅ Done · 🟡 Partial · 🔵 Roadmap.
**Verified (auto)** = proven by an automated e2e this build, with evidence. **Tested by you** = *your* personal
verification — I've left these **`— (please confirm)`** because the e2e proofs were automation-driven; tick the ones
you've validated yourself.

### 5a. Tool plane (zero-trust tool access)
| ID | Requirement | Status | Verified (auto) — evidence | Tested by you |
|----|-------------|:--:|----|:--:|
| T1 | Agent holds only a SPIFFE SVID (no stored secret) | ✅ | pod has no secret volumes; SVID-only calls | — (please confirm) |
| T2 | Delegated read — downstream sees the **user** | ✅ | pfSense `search_firewall_rules` → 200; ext-proc audit `caller_username=arsalan, credential_injected=true` | — (please confirm) |
| T3 | Write blocked by default (fail-closed) | ✅ | `create_firewall_rule` → 403 `grant_scope_denied` | — (please confirm) |
| T4 | Human approves to elevate; **approver ≠ requester** (SoD) | ✅ | mint → 200; self-approve → 403; per-human via Keycloak `approver-alice` | — (please confirm) |
| T5 | JIT short-lived scoped capability, auto-expires (write 5m single-use / exec 30m) | ✅ | capability JWT; elevated write → 200 (real rule id=52) | — (please confirm) |
| T6 | Browser **approval console** (mint-gate UI) | ✅ | `console.apps.ocp-dev…`; approve-via-UI → mint issued | — (please confirm) |
| T7 | Per-human SoD via Keycloak (oauth2-proxy) | ✅ | real OIDC login as `approver-alice`; approver_sub = real human | — (please confirm) |
| T8 | **Webshell** into the agent sandbox | ✅ | xterm.js-over-WebSocket PTY `oc exec` into the pod | — (please confirm) |
| T9 | Tamper-evident WORM audit / attribution | ✅ | CNPG WORM; jit-approver `jit_issued/jit_denied` audit | — (please confirm) |
| T10 | **Real per-user OBO** (downstream sees a real per-user Keycloak token, not the static-token fallback) | 🟡 | proven viable in isolated realm; **NOT applied** — PoC uses static-token fallback | — (please confirm) |

### 5b. Model plane (MaaS)
| ID | Requirement | Status | Verified (auto) — evidence | Tested by you |
|----|-------------|:--:|----|:--:|
| M1 | The **SVID is the model credential** (no model token) | ✅ | no-token → 401; SVID → 200 | — (please confirm) |
| M2 | OpenRouter models behind MaaS, key injected server-side (**LiteLLM cut**) | ✅ | `/openrouter`+SVID → 200 `claude-sonnet-4`; key in Vault, direct to openrouter.ai | — (please confirm) |
| M3 | In-cluster KServe model served (CPU) | ✅ | `style-onnx` (OVMS/OpenVINO) → 200 real inference (FP32 [1,3,224,224]) | — (please confirm) |
| M4 | Premium model = **approve-to-elevate** (JIT capability) | ✅ | `/premium` SVID-only → 403; +capability → 200 (`claude-opus-4`) | — (please confirm) |
| M5 | Agent **brain** calls models via MaaS (credential-less reasoning, default boot) | ✅ | agent reasoned "51" via MaaS proxy; `env` shows no model key; no-SVID → 401 | — (please confirm) |
| M6 | Native **RHOAI 3.4 AI Asset Endpoints** + **Gen AI Studio**, SPIFFE-authed | ✅ | `ModelsAsServiceReady=True`; `style-onnx` labeled `genai-asset`; native endpoint no-token 401 / SVID 200 | — (please confirm) |
| M7 | Large-LLM (vLLM) served in-cluster (kills external egress) | 🔵 | needs a **GPU** node | — |
| M8 | mTLS-SPIFFE for model calls (Istio⇄SPIRE X.509) | 🔵 | flavor-A hardening; flavor-B (JWT-SVID) is M1 | — |

### 5c. Platform / non-functional
| ID | Requirement | Status | Verified (auto) — evidence | Tested by you |
|----|-------------|:--:|----|:--:|
| P1 | Supported components only (one custom Go service) | ✅ | ZTWIM/SPIRE, RHBK, Vault, Kyverno, OSSM, RHCL, OpenShift AI 3.4, GitOps | — (please confirm) |
| P2 | GitOps-deployed / reproducible | 🟡 | app-of-apps + manifests committed (branch `fix/jit-approver-mint-route`); **some live/imperative; `main` diverged; secret bootstrap not fully automated** | — |
| P3 | Fail-closed everywhere | ✅ | both gates required; errors → deny | — (please confirm) |
| P4 | Structural auto-revoke (no cron) | ✅ | short-lived capability + Vault lease TTL | — (please confirm) |
| P5 | Control-plane stability | 🟡 | `mastersSchedulable=false` relieved saturation; **`master-1` currently `NotReady` — see §7 incident** | — |
| P6 | Vault config declarative (`vault-config-operator`) | 🔵 | bootstrap ran imperatively (task #4) | — |

---

## 6. Current deployment (ocp-dev)
RHOAI **3.4.1 GA** (fresh install; 2.25 removed). **RHCL v1.4.0** (community Kuadrant cut over). Native MaaS up
(`maas-api`, `ModelsAsServiceReady=True`). Gen AI Studio enabled. Our SPIFFE/Istio model plane + OpenRouter + premium
all live. Tool plane (SPIRE/Keycloak/Vault/Kyverno/ext-proc/jit-approver/console/webshell) live. Latest commit on
`fix/jit-approver-mint-route` (PR #54).

## 7. Known issues / incidents
- **🔴 INCIDENT (open): `master-1` is `NotReady` (`KubeletNotReady`)** → etcd 2/3 (quorum OK, fragile), API flapping,
  OAuth `server_error` + console Degraded (oauth-openshift rollout can't place its 3rd pod). **Not a config change** —
  a node failure. **Fix = recover the `ocp-dev-master-1` VM (reboot via hub).** Break-glass cert kubeconfig:
  `~/.kube/ocp-dev-admin.kubeconfig` (bypasses OAuth). Do **not** reboot another master until master-1 is back.
- master saturation (root of earlier flaps) — addressed via `mastersSchedulable=false`.

## 8. Roadmap (prioritized)
1. **Recover master-1** + durable control-plane health (etcd on the fragile master).
2. **Durability**: one GitOps source of truth (reconcile branch→main; RHCL/native-MaaS/console/brain into app-of-apps;
   sealed/external secrets) so a fresh cluster rebuilds everything (P2).
3. **Real per-user OBO** (T10) replacing the static-token fallback.
4. **GPU → in-cluster large-LLM** (M7) → point the brain at it (no external egress).
5. **mTLS-SPIFFE** model auth (M8); **`vault-config-operator`** (P6).
6. **Living-agent e2e demo** tying tools + models + console + brain into one continuous proof.

## 9. Acceptance / proof points (this build)
- Tool journey: read 200 → write 403 → console-approve (SoD) → write 200 (real pfSense rule). ✓ (auto)
- Model journey: no-token 401 → SVID 200 (OpenRouter + KServe) → premium SVID-only 403 → +capability 200. ✓ (auto)
- Brain reasons via MaaS with only its SVID, no model key. ✓ (auto)
- Native RHOAI 3.4 AI-Asset-Endpoint authenticates the SVID (401/200). ✓ (auto)
- **Your sign-off:** column "Tested by you" in §5 — to be completed by you.
