# nvidia-ida — Zero-Trust Agentic AI Platform (PoC)

> An AI agent that holds **no stored credential — only a SPIFFE identity**. It can *read as the
> human*, can only *change things or use premium models after a human approves*, and uses that
> **same identity to call AI models** (no model token). Tools and models share **one control
> plane**: identity to read, a human-approved short-lived capability to elevate.

This is a working proof-of-concept on OpenShift that makes an agent have **nothing to steal** and
makes privilege elevation **impossible to forget to revoke** — for *both* tool calls and AI-model
calls — using supported Red Hat components plus a single custom Go service.

---

## The idea in one picture

```
                          ┌───────────────────────── one identity ─────────────────────────┐
   AI agent  ──────────▶  │  SPIFFE JWT-SVID  (short-lived; the agent's ONLY credential)     │
 (no stored key)          └────────────┬───────────────────────────────┬────────────────────┘
                                       │ TOOL plane                     │ MODEL plane
                                       ▼                                ▼
                          agentgateway (MCP)                 Istio/MaaS gateway
                          → Kyverno authz                    → Authorino (validate SVID vs SPIRE-OIDC,
                          → ext-proc-delegation                 authorize the sandbox sub)
                            (verify SVID → Vault consent       → KServe model  /  OpenRouter
                             grant → swap to the USER →           (provider key injected server-side
                             inject downstream token)              from Vault — never in the agent)
                                       │                                │
                                       ▼                                ▼
                          real tool (pfSense, k8s)            real completion (Claude / OVMS)

   ELEVATION (a tool write, or a premium model) = a jit-approver capability JWT, minted ONLY after
   a DIFFERENT human approves in the console (approver ≠ requester), short-lived + single-use.
```

**Invariants (non-negotiable):** no credential in the agent (SVID only) · downstream sees the
*user* (tools) / the SVID *is* the auth (models) · fail-closed (any gate error = deny) · structural
auto-revoke (short-lived capability + Vault lease TTL — no cron) · attribution everywhere (WORM
audit ledger) · approver ≠ requester · default-deny network.

---

## What's proven (PoC, cluster `ocp-dev`)

**Tool plane (zero-trust tool access)** — the agent does the real pfSense journey:
`read → 200` (delegated as the human) → `write → 403` (fail-closed) → **human approves in the
console** (four-eyes, SoD) → `elevated write → 200` (real firewall rule). Audited to a
tamper-evident hash-chain WORM ledger (CNPG postgres; the ledger is append-only at the DB
privilege level).

**Model plane (MaaS)** — the SVID *is* the model credential: `no-token → 401`, `SVID → 200`
(real completion). OpenRouter (frontier Claude) and an in-cluster KServe model are both registered
as **native OpenShift AI Gen AI Studio assets**, SVID-authed, with **no model key stored anywhere**
(injected server-side from Vault). Premium models fold into the *same* approve-to-elevate flow.
A living agent's **brain reasons through the model plane with only its SVID**, and an
OpenShell-namespaced sandbox identity was verified consuming OpenShift AI models SVID-only.

See **[`docs/PRD.md`](docs/PRD.md)** for the requirement-by-requirement status (Done / Partial /
Roadmap, with live evidence) and **[`docs/demo/genai-studio-spiffe-zerotrust-runbook.md`](docs/demo/genai-studio-spiffe-zerotrust-runbook.md)**
for the step-by-step demo.

---

## Architecture

One custom component (**`ext-proc-delegation`**, Go) on the tool path; everything else is supported
product:

| Concern | Component |
|---|---|
| Workload identity | **SPIRE** (Red Hat Zero-Trust Workload Identity Manager) — issues the agent's JWT-SVID + OIDC discovery |
| User identity / OBO | **Keycloak** (RHBK) |
| Secrets / dynamic creds | **HashiCorp Vault** (consent grants, downstream tokens, JIT credential issuance) |
| Policy / admission | **Kyverno** (gateway authz, sandbox confinement) |
| Service mesh / gateway | **OSSM / Istio** (model plane) + **agentgateway** (tool plane MCP) |
| API auth / rate-limit | **RHCL** (Kuadrant 1.x: Authorino + Limitador) |
| Model serving / MaaS | **OpenShift AI 3.4** (KServe + Models-as-a-Service + Gen AI Studio) |
| Identity swap + inject | **ext-proc-delegation** (the one custom Go service) |
| Human approval (JIT) | **jit-approver** + **approval-console** (browser four-eyes mint-gate, SoD, WORM audit) |
| GitOps | **OpenShift GitOps** (ArgoCD) — app-of-apps under `gitops/` |

Deeper reading: **[`docs/architecture.md`](docs/architecture.md)**,
**[`docs/design/maas-spiffe-auth.md`](docs/design/maas-spiffe-auth.md)**, and the ADRs in
**[`docs/adr/`](docs/adr/)**.

---

## Repository layout

```
platform/      Kustomize/Helm manifests for every supported component (SPIRE, Vault, Keycloak,
               Kyverno, RHCL, OpenShift AI / MaaS, jit-approver-db, the Gen AI Studio overlay, …)
services/      Source for the custom services + agent harness:
                 ext-proc-delegation/   the one custom Go service (SVID → user identity swap)
                 jit-approver/          human-approved JIT capability minting + WORM audit ledger
                 approval-console/      browser four-eyes console + webshell
                 sandbox-launcher/      launches credential-less OpenShell agent sandboxes
                 agent-sandbox/         the agent-harness image (brain + svid_bearer + mcp-call)
                 pfsense-mcp-server/    the demo MCP tool server
                 showroom/              the Antora docs site
gitops/        ArgoCD app-of-apps (self-managed, in-cluster destination)
docs/          PRD, architecture, design docs, ADRs, the demo runbook, the showroom source
hack/          deterministic e2e regression anchors (e.g. test-pfsense-jit-ocp-dev.sh)
environment/   cluster config (real secrets are git-ignored — see below)
```

---

## Status & honesty

This is a **PoC**, not production. The core zero-trust loops (tool + model) are proven end-to-end on
`ocp-dev`. Known open seams are tracked transparently in `docs/PRD.md §5/§7/§8` — e.g. real per-user
OBO (static-token fallback today), GPU-served large LLMs (CPU/OpenRouter today), one GitOps source of
truth, and a hub-side reconciler that currently re-pins one Vault address. Where a requirement is
"proven by automation" vs "tested by you," the PRD says so.

## Security note (read before changing visibility)

- **No secrets are committed.** `environment/.env.ocp-dev` (Vault root token + unseal keys),
  `*kubeconfig*`, `*.pem`, `*.key`, and `*.env` are git-ignored; only `*.example` templates are tracked.
- The manifests reference a homelab cluster (internal hostnames/IPs). Review before publishing widely.
- The platform's whole point is that **the agent stores nothing** — its only credential is a
  short-lived SPIFFE SVID, and every elevation is human-approved, scoped, and auto-expiring.

## Install

**→ [`docs/install-guide.md`](docs/install-guide.md)** — the detailed, step-by-step install guide
(prerequisites → node/storage prep → GitOps app-of-apps → Vault/Keycloak secret bootstrap → model plane
→ verify), including every known gotcha. GitOps-first (the app-of-apps under `gitops/` reconciles the
supported components) with a few imperative secret-bootstrap steps; the deterministic anchor
`hack/test-pfsense-jit-ocp-dev.sh` proves the tool journey once the substrate is up.

---

*Built with [Claude Code](https://claude.com/claude-code).*
