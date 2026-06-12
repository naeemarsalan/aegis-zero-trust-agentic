# Components

The platform is composed of one custom component and a set of vendor-supported components wired together. This page summarises each; click through to the per-component page for placement details, interfaces, verify commands, and maturity flags.

---

## At a glance

| Component | Cluster | Namespace | Custom? | Key role |
|---|---|---|---|---|
| [SPIRE / ZTWIM](spire.md) | anaeem | `zero-trust-workload-identity-manager` | No — ZTWIM operator | Workload identity root; SVID issuance; OIDC discovery |
| [Keycloak (RHBK)](keycloak.md) | anaeem | `keycloak` | No — RHBK operator | User identity; RFC 7523 + RFC 8693 token federation |
| [HashiCorp Vault](vault.md) | anaeem | `vault` | No — Helm chart | Per-tool secrets; Kubernetes secrets engine for JIT |
| [agentgateway](agentgateway.md) | anaeem | `mcp-gateway` | No — LF project | JWT authn, ext_authz, ext_proc gateway |
| [**ext-proc-delegation**](ext-proc-delegation.md) | anaeem | `mcp-gateway` | **Yes — Go** | Token exchange + secret fetch + header inject + strip |
| [jit-approver](jit-approver.md) | anaeem | `mcp-gateway` | Yes — Python | JIT PR orchestration + HMAC webhook + Vault issuance |
| [Kyverno](kyverno.md) | anaeem | `kyverno` | No — upstream Helm | Tool RBAC (ext_authz) + admission guardrails |
| [pfsense-mcp](pfsense-mcp.md) | anaeem | `agentic-mcp` | Yes — Python | Demo downstream MCP server; sees user identity |
| [Agent Sandbox (Kata)](agent-sandbox.md) | anaeem | `agent-sandbox` | No — OSC operator | Kata-isolated agent workload namespace |
| [Observability](observability.md) | anaeem | `agentic-observability` | No | OTel → Loki; AlertManager → EDA |
| [EDA / AAP](eda-aap.md) | hammer | (config-only) | No | Self-healing remediation loop |
| [Confidential Containers](confidential-containers.md) | (future) | — | No | Production TEE isolation target; not applied in PoC |

---

## Dependency order

The components must be available in this order; the ArgoCD sync waves enforce it automatically in the GitOps deployment.

```
wave 0 — OLM operators (ZTWIM, RHBK, CNPG, sandboxed-containers)
wave 1 — SPIRE / ZTWIM  ← identity root; everything depends on it
wave 2 — Keycloak + Vault  ← Vault needs SPIRE OIDC; Keycloak needs CNPG
wave 3 — Kyverno  ← needs to be running before any admission request
wave 4 — agentgateway + ext-proc-delegation + jit-approver
wave 5 — pfsense-mcp, agent-sandbox, observability, NetworkPolicies
```

---

## The one custom component

`ext-proc-delegation` is the only code the team owns. It is a single static Go binary running as an Envoy ext_proc filter sidecar next to agentgateway. Every other component is a vendor-supported product, operator, or well-established open-source project. This shapes the supportability argument for a regulated environment: one binary to audit, one binary to maintain.

See [ADR 0001](../decisions/0001-extproc-language-go.md) for the language choice rationale.
