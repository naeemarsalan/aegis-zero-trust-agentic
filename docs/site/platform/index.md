# Platform Overview

The nvidia-ida platform is a **zero-trust agentic AI platform** built on OpenShift. It wires together SPIFFE/SPIRE workload identity, Keycloak user federation, HashiCorp Vault dynamic secrets, an agentgateway MCP gateway with custom `ext_proc` credential delegation, Kyverno policy enforcement, and Kata Containers isolation into a single composable PoC.

The central claim: an AI agent can call any downstream tool **on a user's behalf** — with the downstream service seeing the user's identity, not the agent's — and can escalate to privileged actions **only after a human approves**, with the elevated access auto-revoking when the approval window closes.

This is achieved with **exactly one piece of custom code** (`ext-proc-delegation`) wired into a vendor-supported stack, making it a supportable pattern for a regulated context.

---

## The stack at a glance

```
 virt ACM hub (OCP 4.19.19)
 ├── ArgoCD openshift-gitops  ← GitOps source of truth
 └── ACM GitOpsCluster        ← injects anaeem cluster into ArgoCD
              │  GitOps sync (app-of-apps, sync waves)
              ▼
 anaeem SNO (OCP 4.20.11)  ←  the platform target
 ├── SPIRE / ZTWIM              workload identity (trust domain: anaeem.na-launch.com)
 ├── Keycloak (RHBK)            user identity, RFC 7523 + RFC 8693 token exchange
 ├── Vault (raft)               secrets engine + Kubernetes secrets engine for JIT
 ├── Kyverno + authz server     policy enforcement (admission + ext_authz)
 ├── agentgateway               MCP protocol gateway (JWT authn, ext_authz, ext_proc)
 │   ├── ext-proc-delegation    THE custom component — credential swap (Go)
 │   └── jit-approver           JIT approval gate + Gitea PR orchestration
 ├── pfsense-mcp                demo downstream MCP server
 ├── agent-sandbox (Kata)       isolated agent workload namespace
 └── agentic-observability      OTel → Loki, Alertmanager → EDA

 hammer (AAP 2.6)               EDA remediation loop (config-only)
 git.arsalan.io (Gitea 13)      GitOps source + JIT approval channel
 172.16.2.252                   external Loki + Grafana (existing infra)
```

---

## The two design invariants that everything else serves

### 1. No credential passing

At no point does an agent pod hold a credential for a downstream service. The `ext-proc-delegation` service fetches credentials from Vault into memory for the duration of a single request, injects them into the forwarded request, and discards them. The agent's response has credential headers stripped. This is verifiable by pod inspection and response cred-echo tests.

### 2. Fail closed

Both the authorization filter (Kyverno ext_authz) and the mutation filter (ext_proc) are **required**. If either is unreachable or errors, the request is denied — not allowed. There is no "degrade gracefully" path on the credential-handling chain.

---

## Deployment topology

| Property | Value |
|---|---|
| Platform target | `anaeem` — Single-Node OpenShift (OCP 4.20.11) |
| API server | `https://api.anaeem.na-launch.com:6443` |
| Apps wildcard | `*.apps.anaeem.na-launch.com` |
| GitOps hub | `virt` — OCP 4.19.19, ArgoCD `openshift-gitops` + ACM 2.14 |
| AAP | `hammer` — OCP 4.20.x, AAP 2.6 gateway |
| Trust domain | `anaeem.na-launch.com` (immutable) |
| Container registry | `oci.arsalan.io/nvidia-ida/<name>:dev` |
| Loki push | `http://172.16.2.252:3100` |
| Grafana | `http://172.16.2.252:3000` |

### Key routes on `anaeem`

| Component | URL |
|---|---|
| MCP gateway | `https://mcp-gateway.apps.anaeem.na-launch.com` |
| Keycloak | `https://keycloak.apps.anaeem.na-launch.com` (realm `agentic`) |
| Vault | `https://vault.apps.anaeem.na-launch.com` |
| SPIRE OIDC | `https://spire-oidc.apps.anaeem.na-launch.com` |

---

## Component summary

| Component | Namespace | Custom? | Role |
|---|---|---|---|
| SPIRE server + agent + OIDC | `zero-trust-workload-identity-manager` | No (ZTWIM operator) | Issues SPIFFE SVIDs; OIDC trust for Vault/Keycloak |
| Keycloak RHBK + CNPG | `keycloak` | No | RFC 7523 + RFC 8693 user token federation |
| Vault (raft, single-replica) | `vault` | No (Helm) | Per-tool secrets; Kubernetes engine for JIT |
| agentgateway | `mcp-gateway` | No (LF project) | JWT authn, extAuthz, extProc chain |
| **ext-proc-delegation** | `mcp-gateway` | **Yes — Go** | Token exchange + secret fetch + inject + strip |
| jit-approver | `mcp-gateway` | Yes — Python | PR open + webhook verify + Vault creds issuance |
| Kyverno + authz server | `kyverno` | No | Tool RBAC allow/deny; cleanup backstop |
| pfsense-mcp | `agentic-mcp` | Yes — Python | Demo downstream MCP server |
| agent-sandbox | `agent-sandbox` | No (Kata) | Kata-isolated agent workload namespace |
| OTel collector + AlertManager | `agentic-observability` | No | Audit to Loki; denial → EDA trigger |

---

## Next steps

- [Architecture diagram](architecture.md) — see all components and their connections
- [UC1 walkthrough](../use-cases/uc1-credential-delegation.md) — trace a tool call end to end
- [UC2 walkthrough](../use-cases/uc2-jit-sub-identity.md) — trace the JIT approval flow
- [Security model](../security/index.md) — trust boundaries and STRIDE analysis
