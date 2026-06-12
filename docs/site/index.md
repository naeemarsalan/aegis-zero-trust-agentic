# nvidia-ida — Zero-Trust Agentic AI Platform

A proof-of-concept that proves AI agents can call downstream tools **on a user's behalf without ever holding a credential**, and can obtain **just-in-time, time-boxed elevated access** only after an explicit human approval — with every action attributable to an identity and an approval, and every grant auto-revoked by construction.

> **PoC status.** This platform runs end-to-end on a Single-Node OpenShift cluster (`anaeem`, OCP 4.20.11) managed by ACM GitOps from the `virt` hub. All design invariants are specified and provable; several sign-off gate items require the full deployment to close.

---

## What the platform proves

The two flows that define the PoC:

**UC1 — Delegated MCP tool call.** A Kata-isolated agent pod presents its SPIFFE JWT-SVID. The gateway authenticates it, Kyverno authorizes the specific tool, and the delegation service exchanges the agent identity for the user's federated token (scoped to the downstream MCP server's audience) plus a per-tool Vault secret — so `pfsense-mcp` sees the **user**, never the agent. No credential ever lands in the agent pod.

**UC2 — JIT sub-identity.** A denial triggers a scoped access request; the request becomes a Gitea pull request; a human merging the PR is the approval; an HMAC-verified webhook drives the approver to mint a **Vault-issued, lease-bound ephemeral Kubernetes identity** (SA + Role + RoleBinding, TTL = approval window). The agent acts as that identity; Kube audit attributes every call to it; Vault lease expiry deletes it automatically.

---

## Core invariants

| Invariant | Enforcement |
|---|---|
| No credential in etcd / git / agent pod | Vault Agent Injector → tmpfs only; delegation service holds creds in memory for one request |
| Downstream sees the user, not the agent | Keycloak RFC 8693 exchange inside `ext-proc-delegation`; agent SVID cleared before forwarding |
| Fail closed | ext_authz and ext_proc are required filters; any filter error → request denied, not allowed |
| Auto-revoke is structural, not procedural | Vault lease TTL deletes SA+Role+RoleBinding; no cron on the revocation path |
| Attribution everywhere | SPIFFE ID per workload, user identity downstream, `jit-<agent>-<session>` SA in Kube audit |
| Default-deny network | NetworkPolicy default-deny in every namespace; explicit allows only |

---

## Where to start

| You want to... | Go to |
|---|---|
| Understand the overall shape | [Platform overview](platform/index.md) |
| Read the component diagram | [Architecture](platform/architecture.md) |
| Follow a tool call step by step | [UC1 walkthrough](use-cases/uc1-credential-delegation.md) |
| Follow the JIT approval flow | [UC2 walkthrough](use-cases/uc2-jit-sub-identity.md) |
| Know what each component does | [Components](components/index.md) |
| Deploy or bootstrap | [GitOps & Deployment](deployment/gitops.md) |
| Understand the trust model | [Security Model](security/index.md) |
| See why decisions were made | [Architecture Decision Records](decisions/0001-extproc-language-go.md) |

---

## Project status

**Proof of concept.** The platform is deployed on a Single-Node OpenShift cluster. The identity core (SPIRE, Keycloak, Vault, Kyverno, agentgateway, ext-proc-delegation, jit-approver) is scaffolded and GitOps-managed from the `virt` ACM hub. Static guardrail proofs (Kata runtimeClass, default-deny NetworkPolicies, no SA-token automount) are verifiable now via `make validate`. Runtime sign-off items (pod-inspection, downstream-log assertion, Kube-audit attribution) close as each deployment phase completes.

See [SWOT & sign-off gate](platform/swot.md) for the full picture.
