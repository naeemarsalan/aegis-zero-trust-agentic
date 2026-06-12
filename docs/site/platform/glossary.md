# Glossary

| Term | Definition |
|---|---|
| **agentgateway** | The MCP-protocol-aware ingress gateway. Routes agent MCP calls through authentication, authorization (ext_authz), and credential mutation (ext_proc) before proxying to downstream MCP servers. |
| **CNPG** | CloudNativePG — the Kubernetes operator for PostgreSQL used as the Keycloak backing store. |
| **CoCo** | Confidential Containers — an extension of Kata Containers that adds hardware TEE attestation (Intel TDX or AMD SEV-SNP). Production target; not applied in the PoC. |
| **EDA** | Event-Driven Ansible — the reactive automation engine in AAP 2.6. Listens to alert events and triggers remediation job templates. |
| **ext_authz** | Envoy External Authorization — a required filter that makes an allow/deny decision for each request before it proceeds. In this platform, Kyverno is the ext_authz server. |
| **ext_proc** | Envoy External Processing — a required filter that can read and mutate request/response headers and body. In this platform, `ext-proc-delegation` is the ext_proc service. |
| **Fail closed** | The behavior where a system denies a request (rather than allowing it) when a required check fails, errors, or times out. All critical filters in this platform are configured fail-closed. |
| **HITL** | Human-in-the-loop — requiring explicit human approval before a privileged action proceeds. In this platform, the HITL gate is a Gitea PR merge. |
| **JIT** | Just-in-time — access granted only for the duration it is needed, only after approval, and automatically revoked when the window closes. |
| **jit-approver** | The Python service that orchestrates the UC2 JIT approval flow: opens a Gitea PR, verifies the merge webhook, calls Vault to mint the ephemeral identity, and delivers credentials to the agent. |
| **Kata Containers** | A container runtime that runs each pod inside a lightweight KVM micro-VM, isolating it from the host kernel. Used in `agent-sandbox` via the `kata-qemu` runtime class. |
| **Keycloak / RHBK** | Red Hat Build of Keycloak — the OIDC/OAuth2 identity broker for the `agentic` realm. Issues user tokens; supports RFC 7523 and RFC 8693. |
| **KBS** | Key Broker Service — the Trustee component that performs remote attestation in the Confidential Containers architecture. |
| **MCP** | Model Context Protocol — the JSON-RPC protocol over StreamableHTTP used for agent ↔ tool communication. |
| **RHOAI** | Red Hat OpenShift AI — the AI/ML platform. In this PoC, it provides the `agentic-mcp` Data Science Project namespace. |
| **RFC 7523** | JWT Bearer Token Grant for OAuth 2.0 — allows exchanging an externally-issued JWT (the SPIFFE SVID) for an OAuth2 token. Used as leg 1 of the UC1 token exchange; currently a preview feature in RHBK. |
| **RFC 8693** | OAuth 2.0 Token Exchange — allows exchanging one access token for another scoped to a different audience. Used as leg 2 of the UC1 token exchange to scope the token to the downstream MCP server. |
| **SNO** | Single-Node OpenShift — an OpenShift cluster deployed on a single node. `anaeem` is an SNO cluster. |
| **SPIFFE** | Secure Production Identity Framework for Everyone — the open standard for workload identity. SPIFFE identities are URIs (`spiffe://trust-domain/path`). |
| **SPIRE** | SPIFFE Runtime Environment — the reference implementation of SPIFFE. Issues SVIDs and provides an OIDC discovery endpoint. Deployed via the ZTWIM operator. |
| **SVID** | SPIFFE Verifiable Identity Document — a cryptographic credential (X.509 cert or JWT) that asserts a workload's SPIFFE identity. SVIDs are short-lived and automatically rotated. |
| **TEE** | Trusted Execution Environment — a hardware-isolated execution context (Intel TDX, AMD SEV-SNP) where memory is encrypted and the execution cannot be inspected by the hypervisor. |
| **tmpfs** | A filesystem that lives entirely in memory. Used in this platform for secret delivery (Vault Agent Injector writes secrets to tmpfs mounts; the secrets vanish when the pod dies). |
| **Vault** | HashiCorp Vault — the secrets engine. Stores and dynamically generates credentials; runs the Kubernetes secrets engine for JIT identity minting. |
| **ZTWIM** | Zero Trust Workload Identity Manager — Red Hat's operator for deploying and managing SPIRE on OpenShift. Channel `stable-v1` is GA on OCP 4.20. |
