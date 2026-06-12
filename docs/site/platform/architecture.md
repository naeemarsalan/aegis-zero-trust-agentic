# Architecture

## High-level component diagram

The diagram below shows every component, which cluster it runs on, and the primary communication paths.

```mermaid
flowchart TB
  subgraph anaeem["anaeem — SNO platform target (OCP 4.20.11)"]
    direction TB

    subgraph sandbox["ns: agent-sandbox (Kata runtimeClass)"]
      AGENT["agent pod\nJWT-SVID via SPIRE Workload API\nno SA-token automount"]
    end

    subgraph ztwim["ns: zero-trust-workload-identity-manager"]
      SPIRE["SPIRE server + agent\ntrust domain anaeem.na-launch.com"]
      OIDC["SPIRE OIDC discovery\nspire-oidc.apps.anaeem.na-launch.com"]
    end

    subgraph gw["ns: mcp-gateway"]
      AGW["agentgateway\nJWT authn (Keycloak JWKS)"]
      EXTPROC["ext-proc-delegation (Go)\n:9000 gRPC\nTHE custom component"]
      JIT["jit-approver\n:8080 HTTP"]
    end

    subgraph kv["ns: kyverno"]
      KAUTHZ["kyverno-authz-server\n:9081 gRPC ext_authz\ntool RBAC (Envoy ValidatingPolicy)"]
      KADM["Kyverno admission\nguardrails + cleanup backstop"]
    end

    subgraph kc["ns: keycloak"]
      KEYCLOAK["RHBK (realm: agentic)\nRFC 7523 jwt-bearer + RFC 8693 exchange\nfederated user tokens"]
      CNPG[("CNPG Postgres")]
    end

    subgraph vlt["ns: vault"]
      VAULT["Vault (raft, single-replica SNO)\nauth/jwt ↔ SPIRE OIDC\nkv per-tool secrets\nkubernetes engine: creds/jit-scoped"]
      INJ["Vault Agent Injector\ntmpfs delivery"]
    end

    subgraph mcp["ns: agentic-mcp (Data Science Project)"]
      PFSENSE["pfsense-mcp :8000\nStreamableHTTP /mcp\nsees USER identity"]
    end

    subgraph obs["ns: agentic-observability"]
      OTEL["OTel collector"]
      AMRULES["UWM AlertManager denial rule"]
    end
  end

  subgraph virt["virt — ACM hub (OCP 4.19.19)"]
    ARGO["ArgoCD openshift-gitops\napp-of-apps drives platform/"]
    ACM["ACM 2.14 GitOpsCluster"]
  end

  subgraph hammer["hammer — AAP host (OCP 4.20.x)"]
    AAP["AAP 2.6 gateway\nEDA + Event Streams (HMAC)\njob templates"]
  end

  GITEA["Gitea 13 — git.arsalan.io\nrepo anaeem/nvidia-ida\nPR-merge = JIT approval"]
  LOKI["Loki push 172.16.2.252:3100\nGrafana 172.16.2.252:3000"]

  AGENT -->|"JWT-SVID + MCP JSON-RPC"| AGW
  SPIRE --- OIDC
  AGENT -.->|Workload API| SPIRE
  AGW -->|ext_authz allow/deny| KAUTHZ
  AGW -->|ext_proc mutate| EXTPROC
  EXTPROC -->|"RFC 7523 then RFC 8693"| KEYCLOAK
  EXTPROC -->|"JWT-SVID login + per-tool secret"| VAULT
  EXTPROC -->|"inject Authorization (user token)"| PFSENSE
  KEYCLOAK --- CNPG
  VAULT -.->|OIDC trust| OIDC
  INJ -.->|tmpfs| EXTPROC
  EXTPROC -->|audit args-hashed + OTel| OTEL
  PFSENSE -->|denial metric| AMRULES
  AMRULES -->|webhook HMAC| AAP
  AAP -->|remediation PR| GITEA
  JIT -->|open PR| GITEA
  GITEA -->|merge webhook HMAC| JIT
  JIT -->|creds/jit-scoped| VAULT
  OTEL --> LOKI
  ARGO -->|GitOps| anaeem
  ACM --- ARGO
  ARGO -.->|source| GITEA
```

---

## Design rationale

### One custom component

The entire credential-delegation critical path rides on a single custom Go binary (`ext-proc-delegation`). Everything else — SPIRE, Keycloak, Vault, agentgateway, Kyverno, Kata — is a vendor-supported component. This is the core supportability argument for a regulated environment: one binary to audit, one binary to maintain.

### extAuthz / extProc split (ADR 0004)

Authorization (allow/deny) and mutation (credential injection) are handled by **separate** filters in the gateway pipeline, enforced in a fixed order:

1. **Kyverno ext_authz** decides allow/deny — it cannot mutate.
2. **ext-proc-delegation** mutates headers — it cannot grant access.

This means a bug in the mutation layer cannot become an access-granting path, and a Kyverno DENY short-circuits before any credential is minted.

### Fail closed everywhere

Both filters are marked **required**. An unreachable or erroring filter produces a `503` to the agent, never a pass-through. Vault Agent Injector blocking an init container means the workload never starts without valid credentials.

### Structural auto-revoke

JIT grants are Vault lease objects. When the lease TTL expires, Vault deletes the SA, Role, and RoleBinding — the token becomes invalid and the identity disappears. There is no cron, reconciler, or human step in the revocation path. Kyverno cleanup is a backstop for orphaned leases only.

---

## Namespace map

| Namespace | Components | NetworkPolicy posture |
|---|---|---|
| `zero-trust-workload-identity-manager` | SPIRE server, SPIRE agent, SPIFFE CSI Driver, OIDC discovery | Default deny; SPIRE agent egress to server:8081; OIDC Route ingress from router |
| `keycloak` | RHBK, CNPG Postgres | Default deny; ingress 8443 from router; egress CNPG:5432, SPIRE OIDC:443 |
| `vault` | Vault (raft), Vault Agent Injector | Default deny; ingress 8200 from `mcp-gateway`, `keycloak`, `agentic-mcp`, `agent-sandbox`; Route ingress for CLI |
| `kyverno` | Kyverno admission, kyverno-authz-server | Default deny; ingress 9081 from `mcp-gateway`; admission webhook from API server |
| `mcp-gateway` | agentgateway, ext-proc-delegation, jit-approver | Default deny; ingress 443 from router; ext-proc:9000 from agentgateway; jit:8080 from ext-proc; webhook Route for Gitea |
| `agentic-mcp` | pfsense-mcp | Default deny; ingress 8000 from `mcp-gateway` only |
| `agent-sandbox` | agent pods (Kata) | Default deny; egress to `mcp-gateway.apps.anaeem.na-launch.com:443` only |
| `agentic-observability` | OTel collector, AlertManager | Default deny; ingress OTLP from platform namespaces; egress to Loki:3100, EDA:443 |

---

## Cross-references

- [UC1 sequence diagram](../use-cases/uc1-credential-delegation.md) — delegated tool call, step by step
- [UC2 sequence diagram](../use-cases/uc2-jit-sub-identity.md) — JIT approval flow, step by step
- [Security model & trust boundaries](../security/index.md) — STRIDE per hop
- [Component pages](../components/index.md) — per-component placement, interfaces, and verify commands
