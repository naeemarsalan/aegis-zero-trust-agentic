# nvidia-ida — Zero-Trust Agentic AI Platform (PoC)

## Purpose

This repository is a proof-of-concept for a **zero-trust agentic AI platform** on OpenShift.
It wires together SPIFFE/SPIRE workload identity, Keycloak user federation, HashiCorp Vault
dynamic secrets, an agentgateway MCP gateway with custom `ext_proc` credential delegation,
Kyverno policy enforcement, Kata Containers isolation, and AAP EDA self-healing into a single
composable platform — deployed on the `anaeem` SNO cluster managed by ACM on `virt`.

Every AI agent pod receives a SPIFFE SVID at runtime; that identity flows through the MCP
gateway so downstream MCP servers always see the **user** identity, never the agent's service
account.  No credentials ever land in etcd, git, or agent containers.

---

## Use Cases

**UC-1 — pfSense Network Automation via MCP.**
An RHOAI-hosted agent uses the pfsense-mcp server (StreamableHTTP) through the agentgateway;
the gateway's `ext_proc` sidecar swaps the agent's SVID for a short-lived Vault-issued pfSense
API credential scoped to the requesting user's Keycloak identity before the call leaves the
cluster.

**UC-2 — EDA Self-Healing with JIT Approval.**
An AAP EDA rulebook detects an anomaly (GPU node pressure, network policy violation, etc.),
opens a Gitea pull request carrying a remediation patch, and waits; merging the PR triggers a
webhook that calls the `jit-approver` service which records the human decision in the audit log
and unblocks the EDA job template — full HITL loop with zero standing elevated access.

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────────────────────┐
 │  anaeem SNO cluster (OCP 4.20.11)                                        │
 │                                                                          │
 │  ┌─────────────┐  SVID  ┌──────────────────────────────────────────┐    │
 │  │  agent pod  │───────▶│  agentgateway  (ns mcp-gateway)          │    │
 │  │  (Kata)     │        │  ┌─────────────┐  ┌──────────────────┐  │    │
 │  │  ns:        │        │  │ ext_proc     │  │  jit-approver    │  │    │
 │  │  agent-sand │        │  │ delegation   │  │  (Gitea webhook) │  │    │
 │  │             │        │  └──────┬───────┘  └──────────────────┘  │    │
 │  └─────────────┘        │         │ Vault dyn cred                  │    │
 │                         └─────────┼────────────────────────────────┘    │
 │  ┌──────────────────┐             │                                      │
 │  │  SPIRE server    │◀── SVID ────┘                                      │
 │  │  (ns ztwim)      │                                                    │
 │  └──────────────────┘                                                    │
 │                                                                          │
 │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
 │  │  Keycloak    │  │  Vault       │  │  Kyverno     │                   │
 │  │  realm:      │  │  (raft SNO)  │  │  authz-srvr  │                   │
 │  │  agentic     │  │  ns vault    │  │  ns kyverno  │                   │
 │  └──────────────┘  └──────────────┘  └──────────────┘                   │
 │                                                                          │
 │  ┌──────────────────────────────────────────┐                           │
 │  │  agentic-mcp (Data Science Project)       │                           │
 │  │  pfsense-mcp:8000  (StreamableHTTP /mcp)  │                           │
 │  └──────────────────────────────────────────┘                           │
 │                                                                          │
 │  ┌──────────────────────────────────────────┐                           │
 │  │  agentic-observability                    │                           │
 │  │  OTel collector → Loki (172.16.2.252:3100)│                           │
 │  │  Grafana (172.16.2.252:3000)              │                           │
 │  └──────────────────────────────────────────┘                           │
 └──────────────────────────────────────────────────────────────────────────┘
          ▲ ArgoCD (virt hub)                  ▲ ACM policy sync
          │                                    │
 ┌────────┴──────────┐              ┌──────────┴──────────┐
 │  virt ACM hub     │              │  hammer cluster      │
 │  ArgoCD           │              │  AAP 2.6 EDA         │
 │  openshift-gitops │              │  Event Streams       │
 └───────────────────┘              └─────────────────────┘

External:
  Gitea 13  https://git.arsalan.io  (PR-merge = JIT approval channel)
  Registry  oci.arsalan.io/nvidia-ida/<name>:dev
```

---

## Repo Map

```
nvidia-ida/
├── environment/          # cluster inventory (clusters.yaml) + .env (gitignored)
├── docs/                 # design docs, ADRs, sequence diagrams
├── platform/             # Kustomize components: spire, keycloak, vault, kyverno, ...
│   └── <component>/
│       ├── base/
│       └── overlays/anaeem/
├── services/             # custom Go/Python services
│   ├── ext-proc-delegation/   # gRPC ext_proc credential swap (Go)
│   ├── jit-approver/          # Gitea webhook JIT approver (Go/Python)
│   └── pfsense-mcp/           # pfSense MCP server (Python, StreamableHTTP)
├── integrations/         # AAP EDA rulebooks, job templates, Gitea webhook config
├── usecases/             # end-to-end use-case manifests (UC-1, UC-2)
├── gitops/               # ArgoCD ApplicationSets + ACM GitOpsCluster registration
├── hack/                 # developer scripts (validate.sh, render.sh)
├── Makefile
├── .editorconfig
└── README.md
```

---

## Quickstart

```bash
# 1. Copy and fill in credentials (never commit .env)
cp environment/.env.example environment/.env
$EDITOR environment/.env

# 2. Validate all kustomize overlays and service code (no cluster needed)
make validate

# 3. Render overlays to rendered/ for manual inspection
make render

# 4. Bootstrap GitOps (run once from the virt hub with ArgoCD access)
#    This creates the ArgoCD ApplicationSet that drives all platform/ components.
#    See gitops/README.md for detailed steps.
kubectl apply -k gitops/overlays/virt/ --context virt-admin

# 5. Monitor rollout
watch argocd app list
```

---

## Identity Contract

| Attribute         | Value                                               |
|-------------------|-----------------------------------------------------|
| SPIFFE trust domain | `anaeem.na-launch.com` (immutable)               |
| SVID format       | `spiffe://anaeem.na-launch.com/ns/<ns>/sa/<sa>`     |
| OIDC issuer       | `https://spire-oidc.apps.anaeem.na-launch.com`      |
| Keycloak          | `https://keycloak.apps.anaeem.na-launch.com` realm `agentic` |
| Vault             | `https://vault.apps.anaeem.na-launch.com`           |
| MCP gateway       | `https://mcp-gateway.apps.anaeem.na-launch.com`     |

## Security Invariants

- Zero trust: all inter-service calls authenticated via SPIFFE SVID.
- No credentials in etcd, git, or agent pods — Vault Agent Injector on tmpfs only.
- Dynamic short-lived credentials for every external system.
- Fail-closed everywhere; default-deny NetworkPolicies in every namespace.
- Audit to Loki with tool arguments **sha256-hashed**, never raw.
- Downstream MCP servers see the **user** identity, never the agent identity.
- All AI agent pods run under Kata runtimeClass in `agent-sandbox`.

## Component Apply Order

1. `platform/spire` — workload identity foundation
2. `platform/keycloak` — user identity (depends on CNPG already present)
3. `platform/vault` — secrets engine (Vault ↔ SPIRE OIDC trust)
4. `platform/kyverno` — policy + authz server
5. `platform/mcp-gateway` — agentgateway + ext-proc-delegation + jit-approver
6. `platform/agentic-mcp` — demo MCP servers
7. `platform/agent-sandbox` — Kata agent namespace
8. `platform/agentic-observability` — OTel + alertmanager rules
9. `gitops/` — ArgoCD ApplicationSets (idempotent; safe to apply at any time)
