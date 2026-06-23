# platform/vault

## What

HashiCorp Vault 0.32.0 deployed on the anaeem SNO cluster (namespace `vault`).
Provides:

- **KV-v2** secret store for MCP tool credentials (pfsense API key, etc.)
- **JWT auth** backed by the SPIRE OIDC issuer — platform components authenticate
  with their SPIFFE SVID JWTs; no static credentials anywhere.
- **Kubernetes secrets engine** for JIT-scoped short-lived service account tokens
  minted by the `jit-approver` on demand.
- **Vault Agent Injector** for platform components that need secrets mounted into
  pods via tmpfs (zero-trust: nothing in etcd).

## Why

Secrets never live in etcd, git, or agent pods.  Every credential is dynamic and
short-lived (15 min for platform auth tokens, 30 min–1 h for JIT Kubernetes tokens).
The SPIRE/SPIFFE identity chain is the only credential that enters a workload —
from that SVID, Vault issues a scoped token with the minimal policy for that role.

## Directory layout

```
platform/vault/
├── base/
│   ├── kustomization.yaml   # helmCharts generator (vault 0.32.0)
│   ├── values.yaml          # Helm values — SNO single-replica raft
│   ├── namespace.yaml       # vault Namespace
│   └── networkpolicy.yaml   # default-deny + allow rules
├── overlays/
│   └── anaeem/
│       └── kustomization.yaml   # anaeem-specific overlay (extends base)
├── config/
│   ├── vault-bootstrap.sh   # post-deploy declarative config script
│   ├── ext-proc.hcl         # policy: ext-proc-delegation read mcp-tools only
│   ├── jit-approver.hcl     # policy: jit-approver kubernetes/creds + read jit/*
│   └── agent-deny.hcl       # policy: explicit deny-all for agent identities
└── README.md
```

## Apply order

1. **Namespace + operators** — `platform/00-operators` must be applied first
   (no operator dependency for Vault itself, but the `vault` namespace is
   created by `base/namespace.yaml`).
2. **SPIRE** — `platform/spire` must be running and the OIDC issuer must be
   reachable at `https://spire-oidc.apps.ocp-dev.na-launch.com` before
   running vault-bootstrap.sh (JWT auth config pulls the JWKS from there).
3. **Deploy Vault:**
   ```bash
   kustomize build --enable-helm platform/vault/overlays/anaeem | oc apply -f -
   ```
4. **Init + unseal** — see section below.
5. **Bootstrap config:**
   ```bash
   source environment/.env          # PFSENSE_API_URL, PFSENSE_API_KEY, unseal keys
   export VAULT_ADDR=https://vault.apps.ocp-dev.na-launch.com
   export VAULT_TOKEN=<root-token>
   bash platform/vault/config/vault-bootstrap.sh
   ```

## Init / unseal procedure (PoC — manual)

```bash
# 1. Port-forward or use the Route
export VAULT_ADDR=https://vault.apps.ocp-dev.na-launch.com

# 2. Initialize (5 key shares, 3 threshold — adjust for PoC if desired)
vault operator init -key-shares=5 -key-threshold=3 \
  -format=json > /tmp/vault-init.json

# 3. Save the output into environment/.env (NEVER commit)
#    VAULT_UNSEAL_KEY_1=...
#    VAULT_UNSEAL_KEY_2=...
#    VAULT_UNSEAL_KEY_3=...
#    VAULT_ROOT_TOKEN=...

# 4. Unseal (repeat 3 times with different keys)
vault operator unseal $VAULT_UNSEAL_KEY_1
vault operator unseal $VAULT_UNSEAL_KEY_2
vault operator unseal $VAULT_UNSEAL_KEY_3

# 5. Confirm
vault status
```

After every pod restart Vault starts sealed — the operator must unseal manually
(or configure auto-unseal for production, see note below).

## Production HA note

This deployment uses `server.standalone.enabled: true` with a single raft node —
correct for SNO (one schedulable node).

For a 3-node production cluster:

```yaml
# values.yaml overrides for production
server:
  standalone:
    enabled: false
  ha:
    enabled: true
    replicas: 3
    raft:
      enabled: true
      setNodeId: true
```

Also set `podAntiAffinity` rules and configure auto-unseal (e.g. AWS KMS) so
that rolling restarts do not require manual operator intervention.

## Verify

```bash
# Vault status
vault status

# Auth engines
vault auth list

# Secrets engines
vault secrets list

# Policies
vault policy list
vault policy read ext-proc
vault policy read jit-approver
vault policy read agent-deny

# JWT roles
vault read auth/jwt/role/ext-proc-delegation
vault read auth/jwt/role/jit-approver

# Kubernetes roles — per-session ephemeral; list to confirm none are orphaned
vault list kubernetes/roles/

# KV secret (values hidden in output)
vault kv get secret/mcp-tools/pfsense

# Test Vault Agent Injector webhook
oc get mutatingwebhookconfiguration vault-agent-injector-cfg -n vault
```

## Kubernetes secrets engine — per-session ephemeral roles (H3)

The Kubernetes secrets engine issues short-lived SA tokens for approved JIT sessions.
There is **no static `jit-scoped` role**; every approved session gets its own ephemeral
Vault role with the exact namespace/verbs/resources from the reviewed `grants/<session>.yaml`.

### Issuance flow

1. Gitea PR is merged; jit-approver reads `grants/<session>.yaml` from the `main` branch
   (the reviewed artifact — C2 fix).
2. jit-approver calls `vault write kubernetes/roles/jit-<session-id>` with:
   - `allowed_kubernetes_namespaces` = approved namespace from the YAML
   - `generated_role_rules` = approved rules from the YAML (exact match what the reviewer saw)
   - `token_default_ttl` = approved duration from the YAML
   - `token_max_ttl` = `1h` (hard ceiling, not overridable by the approver)
3. jit-approver calls `vault read kubernetes/creds/jit-<session-id>` to mint the SA token.
4. Session transitions to `issued`; jit-approver mints the signed `X-JIT-Session-JWT` for
   Kyverno policy verification.

### Cleanup backstop

The Kyverno cleanup cronjob (`platform/kyverno/cleanup/`) deletes **both**:
- The K8s ServiceAccount + RoleBinding created by the lease (Vault TTL-based cleanup)
- The ephemeral Vault role: `vault delete kubernetes/roles/jit-<session-id>`

This ensures no orphaned roles accumulate after session expiry or on missed lease renewal.
Agents and platform components that did not create the role cannot delete it (policy scoped
to `jit-*` prefix; `jit-approver.hcl` grants `delete` capability only to the approver).

### Why per-session roles (not static)

The `kubernetes/creds/<role>` endpoint does **not** accept per-call `generated_role_rules`
overrides — that parameter is only honoured at role-creation time and is silently ignored
on cred-generation calls.  A static role always issues the static rules regardless of what
the reviewer approved.  Per-session roles make issued scope == reviewed scope.

## Security invariants

- Agents (in `agent-sandbox`, `agentic-mcp`) **never** talk to Vault directly.
  The `agent-deny` policy is assigned to their identity class as defence-in-depth.
- All credentials are dynamic and short-lived (15 min auth tokens, ≤1 h k8s tokens).
- Vault Agent Injector mounts secrets to `tmpfs` — nothing persists to disk or etcd.
- NetworkPolicy default-deny: only `mcp-gateway` namespace, the injector webhook,
  and the OpenShift Router may reach Vault pods.
- Audit log streams to `/vault/audit/vault_audit.log` (10 Gi PVC, `nfs-csi`).
  Tool arguments are **hashed (sha256)** by the calling platform component before
  any secret path is constructed — raw tool args never appear in Vault audit logs.
- JWT auth `default_role` is **not set** — every caller must name an explicit role.
  A missing role fails closed rather than falling through to a default policy.

## Notes on kustomize build

The base kustomization uses the `helmCharts` generator which requires the
`--enable-helm` flag:

```bash
kustomize build --enable-helm platform/vault/overlays/anaeem
```

`hack/validate.sh` passes `--enable-helm` for all kustomize build invocations
that contain helm chart references.  If you add this component to an ArgoCD
Application, set `spec.source.kustomize.enableHelm: true`.
