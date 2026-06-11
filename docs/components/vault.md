## Purpose

HashiCorp Vault is the secrets backbone for the platform. It stores and dynamically generates credentials (database passwords, API keys, PKI certificates) so that no long-lived secret ever resides in etcd, git, or a pod's environment variables. Vault also acts as the policy enforcement point for secret access: workloads authenticate via their SPIFFE JWT SVID, and Vault policies map SPIFFE IDs to narrowly-scoped secret paths.

## Exists or create

CREATE on anaeem. Deploy via the official HashiCorp Vault Helm chart (version 0.32.0) in namespace `vault`. SNO topology mandates **single-replica Raft** — HA multi-replica is documented for production scale-out but not applied in this PoC. Auto-unseal via an OCP Secret holding the unseal keys is acceptable for PoC; for production, use Vault's native Transit auto-unseal or an HSM-backed KMS.

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11)
- Namespace: `vault`
- Route: `https://vault.apps.anaeem.na-launch.com` (OCP Route, TLS re-encrypt)
- Raft storage PVC: `storageClassName: nfs-csi`, single replica, 10Gi minimum
- No additional DNS changes needed

## Security posture

- SPIFFE ID: `spiffe://anaeem.na-launch.com/ns/vault/sa/vault` (Vault pod's own identity for transit/seal operations)
- Workload authentication: `jwt` auth mount pointed at `https://spire-oidc.apps.anaeem.na-launch.com` — workloads present their SPIFFE JWT SVID; Vault validates the JWKS and maps the `sub` claim (`spiffe://anaeem.na-launch.com/ns/<ns>/sa/<sa>`) to a Vault policy
- Secret engines enabled: `database` (PostgreSQL dynamic creds for Keycloak), `kv-v2` (API keys such as pfsense token), `pki` (intermediate CA for mTLS)
- Vault Agent Injector injects secrets as tmpfs annotations into platform component pods (Keycloak, agentgateway, ext-proc-delegation); no Secret objects in etcd for dynamic creds
- NetworkPolicy: ingress on 8200 from `mcp-gateway`, `keycloak`, `agentic-mcp`, `agent-sandbox` namespaces only; deny all other ingress; egress to SPIRE OIDC on 443
- Fail-mode: if Vault is sealed or unreachable, Vault Agent Injector blocks the pod's init container — workload never starts without valid credentials (fail-closed)

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| All platform workloads | inbound | 8200 HTTPS | Secret fetch / dynamic credential generation |
| Vault Agent Injector | inbound (sidecar) | 8200 HTTPS | Credential injection via init/sidecar pattern |
| SPIRE OIDC | outbound | 443 HTTPS | JWKS for `jwt` auth mount validation |
| CNPG (Keycloak DB) | outbound | 5432 TCP | Database secret engine lease management |
| OCP Route | inbound from operators | 443 HTTPS | UI and CLI (`vault` CLI) access |

## Maturity flags

- HashiCorp Vault 0.32.0 Helm chart is GA; single-replica Raft is a supported topology
- Vault Agent Injector annotation-based injection is stable; the newer Vault Secrets Operator (VSO) is an alternative but not used here to avoid creating Kubernetes Secret objects
- SPIFFE JWT auth (`jwt` mount with OIDC discovery) is a GA Vault feature

## Verify

```bash
# 1. Check Vault pod is Running and initialized/unsealed
oc exec -n vault vault-0 -- vault status

# 2. Confirm jwt auth mount is configured with SPIRE OIDC issuer
oc exec -n vault vault-0 -- vault auth list | grep jwt

# 3. Test a workload SVID can authenticate (from a pod with SPIFFE CSI mount)
SVID=$(cat /run/spire/sockets/svid.jwt)
curl -s --header "X-Vault-Token: " \
  --request POST \
  --data "{\"jwt\": \"$SVID\", \"role\": \"keycloak-db\"}" \
  https://vault.apps.anaeem.na-launch.com/v1/auth/jwt/login | jq .auth.client_token
```
