## Purpose

SPIRE (SPIFFE Runtime Environment) issues cryptographic workload identities (SVIDs) to every pod and platform component, eliminating static long-lived credentials from the cluster. It acts as the root attestation authority for the trust domain `anaeem.na-launch.com` and exposes an OIDC Discovery endpoint so that Vault and Keycloak can accept SPIFFE-bound tokens as first-class login methods.

## Exists or create

CREATE on anaeem. The ZTWIM (Zero Trust Workload Identity Manager) operator is available on channel `stable-v1` (GA on OCP 4.20) and is not yet installed. Deploy a `SPIFFECSIDriver` and a `SPIREServer` + `SPIREAgent` CR through the ZTWIM operator in namespace `zero-trust-workload-identity-manager`. The trust domain `anaeem.na-launch.com` is immutable once the server is bootstrapped — confirm before first apply.

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11)
- Namespace: `zero-trust-workload-identity-manager`
- SPIRE Server: internal ClusterIP only — not exposed via Route
- OIDC Discovery endpoint: `https://spire-oidc.apps.anaeem.na-launch.com` (OCP Route terminating TLS, backed by the SPIRE OIDC provider sidecar)
- No additional DNS changes needed — rides `*.apps.anaeem.na-launch.com` wildcard

## Security posture

- SVID format: `spiffe://anaeem.na-launch.com/ns/<namespace>/sa/<serviceaccount>`
- Node attestation: `k8s_psat` (projected service account token) — no host-level agent secrets
- Workload attestation: Kubernetes pod selectors (namespace + SA + labels)
- SVIDs are short-lived X.509 certificates delivered via the SPIFFE CSI Driver (tmpfs volume mount); never written to etcd or persistent storage
- SPIRE Server raft storage uses a PVC with `storageClassName: nfs-csi`
- NetworkPolicy: SPIRE Agent pods may reach the SPIRE Server on port 8081; all other ingress to the server is denied; agent-to-workload socket is bind-mounted read-only
- Fail-mode: if SPIRE Agent is unavailable, the CSI mount fails and the pod does not start — no fallback to static credentials

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| All workload pods | inbound to agent | Unix socket (tmpfs) | SVID delivery via SPIFFE CSI Driver |
| SPIRE Agent | outbound to Server | 8081 TCP | Agent-to-server attestation stream |
| Vault | outbound (Vault pull) | 443 HTTPS | JWT SVID presented to `jwt` auth mount |
| Keycloak | outbound (OIDC) | 443 HTTPS | OIDC Discovery for RFC 7523 trust |
| OIDC Discovery Route | inbound from Vault/Keycloak | 443 HTTPS | `/.well-known/openid-configuration` + JWKS |

## Maturity flags

- ZTWIM operator channel `stable-v1` reached GA with OCP 4.20 — production-ready for SNO topology
- SPIFFE CSI Driver is upstream stable; in-cluster cert rotation is automatic
- OIDC provider sidecar is a Red Hat supported component in this channel

## Verify

```bash
# 1. Check SPIRE Server and Agent pods are Running
oc get pods -n zero-trust-workload-identity-manager

# 2. Confirm OIDC Discovery endpoint returns a valid JWKS URI
curl -s https://spire-oidc.apps.anaeem.na-launch.com/.well-known/openid-configuration | jq .jwks_uri

# 3. Exec into a workload pod and inspect its SVID (requires spiffe-csi mount)
oc exec -n agentic-mcp deploy/pfsense-mcp -- \
  /opt/spire/bin/spire-agent api fetch x509 \
  -socketPath /run/spire/sockets/agent.sock
```
