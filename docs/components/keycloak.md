## Purpose

Keycloak (RHBK) is the user-facing OIDC/OAuth2 identity broker for the `agentic` realm. It federates human operator logins, issues access tokens scoped to MCP tool permissions, and enforces consent flows. Agents present their SPIFFE-derived JWT to Keycloak via RFC 7523 (JWT client authentication) to exchange for a realm token that carries the downstream user identity — ensuring MCP servers always see the user, never the agent.

## Exists or create

CREATE on anaeem (our own dedicated instance). A pre-existing RHBK operator (`stable-v26.4`) exists in namespace `openshift-mta` as an MTA dependency with a `Keycloak` CR named `mta-rhbk` — do **not** touch that instance. We deploy our **own** `Subscription` + `OperatorGroup` in namespace `keycloak` (namespace-scoped), our own `Keycloak` CR, and a CloudNativePG `Cluster` CR for the backing database. The CNPG operator itself is cluster-scoped (already installed in `openshift-operators`) — no new operator install needed, only the `Cluster` CR. Realm `agentic` is provisioned via Keycloak's `KeycloakRealmImport` CR.

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11)
- Namespace: `keycloak`
- RHBK Route: `https://keycloak.apps.anaeem.na-launch.com` (TLS passthrough or re-encrypt via OCP Route)
- CNPG Cluster: namespace `keycloak`, PVC `storageClassName: nfs-csi`
- Realm: `agentic`
- No additional DNS changes needed

## Security posture

- SPIFFE ID: `spiffe://anaeem.na-launch.com/ns/keycloak/sa/keycloak` — presented to Vault for DB credential rotation approval
- Database password: Vault dynamic credential injected via Vault Agent Injector (tmpfs annotation); never stored in a Secret or etcd long-term
- RFC 7523 preview: agent service accounts authenticate with a SPIFFE JWT SVID as client assertion; Keycloak validates against the SPIRE OIDC JWKS endpoint. This feature is in **RHBK preview** status — see maturity flags
- NetworkPolicy: ingress on 8443 from the OCP router only; egress to CNPG on 5432 and to SPIRE OIDC endpoint on 443; deny all other ingress
- Fail-mode: if CNPG cluster is unavailable, Keycloak refuses to start (fail-closed); if Vault Agent cannot inject DB creds, pod does not reach Ready

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| Browser / operators | inbound | 443 HTTPS (Route) | OAuth2 authorization code flow |
| agentgateway | outbound → Keycloak | 443 HTTPS | Token introspection / JWKS |
| Agent pods | inbound from agents | 443 HTTPS | RFC 7523 JWT assertion exchange |
| CNPG Cluster | outbound | 5432 TCP | PostgreSQL session |
| SPIRE OIDC | outbound | 443 HTTPS | JWKS for RFC 7523 client assertion validation |
| Vault Agent sidecar | inbound (localhost) | 8200 HTTP | Dynamic DB credential delivery |

## Maturity flags

- RHBK `stable-v26.4` is production-supported
- RFC 7523 JWT client authentication for SPIFFE SVIDs is a **RHBK preview feature** in v26.4 — do not rely on it for production without Red Hat confirmation; a fallback using Vault-issued short-lived client secrets is documented in the auth flow ADR
- CNPG `stable-v1.29` is GA

## Verify

```bash
# 1. Check Keycloak pod and CNPG cluster are healthy
oc get pods -n keycloak
oc get cluster -n keycloak

# 2. Confirm OIDC discovery for the agentic realm
curl -s https://keycloak.apps.anaeem.na-launch.com/realms/agentic/.well-known/openid-configuration \
  | jq '{issuer,jwks_uri,token_endpoint}'

# 3. Verify DB credential is Vault-injected (tmpfs) and not a static Secret
oc exec -n keycloak deploy/keycloak -- mount | grep tmpfs
```
