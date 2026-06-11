# keycloak

Red Hat Build of Keycloak (RHBK 26.4) instance for the agentic MCP platform.
Provides the "agentic" realm with OAuth2/OIDC clients for the agent runtime,
gateway audience validation, and downstream identity exchange.

## What is deployed

| Resource | Kind | Notes |
|---|---|---|
| keycloak-db | CNPG Cluster (postgresql.cnpg.io/v1) | PostgreSQL 16, 1 instance (SNO), 10Gi nfs-csi |
| keycloak | Keycloak (k8s.keycloak.org/v2beta1) | RHBK 26.4, 1 instance, token-exchange preview flags |
| agentic-realm | KeycloakRealmImport | clients, groups, demo user, SPIRE IdP stub |
| network-policy | NetworkPolicy x4 | default-deny + ingress from openshift-ingress + mcp-gateway |

## Why this exists

Keycloak is the OIDC authority for the platform.  The gateway (agentgateway +
ext-proc-delegation) validates inbound tokens against the `mcp-gateway` audience,
then performs RFC8693 token exchange to issue a downstream token scoped to the
target MCP server's identity (`mcp-downstream` audience), preserving the original
user identity throughout the call chain.

## Apply order

1. `platform/00-operators/rhbk` — installs the RHBK operator into ns keycloak
   (Subscription + OperatorGroup).  Wait for the operator pod to be Running.
2. `platform/keycloak` (this component) — creates the CNPG Cluster first, then
   the Keycloak CR and realm import.

```
# Apply operators first
kustomize build platform/00-operators/rhbk | oc apply -f -
oc -n keycloak wait --for=condition=Ready pod -l app.kubernetes.io/name=rhbk-operator --timeout=120s

# Apply keycloak component
kustomize build platform/keycloak/overlays/anaeem | oc apply -f -
```

## TLS certificate

The Keycloak CR references `tlsSecret: keycloak-tls`.

**Option A (default — PoC):** Annotate the Keycloak Service with the
service-ca annotation to get a cluster-signed cert injected automatically:

```
oc -n keycloak annotate service keycloak \
  service.beta.openshift.io/serving-cert-secret-name=keycloak-tls
```

The service-ca operator creates `keycloak-tls` within seconds.  The cert is
trusted by all pods on the cluster but NOT by external browsers.

**Option B (production):** Use cert-manager.  Uncomment the `Certificate`
resource in `base/tls-certificate.yaml`, ensure a `ClusterIssuer` exists
(e.g. Let's Encrypt), and remove the service-ca annotation.

## CNPG secret (bootstrap exception)

CNPG auto-creates `keycloak-db-app` in etcd with the generated DB password.
This is the standard CNPG behaviour and is accepted as a bootstrap exception for PoC.

**Production path:** enable the Vault Agent Injector on the keycloak deployment
to deliver DB credentials via an in-memory tmpfs volume instead of reading from
the CNPG-managed secret.  This requires:
1. A Vault dynamic-secrets role for PostgreSQL.
2. A Vault Agent annotation on the Keycloak pod template (operator CR supports
   `podTemplate.spec.initContainers`).
3. Removal of `usernameSecret`/`passwordSecret` from the Keycloak CR in favour
   of environment variables sourced from the Vault-injected file.

## Preview feature flags

The Keycloak CR sets `features: "token-exchange,admin-fine-grained-authz"` in
`additionalOptions`.

- **token-exchange**: enables the legacy Keycloak-proprietary token exchange
  endpoint as a fallback.  The standard RFC8693 exchange endpoint is GA in
  RHBK 26.2+ without this flag.  Keep enabled during PoC until the ext-proc is
  confirmed to use the standard endpoint (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`).
  Remove after validation.
- **admin-fine-grained-authz**: required to configure per-client token exchange
  policies via the Keycloak admin REST API.  Remove once policies are locked in.

## Demo user password

The `arsalan` user is created without a password (security invariant — no secrets
in git).  Set the password after realm import:

```
# Port-forward to Keycloak (or use the Route)
oc -n keycloak port-forward svc/keycloak-service 8443:8443 &

# Get the admin credentials (operator-generated secret)
KC_ADMIN_PW=$(oc -n keycloak get secret keycloak-initial-admin -o jsonpath='{.data.password}' | base64 -d)

# Set arsalan's password
oc -n keycloak exec deploy/keycloak -- /opt/keycloak/bin/kcadm.sh \
  set-password -r agentic --username arsalan --new-password <CHOOSE_A_PASSWORD> \
  --no-config --server https://localhost:8443 \
  --user admin --password "${KC_ADMIN_PW}" --realm master
```

## Verify

```
# Check CNPG cluster is healthy
oc -n keycloak get cluster keycloak-db
oc -n keycloak get pods -l cnpg.io/cluster=keycloak-db

# Check Keycloak is ready
oc -n keycloak get keycloak keycloak
oc -n keycloak get pods -l app=keycloak

# Check realm import succeeded
oc -n keycloak get keycloakrealmimport agentic-realm

# Fetch OIDC discovery document
curl -sk https://keycloak.apps.anaeem.na-launch.com/realms/agentic/.well-known/openid-configuration | jq .

# Test token-exchange (RFC8693) — acquire a subject token first, then exchange it.
# Step 1: get agent-runtime access token (client credentials)
AGENT_SECRET=$(oc -n keycloak get secret agent-runtime-client-secret -o jsonpath='{.data.secret}' | base64 -d 2>/dev/null || echo "<get-from-keycloak-admin>")
SUBJECT_TOKEN=$(curl -sk -X POST \
  https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=agent-runtime" \
  -d "client_secret=${AGENT_SECRET}" | jq -r .access_token)

# Step 2: exchange for a mcp-downstream-scoped token (RFC8693)
GW_SECRET=$(oc -n keycloak get secret mcp-gateway-client-secret -o jsonpath='{.data.secret}' | base64 -d 2>/dev/null || echo "<get-from-keycloak-admin>")
curl -sk -X POST \
  https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=mcp-gateway" \
  -d "client_secret=${GW_SECRET}" \
  -d "subject_token=${SUBJECT_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=mcp-downstream" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" | jq .

# Inspect the exchanged token
EXCHANGED=$(curl -sk ... | jq -r .access_token)
echo "${EXCHANGED}" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

## SPIRE IdP stub

The `spire` identity provider in the realm import is a placeholder.
Full jwt-bearer (RFC7523) wiring is documented in `platform/mcp-gateway/README.md`.
The high-level flow is:

```
SPIFFE SVID (JWT) -> ext-proc -> Keycloak token endpoint
  POST /realms/agentic/protocol/openid-connect/token
  grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
  assertion=<SVID>
  client_id=mcp-gateway
  client_secret=<secret>
```

This yields a Keycloak access token with the workload's SPIFFE URI as `sub`,
which is then used for the downstream token exchange.
