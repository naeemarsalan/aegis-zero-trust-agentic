# Deploying sandbox-launcher (anaeem)

Proven end-to-end on 2026-06-13: `POST /launch` → launcher mints its OWN OIDC
client-credentials token (via the Keycloak **route**, so `iss` matches the
gateway issuer) → `CreateSandbox` with the baseline floor policy → Sandbox CR in
`openshell`. The caller's token is never forwarded (no-credential-passing).

## 1. Image
```
podman build -t oci.arsalan.io/nvidia-ida/sandbox-launcher:dev services/sandbox-launcher
podman push  oci.arsalan.io/nvidia-ida/sandbox-launcher:dev
```

## 2. Keycloak client (realm `agentic`) — its OWN confidential client
Do NOT reuse `openshell-admin`. Create a confidential, service-accounts-enabled
client `sandbox-launcher` with an audience mapper → `openshell-gateway`, and grant
its service account the realm role `openshell-admin` (CreateSandbox authz tier).
A minted client-credentials token must carry `aud:[openshell-gateway]` +
`realm_access.roles:[openshell-admin]`. (Done via the admin REST API; the client
secret goes into Vault below. NOT yet in realm-import.yaml — re-importing the realm
would drop it.)

## 3. Vault (KV v2 mount `secret/`)

### 3a. sandbox-launcher policy (UPDATED — now includes grant write)
```hcl
# File: platform/vault/policies/sandbox-launcher.hcl
# Read own OIDC secret
path "secret/data/sandbox-launcher/*" {
  capabilities = ["read"]
}
# Write consent grants (NOT credentials) keyed by sandbox UID
path "secret/data/sandbox-grants/*" {
  capabilities = ["create", "update"]
}
# Deny everything else
path "*" {
  capabilities = ["deny"]
}
```

Apply and configure:
```
vault policy write sandbox-launcher platform/vault/policies/sandbox-launcher.hcl

# kubernetes-auth role for the injector (Vault Agent + runtime grant write)
vault write auth/kubernetes/role/sandbox-launcher \
  bound_service_account_names=sandbox-launcher \
  bound_service_account_namespaces=mcp-gateway \
  token_policies=sandbox-launcher token_ttl=15m

# the client secret (injected at /vault/secrets/launcher-oidc-secret)
vault kv put secret/sandbox-launcher/launcher-oidc-secret secret=<keycloak-client-secret>
```

### 3b. ext-proc-delegation policy (UPDATED — now includes grant read)
```hcl
# File: platform/vault/policies/ext-proc-delegation.hcl  (ADD this path)
# Read consent grants written by sandbox-launcher
path "secret/data/sandbox-grants/*" {
  capabilities = ["read"]
}
```

Apply:
```
vault policy write ext-proc-delegation platform/vault/policies/ext-proc-delegation.hcl
```

### 3c. Grant path notes
- Logical KV-v2 path: `secret/data/sandbox-grants/<sandbox-uid>`
- Writer: sandbox-launcher SA via Vault k8s auth role `sandbox-launcher`
- Reader: ext-proc-delegation SA via Vault k8s auth role `ext-proc-delegation`
- Grant document is a CONSENT RECORD (not a credential): `{version, sandbox_uid, user, scope, ttl, nonce, created}`
- `VAULT_ADDR` env var on the sandbox-launcher pod must be set (e.g. `https://vault.apps.anaeem.na-launch.com`)
- `VAULT_SKIP_VERIFY=true` for PoC (self-signed ingress cert); use `VAULT_CACERT` in production
- Launcher authenticates via in-cluster SA token (k8s auth, same mechanism as Vault Agent Injector)
- To use SPIFFE SVID auth instead: set `VAULT_JWT_AUTH_PATH=jwt` + ensure `SVID_JWT_PATH` is populated by the workload API helper

## 4. Apply
```
oc apply -k services/sandbox-launcher/deploy/overlays/anaeem
```
Prereqs already present in `mcp-gateway`: the `openshell-client-tls` secret (mTLS).

## Gotchas learned the hard way
- **OIDC token MUST be minted via the route** (`https://keycloak.apps…/realms/agentic`,
  `LAUNCHER_OIDC_INSECURE=true`), NOT the in-cluster `keycloak-service` — the latter
  derives `iss=<svc>.svc`, which the gateway rejects with `InvalidIssuer`.
- The SNO router is hostNetwork, so reaching the route needs an **ipBlock** egress
  (`172.16.2.52/32:443`) — a `namespaceSelector` can never match it (see
  `networkpolicy.yaml` → `sandbox-launcher-egress-keycloak-route`).
- Owner labels are **sanitised** (`openshell.py::_sanitize_label_value`): an entity
  ref `user:default/arsalan` has `:`/`/` which the gateway rejects as a label value.
- The launcher uses NO SVID/Vault at runtime (only the injected OIDC secret + mTLS);
  the jit-approver svid-writer sidecar was vestigial and is removed.

## Remaining for a working RHDH "Run an agent" click
- Merge `platform/devhub/app-config-launcher.yaml` (`/mcp-launcher` proxy) into
  `developer-hub-app-config` + restart RHDH (additive, but shared instance).
- For a cryptographically-bound user identity, the RHDH proxy must forward the
  Backstage token (`credentials: forward`); until then the launcher accepts the
  body `userRef` as advisory (`verified-identity=false`).
