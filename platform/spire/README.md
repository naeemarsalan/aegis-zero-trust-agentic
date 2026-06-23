# platform/spire

Configures SPIRE / SPIFFE workload identity on the anaeem cluster using the
Zero Trust Workload Identity Manager (ZTWIM) OLM operator (channel `stable-v1`,
already installed by `platform/00-operators`).

## What this component does

- Creates the five ZTWIM singleton CRs (all named `cluster` in
  `zero-trust-workload-identity-manager`):
  - `ZeroTrustWorkloadIdentityManager` — top-level operator config; sets
    `trustDomain: anaeem.na-launch.com`.
  - `SpireServer` — SPIRE server with JWT issuer
    `https://spire-oidc.apps.ocp-dev.na-launch.com` and persistent storage on
    `nfs-csi`.
  - `SpireAgent` — DaemonSet agent for node/workload attestation.
  - `SpiffeCSIDriver` — CSI driver that mounts workload API sockets into pods.
  - `SpireOIDCDiscoveryProvider` — exposes the OIDC discovery document so
    Keycloak, Vault, and other relying parties can verify SPIFFE JWTs.
- Creates three `ClusterSPIFFEID` registrations (cluster-scoped,
  `spire.spiffe.io/v1alpha1`):
  - `mcp-gateway-ext-proc-delegation` — pods with label
    `app.kubernetes.io/name: ext-proc-delegation` in `mcp-gateway`.
  - `mcp-gateway-jit-approver` — pods with label
    `app.kubernetes.io/name: jit-approver` in `mcp-gateway`.
  - `agent-sandbox-workloads` — pods with label
    `spiffe.io/spire-managed-identity: "true"` in `agent-sandbox` (opt-in).
- Includes a fallback `Route` for the OIDC discovery provider (see note below).

## CRITICAL: trustDomain is immutable

`ZeroTrustWorkloadIdentityManager.spec.trustDomain` (and by extension the
`SpireServer` CA) **cannot be changed** after the first `oc apply`.  Changing
it requires:

1. Deleting all `ClusterSPIFFEID` registrations.
2. Deleting the `SpireServer` CR (destroys the signing CA).
3. Deleting the `ZeroTrustWorkloadIdentityManager` CR.
4. Waiting for the operator to clean up all managed resources.
5. Re-applying with the new trust domain.

All issued SVIDs will be revoked.  Confirm `anaeem.na-launch.com` is correct
before first apply.

## OIDC Route: check operator-created Route first

The ZTWIM operator may create a Route for the OIDC discovery provider
automatically.  **Before applying, run:**

```bash
oc get route -n zero-trust-workload-identity-manager
```

If a route for `spire-oidc.apps.ocp-dev.na-launch.com` already exists (created
by the operator), remove `oidc-route.yaml` from
`base/kustomization.yaml` (or comment it out) to avoid a conflict.  The
fallback Route uses `reencrypt` TLS termination; adjust `targetPort` if the
operator names the backing Service differently.

## Directory layout

```
platform/spire/
  base/
    kustomization.yaml
    ztwim.yaml                        ZeroTrustWorkloadIdentityManager CR
    spire-server.yaml                 SpireServer CR
    spire-agent.yaml                  SpireAgent CR
    spiffe-csi-driver.yaml            SpiffeCSIDriver CR
    spire-oidc-discovery-provider.yaml SpireOIDCDiscoveryProvider CR
    oidc-route.yaml                   Fallback Route (see note above)
    cluster-spiffe-ids.yaml           ClusterSPIFFEID registrations
  overlays/anaeem/
    kustomization.yaml
    patch-ztwim-trustdomain.yaml
    patch-spireserver.yaml
    patch-oidc-provider.yaml
    patch-oidc-route.yaml
```

## Apply order

This component is sync-wave **1** — the ZTWIM operator (wave 0) must be
installed and its CRDs registered before these CRs can be applied.

```bash
# Verify offline render (no network required):
kustomize build platform/spire/overlays/anaeem

# Apply (ArgoCD handles this; manual bootstrap):
kustomize build platform/spire/overlays/anaeem | oc apply -f -
```

## Verify

```bash
# 1. Operator-managed CRs reach Ready/Running state
oc get zerotrustworkloadidentitymanager cluster -n zero-trust-workload-identity-manager -o yaml
oc get spireserver cluster -n zero-trust-workload-identity-manager -o yaml
oc get spireagent cluster -n zero-trust-workload-identity-manager -o yaml
oc get spiffecsidrivers cluster -n zero-trust-workload-identity-manager -o yaml
oc get spireoidcdiscoveryprovider cluster -n zero-trust-workload-identity-manager -o yaml

# 2. SPIRE server pod is Running
oc get pods -n zero-trust-workload-identity-manager

# 3. OIDC discovery document is reachable and contains the correct issuer
curl -s https://spire-oidc.apps.ocp-dev.na-launch.com/.well-known/openid-configuration | python3 -m json.tool

# Expected: "issuer": "https://spire-oidc.apps.ocp-dev.na-launch.com"

# 4. ClusterSPIFFEIDs are registered
oc get clusterspiffeids

# 5. Confirm a managed pod gets an SVID (example — replace pod name):
oc exec -n mcp-gateway <ext-proc-delegation-pod> -- \
  /opt/spire/bin/spire-agent api fetch x509 \
  -socketPath /run/spiffe/sockets/agent.sock
```

## Extending to another cluster

Copy `overlays/anaeem/` to `overlays/<cluster>/` and update:
- `patch-ztwim-trustdomain.yaml` — new trust domain (confirm it is immutable
  for that cluster too).
- `patch-spireserver.yaml` — new `jwtIssuer` URL and `storageClassName`.
- `patch-oidc-provider.yaml` — new `jwtIssuer` URL.
- `patch-oidc-route.yaml` — new Route hostname.
