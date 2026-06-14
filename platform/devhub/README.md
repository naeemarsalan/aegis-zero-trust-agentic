# DevHub Phase-2 MVP — apply plan

This directory makes the zero-trust agentic platform **consumable through Red Hat
Developer Hub (RHDH)**. RHDH is the *front door*: users sign in as themselves
(Keycloak), discover MCP capabilities in the Software Catalog, launch a sandboxed
agent via a scaffolder template, and see the running `Sandbox` CR + JIT grants on
the entity's Kubernetes tab. The agent conversation itself lives elsewhere;
Keycloak / Vault / Forgejo stay the substrate. **Compose, don't rewrite.**

> Everything here is **write-only drafts + documented apply steps**. Nothing in
> this directory has been applied to the live `anaeem` cluster, and the live RHDH
> ConfigMaps (`developer-hub-app-config`, `developer-hub-dynamic-plugins`) have
> NOT been edited. All snippets are **hand-merge** deltas — preserve every key
> already present in the live config.
>
> Drive the cluster with:
> ```
> oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify ...
> ```

---

## Artifacts in this directory

| Artifact | Kind | What it does |
|---|---|---|
| `app-config-auth.yaml` | merge snippet | OIDC sign-in against Keycloak realm `agentic` + Keycloak org (user/group) ingestion into the catalog. Merge into `developer-hub-app-config`. |
| `catalog/` | catalog descriptors | Models each MCP capability as `kind: Resource` (`spec.type: mcp-server`) — `pfsense.yaml`, `echo.yaml` — plus supporting `groups.yaml` (mcp-admins/mcp-users), `system-agentic-platform.yaml`, and the aggregating `all.yaml` `Location`. Registered by URL. |
| `templates/run-agent/template.yaml` | scaffolder Template | "Run an Agent" wizard: collects goal / scope / kind / capabilities / TTL and POSTs to the sandbox launcher via an RHDH proxy endpoint. Registered by URL. |
| `app-config-k8s.yaml` | merge snippet | Complete `kubernetes:` app-config stanza — cluster entry (`anaeem`, `${K8S_ANAEEM_TOKEN}`, `skipTLSVerify: true`) plus `customResources` for `agents.x-k8s.io/sandboxes`. Merge into `developer-hub-app-config`. |
| `app-config-launcher.yaml` | merge snippet | `proxy.endpoints./mcp-launcher` delta pointing at `http://sandbox-launcher.mcp-gateway.svc:8080`. Uses `credentials: forward` + `allowedHeaders: [Content-Type, Authorization]` so the Backstage user JWT reaches the launcher for identity verification. Depends on `services/sandbox-launcher` being live. |
| `k8s-plugin.md` | operator doc | How to enable the Kubernetes dynamic plugins, teach the plugin about the `agents.x-k8s.io/sandboxes` CR, annotate the launched Sandbox entity, apply RHDH ServiceAccount RBAC, and surface the JIT approval PR queue via `spec.links`. |

---

## Apply order

Apply **in this order** — each step depends on the previous one being live. After
each ConfigMap change, restart RHDH:

```
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  rollout restart deployment/developer-hub -n rhdh
```

### 1. SSO (Keycloak OIDC) — `app-config-auth.yaml`

> **SHARED INSTANCE — TWO-STEP APPLY REQUIRED.** This RHDH also hosts
> migration-catalog and ansible-collection-discovery, whose users rely on the
> Guest provider. Apply in two steps: (Step 1) land OIDC config with the guest
> fallback preserved; validate OIDC round-trip; (Step 2) remove the guest block.
> See `app-config-auth.yaml` header for the full safety rationale.

**1a0. RHDH MUST TRUST THE INGRESS CA — PREREQUISITE (verified blocker).**
The Keycloak route is edge-terminated with the `*.apps` ingress cert (signed by
the ingress-operator router-CA). The RHDH (Node/Backstage) pod does NOT trust that
CA by default — verified: `curl` to the OIDC discovery URL from the RHDH pod fails
with exit 60 (SSL: unable to get local issuer certificate). OIDC discovery and
login will FAIL until RHDH trusts it. Fix: mount the ingress CA bundle
(`openshift-config-managed/default-ingress-cert` key `ca-bundle.crt`) into the
RHDH pod and set `NODE_EXTRA_CA_CERTS` to its path (via the RHDH CR / helm values,
so the operator doesn't revert it). Re-verify discovery returns 200 from the pod
BEFORE flipping `signInPage: oidc`.

Status (anaeem, staged 2026-06-14): the Keycloak `rhdh` client + service-account
roles + the `rhdh-keycloak-secret` (8 env values, incl. a fresh AUTH_SESSION_SECRET)
are CREATED but NOT wired into the deployment and the auth config is NOT merged —
so the sign-in page is unchanged and other tenants are unaffected. To complete:
do 1a0 (CA trust), wire the secret into the `developer-hub` env, then 1c–1e below.

**1a. Create the Keycloak client (manual, in the `agentic` realm) — PREREQUISITE.**
RHDH will fail to start if this client does not exist when the config is applied:

- Client ID: `rhdh` — confidential (Client authentication ON in KC 19+),
  **Standard Flow ON**, **Service Accounts ON**.
- Valid redirect URI:
  `https://developer-hub-rhdh.apps.anaeem.na-launch.com/api/auth/oidc/handler/frame`
- Web origin: `https://developer-hub-rhdh.apps.anaeem.na-launch.com`
- Service-account roles (realm-management): `query-groups`, `query-users`,
  `view-users` — required for catalog ingestion by the keycloak plugin.
- Copy the client secret from the client's **Credentials** tab.

**1b. Create/patch the env Secret** (e.g. `rhdh-keycloak-secret` in `rhdh`) with
the 8 values the snippet expands:
`AUTH_SESSION_SECRET` (`openssl rand -hex 32`), `KEYCLOAK_METADATA_URL`,
`KEYCLOAK_BASE_URL`, `KEYCLOAK_REALM=agentic`, `KEYCLOAK_LOGIN_REALM=agentic`,
`KEYCLOAK_CLIENT_ID=rhdh`, `KEYCLOAK_CLIENT_SECRET`, `RHDH_BASE_URL`. Wire it into
the `developer-hub` deployment's env.

**1c. Enable the Keycloak dynamic plugin** in `developer-hub-dynamic-plugins`
(bundled path — no external pull, SNO/air-gap safe). The OIDC auth module is
compiled into RHDH core; only the catalog ingestion plugin needs an entry:

```yaml
- disabled: false
  package: ./dynamic-plugins/dist/backstage-community-plugin-catalog-backend-module-keycloak-dynamic
```

**1d. Merge the snippet** into `developer-hub-app-config` → `data.app-config.yaml`
(Step 1 — OIDC live, guest preserved as fallback):
- `auth:` block (`environment: production`, `session.secret`,
  `providers.guest` with `dangerouslyAllowOutsideDevelopment: true` **preserved**,
  `providers.oidc.production`),
- the **top-level** `signInPage: oidc` (NOT nested under `auth:`),
- `catalog.providers.keycloakOrg.default`.

Edit the ConfigMap in place (preserving all existing keys), e.g.:
```
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  -n rhdh edit configmap developer-hub-app-config
```
Then restart RHDH (command above). Validate the full OIDC round-trip.

**1e. (Step 2 — separate change after OIDC is validated)** Remove the `guest:`
block (or remove `dangerouslyAllowOutsideDevelopment: true` from it) from the
merged ConfigMap, then restart RHDH. This closes guest access entirely and forces
all users through OIDC. Do not apply Step 2 until Step 1 OIDC validation succeeds.

> **Resolver note:** The config uses `preferredUsernameMatchingUserEntityName` as
> the primary resolver — it works on cold start before `keycloakOrg` has synced.
> Once keycloakOrg entities are confirmed in the catalog, promote
> `oidcSubClaimMatchingKeycloakUserId` (commented out in the snippet) to the
> primary resolver for long-term stability (immutable KC sub UUID). That resolver
> is RHDH-specific and changed from 1.5 — confirm RHDH version before enabling.
>
> Do **not** set `scope:` under the OIDC provider — it gets rejected. Do not
> manually append `/.well-known/openid-configuration` to `metadataUrl` — RHDH
> appends it automatically.

### 2. Catalog location — published to the PUBLIC mirror repo

RHDH's Backstage Gitea URL reader only reliably ingests **public, root-level**
catalog files — it 404s ("no matching files found") on this **private** nvidia-ida
repo even with a valid token (verified: the RHDH pod can `curl` the raw file 200,
but the reader still fails). So the catalog is published to a dedicated PUBLIC repo
and registered from there:

```yaml
catalog:
  locations:
    - type: url
      target: https://git.arsalan.io/anaeem/nvidia-ida-catalog/raw/branch/main/all.yaml
```

The per-entity files in THIS directory (`groups.yaml`, `system-agentic-platform.yaml`,
`pfsense.yaml`, `echo.yaml`) are the **authoring source**. `publish-public-catalog.sh`
concatenates them into the public repo's root `all.yaml` (repointing each
`source-location` annotation at the mirror) — run it after editing any of them:

```sh
GITEA_PAT=<pat-with-write-on-nvidia-ida-catalog> ./publish-public-catalog.sh
```

`Resource` is already allowed by the live `catalog.rules`, so **no plugin install
and no catalog.rules change** is needed. Restart RHDH and confirm the
`mcp-pfsense` / `mcp-echo` Resources appear.

### 3. Scaffolder template — `templates/run-agent/template.yaml`

Register the template, then wire the launcher proxy:

**3a. Register** by adding a second `catalog.locations` entry (or a `Location`
entity) pointing at the template's raw URL:
```yaml
    - type: url
      target: https://git.arsalan.io/anaeem/nvidia-ida/raw/branch/main/platform/devhub/templates/run-agent/template.yaml
```

**3b. Register the launcher proxy endpoint** by merging `app-config-launcher.yaml`
into `developer-hub-app-config`. See that file and the `### Launcher proxy` section
below for the full auth rationale. Key delta:
```yaml
proxy:
  endpoints:
    /mcp-launcher:
      target: http://sandbox-launcher.mcp-gateway.svc:8080   # PLACEHOLDER
      changeOrigin: true
      credentials: forward          # forwards Backstage user JWT to launcher
      allowedHeaders:
        - Content-Type
        - Authorization             # required: carries the user JWT through
      pathRewrite:
        '^/api/proxy/mcp-launcher/': '/'
```
The `roadiehq-scaffolder-backend-module-http-request-dynamic` plugin (which
provides `http:backstage:request`) is already enabled on `anaeem`. Restart RHDH.

### 4. Kubernetes plugin — `k8s-plugin.md`

Last, so launched sandboxes are visible on their entity page. Follow `k8s-plugin.md`:
- add the `kubernetes.customResources` entry for `agents.x-k8s.io/sandboxes`
  (`apiVersion: v1alpha1` — **version only**, a common silent-failure gotcha),
- apply the `rhdh-kubernetes-sandbox-reader` ClusterRole/Binding granting the RHDH
  ServiceAccount `get/list/watch` on the CRs,
- ensure the launcher labels the Sandbox CR and emits a `catalog-info.yaml` with
  matching `backstage.io/kubernetes-id` + `-namespace` annotations.

Restart RHDH and run the verification checklist in `k8s-plugin.md`.

---

## Drafted vs. not-yet-real (be honest)

- **SSO, catalog, k8s-plugin docs:** complete and self-contained as drafts. The
  only blockers are the *manual* Keycloak client (step 1a) and the env Secret
  (1b), which can't be drafted as files because they carry secrets.
- **Helper files referenced by `app-config-auth.yaml`** —
  `dynamic-plugins-patch.yaml`, `rhdh-keycloak-secret.yaml`,
  `keycloak-rhdh-client-patch.yaml` — are referenced as future conveniences but
  **do not exist in this directory yet**. The steps above inline everything they
  would contain, so they are not required to apply.
- **The sandbox launcher is NOT real yet (Phase 1b, in progress).** The template's
  launch step targets `http://sandbox-launcher.mcp-gateway.svc:8080/launch`, which
  is a **placeholder**. Until that launcher exists and returns
  `sandboxName` / `conversationUrl` (and ideally `catalogInfoUrl`), the *Run an
  Agent* template will register and render the wizard, but **submitting it will
  fail** at the launch step. The template is wired and ready; it just needs the
  Phase-1b endpoint stood up and the proxy `target` pointed at its real Service.
- **`catalog:register` of the running sandbox** (template step 3) and the JIT
  grant CRD wiring in `k8s-plugin.md` are intentionally left commented /
  placeholder-grouped until the launcher emits `catalogInfoUrl` and the real JIT
  grant CRD group is known.

---

## Apply order (short)

1. **SSO** — Keycloak `rhdh` client (manual) + Secret + keycloak dynamic plugin + merge `app-config-auth.yaml`; restart RHDH.
2. **Catalog location** — register `catalog/all.yaml` via `catalog.locations`; restart RHDH.
3. **Scaffolder template** — register `templates/run-agent/template.yaml` + merge `app-config-launcher.yaml` proxy endpoint; restart RHDH.
4. **Kubernetes plugin** — add `customResources` for `sandboxes` + RHDH SA RBAC per `k8s-plugin.md`; restart RHDH.

---

### Launcher proxy

`app-config-launcher.yaml` is the hand-merge delta for `proxy.endpoints./mcp-launcher`.
It depends on the `services/sandbox-launcher` service being deployed and running in
namespace `mcp-gateway` (port 8080, `POST /launch`). Until that service exists,
submitting the "Run an Agent" template will error at the launch step.

**Path cross-check:** The scaffolder step in `templates/run-agent/template.yaml` sends:
```
path: /proxy/mcp-launcher/launch
```
The Backstage scaffolder backend prepends `/api`, producing the server-side URL:
```
/api/proxy/mcp-launcher/launch
```
The proxy entry key `/mcp-launcher` and `pathRewrite: '^/api/proxy/mcp-launcher/': '/'`
strip the prefix so the launcher sees `POST /launch`. These three are coupled — if you
rename the proxy key you must update both the template path and the pathRewrite.

**Auth design:** The config uses `credentials: forward` (not `credentials: require`).

With `credentials: require`, RHDH demands that the caller (the scaffolder backend)
authenticate, but the Backstage user JWT is stripped before the request leaves RHDH.
The launcher would receive no cryptographic identity — only the client-supplied
`user` body field (`LaunchRequest.user`), which is unauthenticated.

With `credentials: forward`, RHDH requires the caller to be authenticated AND forwards
the Backstage user JWT as `Authorization: Bearer <token>` upstream. `Authorization` is
listed explicitly in `allowedHeaders` because the proxy strips non-CORS-safe headers
even under `credentials: forward` unless they are whitelisted.

The forwarded token is a **Backstage-issued JWT** — not the user's Keycloak OIDC access
token. The Keycloak credential stays inside RHDH and is never relayed. The launcher
verifies the Backstage JWT once against RHDH's JWKS endpoint, extracts the user entity
ref from the `sub` (or `ent[0]`) claim, cross-checks it against `body.user`
(`LaunchRequest.user`), then discards the token. All outbound launcher calls to
agentgateway/OpenShell use the launcher's own OIDC `client_credentials` token —
the user's token is never stored, logged, or relayed. This preserves the
no-credential-passing invariant.

**Launcher verification env vars** — already set in
`services/sandbox-launcher/deploy/overlays/anaeem/deployment-patch.yaml`.
Listed here for reference; no additional overlay edits are needed.

| Variable | Value (as set in the overlay) |
|---|---|
| `RHDH_JWKS_URL` | `https://developer-hub-rhdh.apps.anaeem.na-launch.com/api/auth/.backstage/jwks.json` |
| `RHDH_TOKEN_ISSUER` | `https://developer-hub-rhdh.apps.anaeem.na-launch.com` |
| `LAUNCHER_OIDC_TOKEN_URL` | `http://keycloak.keycloak.svc:8080/realms/agentic/protocol/openid-connect/token` |
| `LAUNCHER_OIDC_CLIENT_ID` | `sandbox-launcher` |
| `LAUNCHER_OIDC_CLIENT_SECRET_FILE` | `/vault/secrets/launcher-oidc-secret` |

**Fallback — if `credentials: forward` is unavailable** (RHDH/Backstage pre-1.26):
Drop back to `credentials: require`, remove `Authorization` from `allowedHeaders`, and
add a static `headers.X-Launcher-Token: ${LAUNCHER_SHARED_SECRET}` header for
service-to-service authentication. With this fallback, user identity comes only from
`body.user` (`LaunchRequest.user`, advisory/unauthenticated); treat it as owner
labeling metadata only, not as an access-control input. See the inline comments in
`app-config-launcher.yaml` for the exact snippet.

---

### Known wiring discrepancies (flagged, not yet fixed in place)

**`RHDH_JWKS_URL` / `RHDH_TOKEN_ISSUER` — in-cluster HTTP vs. public Route HTTPS.**
The env-var table above and the inline comments in `app-config-launcher.yaml` give the
public HTTPS Route URL (`https://developer-hub-rhdh.apps.anaeem.na-launch.com`). The
launcher overlay (`services/sandbox-launcher/deploy/overlays/anaeem/deployment-patch.yaml`)
already carries both vars set to the public HTTPS Route URL. If you switch `RHDH_JWKS_URL`
to in-cluster HTTP (`http://developer-hub.rhdh.svc:7007/api/auth/.backstage/jwks.json`)
to avoid the wildcard cert, keep `RHDH_TOKEN_ISSUER` set to the public HTTPS origin,
because that is the `iss` claim Backstage embeds in its JWTs. Changing only one and not
the other will cause token verification to fail.

**`template.yaml` sends `userRef`, launcher expects `user`.**
`platform/devhub/templates/run-agent/template.yaml` (line ~227) sends the body field
as `userRef: ${{ user.ref }}`. The launcher's `LaunchRequest` model (`models.py`)
defines the field as `user: str`, and `api.py` cross-checks against `body.user`. This
means the template POST sends `userRef` but the launcher's Pydantic model reads `user`
— the field is silently absent, causing validation to fail with a 422 (required field
missing). This bug lives in `template.yaml` (and/or `models.py`), not in this proxy
artifact. It must be fixed by renaming `userRef` → `user` in the template body before
the end-to-end flow can succeed. Tracked here for visibility; the proxy wiring itself
is correct.

**`template.yaml` sends `scope` — no such field in `LaunchRequest`.**
`platform/devhub/templates/run-agent/template.yaml` sends `scope: ${{ parameters.scope }}`
in the POST body. `LaunchRequest` in `models.py` has no `scope` field. Pydantic v2
ignores unknown fields by default (`model_config` does not set `extra='forbid'`), so
the value is silently dropped and never reaches the launcher logic. If the launcher
needs the scope tier (e.g. to apply the floor policy ceiling), `scope` must be added
to `LaunchRequest` with the matching enum. Tracked here for visibility.

**`template.yaml` sends `ttlMinutes`, launcher field is `ttl_minutes` (no alias).**
`platform/devhub/templates/run-agent/template.yaml` sends `ttlMinutes: ${{ parameters.ttlMinutes }}`
(camelCase). The `LaunchRequest` Pydantic model defines the field as `ttl_minutes` (snake_case)
with no `alias` or `model_config` `populate_by_name`/`alias_generator` declared. Pydantic v2
will not bind the inbound `ttlMinutes` key to `ttl_minutes`, so the field silently falls back
to its default of 60 minutes regardless of what the user selected. Fix by either: (a) adding
`alias='ttlMinutes'` to the `Field(...)` call in `models.py` and setting
`model_config = ConfigDict(populate_by_name=True)`, or (b) changing the template body key to
`ttl_minutes`. Option (b) is simpler for a PoC. Tracked here for visibility.
