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
| `k8s-plugin.md` | operator doc | How to teach the Kubernetes plugin about the `agents.x-k8s.io/sandboxes` CR and JIT grants, plus the RHDH ServiceAccount RBAC, so a launched sandbox renders on its entity page. |

---

## Apply order

Apply **in this order** — each step depends on the previous one being live. After
each ConfigMap change, restart RHDH:

```
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  rollout restart deployment/developer-hub -n rhdh
```

### 1. SSO (Keycloak OIDC) — `app-config-auth.yaml`

**1a. Create the Keycloak client (manual, in the `agentic` realm).** Required
before RHDH can authenticate or ingest:

- Client `rhdh` — confidential, **Standard Flow ON**, **Service Accounts ON**.
- Valid redirect URI:
  `https://developer-hub-rhdh.apps.anaeem.na-launch.com/api/auth/oidc/handler/frame`
- Web origin: `https://developer-hub-rhdh.apps.anaeem.na-launch.com`
- Service-account roles (realm-management): `query-groups`, `query-users`,
  `view-users` — needed for catalog ingestion.
- Copy the client secret from the client's **Credentials** tab.

**1b. Create/patch the env Secret** (e.g. `rhdh-keycloak-secret` in `rhdh`) with
the 8 values the snippet expands:
`AUTH_SESSION_SECRET` (`openssl rand -hex 32`), `KEYCLOAK_METADATA_URL`,
`KEYCLOAK_BASE_URL`, `KEYCLOAK_REALM=agentic`, `KEYCLOAK_LOGIN_REALM=agentic`,
`KEYCLOAK_CLIENT_ID=rhdh`, `KEYCLOAK_CLIENT_SECRET`, `RHDH_BASE_URL`. Wire it into
the `developer-hub` deployment's env.

**1c. Enable the Keycloak dynamic plugin** in `developer-hub-dynamic-plugins`
(bundled path — no external pull, SNO/air-gap safe):

```yaml
- disabled: false
  package: ./dynamic-plugins/dist/backstage-community-plugin-catalog-backend-module-keycloak-dynamic
```

**1d. Merge the snippet** into `developer-hub-app-config` → `data.app-config.yaml`:
- `auth:` block (`environment: production`, `session.secret`,
  `providers.oidc.production`),
- the **top-level** `signInPage: oidc` (NOT under `auth:`),
- `catalog.providers.keycloakOrg.default`.

Edit the ConfigMap in place (preserving existing keys), e.g.:
```
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  -n rhdh edit configmap developer-hub-app-config
```
Then restart RHDH (command above).

> **WARNING:** `auth.environment: production` removes the Guest login button.
> Test the full OIDC round-trip first and keep a Keycloak admin account, or you
> can lock yourself out of Developer Hub. Do **not** set `scope:` under the OIDC
> provider — it gets rejected.

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

**3b. Register the launcher proxy endpoint** in `developer-hub-app-config` so the
`http:backstage:request` step can reach it (it can't call raw URLs):
```yaml
proxy:
  endpoints:
    /mcp-launcher:
      target: http://sandbox-launcher.mcp-gateway.svc:8080   # PLACEHOLDER — see below
      changeOrigin: true
      credentials: require
      allowedHeaders: [Content-Type]
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
3. **Scaffolder template** — register `templates/run-agent/template.yaml` + add the `/mcp-launcher` proxy endpoint; restart RHDH.
4. **Kubernetes plugin** — add `customResources` for `sandboxes` + RHDH SA RBAC per `k8s-plugin.md`; restart RHDH.
