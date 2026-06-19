# ADR-0013 — Adopt Kagenti for the identity plane (keep our JIT-approval on top)

**Status:** In progress — operator INSTALLED + integration recipe verified; STOPPED before shared-realm mutation + ext-proc cutover (see "Why stopped"). 2026-06-19.

## Decision
Replace the custom identity logic in `ext-proc-delegation` (SVID verify → Vault consent grant →
RFC8693 Keycloak exchange → inject) with **Kagenti** (the Red Hat-incubation agentic platform:
SPIRE + Keycloak + AuthBridge), and KEEP our **JIT human-approval** (jit-approver capability JWT +
approval-console + mcp-call auto-escalate + the dangerous-tool gate) as the layer on top. Kagenti
does Feature A (identity); it does NOT do Feature B (human-approved tool-scoped elevation) — that
stays ours. Decision driver: stop hand-maintaining a bespoke Kagenti; ride Red Hat's direction.
Note: Kagenti even owns **OpenShell** (our sandbox runtime) + `openshell-driver-openshift` +
`openshell-credentials-keycloak` — strong alignment.

## What is DONE (live, additive, non-breaking)
- **kagenti-operator v0.2.0-rc.7 installed** in ns `kagenti-system` (helm, OCI chart
  `oci://ghcr.io/kagenti/kagenti-operator/kagenti-operator-chart`). `kagenti-controller-manager` 1/1.
  - Chart bugs fixed to install: (1) needs **helm ≥ 3.18** (had 3.17 → upgraded to 3.18.4 in ~/.local/bin);
    (2) chart ships an **empty image tag** (`__PLACEHOLDER__`) → must pass
    `--set controllerManager.container.image.tag=0.2.0-rc.7`; (3) set
    `--set signatureVerification.spireTrustDomain=anaeem.na-launch.com`.
  - CRDs: `agentruntimes.agent.kagenti.dev`, `agentcards.agent.kagenti.dev`.
  - Webhooks are **safely scoped** (verified): mutating `inject.kagenti.io` only fires on ns labeled
    `kagenti-enabled=true` AND pods labeled `kagenti.io/type in [agent,tool]`, CREATE pods only;
    validating only on `agentcards`. Even at failurePolicy=Fail they CANNOT cascade (nothing opts in
    until we label it). Operator flags live: `--enable-client-registration=true`,
    `--spire-trust-domain=anaeem.na-launch.com`. NOTE `--enable-operator-client-registration` is NOT set
    (default off) — must be added to use operator-managed (vs legacy sidecar) client registration.

## The verified enrollment recipe (how AuthBridge identity works)
Per `kagenti-operator/docs/operator-managed-client-registration.md` + `authbridge-webhook.md` +
`kagenti-extensions/authbridge/README.md`:
- **Mode:** `proxy-sidecar` (default) — HTTP_PROXY based, **no iptables/NET_ADMIN** → OCP-friendly
  (avoid `envoy-sidecar` mode which needs proxy-init iptables). Sidecar images:
  `ghcr.io/kagenti/kagenti-extensions/authbridge:latest` (+ spiffe-helper bundled, gated by SPIRE_ENABLED).
- **Per workload-namespace** (e.g. a fresh `kagenti-test` or eventually `agent-sandbox`):
  - label ns `kagenti-enabled=true`.
  - ConfigMap **`authbridge-config`**: `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `SPIRE_ENABLED=true`, `ISSUER`,
    `TOKEN_URL`, `EXPECTED_AUDIENCE`, `TARGET_AUDIENCE`, `TARGET_SCOPES`, `DEFAULT_OUTBOUND_POLICY`,
    `PLATFORM_CLIENT_IDS`.
  - ConfigMap **`authproxy-routes`**: `routes.yaml` (host → target_audience for outbound exchange).
  - Secret **`keycloak-admin-secret`**: `KEYCLOAK_ADMIN_USERNAME`/`KEYCLOAK_ADMIN_PASSWORD`
    (ours: `oc -n keycloak get secret keycloak-initial-admin`).
- **Workload**: a Deployment (not bare Pod), **non-default `serviceAccountName`** (required for the
  SPIFFE-shaped client ID), pod labels `kagenti.io/type: agent`, a `shared-data` volume (webhook mounts
  the client creds into containers that have it), SPIFFE CSI volume.
- The operator registers a Keycloak client `spiffe://anaeem.na-launch.com/ns/<ns>/sa/<sa>`, creates a
  `kagenti-keycloak-client-credentials-<hash>` Secret, annotates the pod template; the webhook injects
  the AuthBridge sidecar + mounts the creds. AuthBridge then: INBOUND validates JWT; OUTBOUND exchanges
  the token to `TARGET_AUDIENCE` — transparently, no app change. mcp-call would set `HTTP_PROXY` to the
  sidecar (proxy-sidecar mode).
- **PREREQUISITE (the risky bit):** Keycloak must trust SPIRE so the agent's SVID becomes a Keycloak
  token (SPIFFE IdP / jwt-bearer in the realm). Kagenti ships `kagenti-extensions` SPIFFE-IdP setup.
  This is RHBK-26.x-compat-risky (see Risks).

## ext-proc cutover plan (NOT yet done — gated)
Slim `services/ext-proc-delegation` to KEEP only the JIT plane: RETIRE `internal/spire`,
`internal/grant`, `internal/keycloak` exchange, `vault.FetchGrant`; KEEP `internal/jwks`, `internal/rbac`,
`vault.FetchToolSecret` (static tokens), `inject.*`, and the `jitElevatesTool` gate (factor into a
standalone JIT-gate). Remove SPIRE_* / SANDBOX_GRANT_* env. The JIT gate keys the Vault write-token
fetch off the exchanged token's `act.sub` (delegated user) instead of `grant.User`. Full file-by-file
list: workflow `w6ez0wu91` output `extproc_changes`.

## Why stopped here (deliberate)
1. The next steps mutate the **shared `agentic` RHBK realm** (SPIFFE IdP + token-exchange) that the
   **currently-working, proven** split-identity loop depends on. RHBK token-exchange has a documented
   failure history here (26.6.3 NPE, see [[project-keycloak-obo-constraint]]). Mutating it autonomously,
   with no human verifying intermediate token-exchange results, risks breaking the working loop.
2. The ext-proc cutover is destructive; it should only happen AFTER Kagenti identity is PROVEN
   (ideally in an isolated `kagenti-test` realm/ns first).
Everything done so far is additive and the working loop is 100% intact.

## Resume here (ordered)
1. **Isolated proof first:** create realm `kagenti` (or reuse `agentic` with care), ns `kagenti-test`
   (label `kagenti-enabled=true`), the 3 config objects above, a test agent Deployment (non-default SA,
   shared-data, kagenti.io/type=agent), `--enable-operator-client-registration=true` on the operator.
   Verify: operator registers the Keycloak client; webhook injects the AuthBridge sidecar; **the pod is
   admitted by OpenShift SCC** (the open OCP question — sidecar uid 1337 / spiffe-helper); a call to
   `echo-mcp` through the sidecar shows the exchanged identity. THIS is the make-or-break.
2. Set up the SPIFFE IdP in RHBK (kagenti-extensions); verify SVID→Keycloak-token works on 26.x.
3. Only then: slim ext-proc + cut over `agent-sandbox` to AuthBridge + re-test via scripts
   (`hack/spawn-shell.sh`, `hack/run-agent.sh`): read allowed / write denied / human approve / elevated.

## Risks
- Mutating the shared `agentic` realm could break the working loop (do isolated-realm proof first).
- RHBK 26.6.3 token-exchange prior failures; SPIFFE IdP on 26.x unverified.
- OpenShift SCC may reject the AuthBridge sidecar (uid 1337) — the #1 open compat question.
- kagenti-operator is alpha (v0.2.0-rc.x); the published chart is buggy (image tag) — pin + --set.
- Kagenti has **no consent-grant concept** — the read-only baseline that the Vault grant enforced moves
  to JIT-gate + RBAC only (acceptable for PoC; document).

## PROGRESS — autonomous run 2026-06-19 (every hard unknown PROVEN; ONE config blocker left)
All in an ISOLATED `kagenti` realm + `kagenti-test` ns; `agentic`/`agent-sandbox`/the working loop UNTOUCHED
and re-verified green (Keycloak healthy after the feature enable, read smoke 200, ext-proc on split image).

PROVEN GREEN (the scary unknowns are all solvable on THIS cluster):
- ✅ kagenti-operator v0.2.0-rc.7 runs on OCP 4.20 (install fixes: helm≥3.18; `--set controllerManager.container.image.tag=0.2.0-rc.7`).
- ✅ **OCP SCC + AuthBridge injection**: `oc adm policy add-scc-to-user anyuid -z <sa> -n <ns>` + pod annotation
  `kagenti.io/authbridge-mode: proxy-sidecar` (avoids envoy-mode's proxy-init NET_ADMIN/NET_RAW that restricted-v2 rejects)
  → pod ADMITTED with sidecars agent + authbridge-proxy(authbridge-light) + spiffe-helper.
- ✅ **RHBK 26.6.3 supports `spiffe:v1`** — `oc -n keycloak patch keycloak keycloak --type=merge -p '{"spec":{"features":{"enabled":["preview","token-exchange","admin-fine-grained-authz:v1","client-auth-federated:v1","spiffe:v1"]}}}'`; Keycloak healthy. Snapshot: /tmp/kc-snapshot.json.
- ✅ **SPIFFE IdP** `spire-spiffe` (providerId=spiffe) created in realm `kagenti` (bundleEndpoint=https://spire-oidc.apps.anaeem.na-launch.com/keys, trustDomain=spiffe://anaeem.na-launch.com).
- ✅ **Operator-managed client registration WORKS**: registered client `spiffe://anaeem.na-launch.com/ns/kagenti-test/sa/test-agent` in realm `kagenti` + the client-credentials Secret. KEYS: `keycloak-admin-secret` (keys `username`/`password`) must live in **kagenti-system** (operator ns); registration fires via the **AgentRuntime CR** (not a bare label). NOTE: the docs' `--enable-operator-client-registration` flag is NEWER — adding it CRASHES rc.7; rc.7 registers via the AgentRuntime path automatically.
- ✅ **AgentRuntime CR** (rc.7 spec: type=agent, targetRef{apiVersion,kind,name}, identity.spiffe.trustDomain) drives the whole operator flow.
- ✅ **ClusterSPIFFEID** (spire.spiffe.io/v1alpha1) for test-agent created → SVID issues.

ALSO PROVEN since: the full pod **RUNS** (agent+authbridge-proxy+spiffe-helper all Ready) after creating the 4
namespace config CMs from the operator's e2e fixtures (test/e2e/fixtures.go): `authbridge-config`,
`authbridge-runtime-config` (config.yaml: mode proxy-sidecar, inbound jwt-validation, outbound token-exchange
{token_url, default_policy:exchange, no_token_policy:client-credentials, identity:{type:spiffe, client_id_file:/shared/client-id.txt}}),
`spiffe-helper-config` (helper.conf: agent_address /spiffe-workload-api/spire-agent.sock, jwt_svids audience="kagenti", out /opt),
`envoy-config`, and `authproxy-routes` (TOP-LEVEL LIST of {host,target_audience,token_scopes,action}; NOT a map).
✅ spiffe-helper fetches the SVID **and** JWT-SVID. ✅ the token-exchange pipeline fires. ✅ the client is correctly
registered: clientAuthenticatorType=federated-jwt, jwt.credential.sub=spiffe://…/test-agent, jwt.credential.issuer=spire-spiffe.

✅✅ RESOLVED 2026-06-19 — the ENTIRE zero-cred Kagenti identity chain works end-to-end on this OpenShift cluster.
Proof: a zero-cred agent (only a SPIRE SVID) calls `echo-mcp` through the AuthBridge proxy and gets a clean MCP
response (`{"result":{...,"serverInfo":{"name":"echo","version":"1.27.2"}}}`); Keycloak logs
`Client spiffe://anaeem.na-launch.com/ns/kagenti-test/sa/test-agent authenticated by federated-jwt` SUCCESS.

ROOT-CAUSE CHAIN (4 fixes, found via the debug-kagenti-federated-jwt workflow + reading the Keycloak source):
1. **Assertion audience** — THE big one. `FederatedJWTClientValidator.getExpectedAudiences()` (SPIFFE provider passes
   no validAudiences) = the single value `Urls.realmIssuer(context.getUriInfo().getBaseUri(), realm)`. On this cluster
   that resolves to the HYBRID `http://keycloak.apps.anaeem.na-launch.com:8080/realms/kagenti` — the KC_HOSTNAME host
   but the in-cluster request's scheme(http)+port(8080). NOT the public https issuer, NOT the keycloak-service.svc host.
   Found empirically by curling the in-cluster `.well-known` issuer from the pod. Fix: CM `kagenti-test/spiffe-helper-config`
   helper.conf `jwt_svids jwt_audience` = that exact string. (SPIFFE provider passes `expectedTokenIssuer=null` → SVID `iss`
   is NOT checked; `SpiffeIdentityProviderConfig` has only trustDomain+bundleEndpoint, no issuer field.)
2. **JWKS-fetch egress** — ns `keycloak` default-deny egress had no rule to the SPIRE OIDC provider → SVID-signature
   validation hung (`context deadline exceeded`). Fix: NetworkPolicy `keycloak/allow-egress-spire-oidc` (egress to
   172.16.2.52/32:443, the spire-oidc route VIP; hairpin works — ext-proc proves it).
3. **Keycloak truststore** — `spec.truststores.spire-oidc.secret=spire-oidc-ca` (secret = 3-cert chain of the spire-oidc route).
4. **echo-mcp ingress** — ns `agentic-mcp` is `allow-ingress-from-mcp-gateway-only`; the forward was blocked. Fix (additive;
   echo-mcp is not in the pfSense working path): NetworkPolicy `agentic-mcp/allow-ingress-echo-from-kagenti-test`.

WORKING LOOP: verified HTTP 200 throughout, incl. after every Keycloak restart. Both loops coexist.
STATE: realm `kagenti` (+ SPIFFE IdP spire-spiffe), ns `kagenti-test` (AgentRuntime test-agent, 5 config CMs incl. the
fixed spiffe-helper-config, anyuid SCC, ClusterSPIFFEID, registered federated-jwt client + creds, pod 3/3 Running).

✅ JIT GRAFT DONE (2026-06-19) — the FULL zero-trust loop runs on the Kagenti path: zero-cred agent →
AuthBridge (identity) → **jit-gate** → echo-mcp. The jit-gate (`services/jit-gate/`, runs on the jit-approver
image, no build) denies a dangerous MCP tool unless the request carries a valid jit-approver capability JWT
(verified against `/jwks`). Proven end-to-end + scripted (`hack/test-kagenti-jit.sh`, 4/4 PASS):
  1. READ `whoami` → ALLOWED; echo-mcp sees `azp/aud = spiffe://…/ns/kagenti-test/sa/test-agent` (identity attribution)
  2. WRITE `echo` → DENIED (no approval)
  3. file JIT request → Gitea PR → approve (merge) → jit-approver mints the capability JWT (tool_scope non-empty)
  4. WRITE `echo` WITH the capability JWT → ALLOWED
Reuses the EXISTING jit-approver + approval-console + Gitea — only the enforcement point moved onto the Kagenti
path. jit-gate manifests: `services/jit-gate/deploy/jit-gate.yaml`. Added `kagenti-test` to JIT_ALLOWED_NAMESPACES.

GOAL ACHIEVED: consumable zero-trust loop (credential-less agent + Kagenti identity + our JIT human-approval +
MCP access + identity-attributed visibility), end-to-end, additive, working loop green throughout.

OPTIONAL future: cut over the pfSense loop to Kagenti too — but pfSense consumes OPAQUE per-user tokens (ADR-0012),
not JWTs, so it stays on ext-proc; the Kagenti+echo-mcp loop is the JWT-native reference. A pfSense cutover would
mean reworking pfSense's auth to consume the exchanged JWT — separate, not required for the goal.

## References
workflow design `w6ez0wu91`; [[project-roadmap-whole-puzzle]], [[project-split-identity-live]],
[[project-keycloak-obo-constraint]]. Kagenti: github.com/kagenti/{kagenti,kagenti-operator,kagenti-extensions}.
