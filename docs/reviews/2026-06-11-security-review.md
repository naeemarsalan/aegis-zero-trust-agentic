# Security Review — nvidia-ida platform (adversarial)

- **Date:** 2026-06-11
- **Reviewer:** security reviewer (adversarial pass)
- **Scope:** services/ext-proc-delegation, platform/vault/config, services/jit-approver,
  platform/kyverno/authz, platform/networkpolicies, secrets hygiene
- **Invariants checked:** zero-trust; no credentials in etcd/git/agent pods; dynamic
  short-lived creds; fail-closed everywhere; default-deny NetworkPolicies; audit to Loki
  with tool args hashed; downstream MCP servers see the USER identity, never the agent's.

Severity legend: **CRITICAL** (violates a non-negotiable invariant — credential passing,
fail-open, identity spoofing), **HIGH**, **MEDIUM**, **LOW**, **INFO**.

Note on fixes: no purely typo-level safe fix existed in the reviewed surface, so nothing
was auto-applied. Every item below is left for the owning team. Several items are
documentation/contract corrections that are safe but were left un-applied because they
change a stated security contract and the team should ratify the corrected wording.

---

## Summary counts

- CRITICAL: 4
- HIGH: 5
- MEDIUM: 6
- LOW: 4
- INFO: 3

---

## CRITICAL

### C1. ext-proc trusts UNVERIFIED JWT claims from the Authorization header; this is the entire identity basis for delegation
**File:** `services/ext-proc-delegation/internal/claims/claims.go:5-6,98-113`
**Finding:** `parseJWT` base64-decodes the JWT payload and extracts `sub`, `groups`, `iss`
with the comment "Signature verification is intentionally SKIPPED." The resulting identity
is then (a) audited as `caller_user`, and (b) used as `identity.Raw` — the *subject_token*
that is exchanged at Keycloak and ultimately injected as the downstream
`Authorization: Bearer`. The trust assumption is "agentgateway already validated the token."
But the gateway policy (`platform/agentgateway/base/policy.yaml`) only forwards validated
claims to the **ext_authz (Kyverno)** backend via `requestMetadata: dev.agentgateway.jwt`
(lines 84-85) — it does **not** configure that metadata under `extProc`. So in practice
ext-proc receives no `dev.agentgateway.jwt` metadata and falls through to parsing the raw
Authorization header (claims.go:54-60), which it never signature-verifies. The stream test
even exercises an `alg:none` token (`extproc_stream_test.go:62`) and it is accepted.
**Why CRITICAL:** if anything on the path between the JWT-validation edge and the ext-proc
hop can set/replace the Authorization header (header smuggling, a misconfigured route that
forwards a client-supplied header, or a second untrusted gateway hop), ext-proc will mint a
downstream user token for an attacker-chosen `sub`/`groups`. The "downstream sees the USER
identity, never the agent's" invariant becomes "downstream sees whatever sub the header
claimed."
**Compounding bug:** the metadata path is also functionally dead — `parseAgentGatewayMeta`
(claims.go:86) sets `Identity.Raw = ""`, and the exchange leg requires `identity.Raw != ""`
(server.go:158) or it returns an error => deny. So if `dev.agentgateway.jwt` were the active
identity source, *every* request would be denied; the only path that actually mints a
downstream token is the unverified-Authorization-header path. This makes the unverified
header the de-facto sole identity source today.
**Recommended fix:**
1. Make ext-proc consume identity **only** from a gateway-trusted, signature-validated
   channel. Either (a) wire `dev.agentgateway.jwt: jwt.claims` into the `extProc`
   processing options (mirroring extAuth) and treat the metadata as the *sole* identity
   source, removing the Authorization-header fallback; or (b) verify the JWT signature in
   ext-proc against the Keycloak JWKS (iss/aud/exp) before trusting any claim.
2. Until then, do not derive `identity.Raw` (the exchange subject_token) from an unverified
   header. Note explicitly in the threat model that ext-proc has *no* independent identity
   assurance.

### C2. JIT issuance uses the in-memory request, NOT the PR-reviewed scope (TOCTOU / approval bypass)
**File:** `services/jit-approver/src/jit_approver/vault.py:101-204`,
`services/jit-approver/src/jit_approver/webhook.py:155-176`
**Finding:** On PR merge the webhook resolves the session and calls
`issue_credentials(session_id)`, which reads `session["request"]` — the `EscalationRequest`
captured at `POST /requests` time (api.py:75-82) — and builds the grant from
`req.namespace / req.verbs / req.resources / req.duration_minutes`. The committed,
human-reviewed `grants/<session>.yaml` in the PR is **never read back**. A reviewer who
edits the YAML to narrow the scope before merging has zero effect: the original requested
scope is what gets issued. There is also no re-validation of the request against the
ceiling at issue time.
**Why CRITICAL:** the approval channel (Gitea PR merge) is the *only* authorization gate for
privileged credential issuance. If the thing issued is not the thing reviewed, the approval
is meaningless against an attacker who can mutate the in-memory request or who relies on the
reviewer trusting the diff. This is the canonical confused-deputy/TOCTOU on a credential
mint.
**Recommended fix:** at issue time, fetch the merged `grants/<session>.yaml` from the
default branch (the reviewed artifact), parse it, and issue strictly from it — OR re-run the
pydantic `EscalationRequest` validation on the in-memory request AND assert that its
serialized scope byte-for-byte matches the committed YAML's `spec.requestedScope`. Refuse to
issue on any mismatch (fail-closed).

### C3. The dangerous-tool JIT gate is satisfiable by an attacker-chosen header value
**File:** `platform/kyverno/authz/base/dangerous-tools-admins-only.yaml:60-79`
**Finding:** `hasJitSession` is `"x-jit-session" in headers && headers["x-jit-session"] != ""`.
The validation allows a dangerous (write/mutating) pfSense tool iff `isMcpAdmin &&
hasJitSession`. There is **no** verification that the session ID corresponds to a real,
approved, unexpired JIT session in jit-approver. The annotation claims the header "prov[es]
an active JIT approval session exists" (lines 14-16) — it does not. Any `mcp-admins` member
can send `X-JIT-Session: x` and clear the gate.
**Why CRITICAL:** the JIT approval requirement for destructive firewall changes collapses to
"set a non-empty header," nullifying the Gitea PR approval flow for the exact operations it
is meant to protect.
**Recommended fix:** validate the session out-of-band — either have ext-proc/agentgateway
inject a signed/HMAC'd `X-JIT-Session` that the policy can verify, or have the Kyverno authz
server (it already makes egress calls) confirm the session is `issued` and unexpired against
`jit-approver.mcp-gateway.svc:8080`. Fail-closed if the session is unknown/expired. At
minimum, correct the annotation so operators do not believe a real check exists.

### C4. JIT webhook has no replay/idempotency/state guard — re-merge or webhook redelivery re-mints K8s credentials
**File:** `services/jit-approver/src/jit_approver/webhook.py:155-176`,
`services/jit-approver/src/jit_approver/vault.py:132-172`
**Finding:** `handle_gitea_webhook` calls `issue_credentials(session_id)` on every verified
`pull_request closed+merged` event with the right repo/branch/label, with **no check of the
current session state**. Gitea redelivers webhooks on retry/timeout, and a PR can be
reopened+remerged. Each call POSTs `kubernetes/creds/jit-scoped` again, minting a **new**
short-lived SA token (the creds call has no `cas` guard). Only the subsequent KV store uses
`options.cas=0` (vault.py:169), which *fails* on the second write — so the second (and
later) credential is minted but its tracking record is never written, producing an
**untracked, un-revocable-by-this-system credential lease**.
**Why CRITICAL:** uncontrolled minting of privileged credentials from a single approval, plus
loss of the audit/tracking record for the duplicates. Violates "dynamic short-lived creds"
governance and the single-approval-single-grant intent.
**Recommended fix:** guard issuance on session state — only issue when state is `pending`/
`approved`; transition to `issued` atomically before (or as part of) the mint; treat any
non-pending session as a no-op (return 200 idempotently). Add a webhook delivery-ID
dedupe. Ensure a failed KV store revokes the just-minted lease.

---

## HIGH

### H1. ext-proc fail-OPEN when no RequestBody is delivered
**File:** `services/ext-proc-delegation/internal/extproc/server.go:87-114,211-237`
**Finding:** The exchange + Vault legs (the only place a downstream token is minted and the
only deny-on-error path) run **exclusively** in the `RequestBody` case. The `RequestHeaders`
case unconditionally ACKs and continues (lines 106-114). If Envoy/agentgateway delivers
`RequestHeaders` then jumps to `ResponseHeaders` (e.g. a body-less request, a zero-length
body that the gateway elects not to stream, a `requestBodyMode` downgrade, or a streamed
upstream that the proxy forwards before ext-proc sees a body), the request reaches the
upstream MCP server with **no delegation, no exchange, and no deny** — and ext-proc then
emits an `allow` audit at ResponseHeaders with `downToken==""` (`credential_injected:false`).
The gateway policy sets `requestBodyMode: Buffered`, which mitigates in the happy path, but
the service itself does not enforce that a body+exchange occurred before allowing the
response leg. There is no test for the body-less path.
**Recommended fix:** track per-stream that the exchange/vault legs ran and succeeded; in the
`ResponseHeaders` case, if delegation did not happen, return an ImmediateResponse 403 (or at
minimum emit a `deny`). Treat "ResponseHeaders before a successful RequestBody exchange" as
a fail-closed condition. Add a regression test for a body-less request.

### H2. Vault JWT auth `default_role` points at a (non-existent) privileged-ish role
**File:** `platform/vault/config/vault-bootstrap.sh:81-83`
**Finding:** `auth/jwt/config` sets `default_role="ext-proc"`. No role named `ext-proc` is
created (the role is `ext-proc-delegation`). Setting a `default_role` means any successful
JWT login that omits an explicit `role` resolves to that role's policies. Today the dangling
name fails closed, but this is a latent footgun: if anyone later creates an `ext-proc` role
(name collision with the policy name), every SPIRE-SVID-holding workload that can reach the
JWT endpoint could log in *without naming a role* and inherit it.
**Recommended fix:** remove `default_role` entirely (force callers to name a role), or point
it at an explicit deny-only role with no policies and tightly bound subject/audience.

### H3. jit-scoped Vault role grants are STATIC; PR and code imply per-request scoping that Vault does not honor
**File:** `platform/vault/config/vault-bootstrap.sh:121-140`,
`services/jit-approver/src/jit_approver/vault.py:132-140,196-204`,
`services/jit-approver/src/jit_approver/gitea.py:111-152`
**Finding:** The Vault kubernetes secrets-engine role `jit-scoped` has fixed
`generated_role_rules` (get/list/watch on pods + deployments) and fixed
`allowed_kubernetes_namespaces`. The approver POSTs `role_rules` and `kubernetes_namespace`
overrides per request (vault.py:135-139, `_build_role_rules`), but the
`kubernetes/creds/<role>` endpoint does **not** accept a `role_rules` override — that field
is silently ignored. So whatever verbs/resources the requester put in the PR (and that the
reviewer approved), the credential actually issued is always the static role rules. The PR
body (gitea.py:111-152) advertises the requester's verbs/resources as "what will actually be
issued," which is false.
**Why HIGH (not just doc):** reviewers approve based on a scope that is not the scope
enforced. The fail-safe direction (issued ⊆ advertised) holds today, but the moment the
static role is loosened or `kubernetes_namespace` (which *is* honored) is widened, the gap
becomes exploitable. The mismatch also defeats meaningful review.
**Recommended fix:** make the relationship explicit and enforced. Either (a) create one Vault
role per allowed scope and select the role from the reviewed YAML, or (b) keep a single
static role and have the PR/audit advertise the *actual* static rules (not the requester's
asked-for verbs), and reject requests whose asked-for scope exceeds the static role. Pair
with C2's "issue from reviewed artifact."

### H4. Kyverno group-claim policies read `Claims["groups"]` without asserting `decodedJwt.Valid`
**File:** `platform/kyverno/authz/base/dangerous-tools-admins-only.yaml:38-41`,
`deny-restricted-group.yaml:36-39`, `tool-allowlist-mcp-users.yaml:37-41`
**Finding:** Only `no-unauthenticated-calls.yaml` checks `decodedJwt.Valid` (line 58). The
three tool/group policies decode the JWT against JWKS but then branch purely on
`Claims["groups"]` without first asserting `.Valid`. If `jwt.Decode` returns a struct with
populated `.Claims` but `.Valid==false` for an expired/not-yet-valid/aud-mismatched token,
these policies would trust the groups. The deny-restricted policy is the worst case: an
expired token for a `restricted` user might decode with groups present but `.Valid==false`
and slip the hard block (depending on Kyverno's `jwt.Decode` semantics on invalid tokens).
**Residual-trust note:** signature/`alg=none` rejection is delegated to the gateway's Strict
JWT auth, which is acceptable as a stated boundary — but these policies are defense-in-depth
and should not themselves trust an unvalidated decode.
**Recommended fix:** gate every `Claims[...]` read behind `variables.decodedJwt.Valid &&
variables.jwtString != ""`, and make the default branch deny when invalid (especially in
`deny-restricted-group`, which must fail to *deny* on an unparseable/invalid token).

### H5. JIT approval/denial decisions are never audited
**File:** `services/jit-approver/src/jit_approver/audit.py:118-128,161-170` (defined),
`services/jit-approver/src/jit_approver/webhook.py`, `.../api.py` (callers absent)
**Finding:** `emit_approved` and `emit_denied` are defined but never called anywhere. The
moment a PR-merge authorizes a privileged credential mint (the security-relevant decision
boundary) produces **no audit event**; only the later `jit_issued` is logged. PR-closed-
without-merge (a denial) produces nothing. This violates "audit to Loki" for the most
sensitive transition in the JIT flow and breaks incident correlation (who merged, when,
which PR).
**Recommended fix:** call `emit_approved(session_id, merged_by, pr_number)` in the webhook
right after merge verification and before/around issuance; wire `emit_denied` for the
closed-not-merged and validation-rejection paths.

---

## MEDIUM

### M1. ext-proc emits `allow` audit even when no credential was injected
**File:** `services/ext-proc-delegation/internal/extproc/server.go:225-237`
**Finding:** The ResponseHeaders allow-audit runs unconditionally and reports
`credential_injected = downToken != ""`. On the H1 body-less path this logs `allow` with
`credential_injected:false` — an allowed call with no delegation, which should have been a
deny. The audit therefore can record a security-relevant fail-open as a successful allow.
**Recommended fix:** couple to the H1 fix — only emit `allow` when delegation succeeded;
otherwise emit `deny`.

### M2. ext-proc audit log line stops short of the SPIFFE agent identity
**File:** `services/ext-proc-delegation/internal/extproc/server.go` (no `SetAgent` call),
`internal/audit/audit.go:118-121`
**Finding:** `Emitter.SetAgent(spiffeID, sub)` exists but is never called in the stream
handler; the workload's own SPIFFE SVID (available via the X509/JWT source in main.go) is
not recorded. The audit thus cannot attribute which agent workload drove a delegation,
weakening the "downstream sees user, agent is recorded separately" story for forensics.
**Recommended fix:** populate `SetAgent` from the validated SVID (peer identity) on each
stream.

### M3. Vault NetworkPolicy allows ingress from agent-sandbox to Vault :8200
**File:** `platform/networkpolicies/base/np-vault.yaml` (allow-ingress-from-injector-consumers)
**Finding:** The injector-consumers ingress allow includes `agent-sandbox` (and
`agentic-mcp`) among the namespaces permitted to reach Vault on 8200. This directly
contradicts the stated invariant ("agents have NO direct path to Vault," echoed in
`np-agent-sandbox.yaml`) and `agent-deny.hcl`. It is currently inert because
`np-agent-sandbox.yaml` has no matching **egress** allow to vault (egress default-deny blocks
it), but it weakens the L3/4 belt-and-suspenders posture and is a latent hole if an egress
rule is ever added.
**Recommended fix:** remove `agent-sandbox` (and `agentic-mcp`, unless an injected workload
there genuinely needs it) from the Vault injector-consumers ingress list. Keep only the
namespaces that actually run Vault-Agent-injected platform pods. Document which workloads
require it.

### M4. ext-proc does nothing with the fetched Vault secret; downstream credential injection is unclear
**File:** `services/ext-proc-delegation/internal/extproc/server.go:171-185`
**Finding:** The Vault leg fetches the tool secret only to gate the request (error => deny),
then discards the data (`_, err := s.vault.FetchToolSecret(...)`). The downstream MCP server
is given the exchanged **user** token via Authorization, which is correct for identity
propagation — but the tool's own API credential (e.g., pfSense api_key in
`secret/data/mcp-tools/pfsense`) is fetched and thrown away. Either the secret is injected
somewhere not shown (then this is fine) or the fetch is a pure liveness probe of Vault. If
the latter, the design intent ("fetch tool secrets, inject downstream") is unmet and the
pfSense API key path is unused — worth confirming the credential never needs to flow.
**Recommended fix:** clarify intent. If the tool credential must reach the upstream, inject
it deliberately (and ensure it is stripped from any response). If it must not, drop the
fetch or document it as a fail-closed Vault reachability check.

### M5. Webhook accepts the merge before confirming the merger's authority
**File:** `services/jit-approver/src/jit_approver/webhook.py:120-176`
**Finding:** Approval = "PR merged with label `jit-approval` on `main` of the right repo."
There is no check on **who** merged (e.g., that the merger is not the same identity as the
requester, or is in an approver group), nor that branch protection / required reviews were
satisfied. With a Gitea token that can merge, a self-approval is possible. The `merged_by`
login is logged but not enforced. The HMAC verification (good) only proves the payload came
from Gitea, not that the merge was authorized.
**Recommended fix:** enforce approver authority — reject if `merged_by == requester`, and/or
require that Gitea branch protection mandates an independent reviewer. Consider verifying via
the Gitea API that required approvals were met rather than trusting the merge event alone.

### M6. `read_secret`/token files trimmed but no length/format sanity; empty exchange secret yields silent basic-auth with empty password
**File:** `services/ext-proc-delegation/internal/keycloak/exchange.go:108-151`
**Finding:** `readSecret()` errors only on empty path or unreadable file, not on empty
*content*. A zero-byte `client-secret` file (e.g., Vault template rendered empty) produces
`SetBasicAuth(clientID, "")`, which Keycloak rejects (401) — fail-closed, OK — but the 401
is retried/surfaced as a generic exchange error, masking a credential-provisioning failure as
a transient auth error. Minor, but worth a clearer signal.
**Recommended fix:** treat empty secret content as a configuration error distinct from a
Keycloak auth failure.

---

## LOW

### L1. Placeholder secret manifest committed with a literal value
**File:** `platform/observability/alerts/base/eda-webhook-secret.yaml:21-24`
**Finding:** A `kind: Secret` with `stringData.bearer-token: "CHANGEME"` is git-tracked.
It is clearly a placeholder and well-commented, but committing a `Secret` manifest (even with
CHANGEME) invites accidental `kustomize build | oc apply` of a real value later, and is an
anti-pattern vs. ExternalSecret/Vault injection used elsewhere.
**Recommended fix:** replace with an `ExternalSecret` (the README already documents the Vault
path) or move the placeholder to an overlay/example file excluded from the apply path.

### L2. jit-approver SVID path mismatch (functional, fails closed)
**File:** `services/jit-approver/deploy/base/deployment.yaml` (SPIFFE CSI mount
`/var/run/secrets/spiffe.io/`) vs `SVID_JWT_PATH=/var/run/secrets/svid.jwt`, and
`vault.py:37,52-63`
**Finding:** The env var points the loader at `/var/run/secrets/svid.jwt`, but the SPIFFE CSI
volume is mounted at `/var/run/secrets/spiffe.io/`. The JWT-SVID file location will not match,
so Vault login fails (fail-closed, no security exposure) but the JIT issuance path is broken
as deployed.
**Recommended fix:** align `SVID_JWT_PATH` with the CSI driver's actual JWT-SVID file path,
or fetch the SVID via the workload API socket (py-spiffe) as the README suggests.

### L3. In-memory session store loses all pending JIT state on restart / cannot scale
**File:** `services/jit-approver/src/jit_approver/store.py`
**Finding:** `session_store` is a process-local dict. A pod restart between PR-create and
PR-merge orphans the session: `_find_session_for_pr` returns None and the merge is silently
ignored ("no session found"), and the PR-to-session binding for the C4 replay concern is also
lost. Acceptable for SNO PoC per the doc note, but it means approval events can be silently
dropped (availability + audit gap).
**Recommended fix:** back the store with CNPG/Redis for durability before any non-PoC use;
until then, emit an audit/alert when a merge arrives for an unknown PR (currently only a warn
log).

### L4. PR number collision could bind a merge to the wrong session
**File:** `services/jit-approver/src/jit_approver/webhook.py:87-92`,
`services/jit-approver/src/jit_approver/api.py:88-93`
**Finding:** `_find_session_for_pr` matches the first session whose `pr_number` equals the
merged PR number. `_extract_pr_number` can return `None` on a malformed URL; multiple
sessions with `pr_number=None` would all "match" a `None` lookup is avoided (merge always has
a real number), but if `_extract_pr_number` ever mis-parses two PRs to the same int, the
wrong session (and thus wrong scope) would be issued. Low likelihood, but it compounds C2.
**Recommended fix:** key the lookup on the repo-qualified PR id from the webhook payload and
assert a 1:1 session↔PR invariant at creation.

---

## INFO / residual trust (by design, noted)

### I1. Signature/`alg=none` rejection is delegated to the gateway's Strict JWT auth
The Kyverno policies and ext-proc both lean on agentgateway `jwtAuthentication.mode: Strict`
to reject forged/`alg=none` tokens at the edge. This is a reasonable boundary, but it makes
the gateway the single point whose compromise/misconfig (e.g., dropping Strict, or a route
that bypasses the policy) silently removes signature assurance from everything downstream
(see C1, H4). Keep the gateway policy under change control and add a negative test that the
route cannot be reached without passing jwtAuthentication.

### I2. Vault policies are correctly least-privilege and deny-by-default
`ext-proc.hcl` (read-only on `secret/data/mcp-tools/*`), `jit-approver.hcl`
(`kubernetes/creds/jit-scoped` create/update + `secret/data/jit/*` read), and
`agent-deny.hcl` (deny `*`) are tight and each ends with an explicit `path "*" { deny }`.
The agent self-issue question is answered: no agent policy path grants any capability, and
the JWT roles are `bound_subject`-pinned to the exact SPIFFE IDs with 15m TTLs. Good.

### I3. NetworkPolicies are default-deny per namespace with explicit allows; agent-sandbox egress is correctly minimal
Every platform namespace has a `default-deny-all` (ingress+egress) policy plus scoped allows.
`agent-sandbox` egress is limited to mcp-gateway, jit-approver (:8080), kube-API ClusterIP
(:6443/:443), and DNS — with **no** egress to vault, keycloak, or agentic-mcp, satisfying the
"agents never contact credential stores or MCP servers directly" invariant at L3/4. The only
weakening is M3 (vault-side ingress list). CNPG bootstrap exception (keycloak-db-app password
in etcd) is explicitly documented in `platform/keycloak/base/cnpg-cluster.yaml:9-10` and the
keycloak README — acceptable and disclosed. No secrets are git-tracked (`.gitignore` covers
`.env`, `*.pem`, `*.key`, kubeconfigs; `git ls-files` shows none).

---

## Cross-cutting recommendation

The two highest-leverage fixes are **C1** (ext-proc must not trust unverified header claims —
this is the root of the identity-spoofing exposure) and **C2/H3** (issue strictly from the
reviewed artifact and make the Vault role scope match what reviewers see). Together they
restore the two core invariants: "downstream sees the real USER identity" and "what is
approved is what is granted." C3 and C4 close the JIT gate bypass and the credential-replay
hole. None of these are theoretical given the current wiring.
