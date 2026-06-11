# Security Review — ADDENDUM (fix verification)

- **Date:** 2026-06-11
- **Reviewer:** security reviewer (adversarial verification pass)
- **Base review:** `docs/reviews/2026-06-11-security-review.md` (22 findings; C1–C4, H1–H5)
- **Scope of this addendum:** verify the claimed closures of **C1, C2, C3, C4, H1,
  H2, H3, H4, H5, M3** by reading the actual changed code/config — not the fixers'
  claims. Each finding is graded **CLOSED / PARTIAL / OPEN** with file:line evidence,
  plus any NEW issue the fixes introduced.

## Verification method

- Read every changed source/config file directly (no reliance on fixer notes).
- Ran the ext-proc Go suite: `cd services/ext-proc-delegation && go build ./... && go test ./...`
  → build OK; all packages **PASS** (claims, extproc, jwks, keycloak, vault, inject, mcp).
- Ran the jit-approver Python suite: `services/jit-approver/.venv/bin/python -m pytest tests/ -q`
  → **45 passed**.
- Kyverno authz policies graded by reading CEL logic + the kyverno-json expectations in
  `platform/kyverno/tests/authz/test.yaml`. `kyverno-json`/`chainsaw` are not installed
  in this environment, so policy *behavior* is verified by static reading, not execution.

## Grade summary

| Finding | Grade | One-line basis |
|--------|-------|----------------|
| C1 | **CLOSED** | ext-proc now independently verifies sig/iss/aud/exp against Keycloak JWKS; no unverified-header path; metadata cross-check fails closed. |
| C2 | **CLOSED** | Issuance fetches the merged `grants/<session>.yaml`, re-validates through the pydantic ceiling, and mints from THAT; in-memory `session['request']` is never read at issue time. |
| C3 | **PARTIAL** | Bypass is gone (non-empty header no longer passes; a cryptographically valid signed JWT is required) → fail-closed. BUT the positive path is unimplemented: nothing mints/serves/injects `X-JIT-Session-JWT`, so dangerous tools are now permanently un-approvable. |
| C4 | **CLOSED** | Delivery-id dedupe + atomic once-only state flip under `store_lock`; terminal states no-op idempotently; KV `cas` removed so a duplicate cannot leave an untracked lease. |
| H1 | **CLOSED** | Body-less/empty-body/headers-only paths all deny 403; `delegationDone` gate at ResponseHeaders; tests cover all three. |
| H2 | **CLOSED** | `default_role` removed from `auth/jwt/config`. |
| H3 | **PARTIAL** | Per-session ephemeral role makes advertised==enforced and the approver policy matches — good. BUT three new problems (see below): KV-write capability mismatch breaks issuance; ephemeral Vault role is never cleaned up by the reaper; `generated_role_rules` hardcodes the core apiGroup. |
| H4 | **CLOSED** | All three group policies now gate `Claims["groups"]` on `decodedJwt.Valid`; `deny-restricted-group` fails closed (denies) on invalid/absent token. |
| H5 | **CLOSED** | `emit_approved` called at verified merge; `emit_denied` called on closed-not-merged, re-validation failure, and edge 422 ceiling rejection. |
| M3 | **CLOSED** | `np-vault.yaml` injector-consumers ingress no longer lists `agent-sandbox`/`agentic-mcp`. |

---

## CRITICAL

### C1 — ext-proc trusted unverified JWT claims → **CLOSED**

Evidence:
- `services/ext-proc-delegation/internal/jwks/jwks.go:121-174` — `Verify()` parses with
  `jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})` (rejects `alg=none`/algorithm
  confusion at parse, line 128), resolves the signing key by `kid` from the cached JWKS
  (`keyForKID`, lines 178-197), verifies the signature via `tok.Claims(key, …)` (line 148),
  then validates `iss` + audience + exp/nbf with leeway (`std.ValidateWithLeeway`, lines 153-160),
  and rejects an empty `sub` (lines 162-165). Keys are TTL-cached with a single forced refresh
  on unknown `kid` (lines 188-196), failing closed if still absent.
- `services/ext-proc-delegation/internal/claims/claims.go:71-111` — `FromContext` requires a
  verifier (nil ⇒ error, lines 72-74), extracts the Bearer token, calls `v.Verify`, and sets
  `Identity.Raw = verified.Raw` (the **verified** token, line 91) — the old base64-decode /
  "signature verification intentionally SKIPPED" path is gone. Metadata is parsed only as a
  cross-check; on disagreement OR unparseable metadata it returns `ErrMetadataMismatch`
  (lines 95-108) → caller denies.
- `services/ext-proc-delegation/internal/extproc/server.go:109-115` — on any identity error the
  stream returns an ImmediateResponse **401** and emits a `deny` audit. There is no
  unverified fallback.
- Wiring confirmed: `cmd/server/main.go:76-91` builds the `jwks.Verifier` from
  `KEYCLOAK_JWKS_URL` / `KEYCLOAK_ISSUER` / `EXPECTED_AUDIENCE` and passes it to
  `extproc.NewServer`. `config.go:97-105` makes all three mandatory (fail to start otherwise).
- Tests: `jwks_test.go` covers good / bad-signature / **alg=none rejected** (lines 72-83) /
  wrong-iss / wrong-aud / expired / not-yet-valid / empty-sub / unknown-kid-fail-closed.
  `extproc_stream_test.go` covers bad-token-401 and **metadata-mismatch-denies** (lines 316-354).
- Metadata-vs-token mismatch handled fail-closed: yes (`claims.go:104-106`, server returns 401).

### C2 — JIT issued from in-memory request, not the reviewed artifact → **CLOSED**

Evidence:
- `services/jit-approver/src/jit_approver/webhook.py:242-260` — after a verified merge the
  handler calls `_load_reviewed_request(session_id, _merge_ref(pr))`, then
  `issue_credentials(session_id, reviewed_req)`. `_merge_ref` (lines 118-127) prefers the
  **merge commit SHA**, falling back to the base branch.
- `services/jit-approver/src/jit_approver/gitea.py:329-347` — `fetch_merged_grant` reads the raw
  `grants/<session>.yaml` from that ref via the Gitea raw contents API; `parse_grant_yaml`
  (lines 355-392) rebuilds an `EscalationRequest`, which **re-runs the same pydantic ceiling
  validators** (verbs/resources/namespace/duration). Over-ceiling YAML raises ⇒ deny + audit.
- `services/jit-approver/src/jit_approver/vault.py:116-146` — `issue_credentials(session_id, req,…)`
  takes the reviewed `req` and never reads `session["request"]` (docstring + body confirm).
- Tests prove behavior, not just structure:
  - `tests/test_api.py:606-647` (`test_merged_yaml_edited_narrower_is_honored`) — reviewer narrows
    the YAML; the ephemeral-role `generated_role_rules`/`token_max_ttl` come from the **narrowed**
    scope (asserted on the captured Vault request body).
  - `tests/test_api.py:649-689` (`test_in_memory_request_not_used_for_issuance`) — `session["request"]`
    is a `_Boom` object that raises on any attribute read; issuance still succeeds off the merged
    YAML, proving the in-memory request is untouched.
  - `tests/test_api.py:691-730` (`test_merged_yaml_over_ceiling_denied`) — over-ceiling merged YAML
    denies, no Vault role/creds call, `emit_denied` invoked.

### C3 — dangerous-tool gate satisfiable by an attacker-chosen header → **PARTIAL**

What is fixed (the original CRITICAL bypass is closed, fail-closed):
- `platform/kyverno/authz/base/dangerous-tools-admins-only.yaml:123-130,140-146` — the gate now
  requires `hasValidJitSession`: a signed `X-JIT-Session-JWT` whose **signature validates against
  the jit-approver JWKS**, `decodedJitJwt.Valid` (exp/aud), `iss == jit-approver`, and the
  requested tool inside the `tool_scope` claim. A non-empty plain `X-JIT-Session` header is no
  longer sufficient. Missing/empty/invalid ⇒ 403. Regression test
  `mcp-admins-add-firewall-rule-invalid-jit-jwt` expects **fail** (`tests/authz/test.yaml:95-99`).

Why it is only PARTIAL (NEW gap — the positive path does not exist):
- **No component mints or serves the signed JWT.** The policy fetches the jit-approver JWKS at
  `http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks`
  (`dangerous-tools-admins-only.yaml:98-100`), but jit-approver exposes no `/jwks` route
  (`api.py:1-9` endpoint list, and the FastAPI app declares only `/requests`, `/status`,
  `/summary`, `/healthz`, `/metrics`, `/webhooks/gitea`). There is **no JWT signing and no
  `tool_scope` minting anywhere** in `services/jit-approver/src/` (grep for `jwks`/`tool_scope`/
  signing returns nothing in the service code).
- **ext-proc never injects `X-JIT-Session-JWT`.** `internal/inject/inject.go:25-46`
  (`BuildRequestMutation`) sets only `Authorization` and `X-Delegated-By`. No JIT-session header
  is produced; `server.go` only *reads* `x-jit-session` (line 99) and uses it as an audit
  correlation id.
- The passing kyverno test `mcp-admins-add-firewall-rule-with-jit` works **only because the
  kyverno-json harness mocks `jwt.Decode` to return `Valid:true`** for a fake token
  (`tests/authz/test.yaml:11-14`). In production no valid signed JWT can ever be presented, so
  the gate can **only deny** dangerous tools.
- **Net:** the credential-bypass vulnerability is genuinely closed and the direction is
  fail-closed (good), but the design now depends on a signed-session-JWT issuer + injector that
  are not implemented in either service. Grade PARTIAL: bypass closed, legitimate path unwired.
  (Alternatively, the annotation's claimed `apiCall`-to-jit-approver verification was never
  built; the signed-JWT substitute is documented but not produced.)

### C4 — webhook replay / re-mint of credentials → **CLOSED**

Evidence:
- Delivery-id dedupe: `webhook.py:148-153` records `X-Gitea-Delivery` in `seen_deliveries` under
  `store_lock`; a redelivery ACKs 200 and returns without processing.
- Once-only issuance: `webhook.py:220-233` claims the session under `store_lock` — only a
  non-terminal session flips to `issued`, and the flip happens **before** the network mint;
  terminal states (`issued`/`expired`/`denied`, `_TERMINAL_STATES` lines 56-59) no-op with 200.
  On mint failure the claim is rolled back to `approved` so a legitimate retry can proceed
  (lines 262-271).
- The untracked-lease bug is fixed: `vault.py:198-221` writes the KV tracking record with **no
  `cas` guard** (comment lines 215-219), so a second write can't be the thing that fails after a
  mint; once-only is enforced by the state machine, not KV cas.
- Tests: `test_duplicate_delivery_mints_once` (same delivery id) and
  `test_re_merge_distinct_delivery_mints_once` (distinct delivery id, already-issued session)
  both assert exactly one creds mint (`tests/test_api.py:740-821`).

---

## HIGH

### H1 — ext-proc fail-OPEN on body-less / empty request → **CLOSED**

Evidence (`services/ext-proc-delegation/internal/extproc/server.go`):
- `delegationDone` is set true only after BOTH legs minted a real downstream token (lines 82, 229).
- Empty/absent body denies 403 (lines 134-141); empty downstream token denies 403 (lines 223-226).
- ResponseHeaders fails closed: if `!delegationDone || downToken == ""` it emits a `deny` and
  returns ImmediateResponse 403 (lines 243-264) instead of an allow. No allow/inject with an
  empty token.
- Tests: `TestProcess_HeadersThenResponse_NoBody_FailsClosed`,
  `TestProcess_EmptyBody_FailsClosed`, `TestProcess_EmptyExchangeToken_Denies`
  (`extproc_stream_test.go:407-542`). (M1 — allow-audit-on-no-credential — is also resolved as a
  consequence: the allow audit at lines 278-291 is only reached after the fail-closed guard.)

### H2 — Vault `default_role` footgun → **CLOSED**

Evidence: `platform/vault/config/vault-bootstrap.sh:80-88` — the `auth/jwt/config` write sets only
`oidc_discovery_url`; `default_role` is removed with an explicit comment that every login must
name a role (fail closed). No `ext-proc`-named role exists.

### H3 — per-request Vault scope advertised but not enforced → **PARTIAL**

What is fixed (advertised==enforced; approver policy matches):
- Per-session ephemeral roles replace the static `jit-scoped` role: `vault.py:162-186` creates
  `kubernetes/roles/jit-<session>` with `generated_role_rules` = the approved verbs/resources,
  `allowed_kubernetes_namespaces=[req.namespace]`, and `token_*_ttl` from the approved window,
  then mints from that role. The static role is gone from bootstrap
  (`vault-bootstrap.sh:126-165`).
- Approver policy matches issuance: `platform/vault/config/jit-approver.hcl:26-28` grants
  create/update/**read/delete** on `kubernetes/roles/jit-*`, read on `kubernetes/creds/jit-*`
  (lines 39-41), and explicitly **denies** the old `jit-scoped` role/creds (lines 33-46).
- PR body advertises the *actual* enforced scope (`gitea.py:147-159`), and the merged YAML is
  re-validated (C2). So the H3 "reviewers approve a scope that isn't enforced" core is resolved.

NEW issues this fix introduced (why PARTIAL, not CLOSED):

1. **KV-write capability mismatch breaks issuance (fail-closed, but happy path is broken).**
   `vault.py:197-221` does `client.post(".../v1/secret/data/jit/<session>", …)` to **write** the
   token tracking record (KV v2 write ⇒ requires `create`/`update`). But
   `jit-approver.hcl:49-51` grants only **`read`** on `secret/data/jit/*` (and its comment even
   says the path is "written by ext-proc-delegation", which is wrong — jit-approver writes it).
   With the policy as written, the KV write is denied 403 and `issue_credentials` raises ⇒ no
   tracking record, issuance rolls back. Direction is safe (fail closed) but the JIT mint cannot
   complete as deployed. **Fix:** add `create`/`update` (and likely `read`) on `secret/data/jit/*`
   to `jit-approver.hcl`, and correct the "written by ext-proc-delegation" comment.

2. **The ephemeral Vault role is never cleaned up.** Bootstrap, the PR body, and `vault.py`
   docstrings all promise the reaper deletes `kubernetes/roles/jit-<session>`
   (`vault-bootstrap.sh:142-145`, `gitea.py:112-115`, `vault.py:24-27`). The only implemented
   reaper is `platform/kyverno/cleanup/base/jit-resource-cleanup-policy.yaml` — a
   `ClusterCleanupPolicy` that deletes **K8s** ServiceAccount/Role/RoleBinding by label/annotation
   (lines 28-47). It has **no path that calls `vault delete kubernetes/roles/jit-*`**. The CronJob
   alternative is entirely commented out and also only deletes K8s objects
   (`jit-resource-cleanup-cronjob.yaml:9-60`). Result: ephemeral Vault roles accumulate
   indefinitely — a slow standing-scope leak (the very risk H3 warned about). The approver policy
   does grant `delete` on `kubernetes/roles/jit-*`, so the capability exists but nothing exercises
   it. **Fix:** add a step that deletes the ephemeral Vault role on expiry (reaper or a
   short-TTL self-cleanup), or move role lifecycle to Vault lease revocation.

3. **`generated_role_rules` hardcodes the core apiGroup.** `vault.py:248-258` emits a single rule
   block with `"apiGroups": [""]`. Any approved resource outside the core group (e.g.
   `deployments` in `apps`) would silently not be grantable. This is a fail-closed *narrowing*
   (issued ⊆ advertised holds), so not a privilege escalation — but it again makes the issued
   scope diverge from the reviewed YAML for non-core resources, partially re-opening the
   "approved ≠ enforced" concern in the safe direction. **Fix:** derive `apiGroups` per resource
   (or validate that only core-group resources are requestable and document it).

### H4 — group policies read `Claims["groups"]` without `decodedJwt.Valid` → **CLOSED**

Evidence — every group read is now gated on validity:
- `dangerous-tools-admins-only.yaml:73-78` — `isMcpAdmin` requires `jwtString != "" &&
  decodedJwt.Valid` before the groups check.
- `tool-allowlist-mcp-users.yaml:42-48` — `isMcpUsersOnly` requires `decodedJwt.Valid`.
- `deny-restricted-group.yaml:40-51,62-67` — `isRestricted` requires `decodedJwt.Valid`, and an
  explicit `isTokenInvalid` (`jwtString=="" || !decodedJwt.Valid`) makes the validation **deny**
  on an invalid/absent token (the worst-case "expired restricted token slips the block" is closed
  — it now denies, fail closed).
- `no-unauthenticated-calls.yaml:49-65` already gated on `.Valid` and still does.

### H5 — approval/denial decisions never audited → **CLOSED**

Evidence:
- `webhook.py:236` — `emit_approved(session_id, merged_by, pr_number)` at the verified-merge
  decision boundary.
- `webhook.py:181` (closed-not-merged denial), `webhook.py:251` (merged YAML fails
  re-validation) — `emit_denied(...)`.
- `api.py:44-57` — edge 422 ceiling rejection on `POST /requests` also emits `emit_denied`.
- Emitters defined `audit.py:118-128` (`emit_approved`) and `:161-170` (`emit_denied`).
- Test `test_emit_approved_called_on_merge` (`tests/test_api.py:823+`) and the C2 deny test assert
  the calls fire.

---

## MEDIUM (in-scope)

### M3 — Vault NetworkPolicy allowed ingress from agent-sandbox → **CLOSED**

Evidence: `platform/networkpolicies/base/np-vault.yaml:18-50` — the
`allow-ingress-from-injector-consumers` ingress now lists only `keycloak`, `mcp-gateway`,
`agentic-observability`; `agent-sandbox` and `agentic-mcp` are explicitly excluded with a comment
restating the no-direct-credential invariant.

---

## NEW issues introduced by the fixes (summary for the owning teams)

| # | Severity | Where | Issue |
|---|----------|-------|-------|
| N1 | HIGH (functional fail-closed; blocks the feature) | `dangerous-tools-admins-only.yaml` ↔ `jit-approver` ↔ `ext-proc/inject` | C3's signed `X-JIT-Session-JWT` is required by the policy but **never minted (no jit-approver `/jwks`/signing/`tool_scope`) nor injected (ext-proc `inject.go` only sets Authorization/X-Delegated-By)**. Dangerous tools are permanently un-approvable. Bypass is closed; legitimate path is unimplemented. |
| N2 | HIGH (functional fail-closed; breaks JIT mint) | `jit-approver.hcl:49-51` ↔ `vault.py:197-221` | KV write to `secret/data/jit/*` needs `create`/`update`; policy grants only `read`. Issuance KV write is denied; no tracking record; mint rolls back. Comment also misattributes the writer. |
| N3 | MEDIUM (standing-scope leak) | `jit-resource-cleanup-policy.yaml` / cronjob | Ephemeral Vault role `kubernetes/roles/jit-<session>` is promised-but-never-deleted by any reaper (only K8s SA/Role/RoleBinding are cleaned). Roles accumulate. |
| N4 | LOW (fail-closed narrowing) | `vault.py:248-258` | `generated_role_rules` hardcodes `apiGroups:[""]`; non-core resources from the reviewed YAML silently won't be grantable (issued ⊊ advertised for those). |

## Cross-cutting verdict

The two root-cause CRITICALs are genuinely closed: **C1** (ext-proc now cryptographically verifies
the caller JWT and fails closed, with strong negative tests) and **C2** (issuance is strictly from
the reviewed, re-validated merged artifact). **C4**, **H1**, **H2**, **H4**, **H5**, **M3** are
closed with evidence and passing tests. **C3** and **H3** are PARTIAL: in both the *security
direction is fail-closed* (no bypass, issued ⊆ approved), but the fixes introduced an unwired
positive path (C3 signed-session JWT) and a Vault-side capability/cleanup gap (H3) that leave the
JIT-for-dangerous-tools flow non-functional as deployed. None of N1–N4 is an exploitable
fail-open; all are either feature-blocking (N1, N2) or slow standing-scope leaks (N3, N4).

---

## Round 2 verification (JIT completion)

**Date:** 2026-06-11 (round 2). **Scope:** re-verify C3, H3, and the four NEW findings
N1–N4 after the JIT positive-path implementation (`signing.py`, `reaper.py`, ADR 0006,
the `/jwks` route, the `/status` credential delivery, and the `jit-approver.hcl` rewrite).
Method: read the actual code/config (not the round-1 notes); ran the test suites.

### Verification method (round 2)

- jit-approver Python suite: `services/jit-approver/.venv/bin/python -m pytest tests/ -q`
  → **59 passed** (was 45; +14 covering signing/JWKS/reaper/status-delivery/apiGroups).
- ext-proc Go suite: `cd services/ext-proc-delegation && go build ./... && go test ./...`
  → build OK; all packages **PASS** (no regression in inject/extproc).
- Kyverno authz policy graded by static reading of the CEL + the kyverno-json expectations
  in `platform/kyverno/tests/authz/test.yaml` (`kyverno-json` is not installed here; the
  test harness mocks `jwt.Decode`/`jwks.Fetch`, so production claim values are NOT exercised
  by that harness — see the C3 stub-typo note below).
- Token-shape alignment was verified executably on the minting side:
  `test_minted_jwt_iss_matches_policy_constant` (`tests/test_api.py:1055-1072`) greps the
  policy's `Claims["iss"] == "<const>"` and asserts it equals `signing.JIT_SESSION_ISS`;
  `test_minted_jwt_verifies_against_jwks_with_contract_claims` (`:1010-1053`) and
  `test_issued_status_returns_session_jwt_and_sa_token` (`:1135-1189`) decode a real minted
  token against the served `/jwks` with PyJWT — i.e. exactly the verification the gate does.

### Per-item grades

| Finding | Round-1 | Round-2 | Basis |
|---------|---------|---------|-------|
| C3 | PARTIAL | **CLOSED** (functional gap: NetworkPolicy egress) | Token minted + served + presented; gate verifies sig/iss/exp/tool_scope; fail-closed without it. One deploy-time NP gap blocks the JWKS fetch (fail-closed). |
| H3 | PARTIAL | **CLOSED** | N2/N3/N4 all resolved; advertised==enforced; reaper deletes the ephemeral Vault role + KV. |
| N1 | HIGH (open) | **CLOSED** | Minting (`signing.py`) + `/jwks` route + `/status` delivery + SKILL/UC2 presentation all implemented; ext-proc still does NOT inject (correct). |
| N2 | HIGH (open) | **CLOSED** | `jit-approver.hcl` now grants `create/update/read/delete` on `secret/data/jit/*`; code POSTs there. |
| N3 | MEDIUM (open) | **CLOSED** | `reaper.py` deletes `kubernetes/roles/jit-<session>` + KV on expiry; traced + tested. |
| N4 | LOW (open) | **CLOSED** | `_generated_role_rules` derives `apiGroups` per resource, grouped into blocks; tested. |

### C3 — dangerous-tool gate satisfiable + positive path → **CLOSED** (one deploy-time NP gap)

End-to-end, the iss/aud/tool_scope/sig now align on both sides:

- **Mint (source of truth).** `services/jit-approver/src/jit_approver/signing.py:52-64` defines
  `JIT_SESSION_ISS = "https://jit-approver.mcp-gateway.svc.cluster.local:8080"`,
  `JIT_SESSION_AUD = "kyverno-authz"`, `JIT_TOOL_SCOPE_CLAIM = "tool_scope"`, RS256, kid
  `jit-approver-key-1`. `mint_session_jwt` (`:199-239`) emits exactly
  `iss/aud/sub=session_id/jti/tool_scope/iat/nbf/exp` and signs with the private key whose
  public half is at `/jwks`.
- **Verify (policy).** `platform/kyverno/authz/base/dangerous-tools-admins-only.yaml:131-138`
  `hasValidJitSession` requires: non-empty `X-JIT-Session-JWT`, `decodedJitJwt.Valid` (sig +
  exp/nbf, line 134), `Claims["iss"] == "https://jit-approver.mcp-gateway.svc.cluster.local:8080"`
  (line 136 — **string-identical** to `signing.JIT_SESSION_ISS`), and
  `Claims["tool_scope"].exists(s, s == toolName)` (line 138). JWKS fetched from
  `http://jit-approver…:8080/jwks` (line 108) — the route jit-approver serves
  (`api.py:190-199` → `signing.jwks()`). Final decision (`:148-154`): a dangerous tool is
  allowed **only** if `isMcpAdmin && hasValidJitSession`, else `Denied(403)`.
- **Present (agent path).** SKILL `/.claude/skills/jit-escalation/SKILL.md:111-129` and
  `usecases/uc2-jit-escalation/run.sh:170-204,316-329` have the agent read `session_jwt` from
  `/status` and send it as `X-JIT-Session-JWT`. ext-proc does **not** inject it:
  `services/ext-proc-delegation/internal/inject/inject.go:25-46` sets only `Authorization` +
  `X-Delegated-By` — matching the contract (the JWT is the agent's own capability, not a
  downstream cred).
- **Without it → still denies.** No-header (`resources/mcp-admins-add-firewall-rule-no-jit.yaml`)
  and present-but-invalid-sig (`…-invalid-jit-jwt.yaml`) both expect `fail`
  (`tests/authz/test.yaml:90-99`). An empty/missing header decodes the sentinel
  `eyJ…invalid` → `Valid==false` → 403 (policy lines 113-124).

**Forge / replay analysis:** (1) Forge — needs the RS256 private key; a token signed by any
other key fails JWKS verification (`test_bad_signature_jwt_does_not_verify`,
`tests/test_api.py:1074-1102`). `alg=none`/HS confusion is not accepted (RS256 JWKS, asymmetric
verify). (2) Replay past expiry — `decodedJitJwt.Valid` enforces `exp`/`nbf`; an expired token
is rejected with no state lookup (UC2 step 8 asserts this). (3) Tool outside scope — the
`tool_scope.exists(s, s == toolName)` check binds the token to the exact approved tool names; a
token scoped to `add_firewall_rule` cannot clear the gate for any other tool. **Residual (not
exploitable):** within the (≤60 min) validity window the JWT has no per-call nonce/`jti` replay
binding, so anyone who *also* holds a valid `mcp-admins` Keycloak token could replay a captured
session JWT for an in-scope tool. This is acceptable and by-design for a short-lived capability
delivered only over SVID-mTLS to the approved agent (documented ADR 0006 §4); it is not a
bypass of the gate's intent (admin + approved-scope + unexpired).

**Two NON-security caveats (functional, fail-closed — do not reopen the bypass):**
1. **NetworkPolicy gap blocks the JWKS fetch in deployment.** The kyverno-authz-server's egress
   (`platform/kyverno/authz/base/networkpolicy.yaml:38-93` `allow-egress-authz-server`, and
   `platform/networkpolicies/base/np-kyverno.yaml:37-39`) permits egress to mcp-gateway **only on
   gRPC 9081**, plus Keycloak/kube-api/DNS — there is **no egress to `mcp-gateway:8080`**. jit-
   approver's ingress (`services/jit-approver/deploy/base/networkpolicy.yaml`) allows agent-
   sandbox/router/monitoring on 8080 but **not the kyverno namespace**. So
   `jwks.Fetch("http://jit-approver…:8080/jwks")` is dropped → policy eval errors → the gateway
   ext_authz (`platform/agentgateway/base/policy.yaml:79` `failureMode: FailClosed`) **denies**.
   Direction is fail-closed (safe), but the legitimate positive path is blocked as deployed —
   the same class of gap N1 flagged, now at L3. **Fix:** add kyverno→mcp-gateway:8080 egress +
   jit-approver ingress-from-kyverno on 8080. (ADR 0006 §Neutral already calls this NP rule
   "required" but the manifest was not added.)
2. **kyverno-json test stub has an `iss` typo.** The `with-jit` resource's stub token decodes to
   `iss: "https://jkt-approver…"` (`jkt`, not `jit`)
   (`platform/kyverno/tests/authz/resources/mcp-admins-add-firewall-rule-with-jit.yaml:34`). The
   kyverno-json harness mocks `jwt.Decode` to return `Valid:true`, so the policy's exact
   `iss`-equality is **not** exercised by the (uninstalled, mocked) harness — the typo would only
   surface under a real-decode integration (chainsaw). Cosmetic for the mocked test; flagged so a
   future real-decode test does not silently mis-pass/mis-fail. The *production* iss is correct
   and executably pinned to the policy constant by `test_minted_jwt_iss_matches_policy_constant`.

Both caveats are fail-closed and non-exploitable; neither reopens the original attacker-chosen-
header bypass, which is genuinely closed.

### H3 — per-request Vault scope advertised==enforced → **CLOSED** (N2/N3/N4 all resolved)

- **N2 (KV write capability present) → CLOSED.** `platform/vault/config/jit-approver.hcl:76-78`
  grants `["create","update","read","delete"]` on `secret/data/jit/*` (was `read`-only); the
  misattributing "written by ext-proc-delegation" comment is corrected (lines 16-22, 60-75 now
  name jit-approver as owner). `vault.py:217-241` POSTs the tracking + session-JWT record to
  `secret/data/jit/<session>` (KV v2 write), which the policy now permits. (Vault is not running
  here, so this is verified by policy↔code path alignment, not a live 403/200 — `respx` mocks the
  endpoint in `test_api.py:200-201`, and the issuance tests pass.)
- **N3 (reaper deletes the ephemeral Vault role) → CLOSED.** Traced path:
  `api.py:38-68` lifespan starts `reaper.reaper_loop` → `reaper.reap_once`
  (`reaper.py:79-133`) selects issued+expired sessions (`:65-76`) → for each, logs into Vault and
  calls `vault.delete_ephemeral_role` (`vault.py:387-396`, `DELETE kubernetes/roles/<role>`) **and**
  `vault.delete_kv_record` (`vault.py:399-411`, `DELETE secret/metadata/jit/<session>`), then flips
  state to `expired` (`reaper.py:117-121`). A delete error leaves the session un-reaped for the
  next sweep (does NOT prematurely expire). Capability exists: `jit-approver.hcl:38-40` (`delete` on
  `kubernetes/roles/jit-*`) and `:83-85` (`delete` on `secret/metadata/jit/*`). Tested:
  `test_reap_once_deletes_expired_role_and_kv` asserts both DELETEs fire and state→expired
  (`test_api.py:1291-1330`); `…_skips_not_yet_expired`, `…_mixed_only_expired_reaped`,
  `…_delete_failure_leaves_session_unexpired` cover the negative/partial paths (`:1332-1440`).
- **N4 (apiGroups derived per resource) → CLOSED.** `vault.py:295-379`: `_RESOURCE_API_GROUP`
  maps each resource (plural+singular) to its group; `_generated_role_rules` buckets resources by
  apiGroup into separate rule blocks in deterministic order; unknown resources default to core `""`
  with a logged warning (fail-closed narrowing — issued ⊆ advertised). Tested:
  `test_core_apps_batch_grouped_into_blocks`, `test_networking_and_route_groups`,
  `test_unknown_resource_defaults_core_with_warning` (`test_api.py:1221-1281`).
- **Advertised==enforced.** Ephemeral per-session role (`vault.py:182-206`) sets
  `generated_role_rules` = approved verbs/resources, `allowed_kubernetes_namespaces=[req.namespace]`,
  and `token_default_ttl/token_max_ttl` from the approved window; creds are minted from THAT role.
  Issuance is from the reviewed/re-validated merged YAML (C2 path,
  `webhook.py:242-260`), so the issued scope equals the human-approved scope. No residual
  advertised≠enforced.

### No NEW fail-open

The master gateway ext_authz is `failureMode: FailClosed` (`platform/agentgateway/base/policy.yaml:79`).
Every new failure mode is a deny: a failed/blocked `jwks.Fetch` → policy error → ext_authz denies;
a missing/empty/invalid `X-JIT-Session-JWT` → `hasValidJitSession=false` → 403; a reaper delete
failure → session left issued for retry (no silent expiry, no scope leak past the lease/exp). The
session-JWT credential fields are returned by `/status` ONLY when `state==issued`
(`api.py:170-182`, `test_credentials_not_returned_before_issued`, `test_api.py:1191-1213`). No
allow-on-error path was introduced.

### Repo-readiness verdict

**READY with one deploy-time follow-up (non-security, fail-closed):** all round-1 CRITICAL/HIGH
findings including C3 and H3 (N1–N4) are now CLOSED at the code/config layer with passing suites
(59 Python / Go green) — the JIT-for-dangerous-tools flow is implemented, scoped, signed, expiring,
and audited, and every failure mode denies; the only outstanding item is adding the
kyverno↔jit-approver:8080 NetworkPolicy egress/ingress (and fixing the `jkt`→`jit` test-stub typo)
so the legitimate positive path can reach `/jwks` in-cluster — until then the gate is correctly
fail-closed but dangerous tools remain un-approvable in deployment.
