# MASTER IMPLEMENTATION PLAN — Console-Side Mint Gate Migration (L0 → L5)

## 1. Overview

This plan replaces the **Git-PR-merge approval gate** in `services/jit-approver` with a **console-side, Keycloak-authenticated MINT GATE** that:

1. Enforces `approver_sub != requester_sub` (closes the **M5 self-approval gap**),
2. Records a **hash-chained, RS256-signed, append-only WORM audit ledger** for every decision,
3. Adds **dual-control** (two distinct approvers) for the dangerous tier,
4. Adds a **policy-driven auto-approve FAST LANE** for Tier-0/1 requests,
5. Demotes git to an **optional diffable scope mirror** (ArgoCD PR path retained for STANDING policy only).

**Kept byte-for-byte unchanged** (verified): the Vault lease + structural revocation (`vault.py:issue_credentials` ~124, ephemeral role `kubernetes/roles/jit-<session>`), the RS256 session JWT (`signing.py:mint_session_jwt` ~225, claims `iss=JIT_SESSION_ISS` / `aud=kyverno-authz` / `tool_scope` / `sandbox_uid` / `exp=iat+duration*60`, `kid=jit-approver-key-1`), `GET /jwks` (~140), and the ext-proc per-call enforcement (`services/ext-proc-delegation`, the SOLE live enforcer; `grant.go MaxGrantTTLSeconds=3600`).

### Confirmed repo anchors (read, not assumed)

| Anchor | Location | Fact |
|---|---|---|
| **M5 gap** | `webhook.py:214` | `merged_by = pr.get("merged_by", {}).get("login", "unknown")` — never compared to `requester_sub` |
| Atomic once-only flip (C4) | `webhook.py:220-233` | `async with store_lock:` check `_TERMINAL_STATES`, flip `state=issued` |
| Mint + rollback body | `webhook.py:244-308` | `_load_reviewed_request` (anti-TOCTOU re-read) → `issue_credentials` → `emit_issued`; rolls back on failure |
| Credential stash | `vault.py:271-276` | `session_store[sid]["sa_token"|"session_jwt"|...]` set AFTER JWT mint (~257) |
| Signing key load | `signing.py:94-121` | loads PEM from `JIT_SIGNING_KEY_PATH`; **ephemeral fallback only on `FileNotFoundError`** (a non-RSA/corrupt key already RAISES at line 108) |
| In-memory store | `store.py:30-37` | `session_store: dict`, `store_lock: asyncio.Lock`, `seen_deliveries: set` — docstring says "replace with Redis or CNPG" |
| Console merge | `app.py:1016-1047` | `merge_url = .../pulls/{pr_number}/merge` + `{"Do":"merge"}` with `Config.gitea_token()` |
| Console actor | `app.py:209` | `_actor()` reads `X-Forwarded-Preferred-Username` (oauth2-proxy) |
| Hard ceiling | `models.py:23-27,30,83` | `ALLOWED/DENIED_VERBS`, `DENIED_RESOURCE_TOKENS={secret,role,rolebinding,clusterrole}`, ns allowlist, `duration ge=10 le=60` |
| Kyverno disabled | `platform/kyverno/authz/base/kustomization.yaml:17` | `# - dangerous-tools-admins-only.yaml  # DISABLED: needs ... mcp.Parse` — **file does not exist, must be recreated** |
| CNPG pattern | `platform/keycloak/base/cnpg-cluster.yaml` | `kind: Cluster`, `instances: 1`, `storageClass: local-path` (NFS initdb hang) |
| Realm groups | `realm-import.yaml:216-235` | only `/mcp-users` + `/mcp-admins`; single user `arsalan`; `groups` protocol mapper at ~100 already emits the claim |
| Signing mount | `deployment.yaml:39-41,124-125` | Vault inject `secret/data/jit-approver/jit-signing-key` → `JIT_SIGNING_KEY_PATH=/vault/secrets/jit-signing-key` |
| GitOps | `gitops/applications/jit-approver.yaml` | automated + prune=true, **selfHeal=FALSE** (manual hotfix survives until git revert) |

---

## 2. Safety Invariants (enforced and adversarially tested at EVERY loop)

These are non-negotiable; the Stage-4 security gate of each loop verifies them.

- **INV-1 FAIL-CLOSED.** Any ambiguity, missing input, error, or unreachable dependency DENIES/PARKS, never silently degrades. Missing stable key (when required) crashloops the pod; unreachable durable DB returns 503; missing/unparseable policy bundle yields zero auto-approvals; `risk_tier` returns the highest (dangerous) tier on any unexpected shape.
- **INV-2 APPROVER ≠ REQUESTER (SoD).** Exact-string (post-normalization) comparison enforced **before any state change or Vault call**. Empty/whitespace approver_sub is a violation, never a pass. Lives in **exactly one place** (`mint_core._enforce_dual_control`) shared by the console `/mint` path and the still-live webhook git mirror, so the two paths cannot diverge.
- **INV-3 NO CREDENTIAL / PEM IN GIT.** The approval decision never flows through the shared `GITEA_TOKEN` merge after L1. `DATABASE_URL` arrives only via a CNPG-generated `secretKeyRef`; the signing PEM only via the existing Vault inject. Guard: `git grep -E 'BEGIN.*PRIVATE KEY|password=|postgres://[^$]'` over tracked files is empty. The git scope mirror carries **scope only, never tokens/keys**. Ledger payloads carry only `*_sha256`/`*_hash` digests.
- **INV-4 VAULT / EXT-PROC / JWT UNTOUCHED.** `git diff` shows **zero hunks** in `vault.py`, `signing.py:mint_session_jwt`/`jwks`/`tool_scope_for`, and `services/ext-proc-delegation/**` except additive call-sites/kwargs. The `kid`/`iss`/`aud`/claim shape is frozen — changing it is a cross-service break.
- **INV-5 LIVE DEMO NEVER BREAKS.** Every loop ships behind an env/config flag defaulting to today's behavior. The git PR + webhook path stays LIVE as an audit mirror through L1–L4. The `60s reaper` + Kyverno `ClusterCleanupPolicy` backstops stay on throughout.
- **INV-6 ONCE-ONLY MINT.** Exactly one Vault lease + one session JWT per session regardless of how many trigger paths fire, enforced by the atomic check-and-flip (`store_lock` in-memory; DB `UPDATE...WHERE state=ANY(expected)...RETURNING` for Postgres/multi-replica).
- **INV-7 WORM / TAMPER-EVIDENT.** The ledger is append-only at the DB privilege layer (`REVOKE UPDATE,DELETE`) and hash-chained + RS256-signed so any tamper/reorder/splice is detectable. After L2, **no durable signed ledger entry ⇒ no credential**.

---

## 3. Dependency Graph & Sequencing

```
L0 ──┬─► L1 ──► L2 ──► L3 ──► L4 ──► L5
     │         (ledger) (dual)  (fast)  (decommission)
     └─ stable PEM + durable store gate EVERYTHING
```

- **L0 is a HARD prereq for all.** The stable PEM must land before L1 ships a real issuance path — restarting into an ephemeral key would silently invalidate every in-flight session JWT ext-proc verifies (the one breakage invisible to jit-approver's own tests). The durable `session_store` gates L3's `pending_second` (a two-approver interim state cannot survive the 60s reaper / pod restart in an in-memory dict).
- **L1 gates L2** — the ledger signs the MINT decision (incl. `approver_sub`), so the mint handler must exist first.
- **L2 gates L3 and L4** — dual-control approvals and fast-lane auto-approvals must be ledgered identically to human mints, so the signed append-only sink must exist first.
- **L4's fast-lane is gated on re-enabling Kyverno's dangerous-tools policy**, itself blocked by an **external** dependency (kyverno-envoy-plugin must provide `mcp.Parse`). Until then ext-proc is the only dangerous-tool enforcer, so L4 must NOT fast-lane any request with non-empty `tool_scope_for()`.
- **L5 is LAST**, gated on L2 ledger being system-of-record + a proven DR restore drill.

**Coexistence model — "dual-TRIGGER, single-MINT":** both the legacy webhook trigger and the new `/mint` trigger call the SAME `issue_credentials`; the atomic flip guarantees mint-exactly-once, so running both in parallel is safe by construction (you race two gates into one idempotent mint, never double-mint).

---

## 4. Reusable Per-Loop Workflow Pattern

Every loop is built by the SAME five-stage agent loop (implementer ≠ security reviewer):

1. **SCAFFOLD** (`code-writer`): new modules/manifests/empty test skeletons behind a default-off flag. Gate: imports resolve, ruff+mypy clean, `kustomize build` renders, service boots under `TestClient`.
2. **IMPLEMENT** (`code-writer`): fill logic behind the flag; touch no file under `vault.py`/`signing.py`/`ext-proc-delegation` except call-sites. Gate: compiles, mypy clean.
3. **TEST** (`test-writer`): unit (pure-fn) + contract (respx/`TestClient`, mocked Vault+Gitea) + live `hack/test-*-jit.sh` where a stack exists; **re-run the FULL pre-existing suite — must stay green** (default-off ⇒ zero drift). Loop back to 2 on red.
4. **ADVERSARIAL SECURITY GATE** (`security-reviewer`, DIFFERENT agent, VETO): run the loop's `securityGate` attacks; every probe must fail-closed. Any breach → Stage 2.
5. **VERIFY** (`code-reviewer`): diff-review Vault/JWT/ext-proc byte-unchanged; `git grep` no-secret empty; `git diff --stat` only the declared files.

**Loop-until-green (identical every loop):** pre-existing suite green ∧ new tests green ∧ zero adversarial findings ∧ no-secret grep empty ∧ untouched-files invariant holds. Any red routes back to Stage 2 with the failing assertion.

**Regression command per loop:**
```
make validate test-extproc test-policies \
  && (cd services/jit-approver && pytest) \
  && (cd services/approval-console && pytest) \
  && <the relevant hack/test-*-jit.sh against the live cluster>
```
(No GitHub Actions/GitLab CI exists; the gate is the Makefile + `hack/validate.sh` + `hack/test-*-jit.sh`.)

---

## 5. Per-Loop Sections

### L0 — PREREQS: durable persistence + verified-stable RS256 PEM

**Objective.** Stand up the persistence + key foundations every downstream loop needs, WITHOUT changing any user-visible behavior. Verify/lock the RS256 PEM in Vault KV as stable across restarts and fail-closed-loudly on ephemeral fallback; introduce a durable backend (CNPG Postgres) with an INSERT-only WORM ledger table + session/state table + single-row ledger-head; abstract `store.py` from a bare dict into a `Store` interface (in-memory default, Postgres opt-in behind `JIT_STORE_BACKEND`). **Ships the abstraction + durable backend wired but defaulting OFF.**

**Files to change.**
- `services/jit-approver/src/jit_approver/store.py` — replace the bare dict/set/lock with a thin compat shim over an `InMemoryStore` (default); keep module names `session_store`/`seen_deliveries`/`store_lock` so `api.py:27,129`, `webhook.py`, `vault.py:271`, `reaper.py:35`, tests import unchanged. Add `get_store()` factory on `JIT_STORE_BACKEND` (default `memory`). Do NOT change the dict-like access contract (`session_store[id]`, `.items()`, `.get()`).
- `signing.py` — in `_load_or_generate_key` (94-121): when `JIT_SIGNING_KEY_PATH` is set, the file is absent/unreadable AND `JIT_REQUIRE_STABLE_KEY=='true'`, RAISE (fail-closed) instead of the ephemeral fallback. Keep current PoC ephemeral default (flag off). Emit a clearly-leveled startup log distinguishing `stable-PEM-loaded` vs `ephemeral-fallback`. No change to `mint_session_jwt`/`jwks`/`kid`. (Note: the existing non-RSA `raise TypeError` at line 108 already fails-closed — keep it.)
- `api.py` — in `_lifespan` (38-39): `store = get_store(); await store.startup_check()` (Postgres: `SELECT 1` + verify `jit_ledger`/`jit_session` exist → raise on failure so the pod crashloops; in-memory: no-op). Add `store_backend` to `/healthz` (389) and a durable-only readiness gate (503 until DB+schema confirmed).
- `pyproject.toml` — add optional dep group `durable = ["asyncpg>=0.30"]`, OUT of default deps.
- `deploy/base/deployment.yaml` — add default-off env `JIT_STORE_BACKEND=memory`, `JIT_REQUIRE_STABLE_KEY=false`, and a placeholder `DATABASE_URL` via `valueFrom.secretKeyRef(jit-approver-db-app, uri)`. **Confirm the signing-key inject (39-41) + `JIT_SIGNING_KEY_PATH` (124-125) are retained verbatim.**
- `platform/vault/config/vault-bootstrap.sh` — harden the signing-key seed: keep create-once-if-absent, ALSO validate the existing value parses as an RSA key (`openssl pkey -in - -noout`); on corrupt/empty, log loudly and **refuse to overwrite** (overwriting would rotate the key and invalidate live JWTs). Idempotent comment that this PEM MUST stay stable.

**New artifacts.**
- `persistence/{__init__,base,memory,postgres,schema}.py` — `Store` ABC (`get/put_session`, `update_state_atomic(id, expected:set, new)->bool`, `list/iter_sessions`, `add_delivery_if_new`, `read_ledger_head`, `advance_ledger_head_cas`, `async_lock`); `InMemoryStore` (today's dict+set+`asyncio.Lock`, byte-identical); `PostgresStore` (asyncpg pool; `update_state_atomic` = `UPDATE jit_session SET state=$new WHERE id=$id AND state=ANY($expected) RETURNING id`; `add_delivery_if_new` = `INSERT ... ON CONFLICT DO NOTHING RETURNING`; head advance = `UPDATE jit_ledger_head SET seq=$new,head_hash=$h WHERE id=1 AND seq=$expected RETURNING seq`; ledger INSERT-only).
- `schema.sql` — `jit_session`, `jit_delivery`, `jit_ledger(seq bigserial pk, prev_hash, entry_hash, payload_json, sig NULLABLE-until-L2, created_at)` INSERT-only, `jit_ledger_head(id=1 singleton)`. Idempotent. **`REVOKE UPDATE, DELETE ON jit_ledger FROM <app_role>`** so WORM is privilege-enforced.
- `platform/jit-approver-db/{cnpg-cluster,schema-initdb-configmap,kustomization}.yaml` — CNPG Cluster `jit-approver-db` in `mcp-gateway` ns, `instances:1`, `storageClass local-path` (mirrors `keycloak/base/cnpg-cluster.yaml`), `postInitApplicationSQLRefs` → schema configmap. Referenced ONLY from the anaeem overlay.
- `tests/test_persistence.py` — both backends (Postgres skip-if-no-DB) + adversarial.

**Implementing workflow loop.** The reusable five-stage loop. Stage-1 SCAFFOLD: persistence package + schema.sql + CNPG manifests + pyproject/deployment edits; `kustomize build platform/jit-approver-db/base` + YAML/SQL lint must parse. Stage-2 IMPLEMENT: memory.py + postgres.py + store.py shim + signing/api hardening behind default-off flags. Stage-3 TEST: `test_persistence.py` + the FULL existing `test_api.py`/`test_sandbox_binding.py` which MUST pass byte-for-byte. Stage-4 SECURITY GATE: the L0 attacks below. Stage-5 VERIFY: diff-review the live path untouched when `JIT_STORE_BACKEND=memory`; `git grep` no PEM/secret.

**Tests.**
- Existing `test_api.py`/`test_sandbox_binding.py` pass UNCHANGED with default backend (regression gate).
- memory: `update_state_atomic` flips `pending->issued` once; second call with `expected={pending,approved}` → False (mirrors webhook.py:220-233).
- postgres (skip-if-no-DB): two concurrent `update_state_atomic` → exactly one True (DB-level once-only, no in-process lock).
- postgres: `add_delivery_if_new` → id on first, None on duplicate; dedupe survives a new pool (simulated restart).
- **ADVERSARIAL WORM:** `UPDATE jit_ledger SET ...` and `DELETE FROM jit_ledger` as the app role FAIL with insufficient privilege (REVOKE).
- **ADVERSARIAL head CAS:** two `advance_ledger_head_cas` with same `expected_seq` → exactly one succeeds; loser must re-read.
- **ADVERSARIAL fail-closed key:** missing PEM + `JIT_REQUIRE_STABLE_KEY=true` → startup raises; flag false → logs ephemeral-fallback and still mints.
- **ADVERSARIAL fail-closed DB:** `JIT_STORE_BACKEND=postgres` + unreachable DSN or missing table → `startup_check` raises, `/healthz` not-ready (503).
- Durability: write session + ledger row, rebuild the pool, read back identical state + head + seen-delivery.
- vault-bootstrap idempotency: never rotates a valid PEM, refuses to overwrite a malformed one.

**Security gate.** (1) WORM privilege-enforced — UPDATE/DELETE on `jit_ledger` as the app role denied. (2) Once-only preserved across the abstraction — Postgres atomic single-statement is the SOLE flip path (no double-mint); memory is byte-identical to today (no new TOCTOU). (3) No credential/PEM/DSN-with-password in git. (4) Fail-closed defaults — missing stable key + unreachable DB both crash/park; in-memory default unchanged and the live git/webhook/Vault/ext-proc path is NOT in any new durable code's call graph. (5) Signing key never rotated as a side effect.

**Acceptance.** Full existing suite passes with `backend=memory` and the rendered deployment differs from main only by additive default-off env. `kustomize build platform/jit-approver-db/base` renders a valid CNPG Cluster + schema configmap with an explicit `REVOKE UPDATE,DELETE ON jit_ledger`. With `backend=postgres`, session + transitions + seen-delivery + ledger head survive a simulated restart. `/jwks` reports stable PEM (startup log `stable-PEM-loaded`). All adversarial assertions zero findings.

**Rollback.** Pure additive + flag-gated. Set `JIT_STORE_BACKEND=memory` + `JIT_REQUIRE_STABLE_KEY=false` and restart → exact today's behavior; new code dormant. `git revert` the L0 commit restores the dict store (no migration — the flag-off path never wrote Postgres). The CNPG kustomization is referenced only by the anaeem overlay; deleting it removes the DB with zero impact. The bootstrap change only ADDS a guard and never rotates a key.

**Coexistence.** L0 is invisible: the live git-PR-merge path (`create_approval_pr` → Gitea PR → `webhook.py` merge → `issue_credentials` → RS256 JWT → ext-proc) is unchanged because the default in-memory `Store` is byte-for-byte today's dict/set/lock. Flipping `JIT_STORE_BACKEND=postgres` is the reversible lever L1+ uses. The shared stable PEM signs both today's webhook JWTs and tomorrow's mint JWTs (and L2 ledger entries) against one unchanging `/jwks`.

**Effort.** M.

**Risks.** (a) The current once-only guard is a process-local `asyncio.Lock`; multi-replica on in-memory silently breaks it — Postgres moves it to an atomic statement; document multi-replica REQUIRES `backend=postgres` (single-replica in-memory remains correct for SNO). (b) Schema/init race — `startup_check` is fail-closed and `schema.sql` idempotent. (c) `asyncpg` only in the durable image — `get_store()` raises a clear "install .[durable]" error. (d) REVOKE assumes a non-owner role — `DATABASE_URL` must use `jit-approver-db-app`, asserted by a test. (e) False-positive "malformed key" — the validation only refuses to OVERWRITE, never deletes/rotates.

---

### L1 — CLOSE-M5: console-side Keycloak-authenticated MINT GATE

**Objective.** Add `POST /requests/{id}/mint` performing the issuance decision server-side: enforce `approver_sub != requester_sub` (hard, fail-closed) + reviewed-scope equality (`scope_hash`) + the existing atomic `pending->issued` flip, then call the UNCHANGED `issue_credentials()`. Rewrite console `approve()` to POST `{approver_sub, reviewed_scope, scope_hash}` to `/mint` instead of merging the PR. Vault lease + RS256 JWT + ext-proc untouched. Git branch/commit/PR + `webhook.py` stay LIVE as a diffable audit mirror. **Net externally-visible change: a user can no longer approve their own request.**

**Files to change.**
- `api.py` — add `POST /requests/{session_id}/mint` after `post_summary` (~253): (1) authenticate the caller as the console SA (see security gate), (2) parse `MintRequest`, (3) load the pending session (404 if absent), (4) reject if state not in `{pending, approved}` (409), (5) recompute `canonical_scope_hash(session['request'])` and compare to body (409 mismatch — anti-TOCTOU), (6) `mint_core._enforce_dual_control(body.approver_sub, req.requester_sub)` (403), (7) `mint_core._atomic_issue(...)`. Return `{status:'issued', session_id, expires_at}`. Do NOT touch the `/status` credential-exposure invariant.
- `models.py` — add `MintRequest(approver_sub:str min_length=1, reviewed_scope optional, scope_hash:str min_length=1)` and a module-level `canonical_scope_hash(req)->str` (canonical JSON of `namespace` + sorted `verbs` + sorted `resources` + `duration_minutes` + `sandbox` + sorted `[host:port]` policy_delta, then sha256-hex) — the single source of truth for console + handler.
- `webhook.py` — extract the atomic claim-and-flip (220-233) and the mint+rollback body (244-308, minus the Gitea grant re-read which stays) into `mint_core._atomic_issue(session_id, reviewed_req, approver_sub, pr_number)`. webhook now also computes `approver_sub` from `merged_by` and feeds the SAME SoD check, so **even the still-live git path is M5-safe**. Otherwise byte-identical.
- `services/approval-console/src/approval_console/app.py` — rewrite `approve()` (924-1057): keep Step 1 (GET `/detail`) + state checks; REPLACE the Gitea `PUT .../merge` (1016-1047) with an authenticated POST to `{jit_url}/requests/{id}/mint` carrying `{approver_sub:_actor(request), reviewed_scope, scope_hash:_canonical_scope_hash(detail)}`. Map the handler's 403 to a 403 surfaced to the browser. Remove `Config.gitea_token()` from the approval path. `_actor()` (209) unchanged.
- `deploy/base/route-api.yaml` — confirm `/mint` is reachable on the same :8080 the console reaches; no new external route — `/mint` is enforced console-only by in-handler auth, not routing.
- `deploy/base/networkpolicy.yaml` — comment that `/mint` is console-only and the agent-sandbox ingress rule must NOT be widened (defense-in-depth note; enforcement is in-handler).
- `tests/test_api.py`, `services/approval-console/tests/test_app.py` — add mint-gate + SoD tests; assert console POSTs to `/mint` (respx asserts NO Gitea `/merge` call).

**New artifacts.**
- `mint_core.py` — `_enforce_dual_control(approver_sub, requester_sub)` (403 fail-closed), `_verify_scope_hash(stored_req, presented)` (409), `_atomic_issue(...)` (once-only flip + `emit_approved` + `issue_credentials` + `emit_issued` + rollback). **Both `webhook.py` and `api.py` call this so the M5 check exists in exactly one place.**
- `tests/test_mint.py`, `docs/decisions/0007-console-mint-gate-replaces-pr-merge-approval.md` (ADR superseding the approval-decision portion of ADR-0005).

**Implementing workflow loop.** Reusable five-stage. Scaffold: `mint_core.py`, `MintRequest`+`canonical_scope_hash`, an empty `/mint` returning 501, console `_canonical_scope_hash` helper. Implement: fill `_atomic_issue` by extracting from webhook, wire SoD + scope_hash, rewrite console `approve()`, refactor webhook to share `mint_core`. Test: `test_mint.py` + console mint tests incl. adversarial; run both pytest suites. Security gate: the attacks below. Verify: Vault/JWT/ext-proc byte-unchanged; webhook git-mirror still issues; only delta is SoD. **Loop-until-green:** both suites green ∧ every adversarial probe returns 403/409/401 (never 200/issued) ∧ no diff under `vault.py`/`signing.py`/ext-proc except call-sites.

**Tests.**
- UNIT `mint_core`: `_enforce_dual_control` 403 when equal or empty; pass when distinct. `_verify_scope_hash` 409 on mismatch.
- UNIT `models`: `canonical_scope_hash` stable under reordering, changes on duration/ns/verb change; **console helper and handler helper produce identical hashes** (cross-checked).
- INTEGRATION happy: distinct approver + correct hash on a pending session → 200 issued, one Vault lease + one JWT (respx), state==issued.
- INTEGRATION once-only: two concurrent `/mint` mint once (`creds.call_count==1`).
- INTEGRATION status invariant: after mint, `/status` returns creds only when issued; pending still null.
- **ADVERSARIAL M5 self-approval:** `approver_sub == requester_sub` → 403, state stays pending, ZERO Vault calls, `emit_denied` audited. **Canonical M5 regression test.**
- **ADVERSARIAL TOCTOU:** scope mutated after detail / presented hash for a broader scope → 409, no mint.
- **ADVERSARIAL auth:** no/invalid console-SA credential → 401; agent-sandbox-shaped principal → rejected.
- **ADVERSARIAL webhook git-mirror M5:** a merge whose `merged_by` == requester_sub → shared SoD check denies (the still-live git path is also M5-safe).
- CONSOLE: `approve()` POSTs to `/mint` (respx asserts NO `/merge`), forwards `approver_sub` from forwarded-identity; mint 403 surfaced; jit-approver unreachable → 502.
- REGRESSION: full existing webhook/replay/audit suites pass unchanged.

**Security gate.** Reviewer must FAIL to: (1) self-approve (incl. empty/whitespace/unicode-normalized/case-variant) — denied before any state change or Vault call. (2) bypass auth — `/mint` requires the console-service identity (mTLS client-cert OR a verifiable console-SA token, **NOT** the shared `GITEA_TOKEN` and NOT an agent SVID); the SUBMIT principal (agent) must NOT be able to call `/mint`; approver identity taken from the server-trusted forwarded/Keycloak identity, never a requester-controlled field. (3) TOCTOU on scope — issuance bound to server-computed `scope_hash`. (4) no credential in git — the console approval path must not read `GITEA_TOKEN`. (5) anti-replay — a captured mint body cannot re-mint an issued session. Single shared issuance path; zero change to vault/signing/ext-proc.

**Acceptance.** `/mint` exists; distinct approver + matching hash + valid auth → issued + exactly one lease + one JWT. `approver_sub == requester_sub` → 403, pending, zero Vault, `jit_denied` — the closed M5 gap. Console no longer issues `/merge` or reads `GITEA_TOKEN` in the approval path. `git diff` shows no hunks in `vault.py`/`signing.py`/`ext-proc-delegation/*.go`. Git PR + webhook still run and still issue via `mint_core` (now SoD-enforced). Both suites green. Scope mismatch → 409. All five security probes 401/403/409.

**Rollback.** Flags `JIT_MINT_GATE_ENABLED` (jit-approver) + `JIT_APPROVE_VIA_MINT` (console). Console flag off → `approve()` reverts to `PUT .../merge` (code retained). jit-approver flag off → `/mint` returns 503, only webhook issues. Because git PR + webhook stay LIVE, rollback is a flag flip — no data migration, no Vault change. `git revert` for a full revert; session shape is additive (`approver_sub`) and backward compatible.

**Coexistence.** Dual-path window: git path stays fully live (PR is the diffable scope MIRROR, webhook still issues — now via `mint_core`, M5-safe). Console `approve()` switches to `/mint` under `JIT_APPROVE_VIA_MINT`. Issuance once-only regardless of which path fires (both contend on the same `store_lock` + `_TERMINAL_STATES`). No agent-visible contract change. L2 adds the ledger on this same `mint_core` decision point.

**Effort.** M.

**Risks.** (a) **The auth mechanism for `/mint` is the crux** — today console→jit-approver is unauthenticated cluster-internal; without a real caller-identity check any agent-sandbox pod reaching :8080 could self-approve with a forged `approver_sub`. Highest-risk item; the agent-sandbox ingress must not be widened to `/mint`. (b) `approver_sub` trust — `_actor()` reads `X-Forwarded-Preferred-Username`, trustworthy only because oauth2-proxy strips/sets it; the handler trusts the console SA channel, the console derives `approver_sub` only from oauth2-proxy headers. (c) `scope_hash` canonicalization drift → spurious 409s; mitigated by the cross-check test and ideally a shared implementation. (d) Pod restart loses in-memory pending sessions until L0 lands (documented dependency, not a new regression). (e) `requester_sub` normalization (email vs OIDC sub) must match on both sides; tests cover case/whitespace variants.

---

### L2 — LEDGER: hash-chained, RS256-signed, append-only WORM audit ledger

**Objective.** Every authorization decision produces an immutable, independently-verifiable record. New `ledger` module appends a hash-chained entry (`entry_hash = sha256(canonical_json(prev_hash || payload))`) signed RS256 with the SAME signing key (`signing._keys().private_pem`, `kid=jit-approver-key-1`), dual-sunk to (a) the L0 durable WORM store and (b) stdout→Loki via `_JsonFormatter`. The ledger head (`prev_hash` + monotonic `seq`) lives in the L0 durable store, NOT the in-memory dict. Legacy webhook entries record `merge_commit_sha` for cross-check. **Evidence-only: L2 never gates/denies/changes a mint outcome, but a ledger sink failure fails-CLOSED on the mint (no credential without a durable signed entry first).**

**Files to change.**
- `audit.py` — add `emit_ledger(entry)` (logs `jit_ledger` via `_JsonFormatter`→Loki) and `_canonical_json(payload)` (`json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False)`) reused by the ledger so hashed/signed bytes == logged bytes. Keep `emit_approved`/`emit_issued`/`emit_denied` and `_hash` exactly as-is.
- `signing.py` — add `sign_ledger_entry(payload_bytes)->str` + `verify_ledger_signature(payload_bytes, sig)->bool` reusing `_keys().private_pem`/`public_key` (PKCS1v15+SHA256, base64url, detached — NOT a JWT wrapper). Auditors verify against the existing `/jwks`. Do NOT touch `mint_session_jwt`/`tool_scope_for`/`jwks()`/constants.
- `vault.py` — in `issue_credentials._run`, AFTER the JWT mint (~257) and BEFORE the credential stash (~271): build the `mint_issued` payload (session_id, requester_sub, approver_sub, scope_hash, tool_scope, namespace, duration, expires_at, vault_role, `token_sha256` already at ~237, sandbox_uid, optional merge_commit_sha) and call `ledger.append_entry(payload)`. If it raises → raise out of `_run` so the mint fails-CLOSED (no `sa_token`/`session_jwt` stashed, caller rolls back the flip). Thread `approver_sub`/`scope_hash`/optional `merge_commit_sha` as new optional kwargs (default '').
- `webhook.py` — at the `issue_credentials` call (~260) pass `merge_commit_sha=pr.get('merge_commit_sha')`, `approver_sub=merged_by`, `scope_hash=hash(reviewed_req)` so legacy issuances write the cross-check entry. No change to HMAC/dedupe/flip/`_load_reviewed_request`.
- `api.py` — add read-only `GET /requests/{id}/ledger` (ordered entries, no creds — metadata + signatures + hashes only) and `GET /ledger/verify?session_id=...` (re-walks the chain + RS256 sigs + linkage → `{valid, broken_at_seq}`). Neither mutates state.
- `store.py` — import the L0 durable ledger-head accessors; document `seq`+`prev_hash` are L0-durable so a restart resumes (not forks) the chain.
- `deploy/base/deployment.yaml` — add `JIT_LEDGER_BACKEND=cnpg|vaultkv` + L0 DSN/KV env + `JIT_LEDGER_REQUIRED=true`. Confirm `JIT_SIGNING_KEY_PATH` points at the stable PEM (39-41/124-125).

**New artifacts.** `ledger.py` (`append_entry` under the durable head lock — read head, build canonical payload, compute `entry_hash`, sign, INSERT-only with seq CAS, advance head, THEN `emit_ledger`; fail-closed before the Loki sink; `verify_chain`; `GENESIS_PREV_HASH` = 64 zeros; no raw token/PEM/tool-arg ever in a payload — only sha256 digests). `tests/test_ledger.py`, `tests/test_mint_ledger_integration.py`.

**Implementing workflow loop.** Reusable five-stage. Scaffold: `ledger.py` skeleton + signing/audit additions + empty tests (imports clean, ruff/mypy). Implement: `append_entry`/`verify_chain`, sign/verify, `emit_ledger`, vault+webhook+api wiring. Test: `test_ledger.py` + `test_mint_ledger_integration.py`. Security gate: the attacks below — tamper a payload (verify flags `broken_at_seq`), reorder/splice, force a WORM write failure (mint fails-closed, no credential), stub the sink (issuance blocked), grep for raw token/PEM, confirm the sig verifies against the EXISTING `/jwks` and no other. Verify: full pytest + ruff + mypy + the `merge_commit_sha` cross-check. **Hard stop:** do not advance to L3 until `verify_chain` over a mixed (mint + legacy-webhook) set returns `valid:true`.

**Tests.** `entry_hash == sha256(canonical_json(payload))`; first entry `prev_hash == GENESIS`; sig verifies via the `jwks()` PyJWK; **tamper one byte → `{valid:false, broken_at_seq}`**; splice/reorder detected; rogue-key sig False; **fail-closed: forced WORM INSERT failure → mint raises, no `sa_token`/`session_jwt`, `/status` still no creds, flip rolled back**; `JIT_LEDGER_REQUIRED=true` + ledger no-op'd → no credentials; **no-leak scan** of payload + Loki extras for raw `sa_token`/justification/tool-args/PEM (only `*_sha256`/`*_hash`); restart-resume (head `seq=N`/`prev_hash=H` → new entry `seq=N+1`, `prev_hash=H`); mint path writes one `mint_issued` with `approver_sub != requester_sub` BEFORE `/status` exposes creds; legacy cross-check (`merge_commit_sha=='deadbeefcafe'` recorded AND `emit_approved`/`emit_issued` still fire); `GET /ledger/verify` `{valid:true}` over mixed set; regression unchanged.

**Security gate.** Reviewer must FAIL to: (1) get a credential without a durable signed entry written first (no-entry === no-credential; sink/signing failure aborts the mint and rolls back the flip). (2) tamper/reorder/splice/delete without `verify_chain` detecting + `broken_at_seq`. (3) forge a sig with any key other than the stable `/jwks` RS256 key (must be the stable PEM mount, never ephemeral). (4) leak any raw credential/justification/tool-arg/PEM into a payload or Loki extra (only sha256). (5) fork/reset the chain across a restart via in-memory head (head from the L0 durable store under a durable lock; concurrent appends serialize, never reuse a seq). L2 does NOT weaken L1 SoD or alter any outcome.

**Acceptance.** Every mint (L1 `/mint` AND legacy webhook) has exactly one durable WORM entry whose RS256 sig verifies against `/jwks` and whose `prev_hash` links. `GET /ledger/verify` `{valid:true}` over a mixed set; `{valid:false, broken_at_seq}` after a tamper. `JIT_LEDGER_REQUIRED=true` + forced WORM failure → mint fails-closed. No raw secret in any payload/extra. Legacy entries carry `merge_commit_sha`; `emit_approved`/`emit_issued` still fire. Head is durable; restart resumes. All existing tests pass; Vault/JWT/ext-proc behaviorally unchanged. Same key/kid signs JWTs and ledger entries — no second key/JWKS.

**Rollback.** `JIT_LEDGER_REQUIRED=false` (or `BACKEND=disabled`) → `append_entry` best-effort/no-op, mints proceed (reverts to L1's Loki-only audit). Full revert: drop the `append_entry` call sites + `GET /ledger*`; `ledger.py`/sign-verify/`emit_ledger` are additive and dormant. The INSERT-only WORM rows are harmless orphans. Evidence-only ⇒ no in-flight session loses its credential; legacy path untouched.

**Coexistence.** Runs parallel with the live git/ArgoCD-PR path. L2 attaches evidence to BOTH `/mint` and the legacy webhook merge, so each grant has (a) the legacy PR + merged `grants/<session>.yaml` + `emit_approved`/`emit_issued`→Loki and (b) the new signed chained entry carrying `merge_commit_sha`. Auditors cross-check by `merge_commit_sha`. Shared signing key (no new trust root). `JIT_LEDGER_REQUIRED` gates fail-closed: shadow mode (=false) the legacy path is authoritative; =true makes a durable signed entry a precondition for credential exposure. Git not yet demoted (that is L5).

**Effort.** M.

**Risks.** Hard dependency on L0 (no durable store ⇒ `append_entry` has nowhere to persist and fail-closed would block all mints — L0 green before `REQUIRED=true`). Fail-closed coupling adds an availability dependency on the WORM backend — mitigate with shadow mode + backend HA. Canonical-bytes drift breaks `verify_chain` silently — single shared `_canonical_json` + round-trip test. Ephemeral-key trap — deployment MUST assert the stable PEM mount (L0 prereq). Concurrency on `seq` — serialize on the L0 durable lock with CAS. Scope creep into gating — L2 stays evidence-only.

---

### L3 — DUAL-CONTROL: two distinct approvers for the dangerous tier

**Objective.** Extend the L1 single-approver `/mint` so the DANGEROUS tier requires TWO DISTINCT `approver_sub`s before issuance. Introduce a durable `SessionState.pending_second` interim state, a data-driven tier→threshold config (default 1; dangerous=2), and gate WHO may approve behind a Keycloak `approvers` group. First qualifying approval on a dangerous request records approver #1 and parks in `pending_second` WITHOUT minting; a second approval by a DIFFERENT approver (also != requester and != approver_1) clears the threshold and triggers the L1 mint path. Vault/JWT/ext-proc unchanged; git mirror live. Every transition is ledgered.

**Files to change.**
- `models.py` — add `SessionState.pending_second` (after `pending` ~159); add `approvals: list` + `required_approvals: int` optional audit fields to `SessionStatus` (~166). **Do NOT relax the hard ceiling** (23-27, 30, 83).
- `mint.py` (the L1 handler) — replace the single-shot flip with a threshold state machine: `required = threshold_for_tier(risk_tier(reviewed_req))`; `require_approver_group()` (403 if not a member); `approver_sub != requester_sub` (hard); `approver_sub not in session['approvals']` (409 no double-count); append under `store_lock`; if `len(approvals) < required` → `state=pending_second`, ledger `mint_parked`, return 202; else atomic `{pending|pending_second}->issued` flip + scope_hash recheck + `issue_credentials` + ledger `mint_issued`. All branches fail-closed.
- `tiers.py` (NEW) — pure `risk_tier(req)->int` (dangerous when `signing.tool_scope_for(req)` non-empty OR `policy_delta` non-empty OR ns outside the core allowlist) + `threshold_for_tier(tier)->int` (from `JIT_TIER_THRESHOLDS` JSON, default `{"0":1,"1":1,"2":2}`, **fail-closed to >=2 on parse error**). No I/O, deterministic. **Shared with L4.**
- `auth.py` (NEW) — `require_approver_group(request)->approver_sub`: read sub (`X-Forwarded-Preferred-Username`) + groups (`X-Forwarded-Groups`) from oauth2-proxy/Keycloak headers (mirrors `app.py:209-229`); 403 if `approvers` absent; **fail-closed when the groups header is missing** (missing == not a member).
- `store.py` — document new durable per-session keys `approvals`/`required_approvals`/`risk_tier` (in the L0 durable store so a restart between approval #1 and #2 does not lose approver #1).
- `audit.py` — add `emit_mint_parked` + `emit_mint_second_rejected` (feed L2 ledger + Loki; keep `_hash` discipline).
- `ledger.py` — add entry types `mint_parked`, `mint_second_rejected`; `mint_issued` carries `approvals[]` + `risk_tier` + `threshold`. Reuse `sign_ledger_entry` + L2 head.
- `services/approval-console/src/approval_console/app.py` — `approve()` handles the 202 `pending_second` ("Awaiting second approver (1 of 2)", keep polling); forward `X-Forwarded-Groups` on the `/mint` call.
- `platform/keycloak/base/realm-import.yaml` — add an `approvers` group under `groups` (216-220; the groups protocol mapper at ~100 already emits the claim). **Add a SECOND distinct seed approver** so threshold=2 is satisfiable (the realm seeds only `arsalan` today). Additive only — ADR-0013 stop line.
- `deploy/base/deployment.yaml` — add `JIT_TIER_THRESHOLDS` (default `{"0":1,"1":1,"2":2}`) + `JIT_APPROVERS_GROUP` (default `approvers`). Reuse the stable PEM for ledger signing.

**New artifacts.** `tiers.py`, `auth.py`, `tests/test_dual_control.py`.

**Implementing workflow loop.** Reusable five-stage. Scaffold: `tiers.py`, `auth.py`, the enum value, empty tests (imports resolve, existing `test_api.py` green). Implement: the `mint.py` state machine, ledger types, console `pending_second` handling, realm + deployment env. Test: unit + integration + restart-durability (approval #1 survives a store reload). Security gate (VETO): the bypasses below. Verify: Vault/signing/ext-proc byte-unchanged (`git diff` scoped to the L3 file list); git mirror still issues. **Loop-until-green:** stages green with zero adversarial findings ∧ `git diff --stat` only the declared files ∧ no diff in `vault.py`/`signing.py`/`ext-proc-delegation/**`.

**Tests.** UNIT `tiers`: `tool_scope_for` non-empty → threshold 2; read-only in-allowlist → 1; `policy_delta` → 2; malformed config → >=2. UNIT `auth`: `approvers` present → sub; missing header → 403; present-but-no-`approvers` → 403. INTEGRATION happy dangerous: A (member, != requester) → 202 `pending_second`, no Vault, ledger `mint_parked`; B (member, != requester, != A) → 200 issued, ONE `issue_credentials`, ledger lists `[A,B]`. Non-dangerous: single approval → issued (threshold 1, identical to L1). **ADVERSARIAL** self-approval → 403, ledger `mint_second_rejected(reason=self)`; same-approver-twice → 409, still `pending_second`; non-member second → 403; post-consent scope-hash drift → fail-closed, not issued; terminal-state replay → no second mint. DURABILITY: A approves → `pending_second` persisted → simulate reload → `approvals==[A]` → B approves → issued. MIRROR: webhook merge for the same (already-issued) session does not double-issue. CEILING regression: existing `test_api.py` rejections (delete/secrets/escalate/impersonate/duration>60/foreign ns/clusterroles/rolebindings) green.

**Security gate (VETO).** Must FAIL to: (1) self-approve; (2) satisfy threshold=2 as a single human approving twice; (3) approve while not in `approvers` (fail-closed when the groups header is absent); (4) downgrade a dangerous request via a forged/malformed `JIT_TIER_THRESHOLDS` (fail-closed >=2); (5) change scope between approval #1 and #2 (scope_hash recomputed from re-parsed bytes mismatches); (6) double-mint via webhook redelivery or concurrent `/mint` while `pending_second`. INVARIANTS: fail-closed everywhere; requester != approver_1 != approver_2 (all distinct, all members); no credential in git; anti-TOCTOU on BOTH approvals; Vault/JWT/ext-proc byte-unchanged; every accept AND reject ledgered (no silent denials).

**Acceptance.** A dangerous request is not issued until two distinct group-member approvers (both != requester) approve (exactly one `issue_credentials` after #2, zero after #1). First approval → 202 `pending_second`, durable. Self/same-twice rejected; non-member 403. `threshold_for_tier` data-driven + fail-closed; non-dangerous keeps threshold 1. scope_hash enforced on BOTH approvals. Approval #1 survives a restart. Every transition is a chained signed WORM entry; `mint_issued` lists both approvers + tier + threshold. `git diff` touches only the L3 files, zero in Vault/signing/ext-proc. Existing suite green; git mirror issues without double-minting. Realm has `approvers` + two distinct seed approvers.

**Rollback.** `JIT_DUAL_CONTROL_ENABLED=false` (default off until cutover) → `mint.py` uses the L1 single-approver path (threshold forced to 1) — `pending_second` never entered. Pure env flip, no migration; the durable `approvals[]` column is additive/ignored. The realm group + extra user are harmless if left. `git revert` for a hard rollback. The git mirror remains a working fallback approval path.

**Coexistence.** Parallel with the live git path; for dangerous sessions the console `/mint` is the authoritative gate (the webhook merge for an already-issued session no-ops via `_TERMINAL_STATES` + once-only flip). Git demoted to a diffable mirror; `merge_commit_sha` cross-check continues. Gated by `JIT_DUAL_CONTROL_ENABLED`. Standing policy uses the ArgoCD PR path unchanged. Vault/JWT/ext-proc untouched; issued credentials behave identically whether one or two approvers cleared — the only delta is dangerous requests wait for a second different approver.

**Effort.** M.

**Risks.** Single-replica in-memory store: if L0's durable migration is incomplete, a restart between approvals silently loses approver #1 (weakens to single-control) — L3 HARD-depends on L0, gated by the restart-durability test. oauth2-proxy must actually inject `X-Forwarded-Groups` — `auth.py` fails-closed on missing header; an integration test asserts the proxy passes the claim. `risk_tier` mis-classification — L4 re-enables the Kyverno backstop; until then ext-proc `tool_scope` binding remains the per-call enforcer. Approver-pool starvation — realm seeds >=2 approvers. Scope-hash recompute divergence — reuse the exact L1 function. Ledger write failure during a parked/issued transition must fail the mint closed (WORM write before the issuance commit, per L2).

---

### L4 — FAST-LANE: policy-driven Tier-0/1 auto-approve + Kyverno backstop

**Objective.** Add a deterministic `risk_tier(req)` over EXISTING signals and a FAST LANE in `/mint` so Tier-0/1 requests auto-approve SYNCHRONOUSLY at submit time without a human. Auto-approve re-parses the scope from the WRITTEN bytes (`grants/<session>.yaml` fed back through `gitea.parse_grant_yaml` so the ceiling runs on the artifact, never the in-memory request — anti-TOCTOU), mints via the unchanged `issue_credentials`, stamps `approver_sub='policy:<rule-id>'` + the standing-policy bundle digest, and writes a ledger entry. Anything dangerous (or not positively provable Tier-0/1) DEFAULTS TO HUMAN. Independently, **RE-ENABLE the Kyverno dangerous-tools `ValidatingPolicy`** so a mis-tier still cannot clear the per-call dangerous-tool gate — a fast-lane grant carries empty `tool_scope` and is structurally incapable of clearing it.

**Files to change.**
- `models.py` — add `RiskTier` IntEnum (`TIER0_READONLY=0..TIER3_DANGEROUS=3`) + `FAST_LANE_MAX_TIER`. Do NOT touch the ceiling validators or `SessionState.pending_second`.
- `risk.py` (NEW, the L4 core) — `risk_tier(req, *, allowlist=None)->RiskTier` + `is_fast_lane(req)->bool`. Pure. `tool_scope_for` non-empty → TIER3; `policy_delta` non-empty → >=TIER2; ns not in default allowlist → TIER2; MAX of all signals; unexpected shape → TIER3 (fail-closed-high). `is_fast_lane = risk_tier <= FAST_LANE_MAX_TIER AND tool_scope_for(req) == []` (belt-and-suspenders).
- `api.py` — in `create_request` (102) after the session is stored (129), if `is_fast_lane(req)` synchronously run `_auto_approve_and_mint(session_id, req)` and return 202 with issued state; else behave exactly as today. `_auto_approve_and_mint`: re-render via `gitea._render_scope_yaml` + re-parse via `gitea.parse_grant_yaml` (re-runs the ceiling on the artifact), re-assert `is_fast_lane` on the re-parsed object, `policy_bundle.match(reviewed_req)` → `(rule_id, digest)` or fail-closed, atomic flip under `store_lock`, `approver_sub='policy:'+rule_id` + `fastlane_bundle_digest`, `issue_credentials`, ledger entry, `emit_auto_approved` + `emit_issued`; ANY exception → roll state back to pending + `emit_denied` (falls to the human path). **Still calls `create_approval_pr` (123)** — fast-lane issues IN ADDITION to opening the mirror PR (removing git is L5, not L4).
- `audit.py` — add `emit_auto_approved(session_id, rule_id, tier, bundle_digest)` (event `jit_auto_approved`, `_inc('auto_approved')`).
- `policy_bundle.py` (NEW) — load the standing bundle (YAML rules: id, max_tier, ns globs, verb/resource matchers) from `JIT_FASTLANE_POLICY_PATH`, compute a sha256 digest at load, `match(req)->(rule_id,digest)|None`. **Fail-closed: missing/unparseable → None (everything goes human).**
- `deploy/base/deployment.yaml` + `kustomization.yaml` — add `JIT_FASTLANE_POLICY_PATH` env + a read-only `fastlane-policy` configmap volume (default conservative bundle: Tier-0/1 read + standard mutate on the two default namespaces only, no policy_delta, no dangerous tools). Keep the signing mount verbatim.
- `platform/kyverno/authz/base/dangerous-tools-admins-only.yaml` (RE-CREATE — the file does not exist) — fetch `GET /jwks`, assert the `X-JIT-Session-JWT` RS256 sig by `kid`, validity, `iss == JIT_SESSION_ISS`, `aud == JIT_SESSION_AUD`, and the requested MCP tool in the `tool_scope` claim (the contract `signing.py:225-269` documents). The mis-tier backstop.
- `platform/kyverno/authz/base/kustomization.yaml` — **uncomment line 17** to re-add `dangerous-tools-admins-only.yaml`. **Confirm the deployed kyverno-envoy-plugin provides the `mcp.Parse` CEL lib** (the original disable reason); if not, enforce the equivalent at the ext-proc layer and treat the Kyverno re-enable as defense-in-depth-only (deployment gate).
- `tests/test_risk.py` (NEW), `tests/test_api.py` (fast-lane + adversarial), `platform/kyverno/tests/authz/test.yaml` (re-add the dangerous-tool cases).

**New artifacts.** `risk.py`, `policy_bundle.py`, `deploy/base/fastlane-policy-configmap.yaml` (GitOps-owned so what auto-approves is itself a reviewed diffable change), `platform/kyverno/authz/base/dangerous-tools-admins-only.yaml`, `tests/test_risk.py`.

**Implementing workflow loop.** Reusable five-stage. Scaffold: `risk.py`, `policy_bundle.py`, the configmap, empty tests, the enum — no api.py wiring (imports resolve, ruff/mypy). Implement: wire `_auto_approve_and_mint`, add `emit_auto_approved`, recreate + re-enable Kyverno, deploy manifests (service boots under `TestClient`, `JIT_DISABLE_REAPER=1`). Test: `test_risk.py` + fast-lane + Kyverno authz cases (full pytest green AND Kyverno dangerous-tool cases pass). Security gate (AFTER tests green, can send back to implement): submit a dangerous request crafted to be mis-tiered, force a fast-lane grant to carry non-empty `tool_scope`, a render/parse round-trip that widens scope past re-validation, auto-issue with a missing/tampered bundle, a double-issue race, forge `approver_sub` to a human's sub — every attempt denied/fails-closed and ledgered. Verify: run the L2 chain verifier over a fast-lane run; confirm the `merge_commit_sha` mirror still emits; zero behavior change for non-fast-lane. **Loop-until-green:** stages 3,4,5 ALL pass on the same commit, no skipped tests.

**Tests.** `test_risk`: read-only in-allowlist, no policy_delta → TIER0/1, fast-lane True; firewall create (`tool_scope_for` non-empty) → TIER3, False; `policy_delta` → >=TIER2, False; out-of-allowlist ns → TIER2, False; duck-typed req missing `.verbs` → TIER3, False. `test_api` fast-lane happy: Tier-1 standard-mutate-on-allowed-ns → `/status` issued + `session_jwt`+`sa_token`, `approver_sub='policy:<rule-id>'`, `jit_auto_approved` emitted. Dangerous (firewall create) → stays pending. **ADVERSARIAL** mis-tier: classifies TIER3 and stays human-gated, AND even if `FAST_LANE_MAX_TIER` were mis-set, `tool_scope==[]` forces empty `tool_scope`, so the re-enabled Kyverno policy 403s the actual call. TOCTOU: mint from the re-parsed `reviewed_req`, not the in-memory `req`; a round-trip that would widen scope is rejected by `parse_grant_yaml`'s ceiling. Empty/missing/digest-mismatched bundle → no auto-approval. Double-submit → mint once. `approver_sub` can never be set to a human sub (always `policy:<rule-id>`, never from input). Ledger: one chained signed entry (`actor='policy:<rule-id>'`, bundle digest) dual-sunk; chain verifier passes. Kyverno authz: no-JIT → 403, invalid-JIT → 403, valid-in-scope → pass.

**Security gate.** PROVE the fast lane cannot become privilege escalation. (1) FAIL-CLOSED — TIER3 on unexpected input; missing/empty/unparseable/mismatched bundle → zero auto-approvals; any exception rolls back to pending + ledgers a denial; human dual-control is the default. (2) DANGEROUS CANNOT FAST-LANE — `is_fast_lane` requires `tool_scope==[]`, so a fast-lane JWT always carries empty `tool_scope` and the re-enabled Kyverno policy independently 403s the call (defense in depth). (3) ANTI-TOCTOU — issuance from re-parsed-from-written-bytes through the ceiling, never the trusted-on-input object. (4) SoD / NO SELF-APPROVAL CARVE-OUT — `approver_sub='policy:<rule-id>'`, never from input, never a human sub; the fast lane does not weaken L1/L3 for anything reaching the human path. (5) NO-CREDENTIAL-IN-GIT / WORM — every auto-approval ledgered with rule-id + digest before the agent can use the lease; the bundle is GitOps-owned/diffable. (6) ONCE-ONLY — the flip under `store_lock` mints once under concurrent/redelivered submits.

**Acceptance.** Tier-0/1 standard request → issued SYNCHRONOUSLY in one request/response, no human. `approver_sub='policy:<rule-id>'` + bundle digest; never from input. Dangerous/policy_delta/out-of-allowlist/unprovable → pending, routed to L1/L3. Missing/empty/unparseable/mismatched bundle → zero auto-approvals. Kyverno policy present + uncommented + its tests pass (incl. fast-lane empty-tool_scope 403s on a dangerous tool). Each fast-lane issuance → one chained signed WORM entry; chain verifier passes. Vault/JWT/ext-proc byte-unchanged; `create_approval_pr` still called for every request; webhook still issues for human-merged PRs. Full suite green; security stage finds no bypass.

**Rollback.** `JIT_FASTLANE_ENABLED=false` (default false until verified) OR an empty/absent bundle → `is_fast_lane` never true, 100% fall back to L1/L3. No schema/ledger change to revert. Re-comment `dangerous-tools-admins-only.yaml` to revert the Kyverno change independently (but prefer keeping it — it is a backstop). `git revert` removes `risk.py`/`policy_bundle.py`/the api.py branch cleanly.

**Coexistence.** Additive + flag-gated. `create_request` still calls `create_approval_pr` for every request (diffable mirror); the webhook still issues for human-merged PRs; the `merge_commit_sha` cross-check preserved. The fast lane is a synchronous short-circuit that issues IN ADDITION to opening the mirror PR — it skips the human WAIT for proven Tier-0/1, not the human path. Everything not provably Tier-0/1 takes the unchanged L1/L3 path. Vault/JWT/ext-proc untouched. Removing git as the boundary is L5, not L4.

**Effort.** M.

**Risks.** Mis-classification (central) — mitigated by three independent layers (`tool_scope==[]` guard, the re-enabled Kyverno policy, unchanged ext-proc); a single classifier bug is non-exploitable, but the classifier must stay conservative (fail-closed-high). **DEPLOYMENT BLOCKER:** the Kyverno policy was disabled because the plugin lacks `mcp.Parse`; re-enabling REQUIRES confirming the deployed plugin provides it — if not, the JWT assertion must be enforced at ext-proc (already the sole live enforcer) and the Kyverno re-enable is defense-in-depth-only; validate against the live cluster before the L4 security gate claims the Kyverno backstop is active. Synchronous mint adds Vault round-trip latency to POST /requests for fast-lane requests — keep the `store_lock` flip short, fail closed on Vault error. Restart mid-auto-approve — the L0 durable store + the L2 ledger (written in the same critical section, before the agent can use the lease) are the recovery anchors. Bundle drift — a digest change is a security-relevant event for reviewers.

---

### L5 — DECOMMISSION: retire webhook.py as the security boundary

**Objective.** Make the L1 console mint gate the SOLE issuance path and demote the Gitea-PR-merge webhook to an optional, fail-open AUDIT ECHO. `webhook.py` no longer calls `issue_credentials` / flips `pending->issued` — it only emits a `jit_pr_echo` cross-check (`git_mirror_verified`/`git_mirror_drift`) against the already-issued session. Git becomes a diffable scope MIRROR for the mint path (authoritative ONLY for the STANDING/ArgoCD policy path, out of L5's blast radius). Add ledger DR export/backup (periodic signed-segment export + head pointer to an offsite object store, restore-verify runbook). Vault/JWT/ext-proc unchanged. **Assumes L1–L4 landed.**

**Files to change.**
- `webhook.py` — demote `handle_gitea_webhook`: in `echo` mode REMOVE the atomic flip (216-233), `issue_credentials` (260), `openshell.widen_network` (279-299). KEEP HMAC `_verify_signature` + `X-Gitea-Delivery` dedupe. Replace the issuance block with: resolve session (`_find_session_for_pr`), re-read the merged grant (`_load_reviewed_request`), compute `scope_hash`, `audit.emit_pr_echo` comparing `merge_commit_sha` + `scope_hash` against the session's minted `scope_hash` → `git_mirror_verified`/`git_mirror_drift`; ALWAYS return 200. Gate behind `JIT_WEBHOOK_MODE` (default `echo`; legacy `enforce` retained one window). Echo mode is FAIL-OPEN (never denies/mints/alters state). `merged_by` recorded ONLY for cross-check, never approver-of-record.
- `api.py` — in `create_request`, when `JIT_GIT_MODE=='mirror'` make `create_approval_pr` (123) non-fatal (log + audit `git_mirror_pr_skipped`, `pr_url=None`, still 202) instead of the 502 (124-126). The standing/ArgoCD path unaffected. Surface `JIT_WEBHOOK_MODE`/`JIT_GIT_MODE` in `/healthz` (389).
- `gitea.py` — add `mirror_scope(session_id, reviewed_scope, scope_hash)` committing `grants/<session>.yaml` on a mirror branch WITHOUT a PR (reuse `create_branch` 244 + `commit_scope_file` 261; do NOT call `open_pr` 285). `fetch_merged_grant`/`parse_grant_yaml` stay for the echo cross-check; `create_approval_pr` retained for the standing-policy path + legacy `enforce` rollback.
- `audit.py` — add `emit_pr_echo(...)` (`git_mirror_verified`/`git_mirror_drift`) + `emit_ledger_export(...)` (`jit_ledger_export`). Keep `emit_approved` for the standing-policy path (no longer called by the demoted webhook).
- `store.py` — confirm no remaining in-memory-only issuance state the demoted webhook relied on; `store_lock`/`seen_deliveries` become advisory-only in echo mode (dedupe of echo events). Document the security-relevant once-only flip now lives ONLY in the L1 mint handler.
- `deploy/base/deployment.yaml` — add `JIT_WEBHOOK_MODE=echo` + `JIT_GIT_MODE=mirror` + DR export env (`JIT_LEDGER_EXPORT_SINK`, `JIT_LEDGER_EXPORT_INTERVAL`). Verify the stable PEM mount.
- `platform/kyverno/authz/base/kustomization.yaml` — ASSERT-ONLY (do not regress L4): `dangerous-tools-admins-only.yaml` MUST be ENABLED; add a guard test that fails if line 17 is still commented.
- `services/approval-console/src/approval_console/app.py` — remove the dead Gitea-merge path (1016-1047) once the `enforce` window closes; until then keep it behind `JIT_WEBHOOK_MODE`. Update the docstring + page banner copy.

**New artifacts.** `ledger_export.py` (`export_segment(store, sink, signer)`: read durable entries since the last exported seq, seal a contiguous `[from_seq..to_seq]` + head hash, RS256-sign the manifest with `signing._keys`, write to the sink, persist the watermark, `emit_ledger_export`). `ledger_restore_verify.py` (verify each segment sig against `/jwks`, re-link inter-segment hashes, assert continuity to the live head; read-only). `tests/test_webhook_echo.py`, `tests/test_decommission_guard.py`, `tests/test_ledger_export.py`, `deploy/base/ledger-export-cronjob.yaml`, `docs/runbooks/jit-ledger-dr.md`, `docs/adr/0014-decommission-git-approval-boundary.md`.

**Implementing workflow loop.** Reusable five-stage. **PREFLIGHT:** assert L1–L4 merged (`/mint` is the only minting path; durable store; chained signed ledger with durable head; `pending_second` + dual-control; `risk_tier` fast-lane; Kyverno policy ENABLED). If any absent, STOP. Scaffold: config flags, empty export/restore-verify, cronjob YAML, ADR/runbook stubs, failing test skeletons. Implement: demote webhook, add emitters, `mirror_scope`, non-fatal PR, export/restore-verify, console gating — loop until `pytest services/jit-approver` AND `go test ./...` in ext-proc pass AND `kustomize build platform/kyverno/authz/base` contains the dangerous-tools policy. Test: the adversarial cases (never-minted forged merge → no creds; tampered export → verify fails; post-decommission self-approval still 403). Security gate: try to mint via the git path, disable the dangerous-tool gate via the mirror, TOCTOU between mirror-write and mint, forge an export segment — not green until every attack is denied AND no credential material in git or any export. Verify: run the verify skill against a deployed jit-approver — a merged PR for an un-minted session issues nothing and only emits echo events; `/healthz` reports `JIT_WEBHOOK_MODE=echo`. **Loop-until-green:** all four test files pass + security sign-off + ext-proc go test unchanged + Kyverno policy in rendered manifests.

**Tests.** Echo-mode webhook for a MINTED session does NOT call `issue_credentials`, does NOT flip state, emits `git_mirror_verified`, 200; scope_hash mismatch → `git_mirror_drift` (still 200, no mint); unknown/already-issued → 200 fail-open. **ADVERSARIAL core:** a valid HMAC-signed merge for a NEVER-minted session → NO Vault role / SA token / JWT / state change (git provably cannot issue). Self-approval still 403 at the mint gate (M5 not reopened). Gate-off-via-git: re-merging a PR that edits the Kyverno policy does NOT disable enforcement (assert ENABLED in rendered kustomize). TOCTOU mirror vs mint: a scope edited in the mirror AFTER mint does not change the issued credential or ledgered `scope_hash`. Ledger tamper: flipped byte / reordered entry / severed inter-segment link / wrong sig FAILS `ledger_restore_verify`; an untampered N-segment export + live head verifies with zero gaps. INTEGRATION DR: export → restore-verify round-trip reconstructs a continuous signed chain; sink failure surfaces `ok=false` and leaves the live ledger uncorrupted. REGRESSION: standing-policy PR path still opens a PR; ext-proc `go test ./...` unchanged; `TestScopeCeilingRejections` + happy-path green.

**Security gate.** Reviewer MUST try to: (a) MINT via the git path (a valid merge for a never-minted session → ZERO issuance, ZERO state change); (b) DISABLE the dangerous-tool gate through git (the mirror has no authority over the Kyverno policy, which MUST stay ENABLED); (c) REOPEN M5 (approver != requester still hard-enforced at the mint gate); (d) TOCTOU between mirror-write and mint (issuance bound to the minted re-parsed-from-written-bytes scope); (e) FORGE/TAMPER an exported segment (RS256 sigs + hash-chain continuity make any flip/reorder/relink detectable; no credential or key material ever in git or an export). Echo-mode webhook is explicitly OFF the security path and may fail-open, but MUST NOT mint, deny, or alter state.

**Acceptance.** `webhook.py:handle_gitea_webhook` no longer calls `issue_credentials` or flips to issued in echo mode; the only issuance call site is the L1 mint handler. A signed merge for a never-minted session → 200, zero credentials, emits only `git_mirror_verified`/`drift`. `/healthz` reports `JIT_WEBHOOK_MODE=echo` + `JIT_GIT_MODE=mirror`. The Kyverno kustomization has `dangerous-tools-admins-only.yaml` UNCOMMENTED and it appears in `kustomize build`. Mint-gate SoD still 403s on self-approval. `ledger_export` produces signed hash-linked segments; `ledger_restore_verify` reconstructs a continuous chain; every tamper variant fails. The cronjob exists, mounts the stable PEM, writes to the sink; the DR runbook documents restore-verify. ext-proc go test + retained ceiling/happy-path green; no change to Vault/JWT/ext-proc. ADR-0014 records the boundary move.

**Rollback.** Single-flag: `JIT_WEBHOOK_MODE=enforce` (+ `JIT_GIT_MODE` retains PR creation) on jit-approver and the console — the legacy webhook issuance branch and the console PR-merge block are kept verbatim for one window so this is config-only, no redeploy. The L1 mint endpoint stays live in parallel; dual issuance prevented by the once-only durable flip both paths consult. The DR cronjob is additive (scale to zero with no issuance impact). Git history, `grants/*.yaml`, and the WORM ledger are append-only and unaffected.

**Coexistence.** Both paths run parallel one window: the L1 console mint gate is the LIVE boundary (sole issuer); the webhook runs in echo mode as a fail-open cross-check re-reading the merged grant and emitting `git_mirror_verified`/`drift` against the minted `scope_hash` + `merge_commit_sha` (L2 kept `merge_commit_sha` exactly for this). Git stays authoritative ONLY for the STANDING/ArgoCD policy PR path. JIT-grant git artifacts are demoted to a diffable mirror written without merge-gating. `JIT_WEBHOOK_MODE=enforce` + the retained legacy branches provide instant fallback. The window closes (dead merge code deleted) only after the security gate + DR restore-verify pass and `git_mirror_drift` has stayed empty across real traffic.

**Effort.** L.

**Risks.** Hard dependency on L1–L4 being landed and correct (PREFLIGHT gates this). Assumes L0 made `session_store` durable. Echo-mode is fail-open by design — a bug leaving a mint side-effect in the echo branch silently re-creates the git issuance path (the never-minted-merge → zero-creds test is the guard). The stable PEM MUST be genuinely stable (ledger + export sigs + `/jwks` reuse it). DR export adds a new egress + credential surface — export only already-hashed fields, sign manifests, never tokens/keys. Operator muscle memory (banner/docstring + ADR-0014 mitigate). Retargeting the webhook-issuance tests risks dropping coverage of invariants that moved to the mint path — verify each retired assertion has an L1 equivalent before deleting.

---

## 6. Test Harness Strategy

**Reused substrate (no reinvention):** pytest+respx contract suites with a fully-mocked Vault/Gitea boundary (`services/jit-approver/tests/test_api.py`, `services/approval-console/tests/test_app.py`); Go table-driven fail-closed tests in `services/ext-proc-delegation` (the SOLE live enforcer — **regression-frozen**); shell e2e "loop-until-green" journeys (`hack/test-openshift-jit.sh`, `test-kagenti-jit.sh`, `test-kagenti-identity.sh`). No GitHub Actions/GitLab CI — the gate is the Makefile (`test-extproc`, `test-policies`, `validate`) + `hack/validate.sh` (kustomize+kubeconform+go vet/build+py_compile).

**Per-loop pyramid:** LAYER 1 unit (pure fns: SoD comparator, `canonical_scope_hash`, `sign/verify_ledger_entry`, `risk_tier`, threshold lookup) — clone `test_sandbox_binding.py`/`TestApiGroupMapping`. LAYER 2 contract (respx, mocked Vault+Gitea+durable-store, in-proc `TestClient`/`ASGITransport`) — clone the `clear_store` fixture, `_mock_vault_issue`, `_insert_session`, `_post_webhook` helpers verbatim; this is where the bulk + adversarial cases live. LAYER 3 e2e (live cluster via `oc exec`, the `hack/test-*-jit.sh` pattern with ✅/❌ counters + `exit 1` on any fail).

**Mandatory adversarial suite** (new `TestMintGateAdversarial` in jit-approver + negatives in a new `hack/test-mintgate-jit.sh`), each asserting NO Vault mint on the deny path (`assert not creds.called`): self-approval → 403; merge-token-only-no-mint after L1; post-consent scope-edit fail-closed; TOCTOU re-read+re-validate; replay/idempotency mint-once; durable-store survives pod restart; ledger-tamper; dual-control distinct-approvers; fast-lane default-to-human + Kyverno mis-tier block.

**Per-loop live "verified green" scripts** (new `hack/test-*-jit.sh`, same convention): L0 durable-store/PEM-stable-across-restart; L1 mint-gate SoD (self-approve → 403, different user → mint); L2 ledger chain + `merge_commit_sha` cross-check; L3 dual-control (two identities required, same-approver-twice → 403); L4 fast-lane (Tier-0/1 auto, dangerous routed to human + Kyverno-blocked if mis-tiered).

---

## 7. Coexistence & Rollback Strategy (cross-cutting)

**Convergence point:** `issue_credentials()` in `vault.py` is the single mint primitive both the old webhook and the new `/mint` call — "two trigger paths, ONE mint". The atomic flip already guarantees mint-exactly-once.

**Feature-flag scheme (all default = today's behavior):** `JIT_MINT_GATE_ENABLED`, `JIT_APPROVAL_PRIMARY=webhook|mint`, `JIT_WEBHOOK_MODE=enforce|mirror|echo`, `JIT_LEDGER_ENABLED`+`JIT_LEDGER_REQUIRED`, `JIT_DUAL_CONTROL_ENABLED`+`JIT_TIER_THRESHOLDS`, `JIT_FASTLANE_ENABLED`, `JIT_STORE_BACKEND=memory|postgres`; console `APPROVE_MODE=merge|mint`. Each flag is one ArgoCD-synced env var, so cut-over AND rollback are a one-line git change + sync.

**GitOps note:** the jit-approver ArgoCD Application is automated + prune=true but **selfHeal=FALSE** — a manual `kubectl set env` hotfix (e.g. flip `JIT_APPROVAL_PRIMARY` back to webhook) is NOT reverted mid-incident, so emergency rollback is fast and durable until git is reverted. `prune=true` means deleting a manifest deletes the live object — sequence L5 manifest removals behind flags, never by yanking the Route.

**Durable-state migration is the single biggest correctness risk:** the once-only invariant currently relies on a process-local `asyncio.Lock`; moving to multi-replica/CNPG REQUIRES the guard move into a DB conditional UPDATE — keep `replicas:1` until the lock is DB-native. `expires_at` must survive restart (else the reaper over/under-revokes). Do the cutover in L0 behind `JIT_STORE_BACKEND` with shadow-write+compare before flipping read authority; CNPG is low-risk (operator already runs for Keycloak).

---

## 8. Risk Register (consolidated)

| ID | Risk | Loop | Mitigation |
|---|---|---|---|
| R1 | `/mint` caller-auth not enforced → any agent-sandbox pod self-approves with forged `approver_sub` | L1 | mTLS/console-SA-token check in-handler; agent-sandbox ingress NOT widened to `/mint`; adversarial agent-originated test |
| R2 | Restart into an ephemeral signing key invalidates all in-flight session JWTs ext-proc verifies | L0 | Stable PEM in Vault KV; `JIT_REQUIRE_STABLE_KEY`; `/jwks` kid-stable-across-restart test gates L1 |
| R3 | Multi-replica breaks the process-local once-only lock → double-mint | L0 | Postgres atomic `UPDATE...WHERE state=ANY...RETURNING`; document multi-replica REQUIRES `backend=postgres`; stay replicas:1 on SNO |
| R4 | Canonical-bytes drift between hash/sign and verify silently breaks `verify_chain` / spurious 409 | L1/L2 | single shared `_canonical_json`/`canonical_scope_hash`; cross-check + round-trip tests |
| R5 | Fail-closed ledger couples issuance to WORM backend availability | L2 | `JIT_LEDGER_REQUIRED` shadow mode during rollout; backend HA |
| R6 | `risk_tier` mis-classification auto-approves a dangerous request | L4 | three independent layers (`tool_scope==[]` guard, re-enabled Kyverno, unchanged ext-proc); fail-closed-high |
| R7 | Kyverno re-enable blocked by plugin lacking `mcp.Parse` | L4 | confirm plugin version against live cluster; else enforce at ext-proc and treat Kyverno as defense-in-depth-only |
| R8 | Echo-mode webhook bug leaves a mint side-effect → git issuance path re-created | L5 | never-minted-merge → zero-creds adversarial test is the guard; fail-open only, never mint/deny |
| R9 | Restart between dual-control approvals loses approver #1 → single-control | L3 | HARD-depends on L0 durable store; restart-durability test gates the loop |
| R10 | oauth2-proxy not configured to inject `X-Forwarded-Groups` | L3 | `auth.py` fails-closed on missing header; integration test asserts the proxy passes the claim |
| R11 | DR export egress leaks raw ledger fields | L5 | export only hashed fields, sign manifests, never tokens/keys |
| R12 | Retargeting webhook tests drops invariant coverage that moved to `/mint` | L5 | verify each retired assertion has an L1 equivalent before deleting |

---

## 9. Concrete `Workflow()` Example for L1 (representative loop)

The following is the executable workflow script shape for the L1 loop. It drives the reusable five-stage loop-until-green over the real L1 files. Agent types are distinct (`code-writer` ≠ `security-reviewer`) for separation of duties.

```python
def Workflow():
    """L1 CLOSE-M5: console-side mint gate. Loops the 5 stages until green."""

    JIT = "services/jit-approver"
    CONSOLE = "services/approval-console"

    # ---- STAGE 1: SCAFFOLD (code-writer) ----
    scaffold = run_agent(
        agentType="code-writer",
        prompt=f"""
        Create the L1 skeleton, default-off behind JIT_MINT_GATE_ENABLED:
        - {JIT}/src/jit_approver/mint_core.py with stubs:
            _enforce_dual_control(approver_sub, requester_sub) -> raise HTTPException(403)
            _verify_scope_hash(stored_req, presented_hash) -> raise HTTPException(409)
            _atomic_issue(session_id, reviewed_req, approver_sub, pr_number)  # pass for now
        - In {JIT}/src/jit_approver/models.py add MintRequest(approver_sub, reviewed_scope?, scope_hash)
          and canonical_scope_hash(req) (canonical JSON: namespace + sorted verbs + sorted resources
          + duration_minutes + sandbox + sorted host:port policy_delta, then sha256-hex).
        - In api.py add POST /requests/{{session_id}}/mint returning 501 for now.
        - In {CONSOLE}/src/approval_console/app.py add _canonical_scope_hash(detail) helper.
        Gate: ruff + mypy clean, both services import, FastAPI boots under TestClient.
        """,
    )
    require(scaffold.ruff_ok and scaffold.mypy_ok and scaffold.boots,
            on_fail=lambda: Workflow())  # restart from scaffold

    # ---- Loop stages 2..5 until the green condition holds ----
    while True:
        # ---- STAGE 2: IMPLEMENT (code-writer) ----
        run_agent(
            agentType="code-writer",
            prompt=f"""
            Fill the L1 logic, keeping vault.py / signing.py / ext-proc untouched except call-sites:
            1. Extract webhook.py:220-233 (atomic claim+flip) and 244-308 (mint+rollback,
               minus the Gitea grant re-read which stays in webhook) into
               mint_core._atomic_issue(session_id, reviewed_req, approver_sub, pr_number).
            2. mint_core._enforce_dual_control: 403 when approver_sub == requester_sub OR either empty.
            3. Refactor webhook.handle_gitea_webhook to call mint_core._enforce_dual_control(
               merged_by, reviewed_req.requester_sub) + mint_core._atomic_issue(...) so the
               still-live git path is ALSO M5-safe (one shared issuance path).
            4. Implement POST /requests/{{session_id}}/mint in api.py: authenticate the caller as the
               console SA (mTLS client-cert or console-SA token; NEVER GITEA_TOKEN, NEVER an agent SVID);
               parse MintRequest; load pending session (404); reject if state not in {{pending,approved}} (409);
               recompute canonical_scope_hash(session['request']) and compare to body (409 mismatch);
               _enforce_dual_control(body.approver_sub, session['request'].requester_sub) (403);
               _atomic_issue(session_id, session['request'], body.approver_sub, session.get('pr_number')).
            5. Rewrite {CONSOLE} approve(): replace the PUT .../pulls/{{n}}/merge block (app.py:1016-1047)
               with POST {{jit_url}}/requests/{{id}}/mint carrying
               {{approver_sub:_actor(request), reviewed_scope, scope_hash:_canonical_scope_hash(detail)}};
               surface 403 to the browser; remove Config.gitea_token() from the approval path.
            Gate: both services compile, mypy clean.
            """,
        )

        # ---- STAGE 3: TEST (test-writer) ----
        run_agent(
            agentType="test-writer",
            prompt=f"""
            Author {JIT}/tests/test_mint.py and extend {CONSOLE}/tests/test_app.py:
            - UNIT: _enforce_dual_control 403 on equal/empty, pass on distinct; _verify_scope_hash 409/pass.
            - UNIT: canonical_scope_hash stable under reordering; cross-check the console helper and the
              jit-approver helper produce IDENTICAL hashes for the same scope.
            - INTEGRATION happy: distinct approver + matching hash on a pending session -> 200 issued,
              exactly one Vault mint (respx _mock_vault_issue), one session JWT, state==issued.
            - INTEGRATION once-only: two concurrent /mint -> creds.call_count == 1.
            - ADVERSARIAL self-approval (THE M5 test): approver_sub == requester_sub -> 403,
              state stays pending, assert not creds.called, emit_denied audited.
            - ADVERSARIAL TOCTOU: scope edited after detail / hash for a broader scope -> 409, no mint.
            - ADVERSARIAL auth: no/invalid console-SA cred -> 401; agent-sandbox principal -> rejected.
            - ADVERSARIAL webhook git-mirror M5: merge whose merged_by == requester_sub -> denied.
            - CONSOLE: approve() POSTs to /mint (respx asserts NO Gitea /merge call), forwards approver_sub.
            - REGRESSION: run the FULL existing webhook/replay/audit suites unchanged.
            """,
        )
        test = sh(f"(cd {JIT} && pytest -q) && (cd {CONSOLE} && pytest -q)")
        if not test.ok:
            continue  # back to STAGE 2 with the failing assertion in context

        # ---- STAGE 4: ADVERSARIAL SECURITY GATE (security-reviewer, DISTINCT agent, VETO) ----
        sec = run_agent(
            agentType="security-reviewer",
            prompt=f"""
            Adversarially attempt to break the L1 mint gate. Each MUST fail-closed (403/409/401,
            never 200/issued) and make ZERO Vault calls on the deny path:
            (1) self-approve: empty / whitespace / unicode-normalized / case-variant approver_sub
                colliding with requester_sub.
            (2) bypass auth: call /mint with no credential, with the shared GITEA_TOKEN, and from an
                agent-sandbox-shaped SVID; confirm the SUBMIT principal cannot call /mint.
            (3) TOCTOU: edit the stored scope after the approver viewed it / present a hash for a broader scope.
            (4) replay: re-send a captured mint body for an already-issued session.
            (5) no-credential-in-git: assert the console approval path never reads GITEA_TOKEN and
                `git grep -E 'BEGIN.*PRIVATE KEY|password=|postgres://[^$]'` over tracked files is empty.
            Report any probe that returned 200/issued or any Vault mint on a deny path.
            """,
        )
        if sec.findings:
            continue  # VETO -> back to STAGE 2

        # ---- STAGE 5: VERIFY (code-reviewer) ----
        verify = run_agent(
            agentType="code-reviewer",
            prompt=f"""
            Confirm the L1 invariants by diff-review:
            - git diff shows ZERO hunks in {JIT}/src/jit_approver/vault.py, signing.py
              (mint_session_jwt/jwks/tool_scope_for), and services/ext-proc-delegation/**.
            - The webhook git-mirror path still issues via mint_core (now SoD-enforced).
            - The only behavioral delta is approver != requester enforcement.
            - git diff --stat touches only the declared L1 files.
            """,
        )

        green = (test.ok and not sec.findings and verify.untouched_paths_ok
                 and verify.nosecret_grep_empty)
        if green:
            return Result(status="L1-green",
                          artifacts=["mint_core.py", "test_mint.py",
                                     "docs/decisions/0007-console-mint-gate-replaces-pr-merge-approval.md"])
        # else loop: control returns to STAGE 2
```

---

## 10. Done / Ship Criteria (whole migration)

The migration is complete when, in order: L0 proves a stable PEM + durable store; L1 makes self-approval impossible (the M5 gap is objectively closed) with the console no longer holding the `GITEA_TOKEN` approval power; L2 makes every decision a verifiable signed WORM entry that is a precondition for credential exposure; L3 requires two distinct approvers for the dangerous tier; L4 auto-approves Tier-0/1 with the Kyverno backstop active; and L5 makes the mint gate the sole issuer with webhook demoted to a fail-open echo and the ledger DR-exportable — all while `git diff` shows zero behavioral change to Vault, the RS256 session JWT, and ext-proc per-call enforcement, and the live demo never broke because every step shipped behind a flag defaulting to the prior known-good behavior.