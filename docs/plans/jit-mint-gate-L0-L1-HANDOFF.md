# HANDOFF — JIT approval: git-PR → console mint-gate (L0+L1 done)

> **Part of:** [Master Plan — OpenShell Agentic Platform](openshell-agentic-platform-master-plan.md) → **Phase B (JIT/token system)**, Loop B2.

**Date:** 2026-06-20 · **Branch:** `feat/jit-mint-gate-L0-L1` (UNCOMMITTED) · **Author of handoff:** prior Claude session

---

## TL;DR

We are replacing **Git-PR-merge as the JIT approval gate** with a **console-side, Keycloak-authenticated mint gate** in `jit-approver` that enforces `approver_sub != requester_sub` (closes the **M5 self-approval gap**), backed by a hash-chained **CNPG WORM** audit ledger and (later) a policy auto-approve fast lane. Vault lease + RS256 session JWT + ext-proc per-call enforcement are **untouched**; git is demoted to a diffable scope mirror.

**Loops L0 (durable prereqs) and L1 (M5 close) are CODE-COMPLETE and locally green, uncommitted on the branch.** They are **NOT deployed** and **NOT live-tested** — see Blockers.

- Full plan (6 loops L0–L5, reusable loop pattern, risk register): `docs/plans/jit-approval-replacement-implementation.md`
- ADR: `docs/decisions/0007-console-mint-gate-replaces-pr-merge-approval.md`
- Memory: `project-console-mint-gate.md` (+ related `project-jit-ttl-decouple` ADR-0014, `project-openshift-jit-demo`)

---

## Locked decisions (from the user)

| Decision | Choice | Note |
|---|---|---|
| WORM ledger backend | **CNPG INSERT-only table** | operator already runs for Keycloak; REVOKE UPDATE,DELETE enforces WORM at the privilege layer |
| `/mint` caller-auth | **mTLS via SPIFFE SVID** | …but the hop has **no SVID wired today** (see below), so L1 ships SPIFFE code behind `JIT_MINT_REQUIRE_MTLS` + an **interim K8s-SA TokenReview** so `/mint` is never open |

---

## What changed (18 files, +1237/−127, plus new modules)

### L0 — durable prerequisites (invisible to live path; default-off)
- **New** `services/jit-approver/src/jit_approver/persistence/` → `base.py` (Store ABC), `memory.py` (byte-identical compat shim — keeps `session_store`/`seen_deliveries`/`store_lock` working for every caller), `postgres.py` (asyncpg, DB-native atomic once-only flip), `schema.sql` (4 tables; `jit_ledger` INSERT-only with `REVOKE UPDATE,DELETE`).
- **New** `platform/jit-approver-db/` → CNPG `Cluster jit-approver-db` (mcp-gateway ns, instances:1, storageClass local-path) + schema initdb ConfigMap + kustomization (referenced from anaeem overlay only).
- **Mod** `store.py` (compat shim + `get_store()` factory), `signing.py` (fail-closed `JIT_REQUIRE_STABLE_KEY` guard — only change), `api.py` (lifespan `startup_check` + `/healthz` `store_backend` + 503-until-ready), `pyproject.toml` (`[durable]`=asyncpg optional), `deploy/base/deployment.yaml` (additive env), `platform/vault/config/vault-bootstrap.sh` (refuse to rotate an existing signing key).
- **New** `tests/test_persistence.py`.

### L1 — the M5 close
- **New** `services/jit-approver/src/jit_approver/mint_core.py` → ONE shared issuance path used by **both** `/mint` and the still-live webhook: `_enforce_dual_control` (fail-closed `approver_sub != requester_sub`), `_verify_scope_hash` (TOCTOU→409), `_atomic_issue` (once-only flip + emit_approved + issue_credentials + emit_issued + rollback).
- **Mod** `api.py` → `POST /requests/{id}/mint` (auth caller → parse MintRequest → load pending → scope_hash check → SoD → atomic issue). `models.py` → `canonical_scope_hash()` + `MintRequest` + `min_length=1` on `requester_sub`. `webhook.py` → routes through `mint_core`; **SoD now reads `requester_sub` from the re-validated merged grant** (see M5-fix note).
- **Mod** `services/approval-console/src/approval_console/app.py` → `approve()` POSTs to `/mint` with the Keycloak `_actor()` `approver_sub`; **no Gitea merge / no `GITEA_TOKEN`** in default path (legacy merge retained behind `JIT_APPROVE_VIA_MINT=false` for rollback). Sends `X-Console-SA-Token` from the projected SA token (`app.py:245-274`).
- **Mod** console + jit-approver `deploy/base/` → pod `automountServiceAccountToken: true`, new env vars (below).
- **New** `tests/test_mint.py`, ADR-0007.

### Caller-auth on `/mint` (two-tier, `mint_core`/`api.py`)
- `JIT_MINT_REQUIRE_MTLS=true` → extract peer SPIFFE ID from `X-Peer-Spiffe-Id` (set by a TLS proxy), check against `JIT_MINT_ALLOWED_SPIFFE_IDS`. **Not live yet** (no proxy/SVID on this hop).
- `JIT_MINT_REQUIRE_MTLS=false` (current default) → require `X-Console-SA-Token`, validate via **K8s TokenReview**, accept only SA matching `JIT_MINT_CONSOLE_SA_PREFIX`. Test seam: `JIT_MINT_CONSOLE_TOKEN_OVERRIDE`.
- Missing/invalid → 401; wrong identity → 403.

### Feature flags & defaults
| Flag | Service | Default | Effect |
|---|---|---|---|
| `JIT_STORE_BACKEND` | jit-approver | `memory` | `postgres` enables durable store |
| `JIT_REQUIRE_STABLE_KEY` | jit-approver | `false` | `true` crashloops on missing PEM |
| `JIT_MINT_GATE_ENABLED` | jit-approver | (see deployment) | enables `/mint` |
| `JIT_MINT_REQUIRE_MTLS` | jit-approver | `false` | true=SPIFFE mTLS, false=TokenReview interim |
| `JIT_MINT_CONSOLE_SA_PREFIX` | jit-approver | set in manifest | allowed console SA for TokenReview |
| `JIT_APPROVE_VIA_MINT` | console | on | off = legacy Gitea-merge rollback path |

---

## M5-fix note (done beyond the agents' work — IMPORTANT)

The security gate flagged, as *non-blocking*, that the webhook mirror skipped SoD when `requester_sub` was empty (`if _requester_sub:`). That was a real residual self-approval bypass on the live git path. **Fixed:** `webhook.py` now runs SoD **after** `_load_reviewed_request`, reading `reviewed_req.requester_sub` (the re-validated *merged grant* value — authoritative, preserves the C2 "never read in-memory `session['request']`" invariant), and `requester_sub` got `min_length=1` so an empty one fails re-validation. Strengthened `TestWebhookMirrorM5::test_webhook_self_approval_denied` to mock a real grant rather than rely on the removed in-memory read.

---

## Verification status (local, reproducible)

```bash
# jit-approver: 144 passed, 11 skipped (postgres live-DB skip — asyncpg not installed), 1 PRE-EXISTING fail
cd services/jit-approver && .venv/bin/python -m pytest -q
# approval-console: 42 passed
cd services/approval-console && .venv/bin/python -m pytest -q
# invariants (all hold):
git diff -- services/jit-approver/src/jit_approver/vault.py | wc -l        # 0
git status --porcelain -- services/ext-proc-delegation                    # empty
git grep -nE 'BEGIN.*PRIVATE KEY|password=|postgres://[^$]' -- . ':(exclude)**/.venv/**'  # only <pw> doc placeholders
```

**Pre-existing unrelated failure (NOT from this work):** `tests/test_api.py::TestSessionJwtAndJwks::test_minted_jwt_iss_matches_policy_constant` — `FileNotFoundError` on `platform/kyverno/authz/base/dangerous-tools-admins-only.yaml`, a file deleted in an earlier commit. Decide separately whether to fix.

---

## BLOCKERS before a live cluster e2e test

1. **Cluster context is wrong/empty.** `oc` currently → `api.virt.na-launch.com` (context `monopoly-deal/...`), which has `mcp`, `vault`, `rhoai-agentic`… but **NOT `mcp-gateway` or `agent-sandbox`** (the JIT platform namespaces). The PoC platform is not on this context. **ACTION NEEDED:** switch kubeconfig to the cluster where `mcp-gateway`/`agent-sandbox` live (SPIFFE domain in code = `spiffe://anaeem.na-launch.com/...`), or (re)deploy the platform.
2. **Not committed/built/deployed.** Code is uncommitted on the branch, not in images. Deploy is **GitOps/ArgoCD** (`gitops/applications/jit-approver.yaml`). Live test path: commit → build/push images → ArgoCD sync.
3. **Missing TokenReview RBAC.** The interim auth needs a `ClusterRoleBinding` binding the jit-approver SA to `system:auth-delegator` (tokenreviews:create). **It does not exist** — only comments reference it (`grep system:auth-delegator` repo-wide hits only Vault's chart). Without it, `/mint` fail-closes on EVERY console call on-cluster. **Must add before any live interim-auth test.**
4. **Other on-cluster prereqs:** seed a stable signing PEM at `secret/data/jit-approver/jit-signing-key`; to test durability flip `JIT_STORE_BACKEND=postgres` + `oc apply -k platform/jit-approver-db`; for real mTLS later: register an approval-console ClusterSPIFFEID, fix the jit-approver SVID label selector, terminate client-cert TLS on :8080.

---

## How to test

### Local integration smoke (possible NOW, no cluster)
Boot console + jit-approver as uvicorn, mock Vault, drive: approve→`/mint` issues once; **self-approval→403**; scope-hash mismatch→409; webhook-mirror self-approval denied. Use `JIT_MINT_CONSOLE_TOKEN_OVERRIDE` for the console→`/mint` auth. (The unit suites already cover the logic; this proves the HTTP wiring.)

### Live cluster e2e (after blockers 1–3)
Point at the platform cluster → add TokenReview RBAC → commit/build/push → ArgoCD sync → run the journey via the console (the established hand-test: spawn-shell → read 200 / write 403 → approve in console → write 200, now through `/mint` with SoD) and the negative self-approval → "You cannot approve your own request." See `hack/test-openshift-jit.sh`, `hack/spawn-shell.sh`.

---

## Roadmap remaining (per plan doc)

- **L2 LEDGER** — hash-chained RS256-signed append-only WORM entries on the `mint_core` decision point (needs `JIT_STORE_BACKEND=postgres`).
- **L3 DUAL-CONTROL** — two distinct approvers for the dangerous tier; needs a **2nd seed approver identity + an `approvers` Keycloak group** (realm seeds only `arsalan` today; additive only — ADR-0013 forbids broad realm mutation).
- **L4 FAST-LANE** — `risk_tier()` Tier-0/1 auto-approve + re-enable Kyverno dangerous-tools policy. **Blocked** on `kyverno-envoy-plugin` upgrade providing `mcp.Parse` (kustomization.yaml:16-18); until then ext-proc stays sole enforcer and L4 must not fast-lane any non-empty `tool_scope`.
- **L5 DECOMMISSION** — webhook → fail-open audit echo; git → scope mirror only; ledger DR export.

**Other open decisions:** audit field naming during transition (`merged_by` vs explicit `approver_sub`); multi-replica posture (process-local `asyncio.Lock` vs DB-native — requires `JIT_STORE_BACKEND=postgres` for >1 replica).

---

## Key pointers
- Plan: `docs/plans/jit-approval-replacement-implementation.md`
- ADR: `docs/decisions/0007-console-mint-gate-replaces-pr-merge-approval.md`
- This handoff: `docs/plans/jit-mint-gate-L0-L1-HANDOFF.md`
- Reusable per-loop pattern: scaffold → implement → test → **adversarial security gate (distinct agent, veto)** → verify, loop-until-green (pre-existing suite green AND new tests green AND zero security findings AND no-secrets-in-git AND only-declared-files-touched).
