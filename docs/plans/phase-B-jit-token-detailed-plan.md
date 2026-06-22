# Phase B — JIT / Token System: Detailed Plan (resolve-verify loops)

> **Part of:** [Master Plan — OpenShell Agentic Platform](openshell-agentic-platform-master-plan.md) → **Phase B**.
>
> **Status:** Plan of record. Authored 2026-06-22. Phase A core journey PROVEN. Phase B is NOW
> UNBLOCKABLE. Loop B1 (ADR-0014 operation-shaped TTL) and Loop B2 (console mint-gate L0/L1 → live)
> may proceed immediately and in parallel with each other. Loop B3 (k8s TokenRequest per-capability SA)
> is independent of Phase A runtime but requires B1+B2 merged first so the gate is in place.
>
> **Branch:** `feat/openshell-native-svid-grant` (current). File-only authoring here.
> **Do NOT edit** `hack/test-openshift-jit.sh` or any proven-4/4 journey artifacts.

---

## Hard invariants carried through every loop

1. **No long-lived credential in the agent.** The agent holds only its SPIFFE SVID and, for the
   duration of a human-approved window, its own short-lived scoped capability JWT. The SA token
   minted by Vault is never forwarded through the agent.
2. **ext-proc stays in front** as the per-tool tool-scope gate and audit emitter (ADR-0011 hybrid;
   native OpenShell `provider_spiffe` supplies credential mint only).
3. **Approver != requester** (SoD): `mint_core._enforce_dual_control` is the single enforcement
   point; it is not duplicated.
4. **WORM audit**: every gate decision emits a structured audit log entry with `tool_args_hash`
   (SHA-256 of serialised arguments — never raw); credentials are never logged.
5. **Fail-closed on any authz ambiguity**: missing jti row → DENY; CNPG unreachable → 503 (not
   allow); invalid JWT → DENY.

---

## Loop B1 — Operation-shaped JIT TTL (ADR-0014)

### Goal

Implement the five ADR-0014 touch-points so that: one-shot mutating writes get a 5-minute
single-use capability JWT (jti consumed atomically in CNPG on first gate pass); interactive
session tools get 30 minutes reuse-window; the k8s 600s floor on the Vault SA-token mint is
preserved; multi-replica jit-gate replicas are safe because the consumed-jti table is in CNPG.

### Steps

**Step B1.1 — `models.py:86`: relax the JWT-path floor from `ge=10` to `ge=1`**

File: `services/jit-approver/src/jit_approver/models.py`

Current:
```python
duration_minutes: Annotated[int, Field(ge=10, le=60)] = Field(
    ...,
    description="Duration for the credential grant, 10–60 minutes. ..."
)
```

Change: lower the `ge` validator to `ge=1`. Update the `description` to explain that the
`duration_minutes` is now the **capability-JWT TTL only**; the SA-token mint clamps separately.
The `le=60` hard cap stays.

TODO in implementation: update the field docstring to say: "Floor for the session JWT exp is now
1 minute (operation-class derived server-side). The k8s SA-token mint enforces a separate ≥10 min
floor independently."

**Step B1.2 — `signing.py`: add `operation_class_for(tool_scope)` and per-class `exp` derivation**

File: `services/jit-approver/src/jit_approver/signing.py`

Add after `tool_scope_for` (line ~251):

```python
# Single-use class: one-shot mutating writes whose jti is consumed by the gate.
# Reuse-window class: interactive sessions (exec, run) that may call the tool
# multiple times within the approved window.
_SINGLE_USE_TOOLS: frozenset[str] = frozenset({
    "create_firewall_rule_advanced",
    "add_firewall_rule",
    "resources_create_or_update",
    "resources_scale",
})
_REUSE_WINDOW_TOOLS: frozenset[str] = frozenset({
    "pods_exec",
    "pods_run",
})

# Canonical capability TTLs (minutes). These drive session-JWT exp only.
CAPABILITY_TTL_SINGLE_USE_MINUTES: int = 5
CAPABILITY_TTL_REUSE_WINDOW_MINUTES: int = 30


def operation_class_for(tool_scope: list[str]) -> str:
    """Return 'single_use' or 'reuse_window' for the granted tool set.

    Falls back to 'single_use' (shorter, safer) when the tool set is empty
    or unrecognised — fail-closed.
    """
    tools = frozenset(tool_scope or [])
    if tools & _REUSE_WINDOW_TOOLS and not (tools & _SINGLE_USE_TOOLS):
        return "reuse_window"
    return "single_use"


def capability_ttl_minutes(tool_scope: list[str]) -> int:
    """Return the capability-JWT TTL in minutes derived from the operation class."""
    cls = operation_class_for(tool_scope)
    if cls == "reuse_window":
        return CAPABILITY_TTL_REUSE_WINDOW_MINUTES
    return CAPABILITY_TTL_SINGLE_USE_MINUTES
```

Modify `mint_session_jwt` signature and body: remove the caller-supplied `duration_minutes`
argument (or keep it as an override for backward compat only). Instead, derive TTL internally
from `tool_scope` via `capability_ttl_minutes(tool_scope)`. Update the `exp` line:

```python
# exp is derived from the operation class, NOT from the requested duration_minutes.
# duration_minutes is the SA-token floor (caller handles that separately).
cap_ttl = capability_ttl_minutes(tool_scope)
exp = issued_at + cap_ttl * 60
```

The `expires_at` value returned to the agent in `/requests/{id}/status` must reflect the session-JWT
`exp`, not the SA-token lease.

TODO: update `vault.py` call-site of `mint_session_jwt` to pass tool_scope instead of relying on
duration_minutes for exp.

**Step B1.3 — `vault.py:175,189-211`: clamp SA-token TTL to `max(600s, capability_ttl_seconds)`**

File: `services/jit-approver/src/jit_approver/vault.py`

At the point where `ttl` is derived (line 175: `ttl = f"{req.duration_minutes}m"`), add:

```python
# Clamp SA-token TTL to the k8s 600s floor (KEP-1205). The capability JWT
# already enforces the real authz window (single-use or reuse-window); the
# SA token is a coarse outer backstop gated by NetworkPolicy and the consumed-jti
# table. We always request at least 10 minutes to satisfy Vault's kubernetes
# engine (which mirrors the k8s API validation).
_MIN_SA_MINUTES = 10
sa_ttl_minutes = max(_MIN_SA_MINUTES, req.duration_minutes)
ttl = f"{sa_ttl_minutes}m"
```

The `expires_at` timestamp written to `session_store[session_id]["expires_at"]` and returned in
the status response must be computed from the **capability TTL** (session-JWT `exp`), not `sa_ttl_minutes`.

**Step B1.4 — `gate.py`: atomic jti consume-on-use for single-use class**

File: `services/jit-gate/gate.py`

This is the most security-critical change. After validating the JWT (line ~61, `jwt.decode`), and
before returning `(True, ...)`, add the single-use check for single-use-class tools:

```python
# Determine operation class from the capability JWT's tool_scope.
# Import locally to avoid a circular dep on jit_approver (gate runs standalone).
_SINGLE_USE_TOOLS_GATE = {
    "create_firewall_rule_advanced",
    "add_firewall_rule",
    "resources_create_or_update",
    "resources_scale",
}

# After JWT decode, before returning allow:
jti = claims.get("jti") or claims.get("sub")  # jti == session_id (signing.py:305)
if tool in _SINGLE_USE_TOOLS_GATE:
    # Atomic consume-on-use: INSERT ... ON CONFLICT DO NOTHING
    # If rowcount == 0 the jti was already consumed — DENY replay.
    consumed = await _consume_jti(jti, tool)
    if not consumed:
        return False, f"capability already consumed (jti={jti}, tool={tool})"
```

`_consume_jti` is a new async function that connects to CNPG `consumed_jti` table
(connection string from `DATABASE_URL` env, fail-closed if unreachable):

```python
async def _consume_jti(jti: str, tool: str) -> bool:
    """Atomically consume a jti. Returns True on first use, False on replay."""
    if not _db_pool:
        # CNPG not configured: fail-closed for single-use tools.
        print(f"jit-gate: CNPG not configured; denying single-use tool {tool}", flush=True)
        return False
    async with _db_pool.acquire() as conn:
        result = await conn.execute(
            """
            INSERT INTO consumed_jti (jti, tool, consumed_at)
            VALUES ($1, $2, now())
            ON CONFLICT DO NOTHING
            """,
            jti, tool,
        )
        # asyncpg returns "INSERT 0 1" or "INSERT 0 0"
        return result == "INSERT 0 1"
```

`_db_pool` is an `asyncpg.Pool` initialised at FastAPI startup from `DATABASE_URL`. If
`DATABASE_URL` is not set, the gate falls back to fail-closed for single-use tools (logged,
no silent pass). For reuse-window tools, `_consume_jti` is never called.

TODO: add `asyncpg` to `services/jit-gate/` dependencies (or reuse the jit-approver image which
already carries the `[durable]` extra with asyncpg).

**Step B1.5 — CNPG migration: add `consumed_jti` table**

Two files need to be updated in sync:

- `services/jit-approver/src/jit_approver/persistence/schema.sql`
- `platform/jit-approver-db/base/schema-initdb-configmap.yaml`

The migration SQL is authored at:
`platform/jit-approver-db/migration/add-consumed-jti.sql`
(see AUTHORED ARTIFACT below).

Both the `schema.sql` source-of-truth and the ConfigMap inline copy receive the table DDL.

**Step B1.6 — NetworkPolicy: jit-gate egress to CNPG**

File: `services/jit-gate/deploy/jit-gate-k8s.yaml` and `services/jit-gate/deploy/jit-gate-openshell.yaml`

Add an egress NetworkPolicy rule allowing jit-gate pods to reach the CNPG primary in `mcp-gateway`
namespace on port 5432. The existing `allow-egress-kube-api` NP in `mcp-gateway` covers a different
selector; jit-gate lives in `mcp-gateway` (for k8s path) and `openshell` (for openshell path). Add:

```yaml
# In the jit-gate-k8s.yaml or a new NP file:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: jit-gate-egress-cnpg
  namespace: mcp-gateway
spec:
  podSelector:
    matchLabels:
      app: jit-gate-k8s
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              cnpg.io/cluster: jit-approver-db
      ports:
        - port: 5432
          protocol: TCP
```

A matching NP is needed in `openshell` ns for `jit-gate-openshell`.

**Step B1.7 — Add `DATABASE_URL` env to jit-gate deployments (GATED)**

Both `services/jit-gate/deploy/jit-gate-k8s.yaml` and `services/jit-gate/deploy/jit-gate-openshell.yaml`
need:

```yaml
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: jit-approver-db-app
        key: uri
```

This is the same CNPG-generated secret that jit-approver uses for its durable store (already created
by the CNPG Cluster in `platform/jit-approver-db/`). No credentials in git.

NOTE: the `jit-approver-db-app` secret is in `mcp-gateway`; for the `openshell` ns jit-gate, an
`ExternalSecret` or a `Secret` copy (namespaced) is required. TODO for implementation: decide
whether to use an ExternalSecret or a projected secret copy.

**Step B1.8 — tests**

File: `services/jit-approver/tests/test_ttl_decouple.py` (new)

Required tests (table-driven, no network):
- `test_operation_class_single_use`: `["create_firewall_rule_advanced"]` → `"single_use"`
- `test_operation_class_reuse_window`: `["pods_exec"]` → `"reuse_window"`
- `test_operation_class_mixed_falls_back_to_single_use`: mixed set → `"single_use"` (fail-closed)
- `test_operation_class_empty_falls_back_to_single_use`: `[]` → `"single_use"`
- `test_capability_ttl_single_use_is_5_minutes`: TTL == 5
- `test_capability_ttl_reuse_window_is_30_minutes`: TTL == 30
- `test_mint_session_jwt_exp_from_operation_class`: minted JWT `exp - iat` == 300 for single-use
- `test_sa_ttl_clamped_to_600s_floor`: `sa_ttl_minutes(req with duration_minutes=1)` == 10
- `test_expires_at_reflects_capability_not_sa_lease`

File: `services/jit-gate/test_gate_consume_jti.py` (new)

Required tests:
- `test_single_use_first_call_allowed` (mock asyncpg pool returning "INSERT 0 1")
- `test_single_use_second_call_denied` (mock pool returning "INSERT 0 0")
- `test_reuse_window_tool_not_consumed` (verify `_consume_jti` not called for `pods_exec`)
- `test_cnpg_unreachable_denies_single_use_tool` (`DATABASE_URL` unset → False)

### Verify / exit criteria

- `services/jit-approver/tests/test_ttl_decouple.py` all green, no network.
- `services/jit-gate/test_gate_consume_jti.py` all green, mocked pool only.
- Pre-existing suite: `cd services/jit-approver && python -m pytest -q` — 144+ passed, 0 new fails.
- `git diff -- services/ext-proc-delegation/ services/jit-approver/src/jit_approver/vault.py`
  shows no changes to `mint_session_jwt` claims shape or ext-proc (only the `exp` derivation source
  changes; `iss`/`aud`/`tool_scope`/`sandbox_uid`/`kid` are frozen).
- `git grep -E 'BEGIN.*PRIVATE KEY|password=|postgres://[^$]'` over tracked files: empty.
- ADR-0014 verification table: one-shot write → JWT `exp-iat` == 300s; exec → JWT `exp-iat` == 1800s;
  replay of a single-use jti → jit-gate returns HTTP 403 `capability already consumed`.

### Files touched (touch-points)

| File | Change | Gated? |
|------|--------|--------|
| `services/jit-approver/src/jit_approver/models.py` | `ge=10` → `ge=1` on `duration_minutes` | No (code only) |
| `services/jit-approver/src/jit_approver/signing.py` | Add `operation_class_for`, `capability_ttl_minutes`, `CAPABILITY_TTL_*`; update `mint_session_jwt` exp derivation | No |
| `services/jit-approver/src/jit_approver/vault.py` | Clamp SA TTL to `max(10, req.duration_minutes)` minutes; update `expires_at` to use cap TTL | No |
| `services/jit-gate/gate.py` | Add `_consume_jti`, asyncpg pool init, single-use check before allow | No (code) |
| `services/jit-approver/src/jit_approver/persistence/schema.sql` | Add `consumed_jti` table (see authored artifact) | No |
| `platform/jit-approver-db/base/schema-initdb-configmap.yaml` | Sync `consumed_jti` DDL to ConfigMap | No |
| `platform/jit-approver-db/migration/add-consumed-jti.sql` | **NEW** — standalone migration SQL (authored below) | No |
| `services/jit-gate/deploy/jit-gate-k8s.yaml` | Add `DATABASE_URL` secretKeyRef env + jit-gate-egress-cnpg NP | **GATED** (cluster mutation) |
| `services/jit-gate/deploy/jit-gate-openshell.yaml` | Same as above for openshell ns + ExternalSecret/secret-copy for cross-ns | **GATED** |
| `services/jit-approver/tests/test_ttl_decouple.py` | **NEW** test file | No |
| `services/jit-gate/test_gate_consume_jti.py` | **NEW** test file | No |

### Parallelism

B1 code authoring is fully independent of B2 and B3. CNPG migration deployment (Step B1.5 ConfigMap
sync) must precede the jit-gate `DATABASE_URL` env update (Step B1.7, GATED) because the pool will
fail to connect until the table exists.

---

## Loop B2 — Console mint-gate L0/L1 → live (branch `feat/jit-mint-gate-L0-L1`)

### Goal

Land the uncommitted `feat/jit-mint-gate-L0-L1` branch content (L0 durable prereqs + L1 M5
close, 18 files, +1237/-127, locally green at 144 passed) on the platform cluster. Resolve the
three live-e2e blockers documented in the handoff. Then drive the L2-L5 roadmap loops.

### Pre-conditions (confirmed from handoff)

- Code is on `feat/jit-mint-gate-L0-L1` (uncommitted); tests pass locally.
- Live jit-approver is running `:dev` image (not the mint-gate code). ArgoCD tracks `main`.
- Missing blocker B: `system:auth-delegator` ClusterRoleBinding for jit-approver SA not present
  (confirmed: `oc get clusterrolebinding | grep jit` returns no results).
- Missing blocker C: CNPG `jit-approver-db` Cluster not deployed yet.

### Steps

**Step B2.1 — Commit and merge the branch**

Human action (GATED for git operations):
1. Commit `feat/jit-mint-gate-L0-L1` with a message summarising the 18-file L0+L1 delta.
2. Open a PR to `main` (or rebase onto `feat/openshell-native-svid-grant` for the combined
   Phase B branch). The PR title should be: `feat(jit): console mint-gate L0+L1 (SoD, CNPG WORM, /mint)`.
3. After review, merge. ArgoCD sync-wave 5 will pick up the jit-approver overlay.

**Step B2.2 — Author and apply the `system:auth-delegator` RBAC manifest (AUTHORED HERE; apply is GATED)**

The RBAC manifest is at:
`platform/jit-approver-db/rbac/jit-approver-auth-delegator.yaml`
(see AUTHORED ARTIFACT below).

This binds the `jit-approver` ServiceAccount in `mcp-gateway` to the `system:auth-delegator`
ClusterRole, which grants `tokenreviews:create` in `kube-system`. Without this, every `/mint`
call from the console fails with 403 on the Kubernetes SA TokenReview (`JIT_MINT_REQUIRE_MTLS=false`
interim path).

Apply is GATED: `oc apply -f platform/jit-approver-db/rbac/jit-approver-auth-delegator.yaml`
Add to `gitops/applications/jit-approver.yaml` or a new ArgoCD app for the RBAC.

**Step B2.3 — Deploy CNPG `jit-approver-db` (GATED)**

```bash
oc apply -k platform/jit-approver-db/base
```

This creates the `jit-approver-db` CNPG Cluster in `mcp-gateway`, runs `schema.sql` via
`postInitApplicationSQLRefs`, and generates `jit-approver-db-app` secret.

Verify: `oc get cluster jit-approver-db -n mcp-gateway -o jsonpath='{.status.readyInstances}'`
should return `1`. Verify secret: `oc get secret jit-approver-db-app -n mcp-gateway`.

**Step B2.4 — Switch jit-approver to `JIT_STORE_BACKEND=postgres` in overlay (GATED)**

In `services/jit-approver/deploy/overlays/anaeem/deployment-patch.yaml`, add or uncomment:

```yaml
- name: JIT_STORE_BACKEND
  value: "postgres"
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: jit-approver-db-app
      key: uri
- name: JIT_REQUIRE_STABLE_KEY
  value: "true"
```

After commit → ArgoCD sync → verify `/healthz` returns `"store_backend": "postgres"`.

**Step B2.5 — Verify live e2e with mint-gate active**

Run the established hand-test pattern (from handoff):
1. Open approval-console, authenticate as `arsalan` via Keycloak.
2. Spawn a tool session; trigger a write (403 from ext-proc).
3. Approve in console as `arsalan` — expect self-approval denied (SoD: approver == requester).
4. Approve as a different Keycloak user — expect `/mint` issues credential, session state → `issued`.
5. Agent retries write — expect 200.

Verify: `jit_ledger` has one `pending`, one `approved`, one `issued` row.

**Step B2.6 — L2 LEDGER loop**

File: `services/jit-approver/src/jit_approver/persistence/postgres.py`

TODO: implement hash-chained RS256-signed append-only `jit_ledger` writes in `_atomic_issue_pg`.
The ledger head CAS (`jit_ledger_head` singleton row) must be locked for update to prevent
concurrent-write chain split:

```sql
-- In a transaction:
SELECT seq, head_hash FROM jit_ledger_head WHERE id=1 FOR UPDATE;
-- Compute entry_hash = SHA-256(prev_hash || payload_json)
-- Sign entry_hash with the jit-approver RS256 key (signing.py._keys())
INSERT INTO jit_ledger (prev_hash, entry_hash, payload_json, sig) VALUES (...);
UPDATE jit_ledger_head SET seq=$new_seq, head_hash=$entry_hash WHERE id=1;
```

Payload must include: `session_id`, `approver_sub_sha256` (SHA-256 of approver_sub — not raw),
`requester_sub_sha256`, `tool_scope`, `namespace`, `outcome`, RFC3339 timestamp. Never raw subs
or credentials.

Blocked on `JIT_STORE_BACKEND=postgres` being live (B2.4). Can be coded in parallel.

**Step B2.7 — L3 DUAL-CONTROL loop**

Requires a second approver identity in Keycloak `agentic` realm (additive, no realm mutation
beyond adding one user or group member). A `SessionState.pending_second` intermediate state
is stored in CNPG (cannot survive in-memory across restarts — this is why L0's durable store
is the hard prereq). Planned separately; note it here as unblocked once B2.4 is live.

**Step B2.8 — L4 FAST-LANE loop (BLOCKED on kyverno-envoy-plugin upgrade)**

As documented in the handoff: `risk_tier()` Tier-0/1 auto-approve is blocked on the
`kyverno-envoy-plugin` providing `mcp.Parse`. Do not implement until that upgrade is confirmed.
ext-proc remains the sole enforcer in the interim. Document in release notes.

**Step B2.9 — L5 DECOMMISSION loop**

After L2+L3 are proven: webhook → fail-open audit echo (still fires, no longer the critical gate);
git → scope mirror only; ledger DR export configured. Plan separately once L2+L3 are live.

### Verify / exit criteria (B2 live)

- `oc get cluster jit-approver-db -n mcp-gateway -o jsonpath='{.status.readyInstances}'` → `1`.
- `oc get secret jit-approver-db-app -n mcp-gateway` exists.
- `/healthz` on jit-approver returns `"store_backend": "postgres"`.
- `curl -k -H 'X-Console-SA-Token: <token>' ... POST /requests/{id}/mint` with same user → 403
  `approver_sub must differ from requester_sub`.
- Different approver → 200 `state: issued`; `jit_ledger` has one row; `jit_session.state=issued`.
- `SELECT UPDATE, DELETE on jit_ledger from app` → `ERROR: permission denied` (WORM enforced).
- `git grep -E 'BEGIN.*PRIVATE KEY|password=|postgres://[^$]'` empty.
- `hack/test-openshift-jit.sh` remains 4/4.

### Files touched

| File | Change | Gated? |
|------|--------|--------|
| `platform/jit-approver-db/rbac/jit-approver-auth-delegator.yaml` | **NEW** — authored below | **GATED** (apply) |
| `platform/jit-approver-db/base/kustomization.yaml` | Add `rbac/jit-approver-auth-delegator.yaml` to resources | No (code) |
| `services/jit-approver/deploy/overlays/anaeem/deployment-patch.yaml` | Add `JIT_STORE_BACKEND=postgres`, `DATABASE_URL` secretKeyRef, `JIT_REQUIRE_STABLE_KEY=true` | **GATED** (triggers ArgoCD deploy) |
| `gitops/applications/jit-approver.yaml` or new ArgoCD app | Include RBAC manifest path | **GATED** |
| `feat/jit-mint-gate-L0-L1` branch merge | Lands 18-file L0+L1 delta | **GATED** (git + ArgoCD) |

### L2-L5 roadmap loop summary

| Loop | Key file | Blocker | Gated? |
|------|----------|---------|--------|
| L2 LEDGER | `persistence/postgres.py` | `JIT_STORE_BACKEND=postgres` live (B2.4) | Code No / Deploy Yes |
| L3 DUAL-CONTROL | `mint_core.py`, `models.py` (SessionState), `persistence/postgres.py` | L2 live | Code No / Deploy Yes |
| L4 FAST-LANE | `signing.py` `risk_tier()`, `api.py` | kyverno-envoy-plugin upgrade | BLOCKED until then |
| L5 DECOMMISSION | `webhook.py`, `gitops/` | L2+L3 live | BLOCKED until then |

---

## Loop B3 — Short-lived token minting via k8s TokenRequest (narrow per-capability SAs)

### Goal

Replace the current Vault kubernetes-engine SA-token mint (which creates an ephemeral per-session
Vault role → SA token with a 10-minute minimum) with a **direct k8s `TokenRequest` API** call from
jit-approver, using a **narrow per-capability ServiceAccount** that has only the minimal RBAC
needed for the approved operation. The jit-gate injects the SA token per-call. After TTL, a
replay → 401 from k8s. `oc auth can-i` proves minimal scope.

### Pre-conditions

B1 and B2 must be merged and deployed (the operation-shaped TTL and the CNPG-backed gate must be
in place before wiring a new credential mint path, to prevent a regression in the gating surface).

### Approach

**Per-capability SA model:**

| Capability class | ServiceAccount | RBAC binding |
|-----------------|----------------|-------------|
| `firewall-write` | `jit-firewall-write` in `agentic-mcp` | Role `firewall-write-role`: `create` on `networkpolicies` |
| `k8s-resources-scale` | `jit-resources-scale` in `agent-sandbox` | Role `resources-scale-role`: `patch` on `deployments/scale` |
| `pods-exec` | `jit-pods-exec` in `agent-sandbox` | Role `pods-exec-role`: `create` on `pods/exec` |

Each SA has no other RBAC. The naming and roles are the minimum the approved tool requires.

**Step B3.1 — Author per-capability SA manifests**

File: `platform/jit-token-sas/base/` (new directory)

Contents:
- `serviceaccounts.yaml`: 3 SAs (one per capability class above)
- `roles.yaml`: 3 Roles (one per SA, minimal verbs/resources)
- `rolebindings.yaml`: 3 RoleBindings
- `kustomization.yaml`

These are authored below as a scaffold with precise TODOs.

**Step B3.2 — `vault.py` → `token_request.py`: replace Vault kubernetes-engine path**

File: `services/jit-approver/src/jit_approver/token_request.py` (new)

TODO: implement `async def issue_sa_token(session_id, req, ttl_seconds) -> str` using the
k8s `TokenRequest` API:

```python
# POST /api/v1/namespaces/{namespace}/serviceaccounts/{sa_name}/token
# Body: {"spec": {"expirationSeconds": max(600, ttl_seconds), "audiences": ["https://kubernetes.default.svc"]}}
# Returns: status.token (short-lived, audience-bound)
```

The in-cluster k8s client uses the jit-approver SA token (projected service account token, already
mounted at `automountServiceAccountToken: true`) authenticated via the in-cluster config. The
jit-approver SA needs `create` on `serviceaccounts/token` for the per-capability SAs — add this to
the `jit-approver` ClusterRole (additive, no existing binding changes):

```yaml
# platform/jit-approver-db/rbac/jit-approver-token-request.yaml (new)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: jit-approver-token-request
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    verbs: ["create"]
    # Scoped to only the jit-* SAs (enforced by resourceNames):
    resourceNames:
      - jit-firewall-write
      - jit-resources-scale
      - jit-pods-exec
```

TODO: add ClusterRoleBinding binding `jit-approver` SA to this role.

**Step B3.3 — Capability-to-SA mapping in `signing.py` or a new `capability_map.py`**

The operation class (from B1) maps to the SA to token-request:

```python
_TOOL_TO_SA: dict[str, str] = {
    "create_firewall_rule_advanced": "jit-firewall-write",
    "add_firewall_rule": "jit-firewall-write",
    "resources_create_or_update": "jit-resources-scale",
    "resources_scale": "jit-resources-scale",
    "pods_exec": "jit-pods-exec",
    "pods_run": "jit-pods-exec",
}
```

**Step B3.4 — ext-proc/jit-gate: per-call SA-token injection**

ext-proc already injects credentials for the delegated read path. The write path today returns the
session JWT + SA token in the status response, and the agent wields the SA token directly.

With per-capability SAs the flow changes: after /mint issues, the agent polls `/status` and receives
the short-lived SA token (minted via TokenRequest) in `sa_token`. The agent presents it as
`Authorization: Bearer <sa_token>` to the k8s-mcp-edit backend. jit-gate verifies the capability JWT
first (unchanged); the k8s API server verifies the SA token's audience and expiry on the
downstream call. Replay after TTL → k8s returns 401 (not 403 — the token is simply expired).

No change needed to jit-gate's JWT-check logic. The change is in how jit-approver mints the
SA token (TokenRequest instead of Vault kubernetes engine).

**Step B3.5 — Tests**

File: `services/jit-approver/tests/test_token_request.py` (new)

Required tests (mock the k8s client):
- `test_issue_sa_token_happy_path`: mocked `create_namespaced_service_account_token` returns a token
- `test_issue_sa_token_ttl_clamped_to_600s`: `ttl_seconds=1` → `expirationSeconds=600` in request
- `test_issue_sa_token_unknown_tool_raises`: tool not in `_TOOL_TO_SA` → `ValueError` (fail-closed)
- `test_replay_after_ttl_yields_401`: mocked k8s API returns 401 (token expired)

File: `platform/jit-token-sas/test_rbac_minimal.py` (new)

Integration test (tagged `pytest.mark.integration`):
```python
@pytest.mark.integration
def test_jit_firewall_write_can_i():
    """oc auth can-i create networkpolicies --as system:serviceaccount:agentic-mcp:jit-firewall-write"""
    ...
```

### Verify / exit criteria

- `oc auth can-i create networkpolicies --as system:serviceaccount:agentic-mcp:jit-firewall-write` → `yes`
- `oc auth can-i get pods --as system:serviceaccount:agentic-mcp:jit-firewall-write` → `no` (minimal scope)
- `oc auth can-i create pods/exec --as system:serviceaccount:agent-sandbox:jit-pods-exec` → `yes`
- SA token presented to k8s-mcp-edit after TTL → 401 (k8s rejects expired token).
- `services/jit-approver/tests/test_token_request.py` all green (no network).
- `oc auth can-i` integration tests green on cluster.
- `git diff -- services/ext-proc-delegation/` → no changes (ext-proc is unchanged).
- `hack/test-openshift-jit.sh` 4/4 (no regression).

### Files touched

| File | Change | Gated? |
|------|--------|--------|
| `platform/jit-token-sas/base/serviceaccounts.yaml` | **NEW** — 3 per-capability SAs | **GATED** (apply) |
| `platform/jit-token-sas/base/roles.yaml` | **NEW** — 3 minimal Roles | **GATED** (apply) |
| `platform/jit-token-sas/base/rolebindings.yaml` | **NEW** — 3 RoleBindings | **GATED** (apply) |
| `platform/jit-token-sas/base/kustomization.yaml` | **NEW** — scaffold | No (code) |
| `platform/jit-approver-db/rbac/jit-approver-token-request.yaml` | **NEW** — ClusterRole + ClusterRoleBinding | **GATED** (apply) |
| `services/jit-approver/src/jit_approver/token_request.py` | **NEW** — k8s TokenRequest mint | No (code) |
| `services/jit-approver/src/jit_approver/vault.py` | Retire Vault k8s-engine path (keep as fallback flag `JIT_MINT_VIA_VAULT=true` for rollback) | No (code) |
| `services/jit-approver/tests/test_token_request.py` | **NEW** test file | No |
| `platform/jit-token-sas/test_rbac_minimal.py` | **NEW** integration test | No |

---

## Phase B exit criteria (all three loops done)

1. Console approve → `/mint` → short-lived capability JWT (operation-class TTL) + short-lived SA
   token (TokenRequest, narrow per-capability SA) → agent writes → 200.
2. Replay of a single-use jti within the 5-minute window → jit-gate returns 403 `capability already consumed`.
3. SA token presented to k8s after its TTL → 401.
4. Self-approval attempt → 403 `approver_sub must differ from requester_sub`.
5. `jit_ledger` is append-only (WORM); `SELECT UPDATE on jit_ledger` → permission denied.
6. `oc auth can-i` proves minimal scope for each per-capability SA.
7. ext-proc is still in front; `git diff -- services/ext-proc-delegation/` is zero.
8. `hack/test-openshift-jit.sh` 4/4.
9. No credentials in git (`git grep -E 'BEGIN.*PRIVATE KEY|password=|postgres://[^$]'` empty).

---

## What can be authored NOW in parallel with Phase A tail-work

The following have zero dependency on Phase A's remaining last-mile seams (unattended-SVID
file-handoff, ACM image reverter, real per-user OBO) and can be written immediately:

| Artifact | Loop | Status |
|----------|------|--------|
| `platform/jit-approver-db/migration/add-consumed-jti.sql` | B1 | **AUTHORED BELOW** |
| `platform/jit-approver-db/rbac/jit-approver-auth-delegator.yaml` | B2 | **AUTHORED BELOW** |
| `platform/jit-token-sas/base/` scaffold | B3 | **AUTHORED BELOW** |
| `services/jit-approver/tests/test_ttl_decouple.py` | B1 | Author now (no cluster needed) |
| `services/jit-gate/test_gate_consume_jti.py` | B1 | Author now (no cluster needed) |
| `services/jit-approver/src/jit_approver/signing.py` additions | B1 | Author now |
| `services/jit-approver/src/jit_approver/models.py` floor change | B1 | Author now |
| `services/jit-approver/src/jit_approver/token_request.py` scaffold | B3 | Author now |
| `services/jit-approver/tests/test_token_request.py` | B3 | Author now |
| B2.6 ledger code in `persistence/postgres.py` | B2-L2 | Author now (no deploy needed) |

All cluster mutations (CNPG deploy, RBAC apply, SA deploy, ArgoCD sync) are GATED pending commit
and human go.
