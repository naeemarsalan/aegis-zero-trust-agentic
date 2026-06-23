# Solution Scope & Gap Analysis — nvidia-ida zero-trust agentic platform

**Date:** 2026-06-23 · **Branch:** `fix/jit-approver-mint-route` (off `backup/e2e-delegated-zero-trust`)
**Anchors:** `docs/reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md` (worklog), ADRs 0011/0012/0013/0014/0017/0018, `docs/plans/openshell-agentic-platform-master-plan.md`

> One-line vision: a single Keycloak-authed console where a human launches a **living, credential-less agent** (its own SPIFFE SVID, workspace PVC, auto-created Gitea repo, human-selected skills) that **reads delegated as the human** and, on any write, **pauses for in-console human approval (approver ≠ requester)** that **mints a short-lived, operation-shaped-TTL token** — everything WORM-audited, no stored credential anywhere, ext-proc per-tool audit intact, GitOps-durable.

---

## 1. Where we are

The **core zero-trust loop is PROVEN end-to-end** with a live credential-less LLM agent (SPIFFE SVID only):

- **Read delegated → 200** (ext-proc audit: `caller_username=arsalan`, `grant_scope=read-only`, `credential_injected=true`, ~50–52 real pfSense rules).
- **Write → 403 `grant_scope_denied`** (fail-closed; the agent holds no write credential).
- **Human approve** (Gitea PR merge / console mint) → scoped capability JWT.
- **Write → 200**, REAL pfSense rule created (`jit_elevated=true`). Proven on the native OpenShell/ext-proc path (workflow `wxhf010s7`, SVID `…/ns/openshell/sandbox/3d2e5114`, rule id 47) and on the e2e-harness plane. ext-proc carries 151 delegated-read audit records.

The **product console (Phase C) is live and launching real agents**:

| Capability | State |
|---|---|
| Console launches **native OpenShell agents** (`POST /api/agents` → sandbox-launcher → gateway `CreateSandbox`) | LIVE (image `webshell-ondata-20260623`, 2/2) |
| **Per-agent Gitea repo** auto-created on launch (`agents/<id>`) | LIVE (best-effort, never fails launch) |
| **Vault consent grant** written on launch (ext-proc's OBO source) | LIVE (scoped `console-grant-writer` token) |
| **Skills picker** (`GET /api/skills` ← Gitea skills repo tree) | LIVE (list-only) |
| **Webshell** — real PTY into the sandbox, vendored xterm, registered `onData` | LIVE (typing-dead bug fixed) |
| **Persistent agent store** (PVC `approval-console-agent-store`, JSON-file backed) | LIVE |
| **Reaper** (PROVISIONING→READY via launcher phase endpoint; read-only) | LIVE |
| **Sessions exec INSIDE the native sandbox** (not the legacy e2e-harness) | LIVE (commit `e260b85`) |
| **jit-approver mint/approve** (`POST /requests/{id}/mint`, SoD enforced, CNPG WORM) | LIVE (image `mint-fix-20260623`, approve-404 fixed) |
| In-console JIT/token panels (`GET /agents`, JIT filter, token receipt, SoD guard) | LIVE |

Identity substrate proven: **two SVIDs per pod** (UUID-shaped → ext-proc/real-tools; SA-shaped → Kagenti/echo-mcp), the **Kagenti AuthBridge chain green** (federated-jwt → token-exchange → jit-gate → echo-mcp), and the **ADR-0018 binding** (`metadata.id == pod annotation == SVID path == Vault grant key`) holding by construction.

---

## 2. Original vision vs delivered

| Intended capability | Status | Note |
|---|---|---|
| Hard zero-trust invariant (credential-less agent, SVID only) | **done** | Holds across every proven path; no stored write credential anywhere |
| Full journey: read-200 / write-403 / approve / write-200 (REAL tool) | **done** | Proven on native + e2e-harness planes |
| ext-proc delegation (SVID→Vault grant→OBO inject + audit) | **done** | Caveat: injected cred is the **static-token fallback** (real KC OBO returns 403, unapplied) |
| Kagenti AuthBridge identity chain → echo-mcp | **done** | Green; reaches echo-mcp, not yet a real tool via this plane |
| Two SVIDs per pod (shape mutual-exclusion resolved) | **done** | `SVID_REQUIRE_PATH_SUBSTR=/sandbox/` selects UUID for ext-proc |
| Per-sandbox SVID + UID binding (ADR-0018) | **done** | className gate + annotation-keyed template |
| OpenShell native `provider_spiffe` on confined runc (ADR-0017) | **done** | Root cause = missing `CAP_SYS_CHROOT`, delivered via Kyverno mutate |
| Console launches native agents (Phase-C keystone) | **done** | |
| Per-agent Gitea repo auto-create | **done** | |
| Per-agent workspace PVC | **partial** | Launch path does not provision a dedicated `<id>-workspace` PVC per the plan |
| Skills picker (list) | **done** | List-only |
| **Skills LOADING into native sandbox (C3 init-container)** | **partial** | Loader **authored but UNWIRED**; Kyverno injector + seed Job absent on disk |
| Central skills Git repo + seed Job | **partial** | Repo pointed at `anaeem/skills`; idempotent seed Job not on disk |
| Webshell (browser PTY) | **done** | Real bug fixed (see §worklog) |
| In-console mint/JIT/token panels (C5) | **done** | Drives the WORM ledger via jit-approver `/mint` |
| Console mint-gate (approver ≠ requester, WORM) | **done** | SoD enforced server-side; CNPG WORM ledger live |
| Persistent agent store | **done** | JSON-file/PVC; swap-ready toward CNPG |
| Reaper / lifecycle (state transitions) | **partial** | Read-only state flips only; no teardown/GC |
| Session-token audit pipeline (Loki/OTEL correlation) | **partial** | Sources emit; pipeline **built but UNFED** (`OTEL_EXPORTER_OTLP_ENDPOINT` unset on all 5 svcs) |
| Operation-shaped JIT TTL + CNPG `consumed_jti` (ADR-0014) | **planned** | Designed; implementation pending |
| Short-lived narrow-SA token mint (k8s TokenRequest) | **planned** | |
| Real per-user OBO (RFC 8693) | **partial** | Proven viable (RHBK 26.6.3, kagenti realm); **NOT applied** — static-token fallback load-bearing |
| Token-forwarding to retire `LAUNCHER_ALLOW_UNVERIFIED` | **missing** | Console does not relay the oauth2-proxy token to launcher → dev exposure |
| DELETE tears down sandbox CR / PVC / grant / key | **missing** | DELETE orphans the live sandbox, PVC, Vault grant |
| Network deny-by-default floor + ns-openshell egress NP | **missing** | `networkpolicy-sandbox-egress.yaml` exists, **NOT applied** |
| Floor+elevator consumable-policy API (OpenShell `UpdateConfig`) | **planned** | One grant elevating BOTH MCP gate AND network boundary not built |
| RHDH / DevHub consumption UX (catalog → plan/consent → receipt) | **planned** | Console is the live front door; RHDH is the broader catalog vision |
| Plan/consent keystone (front-loaded capability manifest) | **planned** | |
| ida TUI/CLI peer | **planned** | |
| Audit/WORM receipts surface (allowed + denied per session) | **partial** | WORM ledger live; user-facing receipt aggregation pending |
| GitOps durability (ArgoCD/ACM digest-pinned) | **partial** | **No ArgoCD on cluster**; reconciler is ACM hub ManifestWork (hub-side, human) |
| Production hardening (Phase D: NPs, secrets, GC, revoke, reaper) | **planned** | |
| Reaping / hard GC (30-day repo delete, stale sandbox reap) | **missing** | |
| mTLS-SPIFFE on console→jit-approver `/mint` | **partial** | Interim k8s TokenReview on `X-Console-SA-Token`; flag not flipped |
| Showroom / narrative site ("Aegis") | **planned** | |
| Upstream OBO kernel contribution | **planned** | |

---

## 3. Gaps — what's missing from the original solution (prioritized, honest)

**P0 — closes the agent-autonomy + ledger story (highest leverage on the proven foundation):**

1. **C3 — skills LOADING into native sandboxes (not just listing).** The init-container builder (`skills/loader.py`: `build_init_container`/`build_skills_volume`) is fully authored but **never called**: `agents/routes.py` `_create_sandbox` posts skills only as launcher "capabilities", never sets the `agents.x-k8s.io/skills` annotation, never passes `initContainers`. The Kyverno injector (`mutate-openshell-sandbox-skills-loader.yaml`) and the seed Job (`platform/gitea/skills-repo/seed-job/`) **don't exist on disk**. Result: selected skills are not cloned into the sandbox. Wire loader→create_agent (or the Kyverno path) + author the seed Job.
2. **Session-token audit pipeline — built but UNFED.** Plan + Grafana dashboard + filelog receiver exist (`docs/plans/session-token-audit-logs-plan.md`, `observability/dashboards/session-token-audit.json`, `observability/otel/filelog-audit-receiver.yaml`); the otel-collector→Loki pipeline EXISTS but `OTEL_EXPORTER_OTLP_ENDPOINT` is unset on all 5 mcp-gateway services, so the 3 correlated sources (console `_audit` / jit-approver WORM `jit_ledger`+`consumed_jti` / ext-proc `grant_result`, keyed on `jit_session_id`) never reach it. Set the endpoint per service. (Held pending etcd defrag — etcd ~2 GB.)

**P1 — security/exposure debt on the live console:**

3. **Token-forwarding to retire `LAUNCHER_ALLOW_UNVERIFIED` (dev exposure).** Launcher fully supports verified identity (`_extract_and_verify_caller`), but the console posts `/launch` with `userRef=actor` and **no `Authorization` header**, so the live path depends on `LAUNCHER_ALLOW_UNVERIFIED=true` on a public route. Relay the oauth2-proxy `x-forwarded-access-token` and flip the flag to fail-closed.
4. **DELETE should tear down the sandbox CR.** `DELETE /api/agents/{id}` removes the store record + Gitea repo but **never** calls the launcher to delete the Sandbox CR, the PVC, the Vault grant, or the per-agent key Secret → orphaned live resources. Wire console-delete → launcher teardown.
5. **ns-openshell egress NetworkPolicy not applied** (ADR-0018 compensating control). `SYS_CHROOT`+`SYS_ADMIN` sandboxes should not egress arbitrarily; `platform/openshell/networkpolicy-sandbox-egress.yaml` exists but is unapplied. Land before Phase A closes.

**P2 — durability + correctness of the identity story:**

6. **Real per-user OBO.** Proven viable on RHBK 26.6.3 (fine-grained impersonation perms on `mcp-gateway` client, verified in the kagenti realm) but **not applied** — the static per-user opaque-token fallback is load-bearing. Apply when ready to mutate the shared agentic realm.
7. **GitOps durability.** **No ArgoCD on this cluster** — the reconciler is the **ACM hub ManifestWork** (`ida-launcher-componenta` re-pins launcher to `:dev` ~2 min after any managed apply). Live `oc set image` (incl. the `mint-fix` jit-approver) holds only temporarily; durable fix is a **hub-side edit (human)**. The `fix/jit-approver-mint-route` branch (commit `1bd70c3`) is **unpushed**.
8. **mTLS-SPIFFE on console→jit-approver `/mint`** (ADR-0007). Runs interim k8s TokenReview on `X-Console-SA-Token`; register the console in SPIRE, wire client-cert mTLS (`X-Peer-Spiffe-Id`), flip `JIT_MINT_REQUIRE_MTLS=true`.

**P3 — broader vision not yet started:**

9. **Floor+elevator consumable-policy API** — one JIT grant elevating BOTH the MCP per-tool gate AND the OpenShell network boundary (gateway `UpdateConfig{AddNetworkRule}` + reaper revert). Not built.
10. **ADR-0014 operation-shaped TTL + CNPG `consumed_jti`** (write=5m single-use, exec=30m). Designed, not implemented.
11. **RHDH/DevHub UX, plan/consent keystone, ida TUI/CLI, Showroom site, reaping/30-day GC, jit-revoke endpoint** — all planned.

---

## 4. Additional / new scope (this session + user asks)

### (a) SELECT HARNESS / agent-image before launch — MISSING (design)
No harness/agent-type/image selector exists. `CreateAgentRequest` (`agents/models.py`) carries only `display_name` + `skills`; the launch form offers a name input + skills checkboxes; `_create_sandbox` hardcodes `mode='project'` and the launcher chooses the image.

**Approach (brief):**
- Add an `agent_type` (or `harness`) field to `CreateAgentRequest` + a dropdown in `_AGENTS_PAGE` (`ui/routes.py`), populated from a small server-side catalogue (label → image/ref), e.g. `claude-agent-harness` (default), plus future variants.
- Plumb the selection through `_create_sandbox` into the launcher `/launch` payload (a `harness`/`image` key) and have the **launcher honor it** in its image-swap step. The launcher already swaps the sandbox container to the `agent-harness` image — this asks to **parameterise that single choice** rather than hardcode it (default = today's `agent-harness`). Validate against the catalogue server-side (reject unknown refs, fail-closed).

### (b) Attach-to-webshell after launch — DONE
Satisfied by C4. The agent card has a **Webshell** button (enabled only when `state==READY`) opening `GET /api/agents/{id}/webshell/ui`, which connects the WS PTY bridge into the already-running sandbox (RBAC: actor must == owner/admin). Works after the `term.onData` registration fix.

### (c) MCP-helper skill ticked by DEFAULT in the launch form — MISSING
There is **no standalone `mcp-call`/`mcp-helper` skill directory** — `mcp-call` is a `bin/` script (`services/agent-sandbox/agent-harness/bin/mcp-call`) and its usage is embedded inside each task skill's `SKILL.md`. The seedable skills repo has exactly 3 dirs: `list-firewall-rules`, `openshift-troubleshoot`, `pfsense-firewall`. The picker renders **all checkboxes unchecked**; the only default is a silent server-side launcher fallback (`['openshift-troubleshoot']`).

**Proposal:**
- Create a dedicated **`mcp-call`** (a.k.a. `mcp-helper`) skill dir under `…/agent-harness/.claude/skills/` whose `SKILL.md` is the canonical "the ONLY way to reach tools is `mcp-call`" guidance (factor the embedded instructions out of the task skills), seed it into the skills repo, and **pre-tick it by default** in the picker.
- Define a **server-side default-skills list** (config), default-selected = `['mcp-call']` (plus optionally a recommended task skill), and surface that as `checked` checkboxes — so the UI reflects the default instead of relying on the silent launcher fallback.

### (d) Skills default-selection UX generally — MISSING
The picker JS builds plain unchecked `<input type=checkbox>` per skill from `GET /api/skills`; there is no notion of default/recommended/required, and `CreateAgentRequest.skills` defaults to `[]`.

**Proposal:** add a `default`/`recommended` flag to the `GET /api/skills` response (driven by the server-side default-skills config), render those checkboxes `checked`, optionally mark a "required" skill (`mcp-call`) non-deselectable, and make the launcher fallback agree with the UI default so the two can't silently diverge.

---

## 5. Recommended sequencing

Grounded in the proven foundation (the zero-trust loop + a live console launching native agents), the highest-leverage next steps in order:

1. **Wire C3 skills LOADING** (loader→create_agent or Kyverno injector + seed Job) — turns the live picker into a real, skill-driven agent; the loader is already authored, so this is the cheapest big win. Pair with **(c)/(d)**: the `mcp-call` default-selected skill so a launched agent can actually reach tools out of the box. *(Without skills loaded, the "OPAQUE skill-driven harness" vision is not realised even though every other piece is live.)*
2. **Feed the session-token audit pipeline** (set `OTEL_EXPORTER_OTLP_ENDPOINT` on the 5 services) **after the etcd defrag** — makes the WORM/JIT/ext-proc story observable end-to-end; everything else is already emitting.
3. **Close the console exposure debt**: token-forwarding to retire `LAUNCHER_ALLOW_UNVERIFIED` (P1.3), then DELETE→teardown (P1.4) and apply the ns-openshell egress NP (P1.5). These remove real holes on a publicly-routed console.
4. **Add the harness selector (a)** — small, additive, unblocks future agent variants and makes the launcher's existing image-swap a first-class choice.
5. **Durability pass**: push `fix/jit-approver-mint-route`, then get the **ACM hub** updated (human) so the live `mint-fix` jit-approver + console images stop being temporary. Without this, every fix above decays ~2 min after apply.
6. **Then** the deeper identity/policy work: real per-user OBO (P2.6), ADR-0014 operation-shaped TTL + CNPG `consumed_jti`, and the floor+elevator `UpdateConfig` API — the items that move the PoC from "proven slice" toward the full product.

> Honest framing (per the roadmap memory): the proven split-identity loop + live console is **~30–35%** of the full vision. The foundation is solid and the remaining P0/P1 items are last-mile wiring on top of already-authored code, not new research.

## 6. Additional gaps discovered during live testing (2026-06-23) — INCLUDE IN NEXT RUN

These surfaced while the user drove the live console and were NOT in §3/§4 above.

### (e) Separation-of-duties vs single operator — self-approval deadlock — **DESIGN DECISION NEEDED (P0 for demo)**
Symptom: approving an agent's JIT write in-console returns
`403 "You cannot approve your own request (self-approval denied). approver_sub must differ from requester_sub"`.
This is the L1 mint-gate SoD control **working as designed** — but in a single-operator homelab the human
(`arsalan`) is BOTH the agent's delegated identity (so `requester_sub=arsalan`) AND the only approver
(`approver_sub=arsalan`) → permanent deadlock. The real question: **what is `requester_sub` for an
agent-filed elevation?**
- **Option A (recommended for THIS platform):** the requester is the **AGENT identity** (sandbox SVID /
  `agent_id`), not the delegated human. Then "agent requests → human (`arsalan`) approves" satisfies SoD
  naturally — which matches the product's core story ("credential-less agent asks, human approves"). Change
  where the JIT request sets `requester_sub` (jit-approver `POST /requests` / the mcp-call file path) to the
  agent, not the on-behalf-of user.
- **Option B (true 4-eyes):** keep `requester_sub` = the human; require a DIFFERENT human approver. Correct
  for multi-user orgs; needs a 2nd Keycloak user to demo. Deadlocks single-user.
Interim demo unblock: approve as a second Keycloak identity, OR adopt Option A. **Decide before the C5
in-console approval demo is meaningful.** Related: [[project-console-mint-gate]], ADR mint-gate L1.

### (f) Consent-grant lifecycle — 1h TTL, no renewal — **FIXED (verify) + broaden**
Symptom: a living agent older than 1h got `403 grant_expired` on every read. Cause: the console wrote the
grant once at launch with `ttl=3600` and nothing renewed it. **Fix shipped (`grant-renew-20260623`):** the
reaper now re-writes the read-only consent grant for each READY agent every 60s — lifecycle-driven, not
page-refresh-driven, so an autonomously-running agent keeps its delegated read. Writes still require JIT.
Next-run: confirm renewal under load; consider also refreshing on session-start; revisit grant TTL vs the
ADR-0014 operation-shaped TTL story; store `scope` on the Agent model (renewal currently defaults read-only).

### (g) Inference plane — retired model + shared static key → **switch to OpenShift AI per-agent tokens (P1)**
Live session warnings exposed two inference problems plus the strategic ask:
- ⚠️ **`Claude Sonnet 4 retired June 15, 2026`** — agents run a RETIRED model (LiteLLM→OpenRouter
  `anthropic/claude-sonnet-4`); contributes to poor agent recovery behaviour. Needs a model bump now.
- ⚠️ **Both `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_API_KEY` set** — the native-session exec passes both;
  pass exactly one.
- **Strategic (user ask): replace LiteLLM with OpenShift AI (RHOAI) and mint a NEW per-agent API token at
  agent-creation for frontier-model access.** Today all agents share ONE static key (secret
  `agent-harness-inference`) — the one spot violating the no-shared-broad-credential spirit. Target:
  per-agent, scoped, revocable, **audited** model creds via RHOAI's Models-as-a-Service / AI gateway
  (Kuadrant/3scale key issuance). **Elegant:** exchange the agent SVID → a JIT RHOAI token (credential-less,
  not stored). **Pragmatic v1:** launcher/console requests a per-agent key from RHOAI on create + injects it.
  Open question: RHOAI fronts FRONTIER models as a gateway/proxy (frontier stays external) vs hosting open
  models (bigger change). Default: RHOAI as the per-agent token/gateway in front of frontier.
  See [[project-product-inference-scope-2026-06-23]].

### Updated recommended sequencing (supersedes §5 tail)
1. **Decide SoD requester-identity (e)** — unblocks the in-console approval demo (lean Option A: requester=agent).
2. C3 skills-loading into native sandbox + the **mcp-helper default-ticked** skill (§4c) — the agent's core tooling.
3. **Harness selector** (§4a) — parameterise the launcher image-swap.
4. Feed the **session-token audit pipeline** (§3) — now that grants renew + agents persist.
5. **Inference: model bump now (g)**, then the **OpenShift AI per-agent token** rework (the headline zero-trust upgrade).
6. Close console exposure debt (token-forwarding, retire `LAUNCHER_ALLOW_UNVERIFIED`), DELETE-tears-down-CR, durability/hub push.
