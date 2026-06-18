# Variant-B full-journey reproduce + test plan (workflow-orchestrated, loop-until-green)

**Goal:** prove the complete delegated-agent journey end-to-end, looping until every leg is green:

> ida → login → launch/select sandbox → `mcp-call` read (200, real firewall rules, downstream
> identity = arsalan, no credential in the agent) → dangerous tool (403 grant_scope_denied) →
> Approvals tab → Gitea PR merge → webhook issues sandbox-bound session JWT → elevated retry of
> exactly that tool (200, `jit_elevated=true`) → Receipt shows the per-call audit.

## GROUND TRUTH (from `variant-b-journey-discovery`, 6 mappers + opus critic, 2026-06-17)
**The stack is LIVE and healthy — NOT torn down.** Earlier "0 namespaces" reads were a flapping
control-plane replica. Confirmed live (multiple agents, with pod names/ages/imageIDs):
- `mcp-gateway`: agentgateway controller + `mcp-gateway` dataplane (Gateway **Programmed=True**),
  `ext-proc-delegation` 2/2 (image `grant-e2e-jit` **with `SPIRE_TLS_INSECURE=true` live**),
  `jit-approver` 3/3, `sandbox-launcher` 2/2. AgentgatewayPolicy wires ext-proc `:9000` (extProc) +
  kyverno-authz `:9081` (extAuthz), both fail-closed. `/mcp` → `pfsense-mcp.agentic-mcp.svc:8000`.
- `agentic-mcp`: `pfsense-mcp` 2/2 (the MCP backend that calls pfSense). LIVE.
- `agent-sandbox`: `e2e-harness` pod is **Completed** (ran 15h ago — must recreate). SA `e2e-harness`,
  ConfigMap `ztp-helpers`, Secret `agent-harness-inference`, NP `allow-egress-e2e-harness` present.
- SPIRE healthy (server/agent/CSI driver), CSID `agent-sandbox-e2e-harness` registered (1 entry).
  `spire-oidc` JWKS endpoint live. Vault unsealed (working token = k8s secret `vault/vault-init`
  key `root-token`; the `.env`/`~/.vault-init.json` tokens are stale). Keycloak `agentic` realm Done.
  Kyverno **running** (require-networkpolicy enforcing, exclude block live; admission gate is
  belt-and-suspenders — the primary tool-scope gate is ext-proc).
- No ArgoCD (`openshift-gitops` absent) → nothing reverts; all changes are direct `oc apply`.

## CRITICAL CORRECTION — do NOT re-apply the ext-proc overlay for the test
The `spire-oidc` route is **reencrypt serving a Let's Encrypt wildcard cert** (`*.apps.anaeem…`),
NOT a SPIRE passthrough cert. The finding-A fix (commit c028188) anchors JWKS TLS to the in-pod
**SPIFFE bundle**, which an LE cert will never satisfy → TLS handshake fails → SPIRE verifier
disabled → **every SVID call fails-closed (401/403)**. The live pod works only because it carries
`SPIRE_TLS_INSECURE=true` (manually injected, absent from the overlay). `oc apply -k` of the overlay
**strips that flag and silently breaks the read leg** (pod stays 2/2 Running; failures only show on
the next MCP call). **For the journey test: leave the live ext-proc pod untouched.**
- **Hardening follow-up (separate from the test):** the finding-A fix is mis-anchored for this
  topology. Correct it to verify against the **ingress/LE CA** (system roots trust LE; or
  `SPIRE_CA_FILE` = mounted ingress CA), NOT the SPIFFE bundle. Update the overlay comment (it
  falsely claims passthrough/SPIRE cert). Until then, the overlay should carry
  `SPIRE_TLS_INSECURE=true` as a documented PoC escape hatch so a future apply doesn't break the path.

## Invariants asserted every loop
- **No-credential-passing:** agent sends ONLY its SVID; the pfSense token is injected server-side by
  ext-proc from the Vault grant; nothing sensitive in the harness env/MCP args/logs.
- **Fail-closed:** absent/forged SVID, absent/expired grant, out-of-scope tool → 401/403, never allow.
- **Sandbox binding:** JIT session JWT bound (`jwt.sandbox_uid == svid.sandbox_uid`), tool-scoped.

---

## Pre-flight (the bring-up reduces to 2 mutations + verification)
Workflow `variant-b-bringup` becomes a thin **verify + refresh** (the stack is already up):

**P0 — read-only health gate (loop until all green or abort):**
- `ext-proc-delegation` 2/2; `mcp-gateway` Gateway `Programmed=True`; AgentgatewayPolicy
  Accepted+Attached; `kyverno-authz-server` Endpoints present (extAuthz is fail-closed — if down,
  ALL /mcp denied before ext-proc); `pfsense-mcp` 2/2; SPIRE server/agent Ready; CSID registered;
  apiserver latency < 2s on a trivial get (control plane was flaky — abort if not).
- Vault reachable with the `vault/vault-init` token; confirm `secret/data/mcp-tools/mcp-tokens` has
  key `arsalan`; confirm `secret/data/sandbox-grants/<uid>` readable.

**P1 — close the UNVERIFIED gaps (read-only, then fix if needed):**
- **Gitea webhook** on `git.arsalan.io/anaeem/nvidia-ida`: must exist → URL
  `https://jit-approver.apps.anaeem.na-launch.com/webhooks/gitea`, Pull-Request events, HMAC =
  `secret/data/jit-approver/webhook-secret`; the `jit-approval` label must exist. (Legs 4–6 die
  without this.) Verify via the Gitea API with `.env` `GITEA_TOKEN`; create if missing.
- **ida TUI**: `~/.config/ida/config.yaml` exists + populated (verified: `jit_url`, `keycloak_*`,
  `gitea_url`, `kubeconfig`; `gitea_token` is empty → set `IDA_GITEA_TOKEN` from `.env` for the
  Approvals merge). **Keycloak `arsalan`** user with a password + Direct-Access-Grants (ROPC) on
  `ida-cli`/`mcp-gateway` — verify; the backend journey can also be driven by curl if ROPC is off.

**P2 — the only required live mutations (do P2b LAST — TTL is 3600s):**
- **P2a — recreate the harness pod:** `oc -n agent-sandbox delete pod e2e-harness; oc apply -k
  services/agent-sandbox/e2e-harness`. Wait Ready; confirm SVID
  `…/ns/agent-sandbox/sandbox/e2e0a1b2-…` issued. (Applies SA+RBAC+optional-inference patch.)
- **P2b — rewrite the expired grant (LAST):** write `secret/data/sandbox-grants/<uid>`
  `{version:1, sandbox_uid:<uid>, user:arsalan, scope:read-only, ttl:3600, nonce:<hex>,
  created:<RFC3339Nano now>}` via the `vault/vault-init` token (route POST or vault-0 exec).

---

## Journey-test workflow `variant-b-journey-test` (loop-until-green over 7 legs)
Outer **loop-until-green** (≤ N rounds; converge when all legs pass 2 consecutive rounds).
Each round runs the legs as a `pipeline` (state flows: session-id, PR#). **Transient** failures
(pod warming, SVID propagation) retry in-leg; **structural** failures return with full diagnostic
(ext-proc audit line + pod logs + vault read) for a main-loop fix, then resume. Driven via
`oc exec`/curl (TUI verified separately). All credentials server-side — assert no-cred each leg.

| # | Leg | Drive | PASS (assert all — adversarially, from the AUDIT not just HTTP) |
|---|-----|-------|------|
| 0 | Auth | mint token / `ida login` | token; ida reaches jit route |
| 1 | **Read** | `exec e2e-harness -- mcp-call` (search_firewall_rules) | 200; ≥1 real rule; ext-proc audit `agent_spiffe_id=…/sandbox/<uid>, caller_username=arsalan, grant_result=valid, grant_scope=read-only, decision=allow, credential_injected=true`; **no cred in harness env/wire** |
| 2 | **Deny** | `mcp-call create_firewall_rule_advanced …` | 403; audit `decision=deny, reason=grant_scope_denied`; no rule created |
| 3 | Request | jit-approver `POST /requests` (denied tool) | request id; **Gitea PR opened** (PR #, branch `jit/<id>`, label `jit-approval`) |
| 4 | Approve | merge PR (ida Approvals / Gitea API) | PR merged; **webhook fires** `POST /webhooks/gitea`; jit-approver mints session JWT bound to `sandbox_uid`, tool_scope=[that tool] |
| 5 | **Retry** | re-run dangerous tool w/ `X-JIT-Session-JWT` | 200; audit `jit_elevated=true, jit_session_id=…, decision=allow`; rule created; **a 2nd dangerous tool still 403** (elevation tool-scoped) |
| 6 | Receipt | jit `/requests/<id>/receipt` / ida Receipt tab | full chain request→approve→elevated-call for the sandbox |
| ✓ | Invariants | all legs | forged/absent SVID → 401; expired grant → 403; no cred in agent |

**Adversarial verification (legs 1/2/5):** an independent verifier agent reads the **live ext-proc
audit log** (`oc -n mcp-gateway logs deploy/ext-proc-delegation`) + the harness env/wire, defaulting
to FAIL unless the audit corroborates the decision provenance AND the no-credential invariant. Leg 5
additionally proves tool-scoping (second dangerous tool denied under the same JWT).

---

## Risks the loops must surface (do NOT paper over)
- **R1 (resolved → action):** spire-oidc serves an LE cert ⇒ never re-apply the ext-proc overlay
  during the test (would strip `SPIRE_TLS_INSECURE` and break read). Hardening = re-anchor to
  ingress CA. Verify the live pod still has `SPIRE_TLS_INSECURE=true` before the run.
- **R2 (control-plane flakiness):** reads have been contradictory (etcd topology, ArgoCD, Kyverno
  reported inconsistently). Every leg re-checks apiserver latency; abort on degradation. Verify
  state with ≥2 consistent reads before trusting it.
- **R3 (grant TTL 3600s):** rewrite as the LAST pre-flight step; if fixes take >1h, rewrite again.
- **R4 (Gitea webhook):** the single least-verified dependency — verify/configure before legs 4–6.
- **R5 (harness Never-pod):** recreate if it self-terminates (`sleep 10800`).
- **R6 (Keycloak NPE):** RFC8693 exchange returns 5xx but is **non-fatal on /mcp** — expected, audit-only.

## Execution gating
Discovery (done) = read-only. P0/P1-verify = read-only. P1-fix (Gitea webhook), P2 (harness + grant),
and the journey-test = LIVE mutations — run after the plan is approved and the P0 health gate passes.
Both workflows are resumable (`resumeFromRunId`, cached prefix).
