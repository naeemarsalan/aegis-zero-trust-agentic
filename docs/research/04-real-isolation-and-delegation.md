# Research Brief #4 — Real Isolation + Real Delegation (the deeper platform)

**Audience:** an autonomous agent (or a multi-agent workflow) tasked with moving the zero-trust
agentic PoC from its current "attribute" depth to genuine per-user isolation and delegation.
**Repo:** `/home/anaeem/nvidia-ida` · **Branch:** `backup/e2e-delegated-zero-trust`
**Cluster:** OpenShift at `apps.anaeem.na-launch.com` · **Homelab:** `172.16.x`

---

## 0. Context you must load before doing anything

Read these first; do not re-derive what they already record:

- `memory/project-openshift-jit-demo.md` — the working SA-split JIT demo (view-SA reads,
  edit-SA writes behind the gate, human approves in console). **This is the baseline you must
  not break.**
- `memory/project-kagenti-adoption.md` — the identity plane (SPIRE/SPIFFE, Kagenti operator
  installed, ADR-0013, ext-proc cutover NOT done).
- `memory/project-keycloak-obo-constraint.md` — **the OBO dead-end**: naked impersonation is a
  Keycloak NPE (#40328, wontfix; v1 token-exchange deprecated). Real per-user OBO needs a
  `subject_token` (a real broker-issued user token) or the v1-flags workaround.
- `memory/project-e2e-handoff.md` — delegated loop status; ext-proc fix live but not gitops-durable.
- `docs/adr/0013-kagenti-identity-plane-adoption.md`.

**Hard invariant (the whole point of the project — never violate):**
> No long-lived, broadly-scoped credential is ever stored in or forwarded by the agent.
> The agent holds only its SPIFFE SVID. Every privileged action is either (a) read-only via a
> scoped view identity, or (b) a write that is human-approved, just-in-time, short-lived, and
> attributed to a real human. Any design that ends with the agent holding a standing edit token
> is a regression, not progress.

Before proposing ANY change, state how it preserves this invariant. If it can't, stop and report.

---

## 1. The three sub-problems (independent loops, shared invariant)

| # | Sub-goal | Today | Target | Primary blocker |
|---|----------|-------|--------|-----------------|
| A | **Per-session sandbox** | one shared `e2e-harness` pod; every user's agent execs into it | one freshly-minted, isolated OpenShell sandbox per session, torn down after | OCP `CreateSandbox` fails: provider_spiffe `setns` EPERM |
| B | **Ephemeral edit identity** | standing `k8s-mcp-edit` SA + pod with a `edit` RoleBinding | edit credential is minted on approval, scoped to the one action, expires in minutes | no broker minting short-lived k8s creds yet (Vault k8s-secrets engine not wired) |
| C | **Per-user delegation (OBO)** | SA-split; JIT `requester_sub` carries the human's name (attribution only) | agent calls the cluster *as the user*, bounded by the user's real RBAC | Keycloak impersonation NPE #40328; needs `subject_token` or v1 flags |

Each loop below is: **Research → Decide → Implement → Verify → Record.** Run them as separate
workflow phases. They can run in parallel for research, but **serialize the implement/verify
steps** because they all touch the same harness + JIT spine and would race.

---

## LOOP A — Per-session OpenShell sandboxes

### A.1 Research questions
1. **Reproduce & isolate the failure.** What is the exact call path that throws `setns` EPERM?
   Is it the SPIRE agent's `provider_spiffe` workload-attestor trying to enter the new sandbox's
   network/PID namespace? Capture the full error, the pod/securityContext, and the SCC in effect.
   - Commands to start: `oc get pods -n <openshell-ns>`, describe the failing sandbox CR/pod,
     `oc logs` the controller and the SPIRE agent on that node, `oc get scc`, check the
     controller's `securityContext`/`capabilities`.
2. **What does OpenShell's CreateSandbox actually need?** Find the controller source / CRD.
   Does it require `CAP_SYS_ADMIN` / `setns` to join the workload's netns for attestation?
   Is there a rootless/userns mode? (researcher agent: pull the OpenShell + SPIRE
   container-workload-attestor docs and the relevant CRD schema.)
3. **Three candidate fixes — evaluate each:**
   - (a) **Grant the capability properly:** a dedicated SCC granting `CAP_SYS_ADMIN` (or just the
     narrower `setns`-bearing caps) to the sandbox-controller SA only. Blast radius? Does it
     violate the cluster's SCC posture? Is there a node-level seccomp/AppArmor profile blocking
     `setns` even with the cap?
   - (b) **Swap the attestor:** can SPIRE attest the sandbox via a path that doesn't need
     `setns` — e.g. k8s SAT/PSAT attestor or the projected-SVID/CSI driver — so the controller
     never enters another netns?
   - (c) **Drop the per-session controller entirely:** mint sandboxes as plain short-lived Pods
     (one per session, `activeDeadlineSeconds`, own NetworkPolicy, own SA) with the SVID delivered
     via the SPIFFE CSI driver — reuse the existing e2e-harness manifest as the template, just
     parameterize per session. This may sidestep `setns` completely.
4. **Lifecycle:** how does a session pod get created on `POST /api/sessions`, get its SVID, run
   the agent, stream JSONL back, and get reaped? Where does the console's current `k8s exec`
   model change?

### A.2 Decision criteria
- Prefer (c) if it preserves the invariant and removes the blocker with least privilege —
  it's the smallest deviation from what already works and avoids granting `setns`.
- Only choose (a) if the security-reviewer agent signs off that the cap is scoped to one SA and
  the node posture allows it. Record the trade-off in an ADR.

### A.3 Implement
- Parameterize the e2e-harness manifest into a per-session template (Job or Pod):
  unique name `agent-session-<id>`, own SA, own NetworkPolicy (DNS + scoped egress only),
  `automountServiceAccountToken` per current rules, SPIFFE CSI volume, `activeDeadlineSeconds`.
- Update `services/approval-console` (`app.py`, `config.py`): `POST /api/sessions` creates the
  pod (not exec into a shared one); `/stream` relays its logs; add reaping on completion/timeout.
- Console SA RBAC: add `pods create/delete` (it currently has get/list + pods/exec get,create).
- Keep everything gitops-durable (base manifests carry the real values — `apply -k` must be
  non-destructive; mounts over env where ArgoCD reverts env).

### A.4 Verify (the loop's exit gate)
- Two concurrent sessions get two distinct pods with two distinct SVIDs; neither can see the
  other's filesystem/network (prove isolation: exec a probe).
- `hack/test-openshift-jit.sh` still 4/4 PASS using a per-session pod.
- Pod is gone (reaped) after the session ends / deadline.
- `oc apply -k services/agent-sandbox/...` is non-destructive (diff is cosmetic only).
- New script: `hack/test-per-session-sandbox.sh` (loop-until-green).

---

## LOOP B — Ephemeral, Vault-minted edit credentials

### B.1 Research questions
1. **Is Vault present/usable?** Check the cluster for a Vault (or OpenBao) instance and the
   Kubernetes secrets engine. If absent, decide: deploy Vault, or use the **native k8s
   `TokenRequest` API** (BoundServiceAccountToken with a short `expirationSeconds` + audience)
   as the minting primitive instead. Native TokenRequest may be the lighter path and needs no
   new component.
2. **What mints what, and when?** The credential must be created *at approval time* and live
   only long enough for the one action. Map it onto the existing JIT flow:
   `jit-approver` already mints the capability JWT after the Gitea PR merge — that is the natural
   place to also mint (or trigger minting of) the short-lived k8s token, scoped to the approved
   tool/namespace/resource.
3. **Scope of the minted token.** Today `k8s-mcp-edit` SA has a standing `edit` RoleBinding in
   `mcp-demo`. Target: a token bound to an SA whose RBAC is the *minimum* for the approved action
   (e.g. just `patch deployments` in `mcp-demo`), valid ~5 min, single-namespace. Research whether
   to (a) pre-create narrow SAs per capability and mint tokens for them on demand, or (b) use Vault
   k8s engine to generate an ephemeral SA+RoleBinding+token per request and revoke after.
4. **Where does the gate/MCP get the token?** The MCP edit server currently uses its own
   mounted SA token. To make it *ephemeral*, the token must be injected per-request — research
   whether the gate can pass a short-lived token through to the MCP server, or whether the MCP
   server is restarted/reconfigured per mint (too slow). Likely answer: the gate, after verifying
   the capability JWT, attaches the freshly-minted bounded token for that single upstream call.

### B.2 Decision criteria
- Prefer native `TokenRequest` + per-capability narrow SAs if it satisfies the invariant — no new
  infra, k8s-native expiry, audience-bound. Reserve Vault for when you need dynamic SA/RoleBinding
  generation or cross-system secrets.

### B.3 Implement
- Add minting to `jit-approver` (or a small sidecar it calls): on approval, `TokenRequest` for the
  capability-scoped SA with `expirationSeconds` ≈ the JIT window + audience = the MCP edit server.
- Modify `jit-gate` (`gate.py`): after capability-JWT verification, use the minted bounded token
  for the upstream MCP call instead of a standing mount. Fail closed if no/expired token.
- Remove the standing broad `edit` RoleBinding; replace with per-capability narrow Roles.
- Keep `STRICT_TOOL_SCOPE=true` so the token's power matches the approved tool exactly.

### B.4 Verify
- The edit credential used for a fix expires: replay the same token after the window → 401/403.
- The minted token can ONLY do the approved verb/resource/namespace (prove with `oc auth can-i`
  --as the token's SA): e.g. can patch deployments in mcp-demo, cannot delete, cannot touch
  kube-system.
- `hack/test-openshift-jit.sh` still 4/4 (fix still works through the ephemeral path).
- Negative control: with no fresh mint, the write is denied.
- New script: `hack/test-ephemeral-edit-token.sh`.

---

## LOOP C — Per-user OIDC delegation (true OBO)

> This is the hardest and the most security-sensitive. The architect + security-reviewer agents
> must be in the loop. Today we only *attribute* to the human (`requester_sub`); the action still
> runs as a ServiceAccount. Target: the cluster authorizes the call against the *human's* RBAC.

### C.1 Research questions
1. **Confirm the dead-end boundary precisely.** Re-validate `project-keycloak-obo-constraint.md`
   against the *installed* Keycloak/RHBK version: is impersonation still NPE #40328? Is standard
   **RFC 8693 token-exchange (v2)** available and non-deprecated in this build? What exactly does
   it require — a real `subject_token` from the user, a `requested_token_type`, audience config?
   (researcher agent: pull the RHBK release notes + token-exchange admin docs for the deployed
   version.)
2. **Where does a real user token come from?** The console already authenticates the human via
   oauth2-proxy → Keycloak (realm `agentic`, user `arsalan`). Can the console capture the user's
   **access/ID token** (oauth2-proxy can pass it as a header / `--pass-access-token`) and hand it
   to the agent's session as the `subject_token`? That converts attribution into a real delegated
   token — the missing input the OBO dead-end note calls for.
3. **How does OpenShift consume a Keycloak-issued user token?** OpenShift's API server trusts its
   own OAuth/OIDC. Research the bridge: is Keycloak configured as an OIDC identity provider for the
   cluster? If the user logs into the cluster via Keycloak, their cluster identity = their Keycloak
   identity, and a token-exchanged token (audience = cluster) could authorize directly against their
   `oc`-level RBAC. If NOT, the gap is an IdP-federation task, scope it.
4. **Delegation chain design (architect agent).** Draw the full sequence:
   user → console (oauth2-proxy captures user token) → agent session (subject_token, never stored
   long-term) → token-exchange at Keycloak (actor = agent SVID, subject = user) → short-lived
   delegated token (aud = cluster/MCP) → MCP/gate → API server authorizes as the user.
   Where is human-in-the-loop approval still required, and how does it compose with delegation?
   (Likely: delegation replaces the SA-split for *reads*; writes still need JIT approval, but now
   the write also runs as the user — defense in depth.)
5. **Fallback if v2 token-exchange is unavailable:** the v1-flags workaround from the constraint
   note. Document the exact flags, their risk, and whether security-reviewer accepts them, OR
   recommend staying at attribution depth and deferring true OBO until the platform supports it.

### C.2 Decision criteria
- True OBO is only worth shipping if (a) v2 token-exchange (or an acceptable v1 workaround) works
  in the deployed Keycloak, AND (b) OpenShift trusts Keycloak identities (IdP federation exists or
  is cheap to add). If either is false, **record the finding, ship the `subject_token` capture as
  groundwork, and defer** — do not weaken security to force it.

### C.3 Implement (only if C.2 passes)
- oauth2-proxy: pass the user token to the console; console threads it into the session as a
  short-lived `subject_token` (in-memory only, never written to git/logs/disk).
- Add a token-exchange step (in the agent's mcp-call or the gate): exchange `subject_token` +
  agent SVID (actor) → delegated token scoped to the target audience.
- MCP/gate uses the delegated token; API server authorizes as the user.
- Keep JIT approval for writes; now both attribution AND authorization are the human's.

### C.4 Verify
- A read the *user* is allowed → succeeds as the user (prove via audit: the API server sees the
  user, not an SA).
- A read the user is NOT allowed → denied by the user's RBAC (not by our gate) — proves real
  delegation, not SA-split.
- The delegated token is short-lived and never persisted (grep the agent fs/logs — absent).
- Writes still require JIT approval and now run as the user.
- `hack/test-openshift-jit.sh` still 4/4.
- New script: `hack/test-per-user-delegation.sh`.

---

## 2. Cross-cutting rules for every loop

1. **Never break the working demo.** After each implement step, run `hack/test-openshift-jit.sh`
   and confirm 4/4 before moving on. If it goes red, revert and re-plan.
2. **Gitops durability.** Base manifests carry real values; prefer mounted overrides where ArgoCD
   reverts env; `oc apply -k` must stay non-destructive. The real inference Secret and any user
   tokens stay live-only / out of git.
3. **Fail closed.** Every new authz/mint/exchange path denies on error, missing token, or expiry.
4. **Security review gate.** Anything touching RBAC, SCC/capabilities, NetworkPolicy, token
   minting, or token-exchange goes through the security-reviewer agent before merge; findings to
   `docs/reviews/`. Anything hard to reverse gets an ADR under `docs/adr/`.
5. **Record as you go.** Update the relevant `memory/project-*.md` after each loop closes, and
   write/replace the ADR. Convert relative dates to absolute.

## 3. Suggested workflow shape

- **Phase 1 (parallel research):** three researcher/Explore agents, one per loop, answer the
  R-questions above and return a structured findings object (blocker root cause, candidate fixes,
  recommended option, invariant-preservation statement, success criteria).
- **Phase 2 (decide):** architect agent reviews all three findings, sequences the implement order
  (recommended: A → B → C, since C depends on isolation+ephemerality being real), writes ADR(s).
- **Phase 3 (implement+verify, serialized per loop):** codegen/manifest-scaffolder implement;
  after each, run the loop's verify script AND `hack/test-openshift-jit.sh`; security-reviewer
  signs off. Loop until green.
- **Phase 4 (record):** update memory + ADRs; report what shipped vs. what was deferred and why.

## 4. Definition of done for #4

- Per-session isolation is real and proven (two sessions, two SVIDs, isolated) OR the blocker is
  resolved with a recorded, reviewed trade-off.
- The edit credential is ephemeral and minimally-scoped, proven to expire and to be unable to
  exceed the approved action.
- Per-user delegation is either (a) shipped and proven (API server authorizes as the human), or
  (b) explicitly deferred with the `subject_token` groundwork in place and a recorded reason.
- The original demo still passes 4/4, everything is gitops-durable, and the no-stored-credential
  invariant holds throughout.
