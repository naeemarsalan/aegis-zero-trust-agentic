# Phase-A Tail — Detailed Plan (resolve-verify loops)

**Date:** 2026-06-22
**Branch:** `feat/openshell-native-svid-grant`
**Status of core journey:** PROVEN 2026-06-22 (workflow `wxhf010s7`) — a credential-less LLM agent
inside a native OpenShell sandbox completed the real pfSense read-200/write-403/approve/write-200
loop via ext-proc with its SPIFFE SVID. Three last-mile seams remain before the Phase-A gate can
be declared HANDS-OFF green.

**Phase-A gate definition (end state for this plan):**
A `/launch` POST (no human exec, no manual oc exec) boots a brain-bearing sandbox that autonomously
completes read-200/write-403/approve/write-200 against the real pfSense tool via ext-proc — with
the no-credential-passing invariant intact and ext-proc audit emitted.

**Hard invariant (carried through every loop):** the agent holds only its SPIFFE SVID; no
long-lived broadly-scoped credential is stored or forwarded; writes are human-approved + JIT +
short-lived. ext-proc stays in front as the per-tool tool-scope gate + audit emitter. Native
supplies the credential mint only (ADR-0011 hybrid, reaffirmed by ADR-0017).

---

## Current state snapshot (2026-06-22, read from live cluster)

| Component | Live state |
|-----------|-----------|
| Sandbox-launcher image | `sandbox-launcher:svidfile-20260622-010033` (brain-boot capable) |
| SANDBOX_IMAGE (deployment) | `sandbox-agent:brain-svidfile-20260622-010059` |
| Live pod SVID_JWT_PATH | `/tmp/svid-out/mcp-gateway-svid.jwt` (Kyverno mutate `fix-launcher-svid-jwt-path` in effect) |
| Deployment SVID_JWT_PATH | `/shared/mcp-gateway-svid.jwt` (ACM-pinned stale value — overridden by Kyverno) |
| envFrom `agent-harness-inference` | Present on live pod; secret keys all PRESENT |
| ClusterSPIFFEID `openshell-sandbox-extproc` | 7/7 pods selected, 0 render failures, hint=mcp-gateway |
| ClusterSPIFFEID `openshell-sandbox-workloads` | 7/7 pods selected, 0 render failures (SA-shaped) |
| Kyverno `fix-launcher-svid-jwt-path` | APPLIED 4h55m ago, Ready |
| Kyverno `mount-svid-output-on-openshell-agent` | APPLIED 16h ago, Ready |
| Kyverno `mutate-openshell-sandbox-cr-kagenti-label` | APPLIED 46h ago, Ready |
| Kyverno `mutate-openshell-sandbox-kagenti-enroll` | APPLIED (Pod-level, OLD policy — superseded but not reaped) |
| ACM `ida-launcher-componenta` | ManifestWork live; field-manager `work-agent` owns `f:image` + `f:SANDBOX_IMAGE` |

---

## SEAM #1 — Unattended SVID file-handoff (issue #27)

### Goal
The autonomous brain, booted by the launcher via `ExecSandbox`, must obtain its
`aud=mcp-gateway` JWT-SVID from a FILE written by the AuthBridge `spiffe-helper` sidecar rather
than from the SPIRE Workload API socket — because the gateway's confined setns/MCS namespace
masks `/spiffe-workload-api` with an empty tmpfs before the brain's exec, and the Workload API
returns `None` from inside that namespace. The sidecar runs in the normal (attestable) container
namespace and CAN attest; it writes the file; the brain reads it via `SVID_JWT_PATH`. The
`provider_spiffe` and SPIRE entry are both proven working — this is purely a file-delivery
plumbing problem.

### Current state of this seam (from live cluster inspection)

The following pieces are ALREADY APPLIED on the live cluster (all Ready):

- `fix-launcher-svid-jwt-path` (ClusterPolicy): Kyverno mutate on launcher pods — overrides
  `SVID_JWT_PATH` to `/tmp/svid-out/mcp-gateway-svid.jwt` on every pod the ACM reverter spawns.
  Confirmed live: the running launcher pod shows `/tmp/svid-out/mcp-gateway-svid.jwt` even though
  the Deployment spec still has `/shared/mcp-gateway-svid.jwt`.
- `mount-svid-output-on-openshell-agent` (ClusterPolicy): mounts the `svid-output` emptyDir
  (injected by the Kagenti webhook into the spiffe-helper sidecar) as read-only into the agent/brain
  container at `/tmp/svid-out` — after the Kagenti webhook fires (reinvocation ordering).
- `configmaps.yaml` in `platform/openshell/kagenti-authbridge/`: `spiffe-helper-config` CM now
  carries `jwt_svids` with `jwt_audience="mcp-gateway"`, `jwt_svid_file_name="mcp-gateway-svid.jwt"`
  (relative path, fixing the `path.Join` misfile), `jwt_svid_file_mode=0644` (brain uid 1000
  can read), and top-level `hint="mcp-gateway"` for deterministic UUID SVID selection.
- `svid_bearer.py` `_try_read_svid_file`: shape-guard decodes the JWT `sub` and rejects an
  SA-shaped token (lacks `/sandbox/`) even when the file is present. `_brain_env` in
  `openshell.py` sets `SVID_JWT_PATH=/tmp/svid-out/mcp-gateway-svid.jwt` and
  `SVID_REQUIRE_PATH_SUBSTR=/sandbox/`.

### What remains (the file has not been end-to-end confirmed on a fresh unattended launch)

The pieces are authored and applied; they have not been exercised by an unattended `/launch`
that completes the full read-200/write-403/approve/write-200 loop autonomously. The last
hands-on green run (`wxhf010s7`) used a manual in-sandbox exec. The round-4 run (`wppv0j71u`)
confirmed the file-based approach as the correct design but was cut short by the Landlock
confinement EACCES on `/svid-out` (pre-round-2 path) and the LLM policy settle race
(pre-`llm_probe`). Both are now fixed in the authored code.

### Loop AT-1 — Verify file-handoff on a fresh unattended launch

**Goal:** a fresh `/launch` ends with the brain presenting the UUID-shaped ext-proc SVID from
the file, making a real pfSense read-200 call, without any manual exec.

**Steps (GATED — requires cluster mutation: sandbox CREATE):**

1. Trigger a `/launch` POST to the sandbox-launcher HTTP API (or via the approval-console).
   The launcher runs `create_sandbox()` then, after the sandbox is Ready, calls
   `probe_agent_svid()` (SVID gate) and `probe_llm_reachable()` (LLM-proxy-settle gate),
   then calls `exec_agent_brain()` (detached boot).
2. Wait for the brain readiness probe (`brain_readiness_command()` pgrep check) to return true.
3. In the sandbox, poll `/tmp/agent.log` via a read-only `oc exec cat /tmp/agent.log` (DOES NOT
   regress the journey) and look for:
   - `svid_from_file` — the file-based path succeeded.
   - `svid_file_wrong_shape` — shape guard rejected a SA-shaped file (should NOT appear if the
     spiffe-helper `hint="mcp-gateway"` + UUID CSID are working).
   - `mcp_call_result` with `status_code=200` on the first read tool — the ext-proc accepted the
     SVID.
4. Verify ext-proc audit log contains `spiffe_id=.../sandbox/<uuid>`, `caller_username=arsalan`,
   `grant_result=valid`, `credential_injected=true`.

**Verify/exit:** `svid_from_file` in brain log + `mcp_call_result status=200` + ext-proc audit
`caller_username=arsalan, grant_result=valid`. Any `svid_fetch_retry`, `workload_api_fetch_failed`,
or `svid_file_wrong_shape` line fails the loop and drives diagnosis.

**Files already authored (no new files needed for this loop):**
- `platform/openshell/kagenti-authbridge/configmaps.yaml` — spiffe-helper-config (mcp-gateway jwt_svids entry + hint + file_mode)
- `platform/openshell/kagenti-authbridge/kyverno-mount-svid-output-on-agent.yaml` — mounts svid-output at /tmp/svid-out
- `platform/openshell/kagenti-authbridge/kyverno-fix-launcher-svid-jwt-path.yaml` — overrides ACM-pinned SVID_JWT_PATH
- `services/agent-sandbox/agent-harness/src/agent_harness/svid_bearer.py` — file-path + shape-guard + subprocess retry
- `services/sandbox-launcher/src/sandbox_launcher/openshell.py` — `_brain_env` sets SVID_JWT_PATH/SVID_REQUIRE_PATH_SUBSTR; `probe_agent_svid` gates boot; `probe_llm_reachable` gates policy-settle; detached boot + readiness probe

**Gated:** YES — requires a new sandbox CREATE to exercise the end-to-end path.

**Touch-points (for reference):**
- `platform/openshell/kagenti-authbridge/configmaps.yaml` (spiffe-helper-config cm)
- `platform/openshell/kagenti-authbridge/kyverno-mount-svid-output-on-agent.yaml`
- `platform/openshell/kagenti-authbridge/kyverno-fix-launcher-svid-jwt-path.yaml`
- `services/agent-sandbox/agent-harness/src/agent_harness/svid_bearer.py`
- `services/sandbox-launcher/src/sandbox_launcher/openshell.py`

---

### Loop AT-2 — Commit file-handoff authored artifacts as GitOps-durable

**Goal:** every file in `platform/openshell/kagenti-authbridge/`, the Kyverno policies, and the
two Python modules are committed on `feat/openshell-native-svid-grant` so the seam survives a
cluster rebuild.

**Steps (NOT gated — file-only):**

1. `git add platform/openshell/kagenti-authbridge/ services/agent-sandbox/agent-harness/src/agent_harness/svid_bearer.py services/sandbox-launcher/src/sandbox_launcher/openshell.py`
2. Commit with message referencing issue #27 + the 3 defect fixes (path.Join misfile, file_mode 0600, Landlock EACCES /svid-out -> /tmp/svid-out).
3. Confirm `git log` shows the commit on the current branch.

**Verify/exit:** `git status` clean on the above paths; `git log --oneline -3` shows the commit.

**Files touched:** all files in `platform/openshell/kagenti-authbridge/`, `svid_bearer.py`, `openshell.py`.

**Gated:** NO (file-only commit).

---

## SEAM #2 — ACM image reverter (issue #28)

### Problem statement

The ACM klusterlet `work-agent` re-applies the hub `ManifestWork` `ida-launcher-componenta`
approximately every 2 minutes using server-side apply (field-manager `work-agent`). It owns the
`f:image` field on the sandbox-launcher Deployment and the `f:SANDBOX_IMAGE` env var. Any
managed-side `oc apply` or `oc set env` to the Deployment is reverted within ~2 minutes.

The ManifestWork lives on the ACM HUB cluster. This managed cluster has no hub API access.
Therefore a durable fix MUST be a hub-side edit.

The current mitigation is the Kyverno `fix-launcher-svid-jwt-path` ClusterPolicy (proved working:
the live launcher pod shows the correct `SVID_JWT_PATH` despite the Deployment having the stale
value). However, the Kyverno policy cannot override the launcher IMAGE (container image, not an env
var) or the SANDBOX_IMAGE env. If the ACM reverter rolls back the launcher image to a pre-brain
tag (e.g. `:dev` or `:sh3`), the launcher will not boot a brain. Similarly if SANDBOX_IMAGE reverts
to `:dev`, the sandbox will not carry the brain runtime.

Current live state: the Deployment image is `sandbox-launcher:svidfile-20260622-010033` and
SANDBOX_IMAGE is `sandbox-agent:brain-svidfile-20260622-010059` — both are the brain-capable tags.
The ACM reverter has NOT clobbered them since the `svidfile` epoch, which suggests the hub
ManifestWork was already updated at some point to carry the `svidfile` tags, but the
`SVID_JWT_PATH` env was not updated (it still holds `/shared/...`). This is the partial-hub-fix
state: images are durable, SVID_JWT_PATH is the remaining stale field.

### Loop AT-3 — Document the exact HUB edit (human step, not cluster mutation from here)

**Goal:** produce a precise, copy-paste-ready instruction for the human to apply on the hub that
pins the correct values and prevents any future regression without requiring ongoing Kyverno
workarounds.

**Steps (file-only authoring):**

The hub ManifestWork `ida-launcher-componenta` must be edited (via the ACM Hub console or
`oc edit manifestwork ida-launcher-componenta -n <managed-cluster-ns>` on the hub) to set:

1. **Launcher image** — pin to `oci.arsalan.io/nvidia-ida/sandbox-launcher:svidfile-20260622-010033`
   (or the latest brain-boot-capable tag at the time of the hub edit). This is the image that
   contains `openshell.py` with `exec_agent_brain`, detached boot, SVID/LLM probes, and the
   `_brain_env` function with correct `SVID_JWT_PATH`.

2. **SANDBOX_IMAGE env** — pin to `oci.arsalan.io/nvidia-ida/sandbox-agent:brain-gw403retry5-20260622-142214`
   (the latest end-to-end proven brain image, or the latest tag from `overlays/anaeem/deployment-patch.yaml`).
   This is the image vendored with `claude_agent_sdk` under `/app/src` (the srcvendor pattern that
   survives the gateway's site-stripping boot) plus the gw-403 retry, subprocess SVID fetch, and
   the file-SVID `_try_read_svid_file` shape guard.

3. **SVID_JWT_PATH env** — set to `/tmp/svid-out/mcp-gateway-svid.jwt`. This is the Landlock-allowed
   path (the gateway ExecSandbox confines the brain to `/sandbox`, `/tmp`, `/app`; `/opt`, `/svid-out`,
   `/home` all EACCES). The `fix-launcher-svid-jwt-path` Kyverno policy overrides this on every
   launcher pod spawn, so it already takes effect at runtime; the hub edit makes it durable and
   allows the Kyverno workaround to be retired.

4. **envFrom `agent-harness-inference` secretRef** — confirm the ManifestWork carries
   `envFrom: [{secretRef: {name: agent-harness-inference, optional: true}}]` so the launcher pod
   inherits the inference credentials from the secret. Confirm the secret itself is present in
   `mcp-gateway` ns (verified live: all 7 keys present). If the ManifestWork does not carry this
   envFrom, add it; the secret is already provisioned.

**Hub edit summary (copy-paste for the human):**

```yaml
# On the ACM hub: oc edit manifestwork ida-launcher-componenta -n <managed-cluster-namespace>
# In the manifest for the sandbox-launcher Deployment, set:
spec:
  template:
    spec:
      containers:
        - name: sandbox-launcher
          image: oci.arsalan.io/nvidia-ida/sandbox-launcher:svidfile-20260622-010033
          envFrom:
            - secretRef:
                name: agent-harness-inference
                optional: true
          env:
            # ... existing env ...
            - name: SANDBOX_IMAGE
              value: "oci.arsalan.io/nvidia-ida/sandbox-agent:brain-gw403retry5-20260622-142214"
            - name: SVID_JWT_PATH
              value: "/tmp/svid-out/mcp-gateway-svid.jwt"
            # SVID_REQUIRE_PATH_SUBSTR must also be present:
            - name: SVID_REQUIRE_PATH_SUBSTR
              value: "/sandbox/"
```

**After the hub edit:**

The `fix-launcher-svid-jwt-path` Kyverno ClusterPolicy can be retired (it is a bridge until this
hub edit; retaining it is harmless but creates unnecessary policy overhead). To retire it: the
human deletes the ClusterPolicy after confirming the hub edit has propagated (the Deployment
image + env match the desired values and a new launcher pod confirms SVID_JWT_PATH is correct).

**Verify/exit (post-hub-edit):**

- Wait ~2 min for ACM reconciler to re-apply the ManifestWork (it fires on the reconcile cycle).
- `oc get deployment sandbox-launcher -n mcp-gateway -o jsonpath='{.spec.template.spec.containers[0].image}'` == the pinned brain-boot tag.
- `oc get pod -n mcp-gateway -l app=sandbox-launcher -o jsonpath='{.items[0].spec.containers[0].env[?(@.name=="SVID_JWT_PATH")].value}'` == `/tmp/svid-out/mcp-gateway-svid.jwt`.
- Trigger a new `/launch`; confirm the sandbox image matches the SANDBOX_IMAGE tag and the brain boots.

**Gated:** YES — requires hub access (human action on the ACM hub cluster). The managed cluster
(this cluster) cannot perform this step.

**Files to author as part of this loop:** none — the hub manifest is on the hub; a managed-side
GitOps file cannot durably override it. The overlay at
`services/sandbox-launcher/deploy/overlays/anaeem/deployment-patch.yaml` documents the desired
values for reference and for a future hub-integrated GitOps flow (Phase D). Keep the overlay's
values in sync with the hub edit.

---

## SEAM #3 — Real per-user OBO (proven viable, not applied)

### Context

The delegated-read path currently uses the **static-token fallback** in ext-proc: when
Keycloak OBO returns `exchange_4xx`, ext-proc falls back to the per-user static token written
to Vault at bootstrap (arsalan's pfSense token). This is functional for the PoC but not per-user
dynamic identity; every user with approved access gets arsalan's pfSense token injected.

**2026-06-21 correction (worklog KC-OBO section):** the original "OBO is a dead-end due to RHBK
#40328 NPE" conclusion was WRONG for the live RHBK 26.6.3 build. The live cluster has zero NPEs.
The actual blocker is a clean v1 policy denial (`not_allowed, client not allowed to impersonate`)
because the `agentic mcp-gateway` Keycloak client has fine-grained admin permissions disabled.
This is a per-client config change — additive and reversible — proven to work in the isolated
`kagenti` realm.

**Two-phase plan:**

1. **v1 fine-grained-perms (near-term, proven):** enable fine-grained admin permissions on the
   `mcp-gateway` client in the `agentic` realm; bind a client policy + `users-impersonate` scope
   permission for token-exchange. This is the **naked impersonation** path (RFC 8693 with
   `requested_subject`, no `subject_token`) — proven in the isolated `kagenti` realm, HTTP 200
   with `sub=user`.

2. **v2 subject_token (durable end-state):** migrate to RFC 8693 v2 proper OBO with a real
   `subject_token` carried by the launcher from the user's Keycloak session. This requires the
   approval-console to pass the user's Keycloak token to the launcher at `/launch` (the launcher
   currently discards the Backstage token after identity extraction). The durable end-state ensures
   the user's own token flows through (no impersonation), making it shelf-life proof as v1 is
   deprecated.

### Loop AT-4 — v1 fine-grained-perms enablement (GATED, off-hours + snapshot)

**Goal:** enable real per-user OBO on the `agentic` `mcp-gateway` Keycloak client so the
injected pfSense credential is the requesting user's token, not a static fallback.

**Steps (GATED — Keycloak mutation, off-hours, snapshot first):**

Pre-conditions:
- Take a Keycloak database snapshot (CNPG: `oc exec -n keycloak <cnpg-pod> -- pg_dump keycloak`)
  before any Keycloak change. This is reversible; a snapshot makes it fast.
- Perform during off-hours (the `agentic` realm is shared by the approval-console, ext-proc, and
  the launcher — a misconfiguration blocks all authenticated users).

Keycloak changes (in the `agentic` realm, NOT the `kagenti` isolated test realm):

1. **Enable fine-grained admin permissions on the `mcp-gateway` client** (client id
   `17452fe4-...`). In the Keycloak admin UI: Clients → `mcp-gateway` → Permissions → Enable.
   This is additive — it does not disable any existing auth.

2. **Create a Token Exchange permission** for the `mcp-gateway` client. Under the client's
   Permissions tab, create a permission of type `token-exchange`, scope
   `users-impersonate`, associated with a policy that allows the `mcp-gateway` client itself
   to perform the exchange. (Mirror exactly what was done in the isolated `kagenti` realm in
   workflow `wh25z0ez6`.)

3. **Test with a dry-run from ext-proc** (do NOT deploy a new ext-proc version; use the existing
   ext-proc log to confirm OBO succeeds). Trigger a pfSense read from an approved grant;
   look for `keycloak_mode=on_behalf` (not `static_token_fallback`) in the ext-proc audit log.

Rollback: in the Keycloak admin UI, disable fine-grained permissions on the `mcp-gateway` client.
This restores the prior state (clean v1 policy denial, static-token fallback in ext-proc).

**Verify/exit:** ext-proc audit log shows `keycloak_mode=on_behalf, sub=<user>` (not
`static_token_fallback`) on a pfSense delegated read with an active approved grant.

**Gated:** YES — Keycloak `agentic` realm mutation. Off-hours. Snapshot required first.

---

### Loop AT-5 — v2 subject_token (durable OBO end-state, design-only for Phase A)

**Goal:** define the design changes needed for v2 RFC 8693 OBO so Phase B can implement them
alongside the approval-console session model (Loop C1).

**Design (no cluster change; file-only):**

The v2 path requires the **user's Keycloak access token** to be present at the moment ext-proc
calls the token-exchange endpoint. The chain:

1. The approval-console (Keycloak-authenticated via oauth2-proxy) receives the user's Keycloak
   access token in the browser session cookie / header.
2. On `/launch`, the console forwards the user's token to the sandbox-launcher API in a
   dedicated header (e.g. `X-User-Token`), separate from the launcher's own OIDC client-credentials.
3. The sandbox-launcher verifies the user token (JWKS from Keycloak), extracts the subject, writes
   it into the Vault grant (`subject_token_hint`), and passes it to ext-proc via a new grant field.
4. ext-proc, on `FetchGrant`, retrieves the `subject_token` and uses it as the `subject_token`
   parameter in the RFC 8693 v2 exchange call to Keycloak (not `requested_subject`).

**Constraints:**
- The v1 `requested_subject` approach (naked impersonation) uses only the `sub` claim of the user.
  This is fine for the PoC but is marked deprecated in Keycloak's roadmap.
- The v2 approach requires the user's Keycloak access token to reach the launcher. This requires the
  approval-console to preserve and forward it. The console already carries the Keycloak session (oauth2-proxy
  sets the `Authorization: Bearer` header on upstream requests — the launcher can read it from the
  `X-Forwarded-User-Token` or a dedicated header added by oauth2-proxy's `pass-authorization-header`
  feature). Evaluate whether oauth2-proxy already forwards the Keycloak AT or only a proxied OIDC ID token.
- The Vault grant schema must be extended to carry `subject_token` (write-only, never logged, TTL-bounded
  to the grant TTL). The `vault.write_sandbox_grant` guard must be extended to allow this field while
  still rejecting `access_token`, `bearer`, `svid`, `private_key` by name.

**Phase A scope:** this loop is design-only. No code change, no cluster change. The v1 path (Loop
AT-4) is the applied Phase-A milestone; v2 is the Phase-B/C task tracked here for sequencing.

**Verify/exit (design only):** the design choices are documented here; the implementation is a
Phase-B task tied to the approval-console session model (Loop C1 in the master plan).

**Gated:** NO (design / documentation only).

---

## SEAM #4 — Housekeeping

### Loop AT-6 — Commit branch and reap dead `mutate-openshell-sandbox-kagenti-enroll` ClusterPolicy

**Goal:** clean up the dead pod-level Kyverno policy that was superseded by the Sandbox-CR-level
policy (`mutate-openshell-sandbox-cr-kagenti-label`), and commit the current branch.

**Background:**
`mutate-openshell-sandbox-kagenti-enroll` (applied 2d1h ago) mutates **Pod** objects to stamp
`kagenti.io/type=agent` and add the `shared-data` emptyDir. This was the original approach; it
was superseded by `mutate-openshell-sandbox-cr-kagenti-label` (which mutates the **Sandbox CR**
instead, ensuring the label is present before the inject.kagenti.io webhook's objectSelector
check — issue #8 in the worklog). The pod-level policy is now a dead weight: it runs on every pod
CREATE in `openshell`, fires on matching pods, and does a strategic-merge that is redundant with
what the CR mutation already achieved. It adds zero value and increases admission latency.

**Reaping constraint:** `oc delete` of cluster-scoped resources (ClusterPolicy, ClusterRoleBinding,
ClusterSPIFFEID) is HARD-DENIED by the harness permission policy for agent threads. This step is
a HUMAN action.

**Steps (GATED — human cluster-scoped delete):**

1. Confirm the Sandbox-CR-level policy is still in place and working:
   `oc get clusterpolicy mutate-openshell-sandbox-cr-kagenti-label` — should be Ready.
2. Human runs: `oc delete clusterpolicy mutate-openshell-sandbox-kagenti-enroll`
3. Verify the remaining policies are healthy:
   `oc get clusterpolicy` — should not show `mutate-openshell-sandbox-kagenti-enroll`.
4. Trigger a dry-run sandbox CREATE (`oc create -f <minimal-sandbox.yaml> --dry-run=server`) to
   confirm the admission path still produces the expected label + annotation (from the CR policy).

**Commit current branch (NOT gated — file-only):**

After Loop AT-2 (file-handoff commit), ensure all Phase-A tail authored artifacts are on
`feat/openshell-native-svid-grant`:

- `platform/openshell/kagenti-authbridge/` (all files, including the two new Kyverno policies)
- `platform/openshell/networkpolicy-sandbox-egress.yaml`
- `platform/spire/base/cluster-spiffe-ids.yaml` (openshell CSIDs)
- `platform/vault/config/sandbox-launcher.hcl` + `vault-bootstrap.sh`
- `services/agent-sandbox/agent-harness/src/agent_harness/svid_bearer.py`
- `services/sandbox-launcher/src/sandbox_launcher/openshell.py`
- `docs/adr/0017-…`, `docs/adr/0018-…`, `docs/plans/openshell-agentic-platform-master-plan.md`,
  `docs/reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md`,
  `docs/reviews/master-plan-review-2026-06-20.md`
- This plan: `docs/plans/phase-A-tail-detailed-plan.md`

**Verify/exit:** `git status` clean; `git log --oneline -5` shows the tail commits;
`oc get clusterpolicy` does not show the dead pod-level enroll policy.

**Gated:** YES for the clusterpolicy delete (human, cluster-scoped). NO for the commit.

---

### Loop AT-7 — pfSense demo rule id 50 cleanup

**Goal:** remove the `nvidia-ida-e2e-demo` firewall rule (pfSense id 50, tracker 1782050038)
created by the E2E workflow and left DISABLED but present. The pfSense MCP `delete_firewall_rule`
tool has a bug (httpx `AsyncClient.delete(json=...)` misuse — issue #22 in the worklog) that
prevents agent-driven deletion.

**Options (in order of preference):**

1. **Manual pfSense UI deletion** (recommended for speed): log into pfSense web UI → Firewall →
   Rules → locate rule id 50 (`nvidia-ida-e2e-demo`, currently DISABLED) → delete. Does not require
   any code change or cluster mutation.

2. **Fix the MCP server bug first, then use the agent**: edit
   `~/pfsense-mcp-server/src/client.py` line 254:
   `await self._client.delete(url, json=body)` →
   `await self._client.request("DELETE", url, json=body)`.
   Rebuild + redeploy the pfSense MCP container, then use the agent to delete the rule. This is the
   proper fix (issue #17) and should be done regardless of option 1 to prevent future accumulation
   of stuck demo rules.

**Verify/exit:** pfSense firewall rules list does not contain `nvidia-ida-e2e-demo` or any
`tracker=1782050038` entry. `oc logs -n agentic-mcp <pfsense-mcp-pod>` shows no pending
delete errors.

**Gated:** YES — pfSense UI access or pfsense-mcp rebuild + redeploy (human action outside the
cluster's GitOps scope). The pfsense-mcp source fix is at `~/pfsense-mcp-server/src/client.py`
(external to this repo).

---

### Loop AT-8 — Decide fate of retired ext-proc/Vault-grant (Loop-2) path

**Goal:** make an explicit decision on the ext-proc/Vault-grant path and record it, so it is not
accidentally assumed to be the active delegated-read path.

**Background (from worklog "Strategic pivot"):** The delegated-read path moved from the bespoke
ext-proc/Vault-grant design to Kagenti AuthBridge (ADR-0013). On the Kagenti model, the
per-sandbox UUID SVID + the launcher's Vault grant are used for the EXT-PROC plane (the
read-via-SVID path), NOT for delegating user identity — that was the original "Loop 2" Vault-grant
idea which is now retired. The Vault grant is still WRITTEN by the launcher (`vault_grant_write_ok`)
and READ by ext-proc (`ext-proc.hcl`) for the `FetchGrant` path, which maps the sandbox UUID SVID
to the user + scope. This path IS active and proven (issue #3 resolution + the proven `wxhf010s7`
journey). What is RETIRED is using the Vault grant as the sole token-injection mechanism
independent of SPIFFE; that was the "Loop 2" pre-Kagenti design.

**Decision options:**

| Option | Description | Consequence |
|--------|-------------|-------------|
| A — Retain as-is (recommended) | ext-proc uses the Vault grant for scope-gating + user attribution; Kagenti AuthBridge handles the Kagenti/echo-mcp plane separately. The two CSIDs coexist. | No change needed. Document the dual-plane design explicitly so it is not misread as a "retired" path. |
| B — Retire ext-proc entirely | Remove the Vault grant write from the launcher; stop the ext-proc path. | Breaks the proven pfSense real-tool journey (ext-proc IS on the pfSense path). NOT recommended. |
| C — Retire Vault-grant-only read path | Keep ext-proc; retire the Vault grant only if a non-grant ext-proc authz is designed. | Out-of-scope for Phase A; Phase B/C work. |

**Recommendation:** Option A. Record in the worklog and this plan that ext-proc/Vault-grant is
ACTIVE and PROVEN on the real-tools path; the "retired" label applies only to the bespoke
pre-Kagenti "Loop 2" where the grant was intended as the SOLE authz mechanism without SPIFFE.
The current design is a hybrid (ADR-0011): Vault grant = scope metadata; SPIFFE SVID = identity;
ext-proc = authz gate + audit.

**Steps (file-only):**
- Annotate `platform/vault/config/sandbox-launcher.hcl` with a clarifying comment confirming the
  grant-write path is ACTIVE (not retired) and what it gates.
- Annotate the worklog entry "Strategic pivot recorded mid-session" with a correction note.

**Verify/exit:** the doc/comment accurately reflects that ext-proc/Vault-grant is ACTIVE on the
ext-proc plane and only the pre-Kagenti bespoke-grant-as-sole-authz is retired. No cluster change.

**Gated:** NO (file-only).

---

## Phase-A gate

**Definition (hands-off verification):** a `/launch` POST (no human exec, no manual `oc exec`)
boots a brain-bearing sandbox that autonomously completes read-200/write-403/approve/write-200
against the real pfSense tool via ext-proc, with:

- ext-proc audit: `spiffe_id=.../sandbox/<uuid>`, `caller_username=arsalan`,
  `grant_result=valid`, `credential_injected=true`, `jit_elevated=true`
- brain log: `svid_from_file`, no `svid_fetch_retry`/`workload_api_fetch_failed`/`svid_file_wrong_shape`
- `hack/test-openshift-jit.sh` remains 4/4 (non-regression)

**Remaining gates before this is reachable:**

| Loop | Gate | Unblocks |
|------|------|----------|
| AT-1 | Fresh unattended `/launch` + verify file-SVID path end-to-end | Phase-A gate |
| AT-2 | Commit authored artifacts | Phase-A durability |
| AT-3 | HUB ManifestWork edit (human/hub) | Phase-A durability (image reverter) |
| AT-4 | KC v1 OBO enablement (optional for gate; static-token fallback is sufficient) | Phase-B OBO quality |
| AT-6 (delete) | Reap dead pod-level Kyverno policy (human) | Hygiene |
| AT-7 | pfSense rule id 50 cleanup (human) | Demo cleanliness |

**Parallelism:** AT-2 (commit) can run in parallel with AT-1 (verify). AT-3 (hub edit) is
independent of AT-1/AT-2 and can proceed as soon as hub access is available. AT-4 (KC v1 OBO)
is independent and can be deferred to Phase B without blocking the gate. AT-6 and AT-7 are
housekeeping and do not block the gate.

---

## Loop dependency graph

```
AT-2 (commit) ─────────────────────────────────────────────────────┐
                                                                    │
AT-1 (verify SVID file-handoff unattended) ──────────────────────► PHASE-A GATE
                                                                    │
AT-3 (HUB edit) ────────────────────────────────────────────────────┘
    (independent of AT-1; makes AT-1 durable after hub reverts)

AT-4 (KC v1 OBO) ─── independent ─── Phase-B OBO milestone
AT-5 (v2 OBO design) ─── file-only ─── Phase-B/C implementation

AT-6 (reap dead policy) ─── independent housekeeping
AT-7 (pfSense rule cleanup) ─── independent housekeeping
AT-8 (ext-proc fate doc) ─── file-only ─── no dependency
```

---

## Authored files (new, on this branch)

| File | Purpose |
|------|---------|
| `docs/plans/phase-A-tail-detailed-plan.md` | This plan |
| `platform/openshell/kagenti-authbridge/kyverno-fix-launcher-svid-jwt-path.yaml` | Pod-level Kyverno that overrides ACM-pinned SVID_JWT_PATH (bridge until hub edit) |
| `platform/openshell/kagenti-authbridge/kyverno-mount-svid-output-on-agent.yaml` | Mounts svid-output emptyDir at /tmp/svid-out on the agent container |

*(The other kagenti-authbridge files, svid_bearer.py, and openshell.py were authored in the
Phase-A core run and are pending commit — Loop AT-2.)*
