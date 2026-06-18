// Variant-B full-journey loop-until-green TEST harness (run via the Workflow tool:
//   Workflow({ scriptPath: "docs/runbooks/variant-b-journey-test.workflow.js" })
// Tests the LIVE stack with MINIMAL touch (see docs/runbooks/variant-b-journey-test-plan.md).
// DOES LIVE MUTATIONS in Prep/Journey (recreate harness pod, rewrite grant, merge a Gitea PR) —
// run only after the plan is approved and the P0 health gate is green.
//
// Design: Preflight (parallel read-only) -> Prep (live refresh) -> Journey (bounded round-loop;
// stateful legs run sequentially; security-critical legs 1/2/5 adversarially verified from the
// ext-proc audit log, default-FAIL unless the audit corroborates the no-credential invariant).
export const meta = {
  name: 'variant-b-journey-test',
  description: 'Loop-until-green E2E test of the Variant-B delegated-agent journey on the LIVE stack: read 200 -> deny 403 -> JIT PR -> approve -> retry 200 -> receipt, adversarially verified from the ext-proc audit',
  phases: [
    { title: 'Preflight', detail: 'read-only health + unverified-gap checks (webhook, ROPC, insecure-flag, grant)' },
    { title: 'Prep', detail: 'recreate the Completed harness pod; rewrite the expired grant (LAST)' },
    { title: 'Journey', detail: 'bounded round-loop over the 7 legs; adversarial verify 1/2/5' },
  ],
}

const KC = '~/.config/ida/anaeem-admin.kubeconfig'
const NS_GW = 'mcp-gateway'
const NS_SB = 'agent-sandbox'
const UID = 'e2e0a1b2-c3d4-4e5f-8a9b-000000000001'
const GW_URL = 'https://mcp-gateway.apps.anaeem.na-launch.com'
const JIT_URL = 'https://jit-approver-api.apps.anaeem.na-launch.com'

const CTX = `Repo /home/anaeem/nvidia-ida. Cluster: \`oc --kubeconfig ${KC} ...\`. The Variant-B stack is LIVE (do NOT re-apply the ext-proc overlay — it would strip the live SPIRE_TLS_INSECURE=true and break the read leg; the spire-oidc route serves a Let's Encrypt cert, not a SPIRE cert). Working Vault token = the k8s secret value: \`oc --kubeconfig ${KC} -n vault get secret vault-init -o jsonpath='{.data.root-token}' | base64 -d\` (the .env token is stale). Vault writes: prefer \`oc -n vault exec vault-0 -- sh -c 'export VAULT_TOKEN=...; vault kv ...'\`. Harness sandbox uid = ${UID}; SVID path = spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/${UID}. Gateway = ${GW_URL}/mcp. jit-approver API = ${JIT_URL}. ext-proc audit = \`oc --kubeconfig ${KC} -n ${NS_GW} logs deploy/ext-proc-delegation --tail=80\`.`

const VERDICT = {
  type: 'object', additionalProperties: false,
  properties: {
    pass: { type: 'boolean' },
    detail: { type: 'string', description: 'what happened + the evidence (HTTP code, audit line, PR#, session id)' },
    evidence: { type: 'array', items: { type: 'string' }, description: 'raw quoted lines: HTTP status, audit fields, vault read, pod state' },
    diagnostic: { type: 'string', description: 'if !pass: root cause + the exact fix to apply (structural) or whether it is transient' },
    state: { type: 'object', additionalProperties: true, description: 'state to thread forward: requestId, prNumber, sessionJwtPresent, etc.' },
  },
  required: ['pass', 'detail', 'evidence'],
}

// ---------------- Preflight (read-only, parallel) ----------------
phase('Preflight')
const preChecks = [
  { k: 'health', p: `${CTX}\nREAD-ONLY. Verify the live dataplane is healthy enough to test: ext-proc-delegation pod 2/2 Running in ${NS_GW} AND its env still has SPIRE_TLS_INSECURE=true (oc get pod ... -o jsonpath over env) — if that flag is gone the read leg will fail-closed; Gateway mcp-gateway Programmed=True; AgentgatewayPolicy Accepted+Attached; kyverno-authz-server Service has Endpoints (extAuthz is fail-closed); pfsense-mcp 2/2 in agentic-mcp; SPIRE server+agent Ready + ClusterSPIFFEID agent-sandbox-e2e-harness present; apiserver trivial-get latency < 2s (time an oc get ns). Return pass=all-green with evidence; diagnostic names any red.` },
  { k: 'vault-grant', p: `${CTX}\nREAD-ONLY. Using the vault-init token, check: secret/data/mcp-tools/mcp-tokens HAS key 'arsalan' (non-empty); secret/data/sandbox-grants/${UID} exists and report its 'created'+'ttl' (compute if EXPIRED = created+ttl < now); secret/data/jit-approver/{gitea-token,webhook-secret,jit-signing-key} present. pass=mcp-tokens.arsalan present AND jit secrets present (grant may be expired — that's fixed in Prep; just report it).` },
  { k: 'gitea-webhook', p: `${CTX}\nREAD-ONLY. The JIT approve->issue leg needs a Gitea webhook on git.arsalan.io/anaeem/nvidia-ida -> ${JIT_URL.replace('-api','')}/webhooks/gitea (or the jit-approver webhook route), Pull-Request events, HMAC = secret/data/jit-approver/webhook-secret, and a 'jit-approval' label. Use the Gitea API with GITEA_TOKEN from environment/.env (curl -H "Authorization: token <tok>" https://git.arsalan.io/api/v1/repos/anaeem/nvidia-ida/hooks and .../labels). Report whether the webhook + label exist and whether the HMAC matches. pass=webhook present & events include pull_request & label exists; diagnostic = exact create commands if missing.` },
  { k: 'ida-ropc', p: `${CTX}\nREAD-ONLY. The TUI surface needs: ~/.config/ida/config.yaml present+populated (jit_url, keycloak_realm_url, keycloak_client_id, gitea_url, kubeconfig, harness_namespace/selector) — read it; and a Keycloak 'arsalan' user with a password + Direct-Access-Grants(ROPC) on the login client. Try a ROPC token grant against the agentic realm token endpoint with client ida-cli (or mcp-gateway) for user arsalan (use DEMO_USER/DEMO_PASSWORD from environment/.env if present) and report if it returns an access_token. pass = config present AND ROPC works (note: the backend journey can still run via curl if ROPC is off — mark pass=true with a note in that case, since legs are driven by exec/curl).` },
]
const pre = await parallel(preChecks.map(c => () => agent(c.p, { label: `preflight:${c.k}`, phase: 'Preflight', schema: VERDICT, model: 'sonnet' }).then(r => ({ k: c.k, r }))))
const preMap = Object.fromEntries(pre.filter(Boolean).map(x => [x.k, x.r]))
const hardBlock = ['health', 'vault-grant'].filter(k => preMap[k] && preMap[k].pass === false)
log(`preflight: ${pre.filter(Boolean).filter(x => x.r && x.r.pass).length}/${preChecks.length} green; hard-blockers=${hardBlock.join(',') || 'none'}`)
if (hardBlock.length) {
  return { abortedAt: 'preflight', reason: 'hard health/vault blocker', preflight: preMap }
}

// ---------------- Prep (live; webhook if missing, harness recreate, grant rewrite LAST) ----------------
phase('Prep')
const webhookOk = preMap['gitea-webhook'] && preMap['gitea-webhook'].pass
const prepWebhook = webhookOk ? null : await agent(
  `${CTX}\nThe Gitea webhook/label for the JIT leg is missing. Create them (LIVE) via the Gitea API with GITEA_TOKEN from environment/.env: (1) the 'jit-approval' label on anaeem/nvidia-ida if absent; (2) a repo webhook -> the jit-approver webhook route, content-type application/json, secret = \`vault kv get -field=secret secret/jit-approver/webhook-secret\` (read via the vault-init token), events = pull_request only, active=true. Confirm by re-listing hooks. Return pass + the webhook id.`,
  { label: 'prep:gitea-webhook', phase: 'Prep', schema: VERDICT, model: 'sonnet' }
)
const prepHarness = await agent(
  `${CTX}\nRecreate the harness pod (it is Completed). LIVE: \`oc --kubeconfig ${KC} -n ${NS_SB} delete pod e2e-harness --ignore-not-found\` then \`oc --kubeconfig ${KC} apply -k services/agent-sandbox/e2e-harness\`. Wait until pod e2e-harness is Ready (retry-poll up to 120s). Then CONFIRM the SVID is issued: the pod has the csi.spiffe.io volume; check ext-proc/SPIRE for the entry, or exec \`oc -n ${NS_SB} exec e2e-harness -c agent -- ls -la /spiffe-workload-api\`. Return pass=Ready+SVID-present with evidence (pod phase, SVID path listing).`,
  { label: 'prep:harness', phase: 'Prep', schema: VERDICT, model: 'sonnet' }
)
const prepGrant = await agent(
  `${CTX}\nLAST prep step (TTL is 3600s). Rewrite the consent grant at secret/data/sandbox-grants/${UID} via the vault-init token: fields version=1, sandbox_uid=${UID}, user=arsalan, scope=read-only, ttl=3600, nonce=<openssl rand -hex 16>, created=<current RFC3339Nano UTC>. Use \`oc -n vault exec vault-0 -- sh -c 'export VAULT_TOKEN=...; vault kv put secret/sandbox-grants/${UID} version=1 sandbox_uid=${UID} user=arsalan scope=read-only ttl=3600 nonce=$(...) created=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)'\`. Verify by reading it back and confirming created+ttl is in the future. Return pass with the created timestamp.`,
  { label: 'prep:grant', phase: 'Prep', schema: VERDICT, model: 'sonnet' }
)
if (![prepHarness, prepGrant].every(r => r && r.pass)) {
  return { abortedAt: 'prep', reason: 'harness or grant prep failed', prep: { prepWebhook, prepHarness, prepGrant }, preflight: preMap }
}

// ---------------- Journey (bounded round-loop; sequential stateful legs) ----------------
phase('Journey')
const EXEC = `oc --kubeconfig ${KC} -n ${NS_SB} exec e2e-harness -c agent --`

async function runLeg(name, prompt) {
  return agent(`${CTX}\n${prompt}`, { label: `leg:${name}`, phase: 'Journey', schema: VERDICT, model: 'sonnet' })
}
async function verify(name, claim) {
  // adversarial: independent read of the ext-proc audit; default FAIL unless corroborated
  return agent(`${CTX}\nADVERSARIAL VERIFY (default FAIL). Independently confirm: ${claim}\nRead the LIVE ext-proc audit (oc -n ${NS_GW} logs deploy/ext-proc-delegation --tail=120) and the harness wire/env. Do NOT trust the leg's own claim. Confirm the no-credential invariant (no pfSense token / user credential in the harness env or MCP args/logs — only the SVID). pass=true ONLY if the audit corroborates the decision provenance AND no credential leaked.`,
    { label: `verify:${name}`, phase: 'Journey', schema: VERDICT, model: 'opus' })
}

let round = 0, green = false, last = {}
while (!green && round < 3) {
  round++
  log(`journey round ${round}`)
  const r = {}
  // Leg 1 — read (200)
  r.read = await runLeg('1-read', `LEG 1 READ. Run \`${EXEC} mcp-call\` (default tool search_firewall_rules). The harness presents ONLY its SVID. Expect HTTP 200 with real pfSense rules. Capture the mcp-call output AND the matching ext-proc audit line. PASS = 200 + >=1 rule + audit decision=allow, caller_username=arsalan, grant_result=valid, grant_scope=read-only. If 403 grant_expired -> diagnostic transient (re-run prep:grant). If 401/TLS -> diagnostic structural (SPIRE_TLS_INSECURE/cert).`)
  r.readV = r.read.pass ? await verify('1-read', 'the read call returned 200 from a SVID-only request, resolved to caller_username=arsalan via the Vault grant, scope read-only, with the pfSense token injected SERVER-SIDE (credential_injected=true) — never present in the agent.') : { pass: false, detail: 'skipped (leg failed)', evidence: [] }
  // Leg 2 — deny (403)
  r.deny = (r.read.pass && r.readV.pass) ? await runLeg('2-deny', `LEG 2 DENY. Run \`${EXEC} mcp-call create_firewall_rule_advanced '{"interface":"lan","protocol":"tcp"}'\` (a dangerous create_ tool). Expect HTTP 403. PASS = 403 + audit decision=deny reason=grant_scope_denied (read-only grant) + NO rule created. Capture output + audit line.`) : { pass: false, detail: 'skipped (read leg not green)', evidence: [] }
  r.denyV = r.deny.pass ? await verify('2-deny', 'the dangerous tool was denied 403 grant_scope_denied under the read-only grant, fail-closed, and no firewall rule was created.') : { pass: false, detail: 'skipped', evidence: [] }
  // Leg 3 — JIT request + PR
  r.req = r.deny.pass ? await runLeg('3-request', `LEG 3 REQUEST. Drive the JIT request for the denied tool create_firewall_rule_advanced (sandbox uid ${UID}, requester arsalan). POST to the jit-approver /requests API (inspect services/jit-approver/src/jit_approver/api.py for the exact request body/route; use the jit route ${JIT_URL}). Confirm a request id is returned AND a Gitea PR is opened (branch jit/<id>, label jit-approval) — check via the Gitea API. Return state.requestId and state.prNumber.`) : { pass: false, detail: 'skipped', evidence: [] }
  // Leg 4 — approve (merge PR) -> webhook -> session JWT
  r.appr = r.req.pass ? await runLeg('4-approve', `LEG 4 APPROVE. Merge PR #${r.req.state && r.req.state.prNumber} on anaeem/nvidia-ida via the Gitea API (GITEA_TOKEN from environment/.env). The merge fires the Gitea webhook -> jit-approver POST /webhooks/gitea -> jit-approver mints a session JWT bound to sandbox_uid=${UID}, tool_scope=[create_firewall_rule_advanced]. Poll jit-approver /requests/${r.req.state && r.req.state.requestId}/status until state==issued (up to 90s). PASS = PR merged + status issued + a session_jwt is available. Return state.requestId + that the session JWT was issued (do NOT print the JWT). If the webhook never fires -> diagnostic structural (webhook config).`) : { pass: false, detail: 'skipped', evidence: [] }
  // Leg 5 — retry (200, elevated, tool-scoped)
  r.retry = r.appr.pass ? await runLeg('5-retry', `LEG 5 RETRY. Re-run the dangerous tool WITH the issued session JWT in the X-JIT-Session-JWT header through the gateway (fetch the session JWT from jit-approver /requests/${r.req.state && r.req.state.requestId}/status and pass it; the harness mcp-call may support an env/arg for the JIT header — inspect services/agent-sandbox/agent-harness/bin/mcp-call). Expect HTTP 200 + rule created. THEN prove tool-scoping: run a DIFFERENT dangerous tool (e.g. delete_firewall_rule) with the SAME JWT and expect 403. PASS = first 200 (audit jit_elevated=true, jit_session_id set) AND second 403.`) : { pass: false, detail: 'skipped', evidence: [] }
  r.retryV = r.retry.pass ? await verify('5-retry', 'exactly create_firewall_rule_advanced was elevated to 200 (audit jit_elevated=true, jit_session_id present, sandbox-bound) while a second dangerous tool under the same session JWT stayed 403 — elevation is tool-scoped and sandbox-bound.') : { pass: false, detail: 'skipped', evidence: [] }
  // Leg 6 — receipt
  r.receipt = r.retry.pass ? await runLeg('6-receipt', `LEG 6 RECEIPT. Fetch jit-approver /requests/${r.req.state && r.req.state.requestId}/receipt. PASS = it returns the per-call audit chain (request -> approve -> elevated call) for sandbox ${UID}. (Also note if the ida Receipt tab would surface it — config check only, do not require the TUI.)`) : { pass: false, detail: 'skipped', evidence: [] }

  last = r
  const legPass = {
    'leg1-read': r.read.pass && r.readV.pass,
    'leg2-deny': r.deny.pass && r.denyV.pass,
    'leg3-request': r.req.pass,
    'leg4-approve': r.appr.pass,
    'leg5-retry': r.retry.pass && r.retryV.pass,
    'leg6-receipt': r.receipt.pass,
  }
  green = Object.values(legPass).every(Boolean)
  log(`round ${round} legs: ${Object.entries(legPass).map(([k, v]) => `${k}=${v ? 'OK' : 'X'}`).join(' ')}`)
  if (green) return { green: true, round, legs: legPass, detail: r, preflight: preMap }
  // structural failure -> stop and surface for a main-loop fix (resume re-runs)
  const firstFail = Object.entries(legPass).find(([, v]) => !v)
  log(`round ${round} stopped at ${firstFail && firstFail[0]} — see diagnostic; fix then resume`)
}

return { green, rounds: round, legs: last, preflight: preMap, note: green ? 'all legs green' : 'did not converge — inspect the failing leg diagnostic, apply the fix, resume the workflow' }
