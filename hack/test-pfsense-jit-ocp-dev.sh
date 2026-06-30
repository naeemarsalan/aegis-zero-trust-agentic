#!/usr/bin/env bash
# test-pfsense-jit-ocp-dev.sh — deterministic regression anchor for the pfSense
# zero-trust journey on the ocp-dev cluster (3 masters + 2 workers).
#
# Proves, with a credential-less SVID-only caller (the agent-sandbox e2e-harness
# pod, which holds ONLY its SPIFFE SVID):
#   1. READ  delegated-as-user        -> 200  (downstream pfSense sees the USER)
#   2. WRITE without elevation        -> 403  grant_scope_denied (fail-closed)
#   3. APPROVE via jit-approver mint  -> capability JWT (approver != requester, SoD)
#   4. ELEVATED WRITE with capability -> 200  (a REAL pfSense rule)
#
# ocp-dev twin of hack/test-openshift-jit.sh (k8s path). First proven green
# 2026-06-25 (rule id=52, ztp-e2e-test-rule). The six bring-up fixes it depends on
# are asserted as preconditions so a regression surfaces clearly.
#
# Usage:   IDA_KUBECONFIG=~/.kube/ocp-dev-admin.kubeconfig bash hack/test-pfsense-jit-ocp-dev.sh
# Requires: oc reachable via a NON-expired kubeconfig (the break-glass cert
#           ~/.kube/ocp-dev-admin.kubeconfig — the user-token ocp-dev.kubeconfig is EXPIRED);
#           /etc/hosts for the *.apps.ocp-dev.na-launch.com routes -> ingress VIP 172.16.2.59.
# NOTE: all Vault reads/writes go via `oc exec vault-0` (NOT port-forward). port-forward drops on a
#       flapping control plane and produced false 'missing'/connect failures; no local vault CLI needed.
set -uo pipefail

KC="${IDA_KUBECONFIG:-$HOME/.kube/ocp-dev-admin.kubeconfig}"
TRUST_DOMAIN="${TRUST_DOMAIN:-anaeem.na-launch.com}"
SB="${SB:-e2e0a1b2-c3d4-4e5f-8a9b-000000000001}"
AGENT_SPIFFE="spiffe://${TRUST_DOMAIN}/ns/agent-sandbox/sandbox/${SB}"
JIT_API="${JIT_API:-https://jit-approver-api.apps.ocp-dev.na-launch.com}"
RULE_DESC="ztp-e2e-test-rule-$$"
# Payload MUST match the current create_firewall_rule_advanced tool schema:
# required = interface, rule_type, protocol, source, destination ; description is optional.
# (The old type/ipprotocol/descr keys are rejected by the tool's pydantic validation.)
WJSON="{\"interface\":\"lan\",\"rule_type\":\"pass\",\"protocol\":\"tcp\",\"source\":\"any\",\"destination\":\"any\",\"description\":\"${RULE_DESC}\"}"
PASS=0; FAIL=0
oc() { command oc --kubeconfig "$KC" "$@"; }
ok()  { echo "  ✅ $*"; PASS=$((PASS+1)); }
bad() { echo "  ❌ $*"; FAIL=$((FAIL+1)); }
step(){ echo; echo "== $* =="; }
# mcp-call lives on PATH in the agent container (/opt/ztp/bin); pass args directly (no shell re-parse).
# exec_retry: the ocp-dev control plane flaps; transient `oc exec` failures (command terminated /
# unable to upgrade connection / error dialing backend) are retried up to 3x so a flake is not a FAIL.
exec_retry() {
  local n=0 out
  while :; do
    out="$(oc "$@" 2>&1)"
    if echo "$out" | grep -qiE 'command terminated|unable to upgrade connection|error dialing backend|Timeout occurred|TLS handshake'; then
      if [ "$n" -lt 3 ]; then n=$((n+1)); sleep 3; continue; fi
    fi
    printf '%s\n' "$out"; return 0
  done
}
mcpc() { exec_retry -n agent-sandbox exec "$HPOD" -c agent -- mcp-call "$@"; }   # reads: safe to retry (idempotent)
# Writes must NOT auto-retry: if the create succeeds server-side but `oc exec` drops, a retry would
# create a DUPLICATE rule. Single attempt; STEP 4's read-back is the source of truth for "did it land".
mcpc_jit() { oc -n agent-sandbox exec "$HPOD" -c agent -- env JIT_SESSION_JWT="$1" mcp-call "${@:2}" 2>&1; }
# Vault via in-pod exec (NOT port-forward). $VT (root token) is resolved in Preconditions below.
#   vault_exec CMD          — run a read-only vault CMD inside vault-0 (no stdin)
#   vault_put  PATH-SUFFIX  — KV write at secret/<suffix>, data object read from stdin as JSON
#                             (keeps numeric version/ttl as integers, which ext-proc requires)
vault_exec() { oc -n vault exec vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='${VT}' $1" 2>/dev/null; }
vault_put()  { oc -n vault exec -i vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='${VT}' vault kv put -mount=secret $1 -" 2>/dev/null; }

step "Preconditions (the six bring-up fixes)"
oc whoami >/dev/null 2>&1 && ok "cluster reachable ($(oc whoami))" || { bad "cannot reach ocp-dev (oc login first)"; exit 1; }
[ "$(oc get clusterspiffeid agent-sandbox-e2e-harness -o jsonpath='{.spec.className}' 2>/dev/null)" = "zero-trust-workload-identity-manager-spire" ] \
  && ok "e2e-harness CSID className set (UUID SVID issues)" || bad "CSID className empty -> UUID /sandbox/ SVID won't issue (fix1)"
VT="$(oc -n vault get secret vault-init -o jsonpath='{.data.root_token}' 2>/dev/null | base64 -d)"
[ -n "$VT" ] && ok "vault-init root token resolved" || bad "no vault-init secret (Vault not bootstrapped?)"
# in-pod read (no port-forward): a present mcp-tokens-write proves the elevated-write token is seeded.
vault_exec "vault kv get -mount=secret mcp-tools/mcp-tokens-write" >/dev/null 2>&1 \
  && ok "secret/mcp-tools/mcp-tokens-write present (elevated-write token, fix6)" || bad "mcp-tokens-write missing (fix6)"

step "Ensure e2e-harness pod (the SVID-only caller)"
HPOD="$(oc -n agent-sandbox get pods -l app=e2e-harness --field-selector=status.phase=Running -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null)"
if [ -z "$HPOD" ]; then
  oc apply -k services/agent-sandbox/e2e-harness >/dev/null 2>&1
  oc -n agent-sandbox wait --for=condition=Ready pod -l app=e2e-harness --timeout=180s >/dev/null 2>&1
  HPOD="$(oc -n agent-sandbox get pods -l app=e2e-harness --field-selector=status.phase=Running -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null)"
fi
[ -n "$HPOD" ] && ok "harness pod: $HPOD" || { bad "no running harness pod"; exit 1; }

step "Write read-only consent grant (numeric typed + created, fix4)"
NONCE=$(openssl rand -hex 16); NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# stdin JSON keeps numeric version/ttl as integers (ext-proc grant validation requires numeric types).
printf '%s' "{\"version\":1,\"sandbox_uid\":\"${SB}\",\"user\":\"arsalan\",\"scope\":\"read-only\",\"ttl\":3600,\"nonce\":\"${NONCE}\",\"created\":\"${NOW}\"}" \
  | vault_put "sandbox-grants/${SB}" | grep -q 'Secret Path' \
  && ok "grant written (user=arsalan, read-only)" || bad "grant write failed"

step "STEP 1 — delegated READ (expect 200)"
R1=$(mcpc search_firewall_rules)
if echo "$R1" | grep -qiE 'malformed|scope_denied|denied'; then bad "READ blocked: $(echo "$R1" | grep -iE 'HTTP|denied|malformed' | head -1)"
elif echo "$R1" | grep -qiE '"descr"|"tracker"|result|rules'; then ok "READ 200 — pfSense rules returned (delegated as arsalan)"
else bad "READ unexpected: $(echo "$R1" | tail -2 | head -c 160)"; fi

step "STEP 2 — WRITE without elevation (expect 403 grant_scope_denied)"
R2=$(mcpc create_firewall_rule_advanced "$WJSON")
echo "$R2" | grep -qiE 'grant_scope_denied|403|denied' && ok "WRITE 403 grant_scope_denied (fail-closed)" || bad "WRITE was NOT denied (gate broken!): $(echo "$R2" | tail -1 | head -c 160)"

step "STEP 3 — request + mint capability (approver != requester)"
# NOTE: curl uses -k — the *.apps.ocp-dev route edge cert is self-signed (regenerated during
# cluster churn); without -k curl exits 0/http=000 (SSL verify failure, NOT a route outage).
REQ=$(curl -sSk -w '\n%{http_code}' -H 'Content-Type: application/json' -X POST "$JIT_API/requests" -d "{
  \"agent_spiffe_id\":\"${AGENT_SPIFFE}\",\"requester_sub\":\"agent-e2e\",
  \"namespace\":\"agentic-mcp\",\"verbs\":[\"create\"],\"resources\":[\"firewall\"],
  \"duration_minutes\":10,\"justification\":\"regression anchor pfSense write elevation\"}" 2>/dev/null)
RCODE=$(echo "$REQ" | tail -1); RBODY=$(echo "$REQ" | sed '$d')
RID=$(echo "$RBODY" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))' 2>/dev/null)
[ -n "$RID" ] && ok "request filed: id=$RID (http $RCODE)" || bad "POST /requests http=$RCODE body=$(echo "$RBODY" | head -c 160)"
CTOK=$(oc create token approval-console -n mcp-gateway --duration=10m 2>/dev/null)
# mint requires scope_hash (L1 scope-gate): the canonical SHA-256 over the reviewed scope
# fields (jit_approver.models.canonical_scope_hash). The approver presents it to prove they
# minted the EXACT scope they reviewed. Must match the filed request's fields verbatim.
SCOPE_HASH=$(python3 -c 'import json,hashlib;c={"namespace":"agentic-mcp","verbs":sorted(["create"]),"resources":sorted(["firewall"]),"duration_minutes":10,"sandbox":None,"policy_delta":[]};print(hashlib.sha256(json.dumps(c,sort_keys=True,separators=(",",":")).encode()).hexdigest())')
MC=$(curl -sSk -w '\n%{http_code}' -H 'Content-Type: application/json' -H "X-Console-SA-Token: ${CTOK}" \
  -X POST "$JIT_API/requests/${RID}/mint" -d "{\"approver_sub\":\"arsalan-approver\",\"scope_hash\":\"${SCOPE_HASH}\"}" 2>/dev/null)
echo "$MC" | tail -1 | grep -qE '^20' && ok "minted (approver=arsalan-approver != requester=agent-e2e — SoD)" || bad "POST /mint http=$(echo "$MC" | tail -1) body=$(echo "$MC" | sed '$d' | head -c 160)"
SJWT=$(curl -sSk "$JIT_API/requests/${RID}/status" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("session_jwt",""))' 2>/dev/null)
[ -n "$SJWT" ] && ok "capability JWT issued" || bad "no session_jwt from /status"

step "STEP 4 — elevated WRITE with capability (expect a REAL rule, not just HTTP 200)"
# NB: the MCP transport returns 'HTTP 200' even when the TOOL CALL fails (isError:true) — so we must
# inspect the tool RESULT, not the transport code. A real creation echoes the rule (tracker/id/descr);
# a schema/permission failure carries isError:true / 'validation error' / a grant_* denial.
if [ -n "$SJWT" ]; then
  R4=$(mcpc_jit "$SJWT" create_firewall_rule_advanced "$WJSON")
  if echo "$R4" | grep -qiE '"isError"[[:space:]]*:[[:space:]]*true|validation error|missing_argument|grant_[a-z_]+|denied|forbidden'; then
    bad "elevated write reached the tool but was REJECTED: $(echo "$R4" | grep -oiE '[0-9]+ validation error[s]?|grant_[a-z_]+|isError[^,]*true' | head -1)"
  # Source of truth = the rule is visible on the delegated read path (filtered, so pagination can't
  # hide the high-tracker new rule). This holds even if the write's oc-exec dropped after creating it.
  elif mcpc search_firewall_rules "{\"search_description\":\"${RULE_DESC}\",\"page_size\":200}" | grep -q "${RULE_DESC}"; then
    ok "ELEVATED WRITE — real pfSense rule created AND visible on delegated read-back (${RULE_DESC})"
  else
    bad "elevated write produced no visible rule '${RULE_DESC}': $(echo "$R4" | tail -2 | head -c 200)"
  fi
else bad "skipped (no capability JWT)"; fi

step "Cleanup"
echo "  (remove test rule '${RULE_DESC}' via console-approved delete or pfSense UI if it persists)"
echo; echo "================ RESULT: ${PASS} passed / ${FAIL} failed ================"
[ "$FAIL" -eq 0 ] && { echo "E2E_RESULT: PASS"; exit 0; } || { echo "E2E_RESULT: FAIL"; exit 1; }
