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
# Usage:   bash hack/test-pfsense-jit-ocp-dev.sh
# Requires: oc logged in to ocp-dev; ~/.local/bin/vault; /etc/hosts for the
#           *.apps.ocp-dev.na-launch.com routes -> ingress VIP 172.16.2.59.
set -uo pipefail

KC="${IDA_KUBECONFIG:-$HOME/.kube/ocp-dev.kubeconfig}"
TRUST_DOMAIN="${TRUST_DOMAIN:-anaeem.na-launch.com}"
SB="${SB:-e2e0a1b2-c3d4-4e5f-8a9b-000000000001}"
AGENT_SPIFFE="spiffe://${TRUST_DOMAIN}/ns/agent-sandbox/sandbox/${SB}"
JIT_API="${JIT_API:-https://jit-approver-api.apps.ocp-dev.na-launch.com}"
VPORT="${VAULT_LOCAL_PORT:-8209}"
RULE_DESC="ztp-e2e-test-rule-$$"
WJSON="{\"interface\":\"lan\",\"type\":\"pass\",\"ipprotocol\":\"inet\",\"protocol\":\"tcp\",\"source\":\"any\",\"destination\":\"any\",\"descr\":\"${RULE_DESC}\"}"
PASS=0; FAIL=0
oc() { command oc --kubeconfig "$KC" "$@"; }
ok()  { echo "  ✅ $*"; PASS=$((PASS+1)); }
bad() { echo "  ❌ $*"; FAIL=$((FAIL+1)); }
step(){ echo; echo "== $* =="; }
# mcp-call lives on PATH in the agent container (/opt/ztp/bin); pass args directly (no shell re-parse).
mcpc() { oc -n agent-sandbox exec "$HPOD" -c agent -- mcp-call "$@" 2>&1; }
mcpc_jit() { oc -n agent-sandbox exec "$HPOD" -c agent -- env JIT_SESSION_JWT="$1" mcp-call "${@:2}" 2>&1; }

step "Preconditions (the six bring-up fixes)"
oc whoami >/dev/null 2>&1 && ok "cluster reachable ($(oc whoami))" || { bad "cannot reach ocp-dev (oc login first)"; exit 1; }
[ "$(oc get clusterspiffeid agent-sandbox-e2e-harness -o jsonpath='{.spec.className}' 2>/dev/null)" = "zero-trust-workload-identity-manager-spire" ] \
  && ok "e2e-harness CSID className set (UUID SVID issues)" || bad "CSID className empty -> UUID /sandbox/ SVID won't issue (fix1)"
pkill -f "port-forward.*vault.*${VPORT}" 2>/dev/null || true
nohup oc port-forward -n vault svc/vault "${VPORT}:8200" >/tmp/vpf-anchor.log 2>&1 & PF_PID=$!; sleep 4
VADDR="http://127.0.0.1:${VPORT}"
VT="$(oc -n vault get secret vault-init -o jsonpath='{.data.root_token}' 2>/dev/null | base64 -d)"
[ -n "$VT" ] && ok "vault-init root token resolved" || bad "no vault-init secret (Vault not bootstrapped?)"
curl -fsS -H "X-Vault-Token: $VT" "$VADDR/v1/secret/data/mcp-tools/mcp-tokens-write" >/dev/null 2>&1 \
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
curl -fsS -H "X-Vault-Token: $VT" -H 'Content-Type: application/json' -X POST \
  "$VADDR/v1/secret/data/sandbox-grants/${SB}" \
  -d "{\"data\":{\"version\":1,\"sandbox_uid\":\"${SB}\",\"user\":\"arsalan\",\"scope\":\"read-only\",\"ttl\":3600,\"nonce\":\"${NONCE}\",\"created\":\"${NOW}\"}}" >/dev/null \
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
REQ=$(curl -sS -w '\n%{http_code}' -H 'Content-Type: application/json' -X POST "$JIT_API/requests" -d "{
  \"agent_spiffe_id\":\"${AGENT_SPIFFE}\",\"requester_sub\":\"agent-e2e\",
  \"namespace\":\"agentic-mcp\",\"verbs\":[\"create\"],\"resources\":[\"firewall\"],
  \"duration_minutes\":10,\"justification\":\"regression anchor pfSense write elevation\"}" 2>/dev/null)
RCODE=$(echo "$REQ" | tail -1); RBODY=$(echo "$REQ" | sed '$d')
RID=$(echo "$RBODY" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))' 2>/dev/null)
[ -n "$RID" ] && ok "request filed: id=$RID (http $RCODE)" || bad "POST /requests http=$RCODE body=$(echo "$RBODY" | head -c 160)"
CTOK=$(oc create token approval-console -n mcp-gateway --duration=10m 2>/dev/null)
MC=$(curl -sS -w '\n%{http_code}' -H 'Content-Type: application/json' -H "X-Console-SA-Token: ${CTOK}" \
  -X POST "$JIT_API/requests/${RID}/mint" -d '{"approver_sub":"arsalan-approver"}' 2>/dev/null)
echo "$MC" | tail -1 | grep -qE '^20' && ok "minted (approver=arsalan-approver != requester=agent-e2e — SoD)" || bad "POST /mint http=$(echo "$MC" | tail -1) (console SA / allowlist?)"
SJWT=$(curl -sS "$JIT_API/requests/${RID}/status" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("session_jwt",""))' 2>/dev/null)
[ -n "$SJWT" ] && ok "capability JWT issued" || bad "no session_jwt from /status"

step "STEP 4 — elevated WRITE with capability (expect 200, real rule)"
if [ -n "$SJWT" ]; then
  R4=$(mcpc_jit "$SJWT" create_firewall_rule_advanced "$WJSON")
  echo "$R4" | grep -qiE '"id"|"tracker"|created|200' && ok "ELEVATED WRITE 200 — real rule created (${RULE_DESC})" || bad "elevated write failed: $(echo "$R4" | tail -1 | head -c 160)"
else bad "skipped (no capability JWT)"; fi

step "Cleanup"
echo "  (remove test rule '${RULE_DESC}' via console-approved delete or pfSense UI if it persists)"
kill "$PF_PID" 2>/dev/null || true
echo; echo "================ RESULT: ${PASS} passed / ${FAIL} failed ================"
[ "$FAIL" -eq 0 ] && { echo "E2E_RESULT: PASS"; exit 0; } || { echo "E2E_RESULT: FAIL"; exit 1; }
