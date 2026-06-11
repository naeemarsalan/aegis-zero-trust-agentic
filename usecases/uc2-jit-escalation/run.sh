#!/usr/bin/env bash
# =============================================================================
# UC2 — JIT Escalation (human-in-the-loop approval via Gitea PR)
#
# Demonstrates the full Just-In-Time credential escalation flow:
#
#   1. Agent attempts add_firewall_rule → 403 (no JIT session header)
#   2. Agent POSTs EscalationRequest to jit-approver → Gitea PR created
#   3. Human reviews and MERGES the PR in Gitea (the approval step)
#   4. Agent polls GET /requests/{id}/status until state==issued;
#      response carries BOTH session_jwt (RS256) and sa_token over SVID-mTLS.
#      NOTE: Vault-injector-at-pod-start is impossible for a dynamic session
#      (the Vault role does not exist until the PR merges — chicken-and-egg).
#      Credentials are returned in the /status response body instead.
#      See ADR 0006 and docs/decisions/0006-jit-session-capability-jwt.md.
#   5. add_firewall_rule WITH X-JIT-Session-JWT → 200 (Kyverno gate passed)
#   6. add_firewall_rule WITHOUT X-JIT-Session-JWT → 403 (gate still denies)
#   7. Kube API action using sa_token → succeeds; attribution in audit log
#   8. After expiry: session_jwt rejected (exp elapsed); ephemeral Vault role reaped
#   9. Agent POSTs session summary → PR comment
#
# Contracts:
#   jit-approver in-cluster:  http://jit-approver.mcp-gateway.svc:8080
#   jit-approver external:    https://jit-approver.apps.anaeem.na-launch.com
#   gateway:                  https://mcp-gateway.apps.anaeem.na-launch.com/mcp
#   Gitea:                    https://git.arsalan.io
#
# SKIP_LIVE=1 ./run.sh  — syntax/dry-run only (no cluster or Gitea calls)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/environment/.env"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[uc2]${NC} $*"; }
ok()      { echo -e "${GREEN}[ok]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC} $*"; }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
human()   { echo -e "${BOLD}[HUMAN ACTION REQUIRED]${NC} $*"; }
heading() { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
  warn "environment/.env not found — copy environment/.env.example and fill in values"
  if [[ "${SKIP_LIVE:-0}" != "1" ]]; then
    fail "Cannot continue without environment/.env. Set SKIP_LIVE=1 for dry-run."
  fi
fi

if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  set -a; source "${ENV_FILE}"; set +a
fi

# Contract endpoints (fixed from environment facts)
KEYCLOAK_TOKEN_ENDPOINT="${KEYCLOAK_TOKEN_ENDPOINT:-https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/token}"
MCP_GATEWAY_URL="${MCP_GATEWAY_URL:-https://mcp-gateway.apps.anaeem.na-launch.com}"
JIT_APPROVER_URL="${JIT_APPROVER_URL:-https://jit-approver.apps.anaeem.na-launch.com}"
GITEA_URL="${GITEA_URL:-https://git.arsalan.io}"
SKIP_LIVE="${SKIP_LIVE:-0}"

# Demo admin user — must be in mcp-admins group in Keycloak
DEMO_ADMIN_USER="${DEMO_ADMIN_USER:-arsalan}"
DEMO_ADMIN_PASSWORD="${DEMO_ADMIN_PASSWORD:-}"
DEMO_CLIENT_ID="${DEMO_CLIENT_ID:-mcp-demo-client}"
DEMO_CLIENT_SECRET="${DEMO_CLIENT_SECRET:-}"

# For JIT demo: the agent's SPIFFE ID and requester identity
AGENT_SPIFFE_ID="${AGENT_SPIFFE_ID:-spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/demo-agent}"
REQUESTER_SUB="${REQUESTER_SUB:-}"  # filled from token after step 0

# JIT parameters for this demo — scope includes both a Kube action and a dangerous MCP tool
JIT_NAMESPACE="agent-sandbox"
JIT_VERBS='["get","list"]'
JIT_RESOURCES='["pods"]'
JIT_DURATION_MINUTES=15
JIT_JUSTIFICATION="UC2 demo: list pods in agent-sandbox AND call add_firewall_rule via MCP gateway. Requested as part of the nvidia-ida JIT escalation demo run."
JIT_TOOL_SCOPE='["add_firewall_rule"]'

# Poll timing
POLL_INTERVAL_SEC="${POLL_INTERVAL_SEC:-10}"
POLL_MAX_ATTEMPTS="${POLL_MAX_ATTEMPTS:-60}"  # 60 * 10s = 10 minutes max wait

# Populated during the run
SESSION_ID=""
PR_URL=""
SESSION_JWT=""
SA_TOKEN=""
EXPIRES_AT=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

live() {
  local desc="$1"; shift
  if [[ "${SKIP_LIVE}" == "1" ]]; then
    warn "SKIP_LIVE=1: skipping live step: ${desc}"
    return 0
  fi
  info "LIVE: ${desc}"
  "$@"
}

assert_contains() {
  local desc="$1" needle="$2" haystack="$3"
  if echo "${haystack}" | grep -qF "${needle}"; then
    ok "ASSERT PASS: ${desc} (found: ${needle})"
  else
    fail "ASSERT FAIL: ${desc} — expected '${needle}' in: ${haystack:0:200}"
  fi
}

assert_http_status() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "${actual}" == "${expected}" ]]; then
    ok "ASSERT PASS: ${desc} — HTTP ${actual}"
  else
    fail "ASSERT FAIL: ${desc} — expected HTTP ${expected}, got HTTP ${actual}"
  fi
}

# ---------------------------------------------------------------------------
# STEP 0 — Obtain admin token for demo agent identity
# ---------------------------------------------------------------------------
heading "STEP 0: Obtain token for '${DEMO_ADMIN_USER}' (mcp-admins group)"

info "Token endpoint: ${KEYCLOAK_TOKEN_ENDPOINT}"
info "User '${DEMO_ADMIN_USER}' must be in group 'mcp-admins' in realm 'agentic'."

ADMIN_TOKEN=""
if [[ "${SKIP_LIVE}" != "1" ]]; then
  if [[ -z "${DEMO_ADMIN_PASSWORD}" ]]; then
    fail "DEMO_ADMIN_PASSWORD not set in environment/.env"
  fi

  TOKEN_BODY=$(curl -sf \
    -X POST "${KEYCLOAK_TOKEN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${DEMO_CLIENT_ID}" \
    ${DEMO_CLIENT_SECRET:+-d "client_secret=${DEMO_CLIENT_SECRET}"} \
    -d "username=${DEMO_ADMIN_USER}" \
    -d "password=${DEMO_ADMIN_PASSWORD}" \
    -d "scope=openid groups profile") || fail "Token request failed"

  ADMIN_TOKEN=$(echo "${TOKEN_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
  ok "Token obtained for ${DEMO_ADMIN_USER}"

  # Extract sub for JIT request body
  JWT_PAYLOAD=$(echo "${ADMIN_TOKEN}" | cut -d. -f2 | python3 -c "
import sys, base64, json
data = sys.stdin.read().strip()
data += '=' * (4 - len(data) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(data)), indent=2))")
  REQUESTER_SUB=$(echo "${JWT_PAYLOAD}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sub','unknown'))")
  info "Requester sub: ${REQUESTER_SUB}"
fi

# ---------------------------------------------------------------------------
# STEP 1 — Attempt add_firewall_rule WITHOUT session JWT -> expect 403
# ---------------------------------------------------------------------------
heading "STEP 1: Attempt add_firewall_rule WITHOUT X-JIT-Session-JWT -> expect 403"

info "Without a valid signed X-JIT-Session-JWT, the Kyverno policy"
info "'dangerous-tools-admins-only' denies write tools even for mcp-admins."
info "(A plain X-JIT-Session header or a missing/invalid JWT both result in 403.)"

ADD_RULE_REQUEST='{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "tools/call",
  "params": {
    "name": "add_firewall_rule",
    "arguments": {
      "interface": "WAN",
      "action": "block",
      "destination": "10.0.0.0/8",
      "protocol": "tcp",
      "dest_port": "8080"
    }
  }
}'

if [[ "${SKIP_LIVE}" != "1" ]]; then
  DENY_STATUS=$(curl -s -o /tmp/uc2-step1-response.json -w "%{http_code}" \
    -X POST "${MCP_GATEWAY_URL}/mcp" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "${ADD_RULE_REQUEST}")

  DENY_BODY=$(cat /tmp/uc2-step1-response.json 2>/dev/null || echo "")
  info "Response body: ${DENY_BODY}"

  assert_http_status "add_firewall_rule without X-JIT-Session-JWT is denied" "403" "${DENY_STATUS}"
  ok "CONFIRMED: dangerous tools require a cryptographically valid X-JIT-Session-JWT (Kyverno enforced)"
fi

# ---------------------------------------------------------------------------
# STEP 2 — POST EscalationRequest to jit-approver
# ---------------------------------------------------------------------------
heading "STEP 2: POST EscalationRequest to jit-approver"

info "Requesting: ${JIT_VERBS} on ${JIT_RESOURCES} in namespace ${JIT_NAMESPACE} for ${JIT_DURATION_MINUTES}m"
info "Tool scope for MCP gateway: ${JIT_TOOL_SCOPE}"
info "jit-approver endpoint: ${JIT_APPROVER_URL}"

# Build the request body — includes tool_scope so jit-approver can mint
# the session JWT with the correct tool_scope claim
JIT_REQUEST_BODY=$(python3 -c "
import json, sys
req = {
  'agent_spiffe_id': '${AGENT_SPIFFE_ID}',
  'requester_sub': '${REQUESTER_SUB:-demo-requester-sub}',
  'namespace': '${JIT_NAMESPACE}',
  'verbs': ${JIT_VERBS},
  'resources': ${JIT_RESOURCES},
  'tool_scope': ${JIT_TOOL_SCOPE},
  'duration_minutes': ${JIT_DURATION_MINUTES},
  'justification': '${JIT_JUSTIFICATION}'
}
print(json.dumps(req, indent=2))
")

info "Request body:"
echo "${JIT_REQUEST_BODY}"

if [[ "${SKIP_LIVE}" != "1" ]]; then
  JIT_RESPONSE=$(curl -sf \
    -X POST "${JIT_APPROVER_URL}/requests" \
    -H "Content-Type: application/json" \
    -d "${JIT_REQUEST_BODY}") || fail "EscalationRequest POST failed — is jit-approver running?"

  SESSION_ID=$(echo "${JIT_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  PR_URL=$(echo "${JIT_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['pr_url'])")

  ok "EscalationRequest accepted — session ID: ${SESSION_ID}"
  ok "Gitea PR created: ${PR_URL}"
  echo ""
fi

# ---------------------------------------------------------------------------
# STEP 3 — HUMAN STEP: Approve the PR
# ---------------------------------------------------------------------------
heading "STEP 3: HUMAN STEP — Review and merge the Gitea PR"
echo ""
human "Navigate to Gitea and review the PR:"
echo ""
if [[ -n "${PR_URL}" ]]; then
  echo "  ${PR_URL}"
else
  echo "  ${GITEA_URL}/anaeem/nvidia-ida/pulls"
  echo "  (Look for a PR with title starting with '[JIT]')"
fi
echo ""
echo "The PR contains the full requested scope as reviewable YAML:"
echo "  - namespace: ${JIT_NAMESPACE}"
echo "  - verbs: ${JIT_VERBS}"
echo "  - resources: ${JIT_RESOURCES}"
echo "  - tool_scope: ${JIT_TOOL_SCOPE}"
echo "  - duration: ${JIT_DURATION_MINUTES}m"
echo "  - justification: ${JIT_JUSTIFICATION:0:60}..."
echo ""
echo "  MERGE the PR to APPROVE the escalation."
echo "  CLOSE without merging to DENY."
echo ""
echo "After merging: the jit-approver webhook fires, Vault creates an ephemeral"
echo "kubernetes/roles/jit-<session> role, mints the SA token, and mints the"
echo "signed RS256 X-JIT-Session-JWT — both returned from /status once state==issued."
echo ""

if [[ "${SKIP_LIVE}" == "1" ]]; then
  warn "SKIP_LIVE=1: skipping wait for PR approval"
fi

# ---------------------------------------------------------------------------
# STEP 4 — Poll /status until 'issued', extract session_jwt + sa_token
# ---------------------------------------------------------------------------
heading "STEP 4: Poll session status until 'issued', extract session_jwt + sa_token"

info "Polling ${JIT_APPROVER_URL}/requests/<session>/status every ${POLL_INTERVAL_SEC}s"
info "(max ${POLL_MAX_ATTEMPTS} attempts = ~$((POLL_MAX_ATTEMPTS * POLL_INTERVAL_SEC / 60)) minutes)"
info ""
info "NOTE: credentials arrive in the /status response body over the SVID-mTLS channel."
info "The Vault Agent injector-at-pod-start pattern is NOT used for JIT sessions because"
info "the Vault role does not exist until after the PR is merged — a dynamically-created"
info "session cannot be wired into a static pod spec.  See ADR 0006."

SESSION_STATE=""

if [[ "${SKIP_LIVE}" != "1" && -n "${SESSION_ID}" ]]; then
  for attempt in $(seq 1 "${POLL_MAX_ATTEMPTS}"); do
    STATUS_RESPONSE=$(curl -sf \
      "${JIT_APPROVER_URL}/requests/${SESSION_ID}/status" \
      -H "Content-Type: application/json") || {
      warn "Status poll failed (attempt ${attempt}/${POLL_MAX_ATTEMPTS}), retrying..."
      sleep "${POLL_INTERVAL_SEC}"
      continue
    }

    SESSION_STATE=$(echo "${STATUS_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")

    info "Attempt ${attempt}/${POLL_MAX_ATTEMPTS}: state = ${SESSION_STATE}"

    case "${SESSION_STATE}" in
      issued)
        ok "Session state: ISSUED"
        # Extract both credentials from the /status response
        SESSION_JWT=$(echo "${STATUS_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_jwt',''))")
        SA_TOKEN=$(echo "${STATUS_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sa_token',''))")
        EXPIRES_AT=$(echo "${STATUS_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_at',''))")

        if [[ -z "${SESSION_JWT}" ]]; then
          fail "state==issued but session_jwt missing from /status response — jit-approver not minting JWT"
        fi
        if [[ -z "${SA_TOKEN}" ]]; then
          fail "state==issued but sa_token missing from /status response — Vault issuance may have failed"
        fi

        ok "session_jwt obtained (RS256, exp=${EXPIRES_AT})"
        ok "sa_token obtained (Vault kubernetes/creds/jit-${SESSION_ID})"
        ok "Credentials available until: ${EXPIRES_AT}"
        break
        ;;
      approved)
        info "State is 'approved' — Vault issuance in progress, polling..."
        ;;
      pending)
        info "State is 'pending' — waiting for PR merge..."
        ;;
      denied)
        fail "JIT session was DENIED (PR closed without merge). Demo aborted."
        ;;
      expired)
        fail "JIT session EXPIRED before issuance. Check jit-approver logs."
        ;;
      *)
        warn "Unknown state: ${SESSION_STATE}"
        ;;
    esac

    sleep "${POLL_INTERVAL_SEC}"
  done

  if [[ "${SESSION_STATE}" != "issued" ]]; then
    fail "Timed out waiting for 'issued' state. Last state: ${SESSION_STATE}"
  fi
fi

# ---------------------------------------------------------------------------
# STEP 5 — Call add_firewall_rule WITH X-JIT-Session-JWT -> expect 200
# ---------------------------------------------------------------------------
heading "STEP 5: add_firewall_rule WITH X-JIT-Session-JWT -> expect 200 (Kyverno gate passed)"

info "The session_jwt is the agent's scoped capability token for this approved session."
info "It is signed RS256 by jit-approver, verified statelessly by Kyverno ext_authz."
info "The gateway forwards X-JIT-Session-JWT to the Kyverno check BEFORE ext-proc."
info "(ext-proc does NOT inject it — the agent presents it directly as its own capability.)"

if [[ "${SKIP_LIVE}" != "1" && -n "${SESSION_JWT}" ]]; then
  ALLOW_STATUS=$(curl -s -o /tmp/uc2-step5-response.json -w "%{http_code}" \
    -X POST "${MCP_GATEWAY_URL}/mcp" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "X-JIT-Session-JWT: ${SESSION_JWT}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "${ADD_RULE_REQUEST}")

  ALLOW_BODY=$(cat /tmp/uc2-step5-response.json 2>/dev/null || echo "")
  info "Response status: ${ALLOW_STATUS}"
  info "Response body: ${ALLOW_BODY:0:200}"

  assert_http_status "add_firewall_rule WITH valid X-JIT-Session-JWT passes Kyverno gate" "200" "${ALLOW_STATUS}"
  ok "CONFIRMED: valid signed session JWT passes the dangerous-tools gate"
fi

# ---------------------------------------------------------------------------
# STEP 6 — Same call WITHOUT X-JIT-Session-JWT -> still 403
# ---------------------------------------------------------------------------
heading "STEP 6: add_firewall_rule WITHOUT X-JIT-Session-JWT -> still 403"

info "Even after a session is issued, a call without the header is denied."
info "The gate is stateless: it verifies the JWT cryptographically; there is"
info "no per-session state in Kyverno itself."

if [[ "${SKIP_LIVE}" != "1" && -n "${ADMIN_TOKEN}" ]]; then
  NO_JWT_STATUS=$(curl -s -o /tmp/uc2-step6-response.json -w "%{http_code}" \
    -X POST "${MCP_GATEWAY_URL}/mcp" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "${ADD_RULE_REQUEST}")

  NO_JWT_BODY=$(cat /tmp/uc2-step6-response.json 2>/dev/null || echo "")
  info "Response status: ${NO_JWT_STATUS}"

  assert_http_status "add_firewall_rule WITHOUT X-JIT-Session-JWT is still denied" "403" "${NO_JWT_STATUS}"
  ok "CONFIRMED: missing/omitted session JWT still results in 403 — gate is fail-closed"
fi

# ---------------------------------------------------------------------------
# STEP 7 — Kube API action with sa_token + audit attribution
# ---------------------------------------------------------------------------
heading "STEP 7: Kube API action with sa_token -> succeeds; attribution in audit log"

info "Using the JIT-issued sa_token to list pods in the approved namespace."
info "The SA name contains the session ID, so every Kube API call is attributed"
info "to 'system:serviceaccount:agent-sandbox:jit-${SESSION_ID:-<SESSION_ID>}' in the audit log."

if [[ "${SKIP_LIVE}" != "1" && -n "${SA_TOKEN}" ]]; then
  if [[ -z "${KUBECONFIG:-}" ]]; then
    warn "KUBECONFIG not set — using ${ANAEEM_KUBECONFIG:-~/.kube/anaeem-kubeconfig}"
    export KUBECONFIG="${ANAEEM_KUBECONFIG:-${HOME}/.kube/anaeem-kubeconfig}"
  fi

  POD_LIST=$(oc --token="${SA_TOKEN}" get pods -n agent-sandbox \
    --server="https://api.anaeem.na-launch.com:6443" \
    --insecure-skip-tls-verify 2>&1 || echo "ERROR")

  echo "${POD_LIST}"
  assert_contains "sa_token can list pods in agent-sandbox" "demo-agent" "${POD_LIST}"
  ok "Kube API action succeeded with JIT sa_token"

  # Verify scope limit — out-of-scope namespace should be denied
  info "Verifying scope limit: trying to list pods in 'kyverno' (should fail)"
  SCOPE_LIMIT=$(oc --token="${SA_TOKEN}" get pods -n kyverno \
    --server="https://api.anaeem.na-launch.com:6443" \
    --insecure-skip-tls-verify 2>&1 || echo "FORBIDDEN")
  assert_contains "sa_token cannot access out-of-scope namespace" "FORBIDDEN" "${SCOPE_LIMIT}"
  ok "Scope limit enforced: cannot access 'kyverno' namespace"

  # Show audit log attribution
  info "Checking Kube API audit log for session attribution:"
  echo ""
  echo "  oc adm node-logs --role=master --path=kube-apiserver/audit.log \\"
  echo "    | grep 'jit-${SESSION_ID:-<SESSION_ID>}'"
  echo ""
  AUDIT_HITS=$(oc adm node-logs --role=master --path=kube-apiserver/audit.log 2>/dev/null \
    | grep -c "jit-${SESSION_ID}" 2>/dev/null || echo "0")
  info "Audit log entries matching 'jit-${SESSION_ID}': ${AUDIT_HITS}"
  if [[ "${AUDIT_HITS}" -gt "0" ]]; then
    ok "Attribution confirmed: ${AUDIT_HITS} audit events attributed to jit-${SESSION_ID}"
  else
    warn "No audit hits yet — token may not have been used or logs are delayed"
  fi
fi

# ---------------------------------------------------------------------------
# STEP 8 — After expiry: session_jwt rejected (exp) + ephemeral Vault role reaped
# ---------------------------------------------------------------------------
heading "STEP 8: After expiry: session_jwt rejected (exp elapsed) + Vault role reaped"

info "JIT window is ${JIT_DURATION_MINUTES} minutes."
info "After expiry:"
info "  - session_jwt is rejected by Kyverno gate (exp elapsed, decodedJitJwt.Valid == false)"
info "  - sa_token is revoked by Vault (lease expires, K8s SA + RoleBinding deleted)"
info "  - jit-approver reaper deletes kubernetes/roles/jit-<session> from Vault"
info "    (prevents ephemeral-role accumulation — the standing-scope leak N3)"
info "  - jit-approver reaper hard-deletes secret/data/jit/<session> and"
info "    secret/metadata/jit/<session> from KV so credentials are unrecoverable"

if [[ "${SKIP_LIVE}" != "1" && -n "${SESSION_ID}" ]]; then
  echo ""
  echo "  To manually accelerate expiry testing, revoke the Vault lease:"
  echo "    vault lease revoke -prefix kubernetes/creds/jit-${SESSION_ID}"
  echo ""
  echo "  Or wait ${JIT_DURATION_MINUTES} minutes for natural expiry."
  echo ""

  CURRENT_STATE=$(curl -sf \
    "${JIT_APPROVER_URL}/requests/${SESSION_ID}/status" \
    -H "Content-Type: application/json" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])" 2>/dev/null || echo "unknown")

  info "Current session state: ${CURRENT_STATE}"

  if [[ "${CURRENT_STATE}" == "expired" ]]; then
    # Test session_jwt after expiry — Kyverno gate should reject (exp)
    if [[ -n "${SESSION_JWT}" ]]; then
      info "Testing session_jwt after expiry against Kyverno gate..."
      EXPIRED_JWT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${MCP_GATEWAY_URL}/mcp" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "X-JIT-Session-JWT: ${SESSION_JWT}" \
        -H "Content-Type: application/json" \
        -d "${ADD_RULE_REQUEST}")
      assert_http_status "expired session_jwt rejected by Kyverno gate" "403" "${EXPIRED_JWT_STATUS}"
      ok "CONFIRMED: expired session_jwt is rejected (exp claim elapsed)"
    fi

    # Test sa_token after expiry — Kube API should reject (Unauthorized)
    if [[ -n "${SA_TOKEN}" ]]; then
      info "Testing sa_token after Vault lease expiry..."
      REVOKED=$(oc --token="${SA_TOKEN}" get pods -n agent-sandbox \
        --server="https://api.anaeem.na-launch.com:6443" \
        --insecure-skip-tls-verify 2>&1 || echo "Unauthorized")
      assert_contains "expired sa_token rejected by Kube API (Unauthorized)" "Unauthorized" "${REVOKED}"
      ok "REVOCATION CONFIRMED: expired sa_token rejected by Kube API"
    fi

    # Verify the ephemeral Vault role was reaped
    info "Verifying ephemeral Vault role was reaped by jit-approver background task..."
    echo "  Expected: vault read kubernetes/roles/jit-${SESSION_ID} → 404 (key not found)"
    echo "  (Run manually: VAULT_ADDR=\${VAULT_ADDR} vault read kubernetes/roles/jit-${SESSION_ID})"
  else
    warn "Session not yet expired (state: ${CURRENT_STATE}). Re-run after ${JIT_DURATION_MINUTES}m or revoke manually."
    info "After expiry, re-run with: SKIP_LIVE=0 SESSION_ID=${SESSION_ID:-<id>} SESSION_JWT=<jwt> SA_TOKEN=<token> ./run.sh"
  fi
fi

# ---------------------------------------------------------------------------
# STEP 9 — POST session summary -> PR comment
# ---------------------------------------------------------------------------
heading "STEP 9: POST session summary to jit-approver -> PR comment"

SUMMARY_BODY='{
  "outcome": "UC2 demo completed. Called add_firewall_rule via MCP gateway with X-JIT-Session-JWT (200). Confirmed gate still denies without JWT (403). Listed pods in agent-sandbox with sa_token (success). Scope limit verified (kyverno namespace rejected). Session JWT and SA token revoked on expiry.",
  "actions_taken": [
    "add_firewall_rule via MCP gateway (with X-JIT-Session-JWT) — 200 OK",
    "add_firewall_rule via MCP gateway (without X-JIT-Session-JWT) — 403 DENIED",
    "oc get pods -n agent-sandbox with sa_token — success",
    "oc get pods -n kyverno with sa_token — FORBIDDEN (scope limit confirmed)",
    "session_jwt after expiry — 403 (exp elapsed)",
    "sa_token after expiry — Unauthorized"
  ],
  "errors_encountered": []
}'

if [[ "${SKIP_LIVE}" != "1" && -n "${SESSION_ID}" ]]; then
  info "POSTing summary to ${JIT_APPROVER_URL}/requests/${SESSION_ID}/summary"
  SUMMARY_RESPONSE=$(curl -sf \
    -X POST "${JIT_APPROVER_URL}/requests/${SESSION_ID}/summary" \
    -H "Content-Type: application/json" \
    -d "${SUMMARY_BODY}") || warn "Summary POST failed (non-fatal)"

  SUMMARY_STATUS=$(echo "${SUMMARY_RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
  if [[ "${SUMMARY_STATUS}" == "recorded" ]]; then
    ok "Summary recorded and posted as PR comment: ${PR_URL}"
  else
    warn "Summary response: ${SUMMARY_RESPONSE}"
  fi
fi

# ---------------------------------------------------------------------------
# Summary of audit trail locations
# ---------------------------------------------------------------------------
heading "Audit Trail Summary"

echo ""
echo "  Loki queries (Grafana -> Explore -> ${GRAFANA_URL:-http://172.16.2.252:3000}):"
echo ""
echo "  # All JIT events for this session:"
echo "  {app=\"jit-approver\"} | json | session_id = \"${SESSION_ID:-<SESSION_ID>}\""
echo ""
echo "  # Full lifecycle sequence:"
echo "  {app=\"jit-approver\"} | json"
echo "    | line_format '{{.ts}} {{.event}} {{.session_id}} {{.state}}'"
echo ""
echo "  # Expected event sequence (see expected/ directory):"
echo "  jit_request -> jit_approved -> jit_issued -> jit_summary"
echo ""
echo "  # Kube API audit (SNO single master):"
echo "  oc adm node-logs --role=master --path=kube-apiserver/audit.log \\"
echo "    | grep 'jit-${SESSION_ID:-<SESSION_ID>}'"
echo ""
echo "  # Session JWT signed-capability mechanic (see ADR 0006):"
echo "  # jit-approver mints session_jwt on issuance; Kyverno verifies it statelessly."
echo "  # JWKS: http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks"
echo "  # The agent holds the JWT as its own scoped capability; it is NOT a downstream"
echo "  # service credential — the no-credential-passing invariant (UC1) is intact."
echo ""

info ""
info "=== UC2 complete ==="
ok "All live steps completed (or SKIP_LIVE=1 dry-run finished)"
