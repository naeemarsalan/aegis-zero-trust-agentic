#!/usr/bin/env bash
# =============================================================================
# UC1 — Delegated Tool Call (identity forwarding proof)
#
# Demonstrates that a call flowing through the MCP gateway arrives at the
# downstream MCP server with the END-USER's identity (arsalan), never the
# agent's. Validated via the echo-mcp server which echoes the identity it sees.
#
# Prerequisites (see README.md):
#   - environment/.env populated (KEYCLOAK_URL, MCP_GATEWAY_URL, etc.)
#   - User "arsalan" exists in Keycloak realm "agentic" with groups mcp-users
#     (for get_firewall_rules) and an echo-mcp backend registered in the gateway
#   - Cluster reachable (oc / curl via OpenShift routes)
#
# SKIP_LIVE=1 ./run.sh  — syntax/dry-run only; all live curl calls are skipped.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/environment/.env"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[uc1]${NC} $*"; }
ok()    { echo -e "${GREEN}[ok]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
  warn "environment/.env not found — copy environment/.env.example and fill in values"
  if [[ "${SKIP_LIVE:-0}" != "1" ]]; then
    fail "Cannot continue without environment/.env. Set SKIP_LIVE=1 for dry-run."
  fi
fi

# Source .env if it exists
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  set -a; source "${ENV_FILE}"; set +a
fi

# Required variables (with defaults that point at the fixed contract endpoints)
KEYCLOAK_TOKEN_ENDPOINT="${KEYCLOAK_TOKEN_ENDPOINT:-https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/token}"
MCP_GATEWAY_URL="${MCP_GATEWAY_URL:-https://mcp-gateway.apps.anaeem.na-launch.com}"
SKIP_LIVE="${SKIP_LIVE:-0}"

# Demo user credentials — sourced from .env.  In production these would come
# from a device-flow / token exchange; ROPC is used here for automation only.
DEMO_USER="${DEMO_USER:-arsalan}"
DEMO_PASSWORD="${DEMO_PASSWORD:-}"            # must be set in .env

# Client configured in Keycloak realm "agentic" with:
#   - Direct Access Grants enabled (for ROPC/automation demo)
#   - Standard Flow enabled (for real device-flow usage)
#   - audiences: mcp-gateway
#   - Client scope: openid profile groups
DEMO_CLIENT_ID="${DEMO_CLIENT_ID:-mcp-demo-client}"
# client_secret is empty if the client is public; set in .env for confidential clients
DEMO_CLIENT_SECRET="${DEMO_CLIENT_SECRET:-}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

live() {
  # Usage: live <description> <command...>
  local desc="$1"; shift
  if [[ "${SKIP_LIVE}" == "1" ]]; then
    warn "SKIP_LIVE=1: skipping live step: ${desc}"
    return 0
  fi
  info "LIVE: ${desc}"
  "$@"
}

assert_contains() {
  # assert_contains <description> <needle> <haystack>
  local desc="$1" needle="$2" haystack="$3"
  if echo "${haystack}" | grep -qF "${needle}"; then
    ok "ASSERT PASS: ${desc} (found: ${needle})"
  else
    fail "ASSERT FAIL: ${desc} — expected to find '${needle}' in response"
  fi
}

assert_http_status() {
  # assert_http_status <description> <expected_status> <actual_status>
  local desc="$1" expected="$2" actual="$3"
  if [[ "${actual}" == "${expected}" ]]; then
    ok "ASSERT PASS: ${desc} — HTTP ${actual}"
  else
    fail "ASSERT FAIL: ${desc} — expected HTTP ${expected}, got HTTP ${actual}"
  fi
}

# ---------------------------------------------------------------------------
# STEP 1 — Obtain user token via ROPC (arsalan, realm agentic)
# ---------------------------------------------------------------------------
info "=== STEP 1: Obtain user token for '${DEMO_USER}' via ROPC ==="
info "Token endpoint: ${KEYCLOAK_TOKEN_ENDPOINT}"
info "Client ID: ${DEMO_CLIENT_ID}"
info ""
info "Keycloak client requirements:"
info "  realm: agentic"
info "  clientId: ${DEMO_CLIENT_ID}"
info "  Direct Access Grants: ENABLED"
info "  audiences mapper: mcp-gateway"
info "  scope: openid groups profile"
info ""
info "Alternative (device flow — production-preferred):"
info "  POST ${KEYCLOAK_TOKEN_ENDPOINT/token/auth/device}"
info "  Then poll ${KEYCLOAK_TOKEN_ENDPOINT} with device_code"

USER_TOKEN=""

if [[ "${SKIP_LIVE}" != "1" ]]; then
  if [[ -z "${DEMO_PASSWORD}" ]]; then
    fail "DEMO_PASSWORD not set in environment/.env (required for ROPC token request)"
  fi

  TOKEN_BODY=$(curl -sf \
    -X POST "${KEYCLOAK_TOKEN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${DEMO_CLIENT_ID}" \
    ${DEMO_CLIENT_SECRET:+-d "client_secret=${DEMO_CLIENT_SECRET}"} \
    -d "username=${DEMO_USER}" \
    -d "password=${DEMO_PASSWORD}" \
    -d "scope=openid groups profile") || fail "Token request failed — check DEMO_PASSWORD and client config"

  USER_TOKEN=$(echo "${TOKEN_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
  ok "Token obtained for ${DEMO_USER} (truncated): ${USER_TOKEN:0:60}..."

  # Decode and display claims (for audit trail)
  JWT_PAYLOAD=$(echo "${USER_TOKEN}" | cut -d. -f2 | base64 -d 2>/dev/null || \
                echo "${USER_TOKEN}" | cut -d. -f2 | python3 -c "
import sys, base64, json
data = sys.stdin.read().strip()
# add padding
data += '=' * (4 - len(data) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(data)), indent=2))")
  info "JWT claims:"
  echo "${JWT_PAYLOAD}"
fi

# ---------------------------------------------------------------------------
# STEP 2 — MCP initialize (session handshake)
# ---------------------------------------------------------------------------
info ""
info "=== STEP 2: MCP initialize (session handshake) ==="

MCP_ENDPOINT="${MCP_GATEWAY_URL}/mcp"

INIT_REQUEST='{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "uc1-demo-client", "version": "1.0"}
  }
}'

INIT_RESPONSE=""
if [[ "${SKIP_LIVE}" != "1" ]]; then
  INIT_RESPONSE=$(curl -sf \
    -X POST "${MCP_ENDPOINT}" \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "${INIT_REQUEST}") || fail "MCP initialize failed"

  info "initialize response:"
  echo "${INIT_RESPONSE}" | python3 -m json.tool 2>/dev/null || echo "${INIT_RESPONSE}"

  # Strip SSE envelope if present (text/event-stream wraps JSON in "data: {...}")
  if echo "${INIT_RESPONSE}" | grep -q "^data:"; then
    INIT_RESPONSE=$(echo "${INIT_RESPONSE}" | grep "^data:" | head -1 | sed 's/^data: //')
  fi

  assert_contains "initialize returns protocolVersion" "protocolVersion" "${INIT_RESPONSE}"
  ok "MCP session initialized"
fi

# ---------------------------------------------------------------------------
# STEP 3 — tools/list
# ---------------------------------------------------------------------------
info ""
info "=== STEP 3: tools/list — enumerate available tools ==="

TOOLS_LIST_REQUEST='{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}'

TOOLS_LIST_RESPONSE=""
if [[ "${SKIP_LIVE}" != "1" ]]; then
  TOOLS_LIST_RESPONSE=$(curl -sf \
    -X POST "${MCP_ENDPOINT}" \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "${TOOLS_LIST_REQUEST}") || fail "tools/list failed"

  if echo "${TOOLS_LIST_RESPONSE}" | grep -q "^data:"; then
    TOOLS_LIST_RESPONSE=$(echo "${TOOLS_LIST_RESPONSE}" | grep "^data:" | head -1 | sed 's/^data: //')
  fi

  info "tools/list response:"
  echo "${TOOLS_LIST_RESPONSE}" | python3 -m json.tool 2>/dev/null || echo "${TOOLS_LIST_RESPONSE}"
  assert_contains "tools/list returns tools array" "tools" "${TOOLS_LIST_RESPONSE}"
  ok "tools/list succeeded"
fi

# ---------------------------------------------------------------------------
# STEP 4 — tools/call get_firewall_rules (positive case)
# ---------------------------------------------------------------------------
info ""
info "=== STEP 4: tools/call get_firewall_rules (positive — arsalan with mcp-users group) ==="

CALL_REQUEST='{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "get_firewall_rules",
    "arguments": {"interface": "WAN", "limit": 10}
  }
}'

CALL_RESPONSE=""
if [[ "${SKIP_LIVE}" != "1" ]]; then
  CALL_RESPONSE=$(curl -sf \
    -X POST "${MCP_ENDPOINT}" \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "${CALL_REQUEST}") || fail "tools/call get_firewall_rules failed"

  if echo "${CALL_RESPONSE}" | grep -q "^data:"; then
    CALL_RESPONSE=$(echo "${CALL_RESPONSE}" | grep "^data:" | head -1 | sed 's/^data: //')
  fi

  info "get_firewall_rules response:"
  echo "${CALL_RESPONSE}" | python3 -m json.tool 2>/dev/null || echo "${CALL_RESPONSE}"
  assert_contains "tool call returns result" "result" "${CALL_RESPONSE}"
  ok "get_firewall_rules call succeeded"
fi

# ---------------------------------------------------------------------------
# STEP 5 — echo-mcp identity assertion: server MUST see arsalan, not the agent
# ---------------------------------------------------------------------------
info ""
info "=== STEP 5: echo-mcp identity assertion ==="
info "Calling echo_identity tool — response must contain '${DEMO_USER}', proving"
info "that ext-proc-delegation forwarded the user identity, not the agent SVID."

ECHO_ENDPOINT="${MCP_GATEWAY_URL}/mcp/echo"
ECHO_REQUEST='{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "echo_identity",
    "arguments": {}
  }
}'

ECHO_RESPONSE=""
if [[ "${SKIP_LIVE}" != "1" ]]; then
  ECHO_RESPONSE=$(curl -sf \
    -X POST "${ECHO_ENDPOINT}" \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "${ECHO_REQUEST}") || fail "echo_identity call failed"

  if echo "${ECHO_RESPONSE}" | grep -q "^data:"; then
    ECHO_RESPONSE=$(echo "${ECHO_RESPONSE}" | grep "^data:" | head -1 | sed 's/^data: //')
  fi

  info "echo_identity response:"
  echo "${ECHO_RESPONSE}" | python3 -m json.tool 2>/dev/null || echo "${ECHO_RESPONSE}"

  # CRITICAL assertion: the downstream server must see the user's sub/preferred_username
  # ext-proc-delegation injects X-Forwarded-User (user sub) and X-User-Identity (full claims)
  # The echo-mcp server echoes back what it received in its response content
  assert_contains "echo-mcp sees user identity (not agent)" "${DEMO_USER}" "${ECHO_RESPONSE}"
  ok "IDENTITY DELEGATION VERIFIED: echo-mcp saw '${DEMO_USER}' — not the agent SVID"
fi

# ---------------------------------------------------------------------------
# STEP 6 — Negative: call with NO token -> 401
# ---------------------------------------------------------------------------
info ""
info "=== STEP 6: Negative — no token -> expect HTTP 401 ==="

if [[ "${SKIP_LIVE}" != "1" ]]; then
  NO_TOKEN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${MCP_ENDPOINT}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "${CALL_REQUEST}")

  assert_http_status "no-token call rejected 401" "401" "${NO_TOKEN_STATUS}"
fi

# ---------------------------------------------------------------------------
# STEP 7 — Negative: token with group stripped -> expect HTTP 403 (Kyverno)
# ---------------------------------------------------------------------------
info ""
info "=== STEP 7: Negative — token without mcp-users group -> expect HTTP 403 ==="
info "This requires a second Keycloak user/token WITHOUT the mcp-users group."
info "Configure user 'arsalan-no-groups' in realm 'agentic' without mcp-users membership."

# If a stripped-group token was provided explicitly, use it; otherwise skip.
if [[ "${SKIP_LIVE}" != "1" && -n "${DEMO_NOGROUPUSER:-}" && -n "${DEMO_NOGROUPPASSWORD:-}" ]]; then
  NOGROUP_TOKEN_BODY=$(curl -sf \
    -X POST "${KEYCLOAK_TOKEN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${DEMO_CLIENT_ID}" \
    ${DEMO_CLIENT_SECRET:+-d "client_secret=${DEMO_CLIENT_SECRET}"} \
    -d "username=${DEMO_NOGROUPUSER}" \
    -d "password=${DEMO_NOGROUPPASSWORD}" \
    -d "scope=openid groups profile") || fail "No-group token request failed"

  NOGROUP_TOKEN=$(echo "${NOGROUP_TOKEN_BODY}" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

  NOGROUP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${MCP_ENDPOINT}" \
    -H "Authorization: Bearer ${NOGROUP_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "${CALL_REQUEST}")

  assert_http_status "no-group call rejected 403" "403" "${NOGROUP_STATUS}"
else
  warn "STEP 7: skipped — set DEMO_NOGROUPUSER + DEMO_NOGROUPPASSWORD in .env to enable"
  warn "  Create user 'arsalan-no-groups' in Keycloak realm 'agentic' without mcp-users group"
  warn "  Then: DEMO_NOGROUPUSER=arsalan-no-groups DEMO_NOGROUPPASSWORD=<pw> ./run.sh"
fi

# ---------------------------------------------------------------------------
# STEP 8 — Audit trail
# ---------------------------------------------------------------------------
info ""
info "=== STEP 8: Where to see audit events ==="
echo ""
echo "  Loki LogQL (Grafana → Explore):"
echo "    {app=\"ext-proc-delegation\"} | json | line_format '{{.session_id}}'"
echo "    {app=\"ext-proc-delegation\"} |= \"session_id\""
echo "    {app=\"ext-proc-delegation\"} | json | decision = \"allow\" | caller_username = \"${DEMO_USER}\""
echo ""
echo "  Grafana: ${GRAFANA_URL:-http://172.16.2.252:3000}"
echo "    Dashboard: 'Agentic Platform / JIT Audit'"
echo ""
echo "  Direct Loki query (from inside cluster):"
echo "    curl -G 'http://172.16.2.252:3100/loki/api/v1/query_range' \\"
echo "      --data-urlencode 'query={app=\"ext-proc-delegation\"} |= \"session_id\"' \\"
echo "      --data-urlencode 'limit=20'"
echo ""
echo "  From cluster (oc exec into otel-collector or loki-promtail):"
echo "    oc -n agentic-observability exec deploy/otel-collector -- \\"
echo "      curl -s 'http://172.16.2.252:3100/loki/api/v1/query_range?query={app%3D\"ext-proc-delegation\"}'"
echo ""
echo "  NOTE: tool arguments are logged as sha256 hashes, never raw values."
echo "  The audit event shape is in expected/audit-event.golden.json"
echo ""

info ""
info "=== UC1 complete ==="
ok "All live assertions passed (or SKIP_LIVE=1 dry-run completed)"
