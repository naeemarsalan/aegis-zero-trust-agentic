#!/usr/bin/env bash
# test-kagenti-jit.sh — full zero-trust loop on the Kagenti path: identity (AuthBridge)
# + JIT human-approval (jit-approver) gate, end-to-end.
#
# Proves, for a credential-less agent (SPIRE SVID only):
#   1. READ  tool (whoami) -> ALLOWED, and echo-mcp sees the agent's SPIFFE identity
#   2. WRITE tool (echo)   -> DENIED  (no approval)
#   3. file a JIT request  -> Gitea PR -> approve (merge) -> jit-approver mints a capability JWT
#   4. WRITE tool (echo) WITH the capability JWT -> ALLOWED
#
# The path is: agent --HTTP_PROXY--> AuthBridge (token-exchange, identity) --> jit-gate
#              (deny dangerous tool unless capability JWT) --> echo-mcp.
# This is the Kagenti-native analogue of the pfSense split-identity loop (ADR-0012),
# with identity supplied by Kagenti (ADR-0013) instead of ext-proc.
#
# Approval is normally a human clicking "Approve" in the console; for an automated
# test this script merges the PR itself (set NO_AUTO_APPROVE=1 to pause for a human).
set -euo pipefail

KUBECONFIG="${KUBECONFIG:-$HOME/.config/ida/anaeem-admin.kubeconfig}"; export KUBECONFIG
oc() { command oc --kubeconfig "$KUBECONFIG" "$@"; }
NS=kagenti-test
GATE=http://jit-gate.kagenti-test.svc.cluster.local:8000/mcp
SPIFFE="spiffe://anaeem.na-launch.com/ns/kagenti-test/sa/test-agent"
JIT_API=https://jit-approver-api.apps.anaeem.na-launch.com
pass=0; fail=0; ok(){ echo "  ✅ $*"; pass=$((pass+1)); }; no(){ echo "  ❌ $*"; fail=$((fail+1)); }

P=$(oc -n "$NS" get pods -l app=test-agent --field-selector=status.phase=Running \
      --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}')
[ -n "$P" ] || { echo "no running test-agent pod"; exit 1; }

# mcp_call <tool> <args-json> <extra-header-or-empty> -> prints "<body>|||HTTP <code>"
mcp_call() {
  local tool="$1" args="$2" hdr="$3"
  oc -n "$NS" exec -i "$P" -c agent -- sh 2>/dev/null <<SH
PX=http://localhost:8081
H="-H Accept:application/json,text/event-stream -H Content-Type:application/json"
SID=\$(curl -s -x \$PX -m 20 -D - \$H -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' $GATE 2>/dev/null | grep -i 'mcp-session-id' | awk '{print \$2}' | tr -d '\r')
curl -s -x \$PX -m 15 \$H -H "mcp-session-id: \$SID" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' $GATE >/dev/null 2>&1
printf '%s|||HTTP ' "\$(curl -s -x \$PX -m 20 \$H -H "mcp-session-id: \$SID" $hdr -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"$tool","arguments":$args}}' $GATE 2>/dev/null | tr -d '\n')"
curl -s -x \$PX -m 20 -o /dev/null -w '%{http_code}' \$H -H "mcp-session-id: \$SID" $hdr -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"$tool","arguments":$args}}' $GATE 2>/dev/null
SH
}

echo "== Kagenti zero-trust loop: identity + JIT human-approval =="
echo "1) READ whoami -> expect ALLOW + agent SPIFFE identity"
R=$(mcp_call whoami '{}' '')
echo "$R" | grep -q "$SPIFFE" && ok "whoami allowed; echo-mcp sees azp/aud=$SPIFFE" || no "whoami did not return the agent identity"

echo "2) WRITE echo (no approval) -> expect DENY"
R=$(mcp_call echo '{"message":"x"}' '')
echo "$R" | grep -q 'requires approval' && ok "echo denied without a capability JWT" || no "echo was NOT denied: $R"

echo "3) file JIT request (mutating -> non-empty tool_scope)"
RESP=$(curl -sk "$JIT_API/requests" -H 'Content-Type: application/json' \
  -d "{\"agent_spiffe_id\":\"$SPIFFE\",\"requester_sub\":\"$SPIFFE\",\"namespace\":\"$NS\",\"verbs\":[\"create\"],\"resources\":[\"firewall\"],\"duration_minutes\":30,\"justification\":\"kagenti JIT loop test\"}")
SID=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
PR=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["pr_url"])')
PRN="${PR##*/}"
echo "   request=$SID  PR=$PR"

if [ "${NO_AUTO_APPROVE:-0}" = "1" ]; then
  echo "   >>> approve in the console: https://approval-console.apps.anaeem.na-launch.com  (PR #$PRN)"; read -r -p "   press enter once approved..." _
else
  GT=$(oc -n cluster-baseline get secret gitea-anaeem-pat -o jsonpath='{.data.accessToken}' | base64 -d)
  code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "https://git.arsalan.io/api/v1/repos/anaeem/nvidia-ida/pulls/$PRN/merge" -H "Authorization: token $GT" -H 'Content-Type: application/json' -d '{"Do":"merge"}')
  echo "   approve (merge PR #$PRN) -> HTTP $code"
fi

echo "4) poll for the minted capability JWT"
JWT=""; for i in $(seq 1 15); do sleep 5
  ST=$(curl -sk "$JIT_API/requests/$SID/status"); JWT=$(echo "$ST" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("session_jwt") or "")' 2>/dev/null)
  [ -n "$JWT" ] && break; done
[ -n "$JWT" ] && ok "capability JWT issued" || { no "no capability JWT issued"; echo "== $pass passed, $fail failed =="; exit 1; }

echo "5) WRITE echo WITH capability JWT -> expect ALLOW"
R=$(mcp_call echo '{"message":"elevated-by-JIT"}' "-H X-JIT-Session-JWT:$JWT")
echo "$R" | grep -q 'HTTP 200' && ok "echo allowed under the approved capability JWT" || no "echo still denied with JWT: $R"

echo; echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] && echo "PASS — zero-trust Kagenti loop (identity + JIT human-approval) verified." || { echo "FAIL"; exit 1; }
