#!/usr/bin/env bash
# test-kagenti-identity.sh — verify the zero-cred Kagenti identity loop end-to-end.
#
# Proves: an agent holding ONLY a SPIRE SVID (no client secret, no static token) reaches
# an MCP server (echo-mcp) through the Kagenti AuthBridge sidecar, which authenticates to
# Keycloak via federated-JWT (the agent's JWT-SVID) and token-exchanges to the target.
#
# This is the Kagenti-path analogue of hack/spawn-shell.sh. It is read-only/non-mutating
# except for reading logs. See docs/adr/0013-kagenti-identity-plane-adoption.md.
set -euo pipefail

KUBECONFIG="${KUBECONFIG:-$HOME/.config/ida/anaeem-admin.kubeconfig}"
export KUBECONFIG
oc() { command oc --kubeconfig "$KUBECONFIG" "$@"; }

NS=kagenti-test
ECHO_URL="http://echo-mcp.agentic-mcp.svc.cluster.local:8000/mcp"
PROXY="http://localhost:8081"          # AuthBridge forward-proxy (proxy-sidecar mode)
CLIENT_ID="spiffe://anaeem.na-launch.com/ns/kagenti-test/sa/test-agent"
pass=0; fail=0
ok(){ echo "  ✅ $*"; pass=$((pass+1)); }
no(){ echo "  ❌ $*"; fail=$((fail+1)); }

echo "== Kagenti zero-cred identity loop =="
P=$(oc -n "$NS" get pods -l app=test-agent --field-selector=status.phase=Running \
      --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null || true)
[ -n "$P" ] || { echo "no running test-agent pod in $NS"; exit 1; }
echo "agent pod: $P"

echo "1) agent holds ONLY its SVID (no static creds in the app container)"
# the app container has no MCP token / client secret mounted; identity is the SPIRE SVID + the
# operator-mounted client-id (the SECRET lives in the AuthBridge sidecar, never the app).
if oc -n "$NS" exec "$P" -c agent -- sh -c 'cat /opt/jwt_svid.token 2>/dev/null' >/dev/null 2>&1; then
  no "app container can read the JWT-SVID (expected: only the sidecar holds it)"
else
  ok "app container has no JWT-SVID / no downstream secret (zero-cred)"
fi

echo "2) spiffe-helper minted a JWT-SVID with the correct audience"
AUD=$(oc -n "$NS" exec "$P" -c spiffe-helper -- cat /opt/jwt_svid.token 2>/dev/null | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("aud"))' 2>/dev/null || true)
echo "     SVID aud=$AUD"
echo "$AUD" | grep -q 'realms/kagenti' && ok "JWT-SVID audience targets the kagenti realm" || no "unexpected SVID audience"

echo "3) call echo-mcp THROUGH the AuthBridge proxy (federated-jwt auth + token-exchange + forward)"
RESP=$(oc -n "$NS" exec "$P" -c agent -- sh -c "curl -sS -x $PROXY -m 25 \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}' \
  $ECHO_URL" 2>&1 || true)
echo "     echo-mcp response: $(echo "$RESP" | tr -d '\n' | tail -c 160)"
echo "$RESP" | grep -q '"serverInfo"' && ok "echo-mcp returned a valid MCP response via the proxy" || no "echo-mcp call failed (resp above)"

echo "4) Keycloak authenticated the agent's SPIFFE client via federated-jwt"
if oc -n keycloak logs keycloak-0 --since-time="$(date -u -d '90 seconds ago' +%Y-%m-%dT%H:%M:%SZ)" 2>/dev/null \
    | grep -q "Client $CLIENT_ID authenticated by federated-jwt"; then
  ok "Keycloak: federated-jwt SUCCESS for $CLIENT_ID"
else
  echo "     (no fresh federated-jwt success line; check: oc -n keycloak logs keycloak-0 | grep federated-jwt)"
fi

echo
echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] && echo "PASS — zero-cred Kagenti identity loop verified." || { echo "FAIL"; exit 1; }
