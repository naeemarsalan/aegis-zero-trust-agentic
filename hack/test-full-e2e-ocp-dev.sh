#!/usr/bin/env bash
# test-full-e2e-ocp-dev.sh — turnkey full-platform e2e for the zero-trust agentic
# platform on the ocp-dev cluster. ONE command proves all four planes:
#
#   1. TOOL plane   — the credential-less pfSense journey (delegates to the
#                     regression anchor hack/test-pfsense-jit-ocp-dev.sh):
#                     read 200 / write 403 / mint+SoD / elevated write 200.
#   2. MODEL plane  — the SVID *is* the model credential (MaaS):
#                     SVID-driven completion 200 (positive) AND a credential-less
#                     call to the maas-gateway 401 (negative — zero-trust holds).
#   3. WORM audit   — the jit-approver hash-chain ledger is tamper-evident and
#                     append-only: rows present, chain_ok=true, and the `app`
#                     DB role cannot UPDATE/DELETE jit_ledger (REVOKE enforced).
#   4. ASSETS       — OpenRouter + the MCP server are registered as native
#                     RHOAI Gen AI Studio assets (the two ConfigMaps exist).
#
# Usage:   IDA_KUBECONFIG=~/.kube/ocp-dev-admin.kubeconfig bash hack/test-full-e2e-ocp-dev.sh
# Requires: oc reachable via a NON-expired kubeconfig (the break-glass cert
#           ~/.kube/ocp-dev-admin.kubeconfig — the user-token kubeconfig is EXPIRED);
#           /etc/hosts mapping *.apps.ocp-dev.na-launch.com -> ingress VIP 172.16.2.59.
# All cluster reads/writes go via `oc` (and `oc exec` for Vault/Postgres) — no
# port-forward and no local vault/psql CLI needed.
set -uo pipefail

KC="${IDA_KUBECONFIG:-$HOME/.kube/ocp-dev-admin.kubeconfig}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAAS_HOST="${MAAS_HOST:-maas.apps.ocp-dev.na-launch.com}"
PASS=0; FAIL=0
oc() { command oc --kubeconfig "$KC" "$@"; }
ok()  { echo "  ✅ $*"; PASS=$((PASS+1)); }
bad() { echo "  ❌ $*"; FAIL=$((FAIL+1)); }
step(){ echo; echo "========== $* =========="; }

step "PHASE 1 — TOOL plane (pfSense zero-trust journey)"
# The anchor prints its own per-step ✅/❌ and a final 'E2E_RESULT: PASS|FAIL'.
if IDA_KUBECONFIG="$KC" bash "${HERE}/test-pfsense-jit-ocp-dev.sh" 2>&1 | tee /tmp/full-e2e-tool.log | sed 's/^/    /' \
   && grep -q '^E2E_RESULT: PASS' /tmp/full-e2e-tool.log; then
  ok "TOOL plane journey PASS (read 200 / write 403 / mint+SoD / elevated write 200)"
else
  bad "TOOL plane journey FAIL (see output above / /tmp/full-e2e-tool.log)"
fi

step "PHASE 2 — MODEL plane (the SVID is the model credential)"
# Positive: the openrouter-bridge presents its SVID server-side -> a real completion (200).
MP=$(oc exec -n maas deploy/openrouter-bridge -- python3 -c 'import urllib.request,json
b=json.dumps({"model":"anthropic/claude-sonnet-4","messages":[{"role":"user","content":"OK"}],"max_tokens":8}).encode()
print(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8321/v1/chat/completions",b,{"Content-Type":"application/json"})).status)' 2>/dev/null | tail -1)
[ "$MP" = "200" ] && ok "MODEL positive — SVID-driven completion HTTP 200" || bad "MODEL positive expected 200, got '${MP}'"
# Negative: a credential-less call to the in-cluster maas-gateway is rejected by Authorino (401).
MN=$(oc exec -n maas deploy/openrouter-bridge -- curl -s -o /dev/null -w '%{http_code}' \
  -X POST -H "Host: ${MAAS_HOST}" -H 'Content-Type: application/json' \
  http://maas-gateway-istio.maas.svc:80/openrouter/v1/chat/completions \
  -d '{"model":"anthropic/claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"max_tokens":4}' 2>/dev/null | tail -1)
{ [ "$MN" = "401" ] || [ "$MN" = "403" ]; } \
  && ok "MODEL negative — credential-less gateway call rejected (HTTP ${MN}, zero-trust holds)" \
  || bad "MODEL negative expected 401/403, got '${MN}' (200=auth bypass! 503=edge degraded — retry)"

step "PHASE 3 — WORM audit ledger (tamper-evident, append-only)"
PSQL() { oc exec -n mcp-gateway jit-approver-db-1 -c postgres -- psql -U postgres -d jit_approver "$@" 2>/dev/null; }
ROWS=$(PSQL -tA -c "SELECT count(*) FROM jit_ledger;" | tail -1)
[ "${ROWS:-0}" -ge 1 ] 2>/dev/null && ok "jit_ledger has ${ROWS} append-only rows" || bad "jit_ledger empty/unreachable (rows='${ROWS}')"
CHAIN=$(PSQL -tA -c "WITH c AS (SELECT seq, prev_hash, lag(entry_hash) OVER (ORDER BY seq) AS le FROM jit_ledger) SELECT bool_and(prev_hash = COALESCE(le,'')) FROM c;" | tail -1)
[ "$CHAIN" = "t" ] && ok "hash-chain intact (each prev_hash links the prior entry_hash)" || bad "chain_ok='${CHAIN}' (expected t — ledger may be tampered)"
# REVOKE proof: as the app role, UPDATE must be denied at the DB privilege level.
# NB: capture STDERR here (psql writes 'permission denied' to stderr) — do NOT use the
# stderr-silencing PSQL() helper or the proof message is discarded.
REV=$(oc exec -n mcp-gateway jit-approver-db-1 -c postgres -- \
  psql -U postgres -d jit_approver -c "SET ROLE app; UPDATE jit_ledger SET payload_json=payload_json WHERE seq=1;" 2>&1 \
  | grep -ci 'permission denied')
[ "${REV:-0}" -ge 1 ] && ok "app role CANNOT UPDATE jit_ledger (permission denied — WORM enforced)" || bad "app UPDATE was NOT denied (WORM broken!)"
GRANTS=$(PSQL -tA -c "SELECT string_agg(privilege_type,',' ORDER BY privilege_type) FROM information_schema.role_table_grants WHERE table_name='jit_ledger' AND grantee='app';" | tail -1)
[ "$GRANTS" = "INSERT,SELECT" ] && ok "app grants on jit_ledger = INSERT,SELECT only" || bad "app grants='${GRANTS}' (expected INSERT,SELECT)"

step "PHASE 4 — Gen AI Studio assets (native RHOAI registration)"
oc get cm gen-ai-aa-mcp-servers -n redhat-ods-applications >/dev/null 2>&1 \
  && ok "gen-ai-aa-mcp-servers present (MCP server registered as a Gen AI Studio asset)" \
  || bad "gen-ai-aa-mcp-servers missing in redhat-ods-applications"
oc get cm gen-ai-aa-custom-model-endpoints -n maas >/dev/null 2>&1 \
  && ok "gen-ai-aa-custom-model-endpoints present (OpenRouter registered, SVID-callable)" \
  || bad "gen-ai-aa-custom-model-endpoints missing in maas"

echo
echo "################ FULL E2E: ${PASS} passed / ${FAIL} failed ################"
if [ "$FAIL" -eq 0 ]; then echo "FULL_E2E_RESULT: PASS"; exit 0; else echo "FULL_E2E_RESULT: FAIL"; exit 1; fi
