#!/usr/bin/env bash
# run-agent.sh — run the in-sandbox AUTONOMOUS Claude agent with a goal.
#
# The agent holds NO credentials (only its SPIFFE SVID). It reads the goal,
# loads its pfsense-firewall skill, and calls tools through the zero-trust
# gateway. Reads return immediately. On a WRITE it files an approval request and
# PAUSES — you approve in the console, then it continues automatically.
#
# Usage:
#   hack/run-agent.sh                         # default: a read goal
#   hack/run-agent.sh "add a firewall rule on lan that passes tcp any->any, desc demo"
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KC="${IDA_KUBECONFIG:-$HOME/.config/ida/anaeem-admin.kubeconfig}"
VAULT_ADDR="${VAULT_ADDR:-https://vault.apps.anaeem.na-launch.com}"
CONSOLE="https://approval-console.apps.anaeem.na-launch.com"
SB=e2e0a1b2-c3d4-4e5f-8a9b-000000000001
GOAL="${1:-Using your pfsense-firewall skill, list the current firewall rules and tell me how many there are.}"
oc() { command oc --kubeconfig "$KC" "$@"; }

# 1) fresh read-only grant (so reads are delegated as you; writes still need approval)
VT="${VAULT_ROOT_TOKEN:-$(grep -E '^VAULT_ROOT_TOKEN=' "$REPO_ROOT/environment/.env" | cut -d= -f2- | tr -d '"')}"
NONCE=$(openssl rand -hex 16); NOW=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
curl -sk -H "X-Vault-Token: $VT" -H 'Content-Type: application/json' -X POST \
  "$VAULT_ADDR/v1/secret/data/sandbox-grants/$SB" \
  -d "{\"data\":{\"version\":1,\"sandbox_uid\":\"$SB\",\"user\":\"arsalan\",\"scope\":\"read-only\",\"ttl\":3600,\"nonce\":\"$NONCE\",\"created\":\"$NOW\"}}" >/dev/null \
  && echo ">> consent grant refreshed (user=arsalan, read-only)" || { echo "!! grant write failed"; exit 1; }

HPOD=$(oc -n agent-sandbox get pods -l app=e2e-harness --field-selector=status.phase=Running -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null)
[ -n "$HPOD" ] || { echo "!! no running harness pod (try: oc apply -k services/agent-sandbox/e2e-harness)"; exit 1; }

echo ">> agent pod: $HPOD"
echo ">> GOAL: $GOAL"
echo ">> If this is a WRITE it will PAUSE — approve at: $CONSOLE"
echo "------------------------------------------------------------------------"

oc -n agent-sandbox exec "$HPOD" -c agent -- sh -c \
  "cd /app && PYTHONPATH=/app/src AGENT_ALLOWED_TOOLS='Bash' AGENT_MAX_TURNS=14 AGENT_GOAL=\"$GOAL\" python3 -m agent_harness.agent_runner" 2>/dev/null \
| python3 -u -c '
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    t = d.get("type")
    if t == "assistant" and d.get("text", "").strip():
        print("\n\U0001F916 " + d["text"].strip(), flush=True)
    elif t == "tool_use":
        print("   ⚙  tool: " + str(d.get("tool")), flush=True)
    elif t == "tool_result" and d.get("content"):
        print("   ←  " + str(d.get("content"))[:200], flush=True)
    elif t == "result":
        print("\n✅ RESULT: " + str(d.get("status")) + " — " + str(d.get("summary",""))[:400], flush=True)
'
echo "------------------------------------------------------------------------"
echo ">> verify server-side (agent held only its SVID; gateway delegated as you):"
echo "   oc -n mcp-gateway logs deploy/ext-proc-delegation -c ext-proc-delegation | grep credential_delegation | tail"
