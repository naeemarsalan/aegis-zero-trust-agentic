#!/usr/bin/env bash
# test-openshift-jit.sh — loop-until-green e2e journey: a zero-cred Claude agent
# troubleshoots a broken OpenShift workload; reads are allowed (view SA), the fix
# (a write) fires JIT; a human approves; the agent applies the fix via the edit SA.
#
#   agent (SVID) --mcp-call--> k8s-mcp-view (reads, allowed)
#                          \--> jit-gate-k8s --(after JIT approval)--> k8s-mcp-edit (write)
#
# Auto-approves by merging the Gitea PR (the human action); set NO_AUTO_APPROVE=1 to
# approve by hand in the console instead. See docs/adr/0013 + the k8s-mcp manifests.
set -euo pipefail
KUBECONFIG="${KUBECONFIG:-$HOME/.config/ida/anaeem-admin.kubeconfig}"; export KUBECONFIG
oc(){ command oc --kubeconfig "$KUBECONFIG" "$@"; }
JIT_API=https://jit-approver-api.apps.anaeem.na-launch.com
LOG=/tmp/test-openshift-jit-agent.log
pass=0; fail=0; ok(){ echo "  ✅ $*"; pass=$((pass+1)); }; no(){ echo "  ❌ $*"; fail=$((fail+1)); }

echo "== OpenShift troubleshooting journey (Claude + SA-split + JIT) =="
echo "0) arrange: ensure mcp-demo in JIT allowlist + broken-app scaled to 0 (the symptom)"
oc -n mcp-gateway set env deploy/jit-approver JIT_ALLOWED_NAMESPACES=agent-sandbox,agentic-mcp,kagenti-test,mcp-demo >/dev/null 2>&1
oc -n mcp-gateway rollout status deploy/jit-approver --timeout=90s >/dev/null 2>&1 || true
oc -n mcp-demo scale deploy/broken-app --replicas=0 >/dev/null 2>&1
sleep 3
[ "$(oc -n mcp-demo get deploy broken-app -o jsonpath='{.status.readyReplicas:-0}' 2>/dev/null || echo 0)" != "1" ] && ok "broken-app starts at 0 ready (the symptom)" || no "broken-app not at 0"

echo "1) fire off the zero-cred Claude agent (diagnose + fix broken-app)"
HP=$(oc -n agent-sandbox get pods -l app=e2e-harness --field-selector=status.phase=Running -o jsonpath='{.items[-1].metadata.name}')
GOAL='You troubleshoot OpenShift using a SHELL COMMAND named mcp-call (run it with Bash: mcp-call <tool> '"'"'<json-args>'"'"'). Do NOT look for native Kubernetes/MCP tools — they are not available; mcp-call is your ONLY path to the cluster, just run it in Bash. The Deployment broken-app in namespace mcp-demo has 0 running pods. STEP 1 diagnose: run  mcp-call pods_list_in_namespace '"'"'{"namespace":"mcp-demo"}'"'"'  and  mcp-call resources_get '"'"'{"apiVersion":"apps/v1","kind":"Deployment","name":"broken-app","namespace":"mcp-demo"}'"'"' . STEP 2 fix: run  mcp-call resources_scale '"'"'{"apiVersion":"apps/v1","kind":"Deployment","name":"broken-app","namespace":"mcp-demo","scale":1}'"'"'  — this write is denied and needs human approval; mcp-call files the request and WAITS; keep waiting until it returns. STEP 3 verify with mcp-call resources_get that replicas is 1, then report what you did.'
nohup oc -n agent-sandbox exec "$HP" -c agent -- sh -c "cd /app && PYTHONPATH=/app/src \
  MCP_READ_URL=http://k8s-mcp-view.k8s-mcp.svc.cluster.local:8080 \
  MCP_WRITE_URL=http://jit-gate-k8s.k8s-mcp.svc.cluster.local:8000 \
  JIT_TARGET_NAMESPACE=mcp-demo MCP_SEND_SVID=false AGENT_ALLOWED_TOOLS=Bash \
  AGENT_MAX_TURNS=20 AGENT_GOAL=\"$GOAL\" python3 -m agent_harness.agent_runner" >"$LOG" 2>&1 &
ok "agent launched"

echo "2-4) agent diagnoses (reads) -> write denied -> JIT (fresh approval OR reuse of a still-valid one) -> fix applies"
GT=$(oc -n cluster-baseline get secret gitea-anaeem-pat -o jsonpath='{.data.accessToken}' | base64 -d 2>/dev/null)
healed=""; approved=""
for i in $(seq 1 30); do
  # approve any pending mcp-demo request that appears (the human action)
  if [ "${NO_AUTO_APPROVE:-0}" != "1" ] && [ -z "$approved" ]; then
    SID=$(curl -sk "$JIT_API/requests" 2>/dev/null | python3 -c 'import sys,json,urllib.request,ssl
ctx=ssl._create_unverified_context()
for s in json.load(sys.stdin):
  if s.get("state")!="pending": continue
  try: d=json.load(urllib.request.urlopen("'"$JIT_API"'/requests/%s/detail"%s["id"],context=ctx))
  except Exception: continue
  if d.get("namespace")=="mcp-demo": print(s["id"]); break' 2>/dev/null)
    if [ -n "$SID" ]; then
      PRN=$(curl -sk "$JIT_API/requests/$SID/detail" | python3 -c 'import sys,json;print(json.load(sys.stdin)["pr_url"].split("/")[-1])')
      curl -sk -o /dev/null -X POST "https://git.arsalan.io/api/v1/repos/anaeem/nvidia-ida/pulls/$PRN/merge" -H "Authorization: token $GT" -H 'Content-Type: application/json' -d '{"Do":"merge"}'
      approved=1; echo "   approved fresh request (merged PR #$PRN)"
    fi
  fi
  [ "$(oc -n mcp-demo get deploy broken-app -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)" = "1" ] && { healed=1; break; }
  sleep 6
done
[ -n "$healed" ] && ok "broken-app healed to 1/1 (write applied only via an approved capability)" || no "broken-app did not heal"
[ -n "$approved" ] && echo "   path: fresh human approval" || echo "   path: reused a still-valid prior approval (mcp-call anti-spam; correct within the grant window)"

echo "5) negative control: a write WITHOUT approval is still denied"
DENY=$(oc -n agent-sandbox exec "$HP" -c agent -- sh -c 'curl -s -m15 -x "" -H "Accept: application/json, text/event-stream" -H "Content-Type: application/json" -o /dev/null -w "%{http_code}" -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"resources_scale\",\"arguments\":{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"name\":\"broken-app\",\"namespace\":\"mcp-demo\",\"scale\":3}}}" http://jit-gate-k8s.k8s-mcp.svc.cluster.local:8000/mcp 2>/dev/null' 2>/dev/null || true)
[ "$DENY" = "403" ] && ok "unapproved write still denied (403)" || no "negative control unexpected: $DENY"

echo; echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] && echo "PASS — Claude troubleshoots OpenShift: read-allowed, write JIT-gated, human-approved, fixed." || { echo "FAIL"; exit 1; }
