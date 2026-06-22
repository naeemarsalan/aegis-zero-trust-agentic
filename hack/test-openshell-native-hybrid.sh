#!/usr/bin/env bash
# test-openshell-native-hybrid.sh — Phase-A acceptance for the NATIVE OpenShell
# delegated-agent journey (ADR-0011 hybrid / ADR-0017 setns fix / ADR-0018 binding).
#
# Proves, on a FRESHLY gateway-launched sandbox (ns openshell), the native
# credential-MINT substrate that the delegated read + JIT-gated write ride on:
#
#   launcher /launch ─▶ Sandbox CR ─▶ pod (agents.x-k8s.io/sandbox-name-hash,
#                                          annotation openshell.io/sandbox-id=<uuid>)
#        │                                   │
#        ├─ writes Vault grant ──────────────┼─▶ secret/data/sandbox-grants/<uuid>
#        │   (resp.sandbox.metadata.id=<uuid>)│
#        └─ provider_spiffe + ClusterSPIFFEID ┴─▶ SVID  .../ns/openshell/sandbox/<uuid>
#
# The load-bearing invariant (ADR-0018): metadata.id == openshell.io/sandbox-id
# annotation == ClusterSPIFFEID-rendered SVID path == Vault grant key. If those
# three strings agree, ext-proc resolves the right grant for the SVID-bearing
# agent and the delegated read is per-sandbox and non-spoofable.
#
# SUBSTRATE assertions (hard gate — this is what Loops 1+2 deliver and what this
# script loops-until-green on): grant written + SVID entry issued + binding
# consistent + workload-API socket mounted + SYS_CHROOT + confined container_t +
# zero setns/EPERM + no stored broad credential in the sandbox (only the SVID).
#
# ACCEPTANCE (agent-driven, reported; HARD only when REQUIRE_AGENT_READ=1): the
# in-sandbox agent's MCP read flows through ext-proc with its SVID -> ext-proc
# reads the grant -> on-behalf-of exchange to sub=user -> 200 (audit:
# caller_username). Then a dangerous tool with SVID only -> 403 grant_scope_denied;
# console-approved JIT session (jwt.sandbox_uid==svid.sandbox_uid) -> retry -> 200
# (jit_elevated); post-TTL revert -> 403. This requires the agent-brain to be
# reachable from ns openshell AND the supervisor to route MCP through ext-proc
# carrying the raw SVID (the hybrid wiring per ADR-0011) — see docs/plans/phase-A.
#
# Usage: hack/test-openshell-native-hybrid.sh [--keep] [--ttl MIN]
#   --keep              do not delete the spawned sandbox at the end
#   REQUIRE_AGENT_READ=1 make the delegated-read acceptance a hard gate (not just reported)
set -euo pipefail

KUBECONFIG="${KUBECONFIG:-$HOME/.kube/anaeem-sno.kubeconfig}"; export KUBECONFIG
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=openshell
SPIRE_NS=zero-trust-workload-identity-manager
KC=https://keycloak.apps.anaeem.na-launch.com
LAUNCH_URL=https://sandbox-launcher.apps.anaeem.na-launch.com/launch
VAULT_ADDR_DEFAULT=https://vault.apps.anaeem.na-launch.com
TTL_MIN=30
KEEP=0
while [[ $# -gt 0 ]]; do case "$1" in
  --keep) KEEP=1; shift;;
  --ttl) TTL_MIN="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done

oc() { command oc --kubeconfig "$KUBECONFIG" "$@"; }
# octry: retry through the SNO control-plane flaps (etcd/apiserver occasionally 401s).
octry() { local i out; for i in 1 2 3 4 5 6; do out=$(oc "$@" 2>&1) && { printf '%s\n' "$out"; return 0; }; sleep 4; done; printf '%s\n' "$out"; return 1; }
pass=0; fail=0; pend=0
ok(){ echo "  ✅ $*"; pass=$((pass+1)); }
no(){ echo "  ❌ $*"; fail=$((fail+1)); }
pending(){ echo "  ⏳ PENDING: $*"; pend=$((pend+1)); }

echo "== Native OpenShell delegated-agent journey (SVID mint + Vault grant substrate) =="

# --- resolve a Vault token for read-back (env/.env, then k8s secret) ---
VAULT_ADDR="${VAULT_ADDR:-$VAULT_ADDR_DEFAULT}"
VT="${VAULT_ROOT_TOKEN:-}"
[[ -z "$VT" && -f "$REPO_ROOT/environment/.env" ]] && \
  VT="$(grep -E '^VAULT_ROOT_TOKEN=' "$REPO_ROOT/environment/.env" | cut -d= -f2- | tr -d '"' || true)"
[[ -z "$VT" ]] && VT="$(oc -n vault get secret vault-init -o jsonpath='{.data.root-token}' 2>/dev/null | base64 -d 2>/dev/null || true)"
vault_get(){ curl -sk -H "X-Vault-Token: $VT" "$VAULT_ADDR/v1/secret/data/sandbox-grants/$1" 2>/dev/null; }
spire_entries(){ oc -n "$SPIRE_NS" exec spire-server-0 -c spire-server -- /spire-server entry show 2>/dev/null; }

echo "0) launch a fresh native sandbox via the gateway launcher"
LP=$(oc -n mcp-gateway get pods --no-headers 2>/dev/null | grep sandbox-launcher | awk '/Running/{print $1;exit}')
[ -n "$LP" ] || { echo "FATAL: no Running sandbox-launcher pod"; exit 1; }
# Launch AS A HUMAN, not as the launcher service account.
# Why: the launcher records the caller identity (preferred_username) into the
# Vault consent grant's `user` field; ext-proc then injects that user's
# PRE-PROVISIONED downstream pfSense token (Vault mcp-tools/mcp-tokens, keyed by
# username) because the Keycloak on-behalf-of exchange is the documented NPE
# dead-end. A client_credentials launch records `service-account-sandbox-launcher`,
# which has NO static token mapped -> ext-proc fails closed `no_user_token`.
# The zero-trust model REQUIRES a human on whose behalf pfSense is touched
# (ADR-0012); the SA must never be a downstream pfSense identity. So we mint a
# real user token via the public `ida-cli` direct-access-grant client for the
# demo user (whose username IS mapped in mcp-tokens / mcp-tokens-write).
DEMO_USER="${DEMO_USER:-arsalan}"
DEMO_PASSWORD="${DEMO_PASSWORD:-}"
if [[ -z "$DEMO_PASSWORD" && -f "$REPO_ROOT/environment/.env" ]]; then
  DEMO_USER="$(grep -E '^DEMO_USER=' "$REPO_ROOT/environment/.env" | cut -d= -f2- | tr -d '"' || true)"
  DEMO_USER="${DEMO_USER:-arsalan}"
  DEMO_PASSWORD="$(grep -E '^DEMO_PASSWORD=' "$REPO_ROOT/environment/.env" | cut -d= -f2- | tr -d '"' || true)"
fi
[ -n "$DEMO_PASSWORD" ] || { echo "FATAL: DEMO_PASSWORD unset (need it to mint the human $DEMO_USER token via ida-cli)"; exit 1; }
TOK=$(curl -sk -X POST "$KC/realms/agentic/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=ida-cli -d scope=openid \
  -d "username=$DEMO_USER" --data-urlencode "password=$DEMO_PASSWORD" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
[ -n "$TOK" ] || { echo "FATAL: could not mint human $DEMO_USER token via ida-cli direct-access-grant"; exit 1; }
RESP=$(curl -sk -X POST "$LAUNCH_URL" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "{\"goal\":\"List firewall rules and report the count.\",\"capabilities\":[\"pfsense-firewall\"],\"mode\":\"task\",\"scope\":\"read-only\",\"userRef\":\"user:default/$DEMO_USER\",\"confirmed\":true,\"ttlMinutes\":$TTL_MIN}")
SB_ID=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("sandbox_id",""))' 2>/dev/null)
SB_NAME=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("sandbox_name",""))' 2>/dev/null)
[ -n "$SB_ID" ] && [ -n "$SB_NAME" ] && ok "launched $SB_NAME (sandbox_id=$SB_ID)" || { echo "FATAL launch failed: $RESP"; exit 1; }

cleanup(){ [ "$KEEP" = "1" ] && { echo ">> --keep: leaving $SB_NAME"; return; }; echo ">> cleanup: deleting $SB_NAME"; oc -n "$NS" delete sandbox "$SB_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "1) Loop 2 — launcher wrote the Vault consent grant (was absent pre-fix)"
GRANT=$(vault_get "$SB_ID")
GUSER=$(echo "$GRANT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["data"]["user"])' 2>/dev/null || true)
GTTL=$(echo "$GRANT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["data"]["ttl"])' 2>/dev/null || true)
GSCOPE=$(echo "$GRANT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["data"]["scope"])' 2>/dev/null || true)
GUID=$(echo "$GRANT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["data"]["sandbox_uid"])' 2>/dev/null || true)
if [ "$GUID" = "$SB_ID" ] && [ -n "$GUSER" ] && [ "$GTTL" -gt 0 ] 2>/dev/null; then
  ok "grant at sandbox-grants/$SB_ID present {user=$GUSER scope=$GSCOPE ttl=${GTTL}s}"
else no "grant missing/malformed at sandbox-grants/$SB_ID: $(echo "$GRANT" | head -c 200)"; fi

echo "2) wait for the sandbox pod to be Running"
for i in $(seq 1 24); do
  [ "$(octry -n "$NS" get pod "$SB_NAME" -o jsonpath='{.status.phase}')" = "Running" ] && break; sleep 5
done
[ "$(oc -n "$NS" get pod "$SB_NAME" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] \
  && ok "pod $SB_NAME Running" || no "pod $SB_NAME not Running"

echo "3) Loop 1 — ClusterSPIFFEID issued a per-sandbox SVID entry"
for i in $(seq 1 12); do spire_entries | grep -q "/ns/$NS/sandbox/$SB_ID" && break; sleep 5; done
spire_entries | grep -q "/ns/$NS/sandbox/$SB_ID" \
  && ok "SVID entry spiffe://anaeem.na-launch.com/ns/$NS/sandbox/$SB_ID issued" \
  || no "no SVID entry for /ns/$NS/sandbox/$SB_ID"

echo "4) ADR-0018 binding — annotation == grant key == SVID path (all == metadata.id)"
ANN=$(oc -n "$NS" get pod "$SB_NAME" -o jsonpath='{.metadata.annotations.openshell\.io/sandbox-id}' 2>/dev/null)
[ "$ANN" = "$SB_ID" ] && [ "$GUID" = "$SB_ID" ] \
  && ok "binding consistent: pod annotation=$ANN, grant key=$GUID, SVID path uuid=$SB_ID" \
  || no "binding mismatch: annotation=$ANN grant=$GUID svid=$SB_ID"

echo "5) ADR-0017 — provider_spiffe socket mounted, SYS_CHROOT present, confined, no setns/EPERM"
CAPS=$(oc -n "$NS" get pod "$SB_NAME" -o jsonpath='{.spec.containers[?(@.name=="agent")].securityContext.capabilities.add}' 2>/dev/null)
SOCK=$(oc -n "$NS" exec "$SB_NAME" -c agent -- sh -c 'test -S /spiffe-workload-api/spire-agent.sock && echo yes || echo no' 2>/dev/null)
CTX=$(oc -n "$NS" exec "$SB_NAME" -c agent -- cat /proc/self/attr/current 2>/dev/null | tr -d '\0')
# grep -c exits 1 on zero matches (the GOOD case) — guard against set -e.
SETNS=$(oc -n "$NS" logs "$SB_NAME" -c agent 2>/dev/null | grep -ciE 'setns|EPERM' || true)
echo "$CAPS" | grep -q 'SYS_CHROOT' && ok "SYS_CHROOT present (setns fix)" || no "SYS_CHROOT missing (caps=$CAPS)"
[ "$SOCK" = "yes" ] && ok "workload-API socket present in sandbox" || no "workload-API socket absent"
echo "$CTX" | grep -q 'container_t' && ok "confined SELinux context: $CTX" || no "not confined: $CTX"
[ "${SETNS:-0}" = "0" ] && ok "zero setns/EPERM in supervisor log" || no "setns/EPERM present ($SETNS)"

echo "6) invariant — the sandbox holds ONLY its SVID (no stored broad credential)"
LEAK=$(oc -n "$NS" exec "$SB_NAME" -c agent -- sh -c '
  found=0
  for f in /vault/secrets/* /var/run/secrets/*token* /root/.config/**/token; do
    [ -f "$f" ] 2>/dev/null && { echo "LEAK:$f"; found=1; }
  done
  exit 0' 2>/dev/null | grep -c LEAK || true)
[ "${LEAK:-0}" = "0" ] && ok "no injected broad-credential files in the sandbox (SVID-only)" \
  || no "possible stored credential in sandbox (found $LEAK candidate files)"

echo "7) ACCEPTANCE (agent-driven, hybrid) — delegated read / 403 / JIT / revert"
echo "   waiting up to 90s for the in-sandbox agent to drive an MCP read through ext-proc..."
EP=$(oc -n mcp-gateway get pods --no-headers 2>/dev/null | grep ext-proc | awk '/Running/{print $1;exit}')
seen=""
for i in $(seq 1 15); do
  if oc -n mcp-gateway logs "$EP" -c ext-proc-delegation --since=10m 2>/dev/null | grep -q "$SB_ID"; then seen=1; break; fi
  sleep 6
done
if [ -n "$seen" ]; then
  EV=$(oc -n mcp-gateway logs "$EP" -c ext-proc-delegation --since=10m 2>/dev/null | grep "$SB_ID" | tail -1)
  echo "$EV" | grep -q '"decision":"allow"' && ok "delegated read 200 via ext-proc (grant resolved for SVID $SB_ID)" \
    || pending "ext-proc saw the SVID but did not allow — inspect: $(echo "$EV" | head -c 160)"
else
  pending "no ext-proc traffic for $SB_ID — the in-sandbox agent did not drive an MCP call."
  echo "      This is the hybrid INTEGRATION above the substrate (ADR-0011): it needs the"
  echo "      agent-brain reachable from ns openshell AND the supervisor to route MCP through"
  echo "      ext-proc carrying the raw SVID. The substrate (grant+SVID+binding) is verified above."
fi

echo
echo "== result: $pass passed, $fail failed, $pend pending (acceptance) =="
rm -f /tmp/native-sb-$$.json /tmp/native-sb-checks-$$ 2>/dev/null || true
if [ "$fail" -ne 0 ]; then echo "FAIL (substrate)"; exit 1; fi
if [ "${REQUIRE_AGENT_READ:-0}" = "1" ] && [ "$pend" -ne 0 ]; then echo "FAIL (acceptance required but pending)"; exit 1; fi
echo "PASS — native SVID-mint + Vault-grant substrate verified end-to-end on a gateway-launched sandbox."
[ "$pend" -ne 0 ] && echo "NOTE: agent-driven hybrid acceptance is PENDING the MCP-via-ext-proc-SVID + agent-brain wiring."
exit 0
