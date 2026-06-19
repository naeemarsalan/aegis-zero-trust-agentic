#!/usr/bin/env bash
# spawn-shell.sh — spawn a zero-trust agent shell that "impersonates your identity".
#
# What this does, in one command (the de-ritualized version of the old HOW-TO):
#   1. Writes a FRESH Vault consent grant for the sandbox (user + read-only scope),
#      integer-typed via the Vault HTTP API (the vault CLI corrupts ints -> strings).
#   2. Restarts the durable harness Deployment so you get a clean pod + SVID.
#   3. Waits for the pod to be Ready, then drops you into its shell.
#
# Inside the shell the container holds NO credentials — only its SPIRE SVID. Use:
#   mcp-call                                  # read  -> 200 (delegated as you)
#   mcp-call create_firewall_rule_advanced '{"interface":"lan","protocol":"tcp"}'  # write -> 403 until approved
# After you approve a write in the console (approval-console route), re-run with:
#   JIT_SESSION_JWT=<jwt> mcp-call create_firewall_rule_advanced '{...}'   # -> 200 (write identity)
#
# Usage: hack/spawn-shell.sh [--user USER] [--uid SANDBOX_UID] [--ttl SECONDS] [--no-exec]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBECONFIG_PATH="${IDA_KUBECONFIG:-$HOME/.config/ida/anaeem-admin.kubeconfig}"
VAULT_ADDR_DEFAULT="https://vault.apps.anaeem.na-launch.com"

USER_NAME="arsalan"
SANDBOX_UID="e2e0a1b2-c3d4-4e5f-8a9b-000000000001"   # matches the harness SVID label
TTL="3600"
DO_EXEC=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) USER_NAME="$2"; shift 2;;
    --uid)  SANDBOX_UID="$2"; shift 2;;
    --ttl)  TTL="$2"; shift 2;;
    --no-exec) DO_EXEC=0; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

oc() { command oc --kubeconfig "$KUBECONFIG_PATH" "$@"; }
# octry: retry a non-interactive oc call through the cluster's intermittent
# control-plane flaps (etcd/apiserver on this SNO occasionally 401s / NotFounds).
octry() { local i out; for i in 1 2 3 4 5 6; do out=$(oc "$@" 2>&1) && { printf '%s\n' "$out"; return 0; }; sleep 4; done; printf '%s\n' "$out"; return 1; }

# --- resolve a working Vault token (env/.env first, then the vault-init secret) ---
VAULT_ADDR="${VAULT_ADDR:-$VAULT_ADDR_DEFAULT}"
VT="${VAULT_ROOT_TOKEN:-}"
if [[ -z "$VT" && -f "$REPO_ROOT/environment/.env" ]]; then
  VT="$(grep -E '^VAULT_ROOT_TOKEN=' "$REPO_ROOT/environment/.env" | cut -d= -f2- | tr -d '"' || true)"
fi
if [[ -z "$VT" ]]; then
  VT="$(oc -n vault get secret vault-init -o jsonpath='{.data.root-token}' 2>/dev/null | base64 -d 2>/dev/null || true)"
fi
if [[ -z "$VT" ]]; then
  echo "ERROR: no Vault token (set VAULT_ROOT_TOKEN, or environment/.env, or k8s secret vault/vault-init)" >&2
  exit 1
fi

# --- 1. write a fresh consent grant (integer-typed JSON via the HTTP API) ---
NONCE="$(openssl rand -hex 16)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
echo ">> writing consent grant: user=$USER_NAME scope=read-only uid=$SANDBOX_UID ttl=${TTL}s"
resp="$(curl -sk -H "X-Vault-Token: $VT" -H 'Content-Type: application/json' -X POST \
  "$VAULT_ADDR/v1/secret/data/sandbox-grants/$SANDBOX_UID" \
  -d "{\"data\":{\"version\":1,\"sandbox_uid\":\"$SANDBOX_UID\",\"user\":\"$USER_NAME\",\"scope\":\"read-only\",\"ttl\":$TTL,\"nonce\":\"$NONCE\",\"created\":\"$NOW\"}}")"
if ! grep -q '"version"' <<<"$resp"; then
  echo "ERROR: grant write failed: $resp" >&2; exit 1
fi
echo "   grant OK"

# --- 2. restart the harness so we get a clean pod + SVID ---
echo ">> restarting the agent harness (fresh SVID)"
octry -n agent-sandbox rollout restart deploy/e2e-harness >/dev/null
octry -n agent-sandbox rollout status deploy/e2e-harness --timeout=120s >/dev/null && echo "   harness ready"

# --- 3. wait for the SVID to be issued + verifiable, then drop into the shell ---
# After a pod restart, spire-agent takes ~10-30s to attest the new pod and issue
# its JWT-SVID. Poll the read path until it returns 200 (also rides control-plane
# flaps) rather than racing it with a fixed sleep.
echo ">> waiting for the delegated read path (SVID issuance can take ~30s)..."
ok=0
for i in $(seq 1 12); do
  out=$(oc -n agent-sandbox exec deploy/e2e-harness -c agent -- mcp-call 2>&1 || true)
  if grep -qE 'HTTP 200' <<<"$out"; then
    echo "   read OK (HTTP 200) on try $i — delegated as you, SVID-only:"
    grep -E 'identity I present|tools/call|HTTP 200' <<<"$out" | head -3
    ok=1; break
  fi
  sleep 6
done
[[ "$ok" == "1" ]] || echo "   NOTE: read not yet 200 after ~70s (SVID still issuing, or cluster flapping) — retry mcp-call in the shell."

if [[ "$DO_EXEC" == "1" ]]; then
  echo ">> dropping into the agent shell (no credentials inside; only your SVID)"
  # The data path already works (read 200 above). `oc exec` needs the apiserver,
  # which flaps on this SNO — so retry the attach. A real session lasts >5s; a flap
  # fails in <1s, so only sub-5s failures are treated as flaps and retried.
  for i in 1 2 3 4 5 6 7 8; do
    start=$(date +%s)
    oc -n agent-sandbox exec -it deploy/e2e-harness -c agent -- bash && exit 0
    rc=$?
    (( $(date +%s) - start >= 5 )) && exit $rc   # genuine session ended — don't re-attach
    echo "   (apiserver flap on attach — retry $i in 3s; the loop itself is fine)"
    sleep 3
  done
  echo "   Could not attach after retries — the apiserver is flapping (etcd likely needs a defrag)."
  echo "   The loop still works; retry: oc -n agent-sandbox exec -it deploy/e2e-harness -c agent -- bash"
  exit 1
else
  echo ">> shell ready: oc -n agent-sandbox exec -it deploy/e2e-harness -c agent -- bash"
fi
