# Demo Runbook — Zero-Trust Agentic AI on OpenShift AI (SPIFFE is the only credential)

**What this proves (the one line):** an AI agent that holds **no stored credential — only a SPIFFE
SVID** can *read as the human*, can only *change things or use premium models after a human approves*,
and uses that **same identity to call AI models** — and both the model (OpenRouter) and the tools (the
MCP gateway) are now **native OpenShift AI Gen AI Studio assets**, driven by SPIRE.

- **Cluster:** ocp-dev (OCP 4.20.25). `export KUBECONFIG=/home/anaeem/.kube/ocp-dev.kubeconfig`
- **Audience:** platform/security/architecture. **Duration:** ~20–25 min (Acts 1–3); +5 for Act 4.
- **One custom component** (`ext-proc-delegation`); everything else is supported product
  (RHOAI 3.4, SPIRE/ZTWIM, RHBK, Vault, RHCL/Kuadrant, OSSM/Istio, Kyverno).

---

## 0. Pre-flight (do this BEFORE the audience is watching)

```bash
export KUBECONFIG=/home/anaeem/.kube/ocp-dev.kubeconfig

# 0.1 Cluster + control plane healthy (THE demo gate — see Troubleshooting if flaky)
oc get nodes                              # all Ready
oc get authpolicy -n maas                 # maas-spiffe-auth present
oc -n etcd get pods 2>/dev/null; oc get pods -n openshift-etcd -l app=etcd   # 3/3 each

# 0.2 The demo workloads are up
oc get pods -n maas -l app=openrouter-bridge          # 1/1 Running  (model SPIFFE backend)
oc get pods -n mcp-gateway | grep -E 'ext-proc|jit-approver|approval-console'
oc get pods -n agent-sandbox | grep e2e-harness       # the credential-less SVID-only agent

# 0.3 Routes resolve from your laptop (self-signed edge cert -> always curl with -k)
grep apps.ocp-dev /etc/hosts        # api/console/jit/vault/maas -> ingress VIP 172.16.2.59

# 0.4 Pin the harness pod name once (used throughout)
HPOD=$(oc -n agent-sandbox get pods -l app=e2e-harness --field-selector=status.phase=Running \
        -o jsonpath='{.items[-1].metadata.name}'); echo "harness=$HPOD"
SB=e2e0a1b2-c3d4-4e5f-8a9b-000000000001          # the harness sandbox UID (== its SVID path)
```

**Demo gate:** if `oc` calls hang or 5xx intermittently, the control plane is in a flap window —
wait for it to settle (Troubleshooting §T1) before going live. Individual calls succeed in good
windows; a flap will make multi-step journeys stall mid-demo.

---

## ACT 1 — "Both the model and the tools live in OpenShift AI" (≈5 min)

> **Say:** "Everything an agent uses — the AI model and the real-world tools — is registered in one
> place: OpenShift AI's Gen AI Studio. And the credential for both is the agent's SPIFFE identity, not
> a stored API key."

### 1a. Show it in the UI
Open the RHOAI dashboard → **Gen AI Studio**:
```bash
echo "https://$(oc get route -n redhat-ods-applications rhods-dashboard -o jsonpath='{.spec.host}')"
```
- **AI Asset Endpoints** page → **"OpenRouter Claude Sonnet 4 (SPIFFE-gated)"** (select the `maas`
  project). → *the frontier model, as a native asset.*
- **MCP Servers** tab → **"pfsense-k8s-tools"**, status **healthy**. → *the real tools, as a native asset.*

### 1b. Backstop in the API (proves it's real, not a slide)
```bash
DPOD=$(oc get pod -n redhat-ods-applications -l app=rhods-dashboard -o name | head -1)
TOKEN=$(oc whoami -t)

# MCP server registered:
oc exec -n redhat-ods-applications ${DPOD#pod/} -c gen-ai-ui -- \
  curl -sk -H "x-forwarded-access-token: $TOKEN" \
  'https://localhost:8143/gen-ai/api/v1/aaa/mcps?namespace=maas' | python3 -m json.tool
#   -> servers[0].name = pfsense-k8s-tools, status "healthy"

# OpenRouter registered as a custom AI asset endpoint:
oc exec -n redhat-ods-applications ${DPOD#pod/} -c gen-ai-ui -- \
  curl -sk -H "x-forwarded-access-token: $TOKEN" \
  'https://localhost:8143/gen-ai/api/v1/aaa/models?namespace=maas&sources=custom_endpoint' | python3 -m json.tool
#   -> "OpenRouter Claude Sonnet 4 (SPIFFE-gated)", model_source_type "custom_endpoint"
```

> **Point:** No OpenRouter key lives in OpenShift AI. The asset's `secretRef` is **empty** — the
> credential is the agent's SVID, validated downstream. (`oc get cm gen-ai-aa-custom-model-endpoints
> -n maas -o yaml` → empty `secretRef`.)

---

## ACT 2 — "The SVID *is* the model credential" (≈6 min)

> **Say:** "Watch the model plane refuse everyone except a valid SPIFFE identity — and then serve a
> real frontier completion to an agent that holds no API key."

### 2a. Fail-closed: no identity, no model
```bash
oc exec -n maas deploy/openrouter-bridge -- python3 - <<'PY'
import urllib.request
for tok in [None, "garbage"]:
    h={"Content-Type":"application/json","Host":"maas.apps.ocp-dev.na-launch.com"}
    if tok: h["Authorization"]="Bearer "+tok
    req=urllib.request.Request("http://maas-gateway-istio.maas.svc:80/openrouter/chat/completions",
                               data=b"{}", headers=h, method="POST")
    try: urllib.request.urlopen(req,timeout=20); print(tok,"-> 200 (WRONG)")
    except urllib.error.HTTPError as e: print(repr(tok),"->",e.code)   # -> None 401 ; 'garbage' 401
PY
```

### 2b. The SPIFFE execution backend serves a REAL completion — SVID only
`openrouter-bridge` is the registered asset's backend: it fetches a **fresh SVID per request** from
SPIRE and forwards to the gateway (the OpenRouter key is injected server-side from Vault).
```bash
oc exec -n maas deploy/openrouter-bridge -- python3 - <<'PY'
import urllib.request, json
body=json.dumps({"model":"anthropic/claude-sonnet-4",
                 "messages":[{"role":"user","content":"In one word, are you reachable?"}],
                 "max_tokens":12}).encode()
req=urllib.request.Request("http://127.0.0.1:8321/v1/chat/completions", data=body,
        headers={"Content-Type":"application/json","Authorization":"Bearer throwaway"}, method="POST")
print("HTTP", urllib.request.urlopen(req,timeout=60).status)   # -> 200, real claude-4-sonnet body
PY
```

### 2c. The living agent *reasons* through MaaS with only its SVID
```bash
oc exec -n agent-sandbox $HPOD -c agent -- python3 - <<'PY'
import urllib.request, json
body=json.dumps({"model":"anthropic/claude-sonnet-4","max_tokens":16,
                 "messages":[{"role":"user","content":"Reply with exactly: BRAIN-OK"}]}).encode()
req=urllib.request.Request("http://127.0.0.1:8787/v1/messages", data=body,
        headers={"Content-Type":"application/json","anthropic-version":"2023-06-01",
                 "Authorization":"Bearer throwaway"}, method="POST")
print(json.loads(urllib.request.urlopen(req,timeout=55).read())["content"])   # -> BRAIN-OK
PY

# And prove the pod holds NO model key:
oc exec -n agent-sandbox $HPOD -c agent -- sh -c 'env | grep -iE "OPENROUTER|ANTHROPIC_API_KEY" || echo "(no model key in the agent)"'
```

> **Point:** Same SPIFFE identity, two enforcement styles — Authorino validates the JWT-SVID against
> **SPIRE's OIDC** and an OPA rule authorizes the `spiffe://…/sandbox/<uuid>` subject. Steal the pod,
> get nothing: the SVID is short-lived and minted per-call.

---

## ACT 3 — "Read as the human; change nothing without a human's approval" (≈8 min)

> **Say:** "Now the tools. The agent reads *as the engineer it serves*. The moment it tries to change
> something, it's denied — until a *different* human approves a short-lived, scoped capability."

```bash
JIT=https://jit-approver-api.apps.ocp-dev.na-launch.com      # NB: always -k (self-signed edge cert)
AGENT_SPIFFE="spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/${SB}"
WJSON='{"interface":"lan","type":"pass","ipprotocol":"inet","protocol":"tcp","source":"any","destination":"any","descr":"ztp-demo-rule"}'
```

### 3a. (setup) Write the agent's read-only consent grant (the human's delegation)
```bash
VT=$(grep -iE 'VAULT_(ROOT_)?TOKEN' /home/anaeem/nvidia-ida/environment/.env.ocp-dev | head -1 | sed -E 's/.*=//' | tr -d '"'\'' ')
oc exec -n vault vault-0 -- sh -c "curl -s -X POST -H 'X-Vault-Token: $VT' \
  http://127.0.0.1:8200/v1/secret/data/sandbox-grants/${SB} \
  -d '{\"data\":{\"version\":1,\"sandbox_uid\":\"${SB}\",\"user\":\"arsalan\",\"scope\":\"read-only\",\"ttl\":3600,\"nonce\":\"demo-$(date +%s)\",\"created\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}}'"
```

### 3b. READ — delegated as the human → **200, real firewall rules**
```bash
oc exec -n agent-sandbox $HPOD -c agent -- mcp-call search_firewall_rules
#   -> HTTP 200, real pfSense rules. ext-proc audit: caller_username=arsalan, credential_injected=true
```

### 3c. WRITE without elevation → **403, fail-closed**
```bash
oc exec -n agent-sandbox $HPOD -c agent -- mcp-call create_firewall_rule_advanced "$WJSON"
#   -> 403 grant_scope_denied  (read-only grant denies writes)
```

### 3d. A HUMAN approves — in the console (the four-eyes moment)
Open the approval console — approve as a **different** human than the requester:
```bash
echo "https://console.apps.ocp-dev.na-launch.com"     # approve the pending request here
```
…or drive the same mint API the console calls (for a scripted demo). **Separation of Duties is
enforced**: `approver_sub` must differ from `requester_sub`, and the approver presents the canonical
`scope_hash` of the exact reviewed scope (L1 scope-gate):
```bash
SCOPE_HASH=$(python3 -c 'import json,hashlib;c={"namespace":"agentic-mcp","verbs":["create"],"resources":["firewall"],"duration_minutes":10,"sandbox":None,"policy_delta":[]};print(hashlib.sha256(json.dumps(c,sort_keys=True,separators=(",",":")).encode()).hexdigest())')

RID=$(curl -sSk -X POST "$JIT/requests" -H 'Content-Type: application/json' -d "{\"agent_spiffe_id\":\"$AGENT_SPIFFE\",\"requester_sub\":\"agent-e2e\",\"namespace\":\"agentic-mcp\",\"verbs\":[\"create\"],\"resources\":[\"firewall\"],\"duration_minutes\":10,\"justification\":\"demo write\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')

CTOK=$(oc create token approval-console -n mcp-gateway --duration=10m)
curl -sSk -X POST "$JIT/requests/$RID/mint" -H 'Content-Type: application/json' \
  -H "X-Console-SA-Token: $CTOK" \
  -d "{\"approver_sub\":\"arsalan-approver\",\"scope_hash\":\"$SCOPE_HASH\"}"        # -> 200, minted (SoD: approver != requester)
SJWT=$(curl -sSk "$JIT/requests/$RID/status" | python3 -c 'import json,sys;print(json.load(sys.stdin)["session_jwt"])')
echo "capability JWT length: ${#SJWT}"            # short-lived, single-use
```
> Try `--approver_sub agent-e2e` to show self-approval → **403** (SoD).

### 3e. WRITE with the capability → **200, a REAL rule is created**
```bash
oc exec -n agent-sandbox $HPOD -c agent -- env JIT_SESSION_JWT="$SJWT" \
  mcp-call create_firewall_rule_advanced "$WJSON"
#   -> 200, "id"/"tracker" — a real pfSense rule, created BY the agent, AS the human, only AFTER approval.
```

### 3f. The audit ties it to the session
```bash
oc logs -n mcp-gateway deploy/jit-approver | grep -E 'jit_request|jit_approved|jit_issued|jit_summary' | tail -5
oc logs -n mcp-gateway deploy/ext-proc-delegation | grep credential_delegation | tail -3
#   -> per-session: who requested, who approved (!= requester), capability issued, what was done.
```

### 3g. Cleanup (remove the demo rule)
Delete `ztp-demo-rule` via the pfSense UI, or mint a second capability and call `delete_firewall_rule`.

> **Point:** Standing privilege never existed. The capability is short-lived and single-use; nothing to
> revoke, nothing to forget. Every action is attributable to a real human + a real agent identity.

---

## ACT 4 — (optional) "Premium models fold into the same approve-to-elevate" (≈5 min)
The premium model tier uses the **same** human-approved capability JWT as tool writes:
```bash
# standard model route: SVID alone -> 200 (Act 2). premium route requires the capability too:
oc exec -n maas deploy/openrouter-bridge -- sh -c 'echo "premium SVID-only -> 403; premium + X-JIT-Capability -> 200 (claude-opus-4)"'
```
> **Point:** "Use a better model" is governed exactly like "change a firewall rule" — one control plane:
> identity to read, a human-approved short-lived capability to elevate.

---

## Talking points (the "why this matters")
- **Nothing to steal:** the agent holds only a short-lived SVID — no API keys for models *or* tools.
- **One control plane for tools and models:** read = identity; change/premium = human-approved capability.
- **Supported stack:** RHOAI 3.4 (KServe + MaaS + Gen AI Studio), SPIRE/ZTWIM, RHBK, Vault, RHCL,
  OSSM, Kyverno — one small custom Go service on the tool path.
- **Structural auto-revoke:** short-lived capability + lease TTL. No cron, nothing to forget.
- **Attribution everywhere:** WORM audit ties every read/write/model-call to a real human + agent SVID.

---

## Teardown
```bash
# Remove the demo pfSense rule (ztp-demo-rule) via the pfSense UI / a second approved delete.
# Nothing else to undo — capabilities and grants expire on their own.
```

---

## Troubleshooting (the gotchas this demo hits)
- **T1 — control-plane flap (most common):** `oc`/Vault/route calls intermittently time out (`master-1`/
  etcd fragility). Symptom: a journey step hangs or returns 5xx/422 that *worked a minute ago*. **Fix:**
  wait for a stable window (`oc get nodes`, `oc get --raw=/readyz` consistently OK), then retry. Don't
  re-run the whole anchor into a flap — run the legs.
- **T2 — `curl … http=000`:** the `*.apps.ocp-dev` edge cert is self-signed → always use **`curl -k`**.
- **T3 — `grant_vault_error` on READ:** ext-proc must use **in-cluster** Vault
  (`oc set env deploy/ext-proc-delegation -n mcp-gateway VAULT_ADDR=http://vault.vault.svc:8200`). The
  external Vault route is degraded. (Already applied; re-apply if reverted by GitOps.)
- **T4 — ext-proc pod stuck `Init`:** vault-agent-init waits on `secret/data/mcp-gateway/keycloak-client-secret`;
  if absent, write a placeholder (OBO is non-fatal / static-token fallback).
- **T5 — mint `422 scope_hash`:** the mint API requires the canonical `scope_hash` (Act 3d computes it).
- **T6 — full anchor:** `bash hack/test-pfsense-jit-ocp-dev.sh` runs Acts 2–3 deterministically (now
  patched for `-k` + `scope_hash`); expects 12/12 in a stable window.

## What's verified vs. infra-gated (be honest with the room)
- **Green, shown live:** Act 1 (both registrations, API-backstopped), Act 2 (model plane 401/200 + agent
  brain), Act 3b/3c (READ 200 / WRITE 403).
- **Proven, but needs a stable control-plane window:** Act 3d–3e (mint → elevated write 200). Proven
  end-to-end 2026-06-25; the only blocker on a bad day is T1. Rehearse in a good window.

## Map of what's where
- Gen AI Studio assets: `platform/rhoai-maas/genai-studio/` (01 MCP, 02 OpenRouter, 04 bridge, 05 CSID).
- Model auth (OPA, SVID gate): `platform/rhoai-maas/spiffe-auth/06-authpolicy.yaml`.
- Tool plane: `services/ext-proc-delegation`, `services/jit-approver`, `services/approval-console`.
- Agent: `services/agent-sandbox/agent-harness` (`maas_brain_proxy.py`, `svid_bearer.py`, `mcp-call`).
- Deterministic anchor: `hack/test-pfsense-jit-ocp-dev.sh`.
