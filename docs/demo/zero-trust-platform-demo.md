# Demo walkthrough — Zero-Trust Agentic Platform (ocp-dev)

**What you're proving in one line:** an AI agent that holds **no stored credential — only a
SPIFFE identity** — can *read as the human*, can only *change anything after a human approves it*,
and uses that **same identity to call AI models** (no model token). Tools and models share **one
control plane**: identity to read, a human-approved short-lived capability to elevate.

Audience: works for SA / presales / managers (lead with the beats + the "say this" lines) and for
engineers (the commands + the audit evidence are real).

Total run time: ~12–15 min for all four acts. Each act stands alone.

---

## 0. Pre-flight (do this before the audience is watching)

```bash
# 1) Cluster access (token TTL is short on ocp-dev — re-run if anything says "Unauthorized")
oc login --kubeconfig=$HOME/.kube/ocp-dev.kubeconfig -u kubeadmin \
  -p '<kubeadmin-pw>' --server=https://api.ocp-dev.na-launch.com:6443 --insecure-skip-tls-verify=true
export KUBECONFIG=$HOME/.kube/ocp-dev.kubeconfig

# 2) Local name resolution for the demo routes (ocp-dev records aren't in the lab DNS)
grep -q ocp-dev /etc/hosts || sudo tee -a /etc/hosts <<'EOF'
172.16.2.58 api.ocp-dev.na-launch.com
172.16.2.59 jit-approver-api.apps.ocp-dev.na-launch.com maas.apps.ocp-dev.na-launch.com console-openshift-console.apps.ocp-dev.na-launch.com
EOF

# 3) The "agent" — the credential-less caller pod (deploy if not already Running)
oc -n agent-sandbox get pods -l app=e2e-harness 2>/dev/null | grep Running \
  || oc apply -k services/agent-sandbox/e2e-harness
HPOD=$(oc -n agent-sandbox get pods -l app=e2e-harness --field-selector=status.phase=Running -o jsonpath='{.items[-1].metadata.name}')
echo "agent pod = $HPOD"

# 4) Sanity: the platform is healthy (spire, vault, keycloak, ext-proc, jit-approver, istio, maas)
oc get applications -n openshift-gitops -o custom-columns='APP:.metadata.name,HEALTH:.status.health.status' | sort
oc -n maas get gateway,httproute,inferenceservice
```

> Easy-button alternative for Act 1: `bash hack/test-pfsense-jit-ocp-dev.sh` runs the whole tool
> journey deterministically and prints PASS/FAIL. Use it as a smoke-test before the demo, or to run
> Act 1 hands-free. The manual beats below are the *dramatic* version.

**The "wow" framing to open with:**
> "This agent has no API keys, no passwords — nothing to steal. Watch what it can do, what it can't,
> and what happens when a human steps in."

---

## Act 1 — Tools: read delegated, write only with approval (pfSense)

### Beat 1 — It holds only an identity
```bash
# No secret volumes, no SA-token automount — only its SPIFFE SVID
oc -n agent-sandbox get pod "$HPOD" -o json | jq '.spec.volumes[]|select(.secret!=null)'   # → empty
```
**Say:** *"Its entire credential is a cryptographic identity issued by SPIRE. A prompt-injection or a
pod compromise yields nothing usable."*

### Beat 2 — READ → 200, *as the user*
```bash
oc -n agent-sandbox exec "$HPOD" -c agent -- mcp-call search_firewall_rules
```
→ **HTTP 200**, real pfSense rules. Then show the gateway saw the *human*, not the agent:
```bash
oc -n mcp-gateway logs deploy/ext-proc-delegation | grep credential_delegation | tail -1
# caller_username=arsalan  grant_scope=read-only  credential_injected=true
```
**Say:** *"The agent presented its identity; the platform swapped it for the user's and injected the
real downstream credential — outside the agent's reach. pfSense logs the person, not a shared bot."*

### Beat 3 — WRITE → 403 (fail-closed)
```bash
oc -n agent-sandbox exec "$HPOD" -c agent -- mcp-call create_firewall_rule_advanced \
  '{"interface":"lan","type":"pass","ipprotocol":"inet","protocol":"tcp","source":"any","destination":"any","descr":"demo-rule"}'
```
→ **HTTP 403 `grant_scope_denied`**.
**Say:** *"A change is blocked by default. Not policy-by-convention — the agent physically cannot
elevate itself."*

### Beat 4 — A human approves *in the console UI* (four-eyes)
The approval is done **in the web console**, not the raw API — that's what a real
approver uses.

```bash
# The agent files a scoped, time-boxed request...
RID=$(curl -sS -X POST https://jit-approver-api.apps.ocp-dev.na-launch.com/requests \
  -H 'Content-Type: application/json' -d '{
    "agent_spiffe_id":"spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/e2e0a1b2-c3d4-4e5f-8a9b-000000000001",
    "requester_sub":"agent-e2e","namespace":"agentic-mcp","verbs":["create"],"resources":["firewall"],
    "duration_minutes":10,"justification":"demo: create one firewall rule"}' | jq -r .id)
```

Now open the **JIT Approval Console** and approve it by clicking:

> **https://console.apps.ocp-dev.na-launch.com** — the pending request shows scope,
> justification, requester, and TTL. Click **Approve**. The console calls
> jit-approver `/mint` (authenticated by the console SA via TokenReview), which
> mints the capability. Separation of duties is enforced at the mint layer:
> **approver ≠ requester** — a self-approval returns `403 self-approval denied`.

```bash
# Pull the minted capability for the agent to use
SJWT=$(curl -sS https://jit-approver-api.apps.ocp-dev.na-launch.com/requests/$RID/status | jq -r .session_jwt)
```
**Say:** *"A human approved this in the console — and the platform enforces that the
approver is a different identity than the requester. Approval mints a capability
scoped to exactly this action that expires on its own."*

> Console deployment note (PoC, ocp-dev): the console is live at
> `console.apps.ocp-dev.na-launch.com` (ns `mcp-gateway`). It has **no
> oauth2-proxy/Keycloak** wired here, so the approver identity resolves to
> `anonymous` — real per-human SoD needs the Keycloak client + cookie secret. The
> SoD *mechanism* (approver ≠ requester) is still proven negatively.

### Beat 5 — Elevated WRITE → 200 (a real change)
```bash
oc -n agent-sandbox exec "$HPOD" -c agent -- env JIT_SESSION_JWT="$SJWT" \
  mcp-call create_firewall_rule_advanced \
  '{"interface":"lan","type":"pass","ipprotocol":"inet","protocol":"tcp","source":"any","destination":"any","descr":"demo-rule"}'
```
→ **HTTP 200**, a **real pfSense rule** created (note the id/tracker). Show it, then it's gone when the
capability expires.
**Say:** *"Machine-speed action, human authority, zero standing privilege. Every step is in a
tamper-evident audit trail — who asked, who approved, exact scope, TTL."*

---

## Act 2 — Models: the SAME identity is the credential (MaaS, no tokens)

Set up a shell inside the agent that fetches its JWT-SVID (the *same* identity), then call a model
served by OpenShift AI through the SPIFFE-auth gateway.

```bash
# Helper: run a curl from inside the agent, fetching its own SVID first
modelcall() {  # $1 = extra curl args (path etc.)
  oc -n agent-sandbox exec "$HPOD" -c agent -- sh -c '
    SVID=$(PYTHONPATH=/app/src python3 -c "from agent_harness.svid_bearer import fetch_agent_svid; print(fetch_agent_svid())")
    curl -s -o /dev/null -w "%{http_code}\n" -H "Host: maas.apps.ocp-dev.na-launch.com" '"$1"' \
      ${SVID:+-H "Authorization: Bearer $SVID"} http://maas-gateway-istio.maas.svc.cluster.local'"$2"
}
```

### Beat 1 — No identity, no model
```bash
oc -n agent-sandbox exec "$HPOD" -c agent -- \
  curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: maas.apps.ocp-dev.na-launch.com' \
  http://maas-gateway-istio.maas.svc.cluster.local/v2/models/style-onnx
```
→ **401**. **Say:** *"No anonymous model access. The gateway demands a verifiable identity."*

### Beat 2 — The agent's SVID → 200, real inference
```bash
oc -n agent-sandbox exec "$HPOD" -c agent -- sh -c '
  SVID=$(PYTHONPATH=/app/src python3 -c "from agent_harness.svid_bearer import fetch_agent_svid; print(fetch_agent_svid())")
  curl -s -H "Host: maas.apps.ocp-dev.na-launch.com" -H "Authorization: Bearer $SVID" \
    http://maas-gateway-istio.maas.svc.cluster.local/v2/models/style-onnx'
```
→ **200**, real OpenVINO model metadata (FP32 `[1,3,224,224]`). (Optional: POST to `/v2/models/style-onnx/infer`
for a live forward pass.)
**Say:** *"That's the exact same SPIFFE identity it used for the firewall — now authenticating to an
AI model. There is no model API key anywhere. Authorino validated the SVID against SPIRE's OIDC and
authorized on the identity itself."*

### Beat 3 — A real external LLM (OpenRouter / Claude) through the same gateway
The gateway also fronts a **real external LLM** — OpenRouter's `claude-sonnet-4`.
The OpenRouter API key lives **only in Vault** and is injected **server-side** by
the MaaS `llm-proxy`; the agent never sees it.

```bash
oc -n agent-sandbox exec "$HPOD" -c agent -- sh -c '
  SVID=$(PYTHONPATH=/app/src python3 -c "from agent_harness.svid_bearer import fetch_agent_svid; print(fetch_agent_svid())")
  curl -s -H "Host: maas.apps.ocp-dev.na-launch.com" -H "Authorization: Bearer $SVID" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"anthropic/claude-sonnet-4\",\"messages\":[{\"role\":\"user\",\"content\":\"say HELLO\"}]}" \
    http://maas-gateway-istio.maas.svc.cluster.local/openrouter/chat/completions'
```
→ **200**, Claude replies "HELLO". No token → **401**.
**Say:** *"A frontier LLM, reached with nothing but the agent's identity. The model
vendor's API key never touches the agent — the platform injects it server-side from
Vault, for this one request."*

---

## Act 3 — Premium models = approve-to-elevate (the unifying finale)

The premium model path requires the SVID **and** a human-approved capability — the **same** mint-gate
as the firewall write.

### Beat 1 — Premium with identity alone → denied
```bash
oc -n agent-sandbox exec "$HPOD" -c agent -- sh -c '
  SVID=$(PYTHONPATH=/app/src python3 -c "from agent_harness.svid_bearer import fetch_agent_svid; print(fetch_agent_svid())")
  curl -s -o /dev/null -w "%{http_code}\n" -H "Host: maas.apps.ocp-dev.na-launch.com" \
    -H "Authorization: Bearer $SVID" http://maas-gateway-istio.maas.svc.cluster.local/premium/v2/models/style-onnx'
```
→ **403**. **Say:** *"Standard model: identity is enough. Premium model: identity isn't — it needs a
human-approved capability."*

### Beat 2 — Approve (reuse the mint-gate from Act 1) → 200
Mint a capability exactly as in Act 1 Beat 4 (`$SJWT`), then:
```bash
oc -n agent-sandbox exec "$HPOD" -c agent -- sh -c '
  SVID=$(PYTHONPATH=/app/src python3 -c "from agent_harness.svid_bearer import fetch_agent_svid; print(fetch_agent_svid())")
  curl -s -H "Host: maas.apps.ocp-dev.na-launch.com" -H "Authorization: Bearer $SVID" \
    -H "X-JIT-Capability: '"$SJWT"'" \
    http://maas-gateway-istio.maas.svc.cluster.local/premium/v2/models/style-onnx'
```
→ **200**, real inference. (The same gate guards the **premium external LLM** too:
`/premium/openrouter` with SVID only → **403**; with SVID **+** `X-JIT-Capability`
→ **200**, `claude-opus-4`.) **Say (the closer):**
> *"Tools and models, one control plane: your identity lets you read; a human-approved, short-lived
> capability lets you do the expensive or dangerous thing. No standing credentials anywhere — for
> tools or for AI. That's what makes it safe to put an autonomous agent near production."*

---

## Act 4 — The agent's *brain* runs on MaaS, and you can watch it (operator view)

### Beat 1 — The brain itself reasons credential-less through MaaS
The agent's Claude **brain** authenticates to the model with its own SVID — no model
key in the pod. A tiny loopback proxy injects a fresh SVID per request and rewrites
the Anthropic call onto the MaaS `/openrouter` route.

```bash
# The brain run emits an assistant turn proxied through MaaS (SVID-authed)
oc -n agent-sandbox exec "$HPOD" -c agent -- env MAAS_BRAIN=1 \
  PYTHONPATH=/app/src python3 -m agent_harness.runner --prompt 'reply: hello from the SVID-authed brain' --max-turns 2
# llm-proxy log: "POST /v1/messages?beta=true HTTP/1.1" 200   (reached only after Authorino validated the SVID)
```
**Say:** *"It's not just tool calls — the model that *drives* the agent is itself
behind the same identity wall. The agent has nothing to steal, not even for its own
reasoning."*

### Beat 2 — Watch / drive the agent live (webshell)
The console embeds a same-origin xterm.js **webshell** that `oc exec`s into the
agent pod — scope-locked to one pod, resolved server-side, gated by an owner/admin
check.

> Open **https://console.apps.ocp-dev.na-launch.com**, click **Webshell** on the
> *"e2e-harness (agent-sandbox PoC)"* card (direct:
> `…/api/agents/e2eharness/webshell/ui`). You get a live terminal in the agent pod.

**Say:** *"An operator can watch and drive the exact pod — but the shell is locked to
that one sandbox, resolved server-side, never from the browser."*

> PoC notes (ocp-dev): no oauth2-proxy, so actor/owner are `anonymous` (no real
> per-human SoD on the shell); the Agent record is seeded via ConfigMap and pinned
> to the current pod hash (update it if the pod is recreated). Exec RBAC is
> namespaced to `agent-sandbox`.

---

## Talk track / likely questions
- **"Where's the token?"** There isn't one. The agent holds only a SPIFFE SVID (auto-rotating). The
  downstream credential for tools is injected by the platform for one request and never reaches the
  agent; for models, the SVID itself is the auth.
- **"What if the agent is jailbroken?"** It still can't write or hit a premium model without a human
  approving — and it has no stored secret to exfiltrate. Blast radius = its read scope, which expires.
- **"How is this auditable?"** Every elevation is a tamper-evident record: requester, approver
  (≠ requester), exact scope, TTL, single-use. The capability *is* the receipt.
- **"Is it bespoke?"** One small custom component (`ext-proc-delegation`); everything else is
  supported/established: SPIRE, Keycloak (RHBK), Vault, Kyverno, Istio/OSSM, Authorino/Kuadrant,
  KServe/OpenShift AI, OpenShift GitOps.

## Architecture / deeper dives
- Tool plane (read-delegated / write-approved): `docs/showroom` (UC1, UC2), `docs/reviews/phaseA-*`.
- Model plane (SVID-auth MaaS + premium tier): `docs/design/maas-spiffe-auth.md`,
  `platform/rhoai-maas/spiffe-auth/`.
- Deterministic regression for Act 1: `hack/test-pfsense-jit-ocp-dev.sh`.

## Troubleshooting (live demo)
- **"Unauthorized" mid-demo** → the kube:admin token lapsed; re-run `oc login` (pre-flight step 1).
- **harness pod missing** → `oc apply -k services/agent-sandbox/e2e-harness`; wait Ready.
- **READ returns `grant_malformed`** → refresh the consent grant (the anchor script does this; or
  re-write `secret/data/sandbox-grants/<uid>` with numeric `version`/`ttl` + a `created` RFC3339).
- **Model call hangs (000)** → check egress NetworkPolicy from `agent-sandbox` to `maas:80` exists,
  and that `maas-gateway-istio` + the InferenceService pods are Running.
- **Control-plane flaps** (slow responses) → master-node load; harmless to the demo, just retry.
```
