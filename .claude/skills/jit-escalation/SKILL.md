---
name: jit-escalation
description: Request a time-boxed, scoped privilege escalation after receiving a 403 or extAuthz DENY response. Use this skill ONLY when an operation was blocked by the platform's authorization layer and the operation is genuinely required to progress a legitimate task. Do NOT invoke proactively or speculatively.
---

# JIT Escalation Skill

## When to use

Invoke this skill ONLY after:
- Receiving an HTTP 403 response from a cluster API call, OR
- Receiving an `ext_authz` DENY decision logged from `kyverno-authz-server.kyverno.svc.cluster.local:9081` or `ext-proc-delegation.mcp-gateway.svc.cluster.local:9000`.

Do NOT invoke this skill:
- Speculatively before attempting an operation.
- To obtain standing access or reusable credentials.
- To access resources outside the current task's documented scope.
- If you already hold a valid escalated token for the required scope.

## Core invariants

1. **Read-only derived sub-identity by default.** The escalated identity is a scoped, ephemeral ServiceAccount — not your primary identity. Default to requesting only the minimum verbs needed.
2. **Never hold downstream credentials.** The ephemeral SA token lives at a tmpfs path injected into the pod. Read it at the point of use; do not copy it to memory, logs, or any persistent store.
3. **Downstream sees user identity.** If the escalated session involves calling a downstream MCP server, token exchange (RFC 8693) must still be performed so the downstream server sees the user's identity, not the escalated SA token.
4. **Every escalation requires human approval.** Approval happens when Arsalan merges the generated PR in Gitea (`https://git.arsalan.io/anaeem/nvidia-ida`). There is no Slack channel — the PR merge IS the approval signal. Do not poll for approval more frequently than every 30 seconds.
5. **Riskier follow-on = new request.** If, after escalation, you discover that completing the task requires broader permissions than originally requested, stop, let the current escalation expire, and file a new request with the updated scope. Do not attempt to stretch an existing escalation.

## Scope ceiling (hard limits enforced by jit-approver)

| Limit | Value |
|-------|-------|
| Maximum duration | 60 minutes |
| Scope | Single namespace only |
| Cluster-scoped access | Never |
| `secrets` read/delete cluster-wide | Forbidden |
| Node access | Forbidden |
| RBAC mutation verbs (`bind`, `escalate`, `impersonate`) | Forbidden |

Any request that exceeds these limits will be rejected by the jit-approver service before a PR is generated.

## Procedure

### Step 1 — ESTIMATE minimal scope

Before calling the API, determine the minimum required scope. Ask yourself:
- Which single namespace contains the resource I need?
- Which API group and resource type is required?
- Which verbs are strictly needed (prefer `get`, `list` over `update`, `patch`, `delete`)?
- What is the shortest duration that would allow the task to complete (max 60 minutes)?
- What is the specific justification for this access?

Construct an `EscalationRequest` (see schema below).

### Step 2 — REQUEST

POST the `EscalationRequest` JSON to the jit-approver service:

```
POST http://jit-approver.mcp-gateway.svc.cluster.local:8080/requests
Content-Type: application/json

<EscalationRequest JSON>
```

The service will:
1. Validate the request against the scope ceiling.
2. Generate a Gitea PR in `anaeem/nvidia-ida` with the proposed RBAC manifest.
3. Return a response containing the request `id` and current `status`.

Save the returned `id` for polling.

### Step 3 — WAIT for approval

Poll the request status at most once every 30 seconds:

```
GET http://jit-approver.mcp-gateway.svc.cluster.local:8080/requests/<id>/status
```

Continue polling until `state == "issued"`. Once issued, the response body contains
**both** credentials needed for the session:

```json
{
  "state": "issued",
  "session_jwt": "<RS256-signed session-capability JWT>",
  "sa_token":    "<short-lived Kubernetes SA token>",
  "expires_at":  "<RFC3339 expiry matching the approved window>"
}
```

- `session_jwt` — a short-lived RS256 JWT signed by jit-approver (JWKS at
  `http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks`).
  Claims: `sub=<session_id>`, `iss="https://jit-approver.mcp-gateway.svc.cluster.local:8080"`,
  `aud=["kyverno-authz"]`, `tool_scope=[<approved MCP tool names>]`, `nbf`/`iat`/`exp` aligned
  to the approved window.  This JWT is the **agent's scoped capability token** — proof that
  jit-approver approved this exact session for these exact tools.  It is NOT a downstream
  service credential; it never leaves the gateway layer.
- `sa_token` — the Vault-minted ephemeral Kubernetes SA token for direct Kube API actions.

The channel for this exchange is the **SVID-mTLS** session between the agent pod and
jit-approver (SPIFFE mTLS, not plain HTTP).  Credentials are in the response body,
not injected by a Vault sidecar — the "Vault injector at pod start" approach is
impossible for dynamically-created sessions (chicken-and-egg: the Vault role does not
exist until the PR is merged).  See ADR 0006.

Do not poll more frequently than every 30 seconds. If the status is `denied`, stop —
do not retry with a different request without understanding why the request was denied.

### Step 4 — ACT

Use `session_jwt` and `sa_token` from the Step 3 response as follows:

**For a dangerous MCP tool call through the gateway** (tools blocked by the Kyverno
`dangerous-tools-admins-only` policy):

```
POST https://mcp-gateway.apps.anaeem.na-launch.com/mcp
Authorization: Bearer <user-keycloak-token>
X-JIT-Session-JWT: <session_jwt>
Content-Type: application/json

{ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "<tool>", ... } }
```

The gateway forwards `X-JIT-Session-JWT` to the Kyverno ext_authz check (before ext-proc).
Kyverno verifies the JWT signature against the jit-approver JWKS, checks `exp`/`aud`/`iss`,
and confirms the requested tool is in `tool_scope`.  The session JWT passes the gate
statelessly — no live callback to jit-approver at check time.

**For a direct Kubernetes API action** (read/write K8s resources within the approved scope):

```bash
kubectl --token="${sa_token}" --server=https://api.anaeem.na-launch.com:6443 \
  <verb> <resource> -n <approved_namespace>
```

The `sa_token` carries a ServiceAccount name containing the session ID, so every Kube API
server audit-log entry is attributed to `system:serviceaccount:<ns>:jit-<session_id>`.

**Invariants:**
- The `session_jwt` is the agent's own scoped capability (approved tool list, signed, expiring).
  It is NOT a downstream service credential — holding it does not violate the no-credential-
  passing invariant, which targets downstream service creds proxied via ext-proc in UC1.
- Do not cache either token beyond immediate use.
- Do not use `session_jwt` past its `exp` claim — the Kyverno gate will reject it (exp elapsed).
- Do not use `sa_token` to access resources outside the approved namespace or beyond the
  approved verbs/resources — the Vault role's `allowed_kubernetes_namespaces` and
  `generated_role_rules` enforce this at the Kube API server.
- If performing downstream MCP calls that reach a third-party MCP server (not the gateway
  itself), still execute RFC 8693 token exchange to present the user's identity downstream —
  not the escalated SA token.

### Step 5 — Never renew

When the escalation expires (per `durationMinutes`), stop. Expiry is final. Do not attempt to re-use the token path or request a renewal. If additional work remains, file a new `EscalationRequest` from Step 1.

### Step 6 — SUMMARIZE

After the escalation session ends (task complete or token expired), produce a `SessionSummary` (see schema below) and emit it to the audit log with `event: jit.session.end`.

## JSON Schemas

### EscalationRequest

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "EscalationRequest",
  "type": "object",
  "required": ["namespace", "verbs", "resources", "durationMinutes", "justification", "requestorSvid"],
  "additionalProperties": false,
  "properties": {
    "namespace": {
      "type": "string",
      "description": "Single namespace where access is required. Must be one of the fixed platform namespaces.",
      "enum": [
        "zero-trust-workload-identity-manager",
        "keycloak",
        "vault",
        "mcp-gateway",
        "kyverno",
        "agentic-mcp",
        "agent-sandbox",
        "agentic-observability"
      ]
    },
    "verbs": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Kubernetes RBAC verbs required. Forbidden: 'bind', 'escalate', 'impersonate'.",
      "minItems": 1
    },
    "resources": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["group", "resource"],
        "properties": {
          "group": { "type": "string", "description": "API group, e.g. '' for core, 'apps', 'route.openshift.io'" },
          "resource": { "type": "string", "description": "Resource plural name, e.g. 'pods', 'deployments'" }
        }
      },
      "description": "Resources to access. Do not include 'secrets' unless strictly required and justification explicitly addresses it.",
      "minItems": 1
    },
    "durationMinutes": {
      "type": "integer",
      "minimum": 1,
      "maximum": 60,
      "description": "How long the escalation should remain active. Must be <= 60."
    },
    "justification": {
      "type": "string",
      "minLength": 20,
      "description": "Human-readable explanation of why this access is needed and what task it unblocks. Be specific."
    },
    "requestorSvid": {
      "type": "string",
      "pattern": "^spiffe://anaeem\\.na-launch\\.com/",
      "description": "The SPIFFE SVID of the requesting workload. Must be in trust domain anaeem.na-launch.com."
    },
    "taskReference": {
      "type": "string",
      "description": "Optional: Gitea issue or PR reference that this escalation supports."
    }
  }
}
```

### SessionSummary

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "SessionSummary",
  "type": "object",
  "required": ["requestId", "namespace", "startedAt", "endedAt", "reason", "actionsPerformed", "outcome"],
  "additionalProperties": false,
  "properties": {
    "requestId": {
      "type": "string",
      "description": "The id returned by the jit-approver POST /requests response."
    },
    "namespace": {
      "type": "string",
      "description": "The namespace in which escalated actions were taken."
    },
    "startedAt": {
      "type": "string",
      "format": "date-time",
      "description": "RFC3339 timestamp when the first escalated action was taken."
    },
    "endedAt": {
      "type": "string",
      "format": "date-time",
      "description": "RFC3339 timestamp when the session ended (task complete or token expired)."
    },
    "reason": {
      "type": "string",
      "description": "The original justification from the EscalationRequest."
    },
    "actionsPerformed": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["ts", "verb", "resource", "name"],
        "properties": {
          "ts": { "type": "string", "format": "date-time" },
          "verb": { "type": "string" },
          "resource": { "type": "string" },
          "name": { "type": "string", "description": "Resource name acted upon." },
          "outcome": { "type": "string", "enum": ["success", "error"] }
        }
      },
      "description": "List of every Kubernetes API call made under the escalated identity."
    },
    "outcome": {
      "type": "string",
      "enum": ["completed", "expired", "aborted"],
      "description": "How the session ended."
    },
    "followUpRequired": {
      "type": "boolean",
      "description": "Set to true if a new EscalationRequest will be needed to complete the remaining work."
    },
    "followUpJustification": {
      "type": "string",
      "description": "If followUpRequired is true, describe what additional scope is needed and why."
    }
  }
}
```
