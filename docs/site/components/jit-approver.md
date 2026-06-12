# jit-approver — JIT Approval Gate

## Purpose

`jit-approver` implements the human-in-the-loop Just-In-Time approval gate for privileged MCP tool calls and elevated Kubernetes access (UC2). When an agent is denied access, it requests a scoped, time-boxed grant through `jit-approver`, which:

1. Validates the requested scope against the configured ceiling
2. Opens a **Gitea pull request** carrying the grant manifest and justification
3. Waits for a human to merge the PR (the approval act)
4. Verifies the merge webhook (HMAC + repo allowlist)
5. Re-reads the scope from the committed manifest and re-validates it
6. Calls the Vault Kubernetes secrets engine to mint an ephemeral SA + Role + RoleBinding
7. Mints a signed RS256 **session-capability JWT** for the Kyverno gate
8. Writes both credentials to `secret/data/jit/<session>` in Vault KV
9. Returns credentials to the agent via `GET /requests/{id}/status` over SVID-mTLS
10. Posts a summary PR comment and emits an OTel span when the session closes

---

## Placement

| Property | Value |
|---|---|
| Cluster | `anaeem` (SNO, OCP 4.20.11) |
| Namespace | `mcp-gateway` |
| Image | `oci.arsalan.io/nvidia-ida/jit-approver:dev` |
| Internal service | `jit-approver.mcp-gateway.svc.cluster.local:8080` (HTTP) |
| Webhook Route | OCP Route exposing `:9443` for inbound Gitea merge webhooks only |
| JWKS endpoint | `http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks` |
| Source | `services/jit-approver/` (Python) |
| Gitea repo | `anaeem/nvidia-ida` at `https://git.arsalan.io` |

---

## Approval flow summary

```
Agent denied → POST /request {scope, session-id, justification}
  ↓ ceiling check → reject if over-ceiling
jit-approver opens Gitea PR (grant manifest committed)
  ↓ human reviews and merges PR
Gitea fires HMAC-signed webhook
  ↓ HMAC verify + repo allowlist + scope re-read from git
jit-approver calls Vault kubernetes engine → mint SA+Role+RoleBinding
jit-approver mints RS256 session-capability JWT
  ↓ writes {sa_token, session_jwt} to secret/data/jit/<session>
Agent polls GET /requests/{id}/status → receives credentials
  ↓ session window expires
Vault lease TTL deletes SA+Role+RoleBinding (auto-revoke)
jit-approver reaper deletes kubernetes/roles/jit-<session>
```

---

## Session-capability JWT (ADR 0006)

When a session is issued, `jit-approver` mints an RS256 JWT:

```json
{
  "iss": "https://jit-approver.mcp-gateway.svc.cluster.local:8080",
  "aud": ["kyverno-authz"],
  "sub": "<session_id>",
  "tool_scope": ["pfsense.block_ip"],
  "exp": <now + approved_window_seconds>
}
```

The agent presents this as `X-JIT-Session-JWT` on dangerous tool calls through the gateway. Kyverno fetches the JWKS from `/jwks` and verifies the JWT stateless — no live HTTP callback to `jit-approver` per request. A missing, invalid, or expired JWT → 403.

The JWT is the agent's **own scoped capability** — it does not carry any downstream service credential and does not violate the no-credential-passing invariant.

---

## Security posture

- **SPIFFE ID:** `spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/jit-approver`
- **Gitea API token:** stored in Vault (`kv-v2/gitea/jit-approver-token`); injected via Vault Agent Injector (tmpfs); never in etcd or a Kubernetes Secret
- **Webhook HMAC secret:** stored in Vault; delivered via tmpfs; never in git/etcd
- **Approval state:** held in-memory with a configurable timeout (default 15 minutes); if no approval arrives within the timeout, `jit-approver` returns DENY — fail-closed
- **RS256 signing key:** must be persisted across pod restarts (stored in Vault or a Kubernetes Secret — not ephemeral in-process memory) so JWTs issued before a restart remain verifiable after it

**NetworkPolicy:** ingress on 8080 from `ext-proc-delegation` pod only; ingress on 9443 from OCP router (webhook endpoint only); egress to Gitea:443, Vault:8200, Alertmanager:9093; deny all other.

---

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|---|---|---|---|
| ext-proc-delegation | inbound | 8080 HTTP | Hold/release decisions; scope requests |
| Agent pods | inbound | 8080 HTTP (SVID-mTLS) | `GET /requests/{id}/status` — credential delivery |
| Gitea (`git.arsalan.io`) | outbound | 443 HTTPS | PR creation for JIT approval requests |
| Gitea webhook | inbound | 9443 HTTPS (Route) | Merge event callback — release held session |
| Vault | outbound | 8200 HTTPS | Kubernetes engine + KV write + HMAC secret read |
| Alertmanager | outbound | 9093 HTTP | Timeout/failure alerting |
| Kyverno | outbound (JWKS pull) | 8080 HTTP | Serve RS256 JWKS for session JWT verification |

---

## Verify

```bash
# 1. Check jit-approver pod is Running
oc get pods -n mcp-gateway -l app=jit-approver

# 2. Confirm the Gitea token is Vault-injected (tmpfs, not a Kubernetes Secret)
oc exec -n mcp-gateway deploy/jit-approver -- mount | grep tmpfs

# 3. Confirm the JWKS endpoint is reachable from within the cluster
oc exec -n kyverno deploy/kyverno-authz-server -- \
  curl -s http://jit-approver.mcp-gateway.svc.cluster.local:8080/jwks | jq .keys[0].kty
```

---

## Maturity flags

!!! warning "Custom component — no upstream support"
    `jit-approver` is a bespoke Python service. The Gitea PR-merge-as-approval pattern is a custom integration. Consider it PoC-grade.

- In-memory approval state means a pod restart loses pending approvals. Production requires a persistent queue (Redis or CNPG)
- Gitea webhook reliability depends on network reachability from `git.arsalan.io` to the OCP Route on `anaeem` — confirm firewall rules allow inbound webhook traffic
- The RS256 signing key rotation procedure requires a brief JWKS overlap window to avoid rejecting in-flight JWTs
