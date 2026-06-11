## Purpose

jit-approver implements human-in-the-loop Just-In-Time approval for high-risk MCP tool calls. When agentgateway (via ext-proc-delegation) identifies a tool call that exceeds the auto-approve threshold defined in Kyverno policy, it places the request on hold and calls jit-approver to open a Gitea pull request. The tool call proceeds only after a human approves (merges) the PR — turning Gitea PR-merge into the approval signal with a full audit trail.

## Exists or create

CREATE on anaeem. Deploy as a Deployment in namespace `mcp-gateway`. The image is `oci.arsalan.io/nvidia-ida/jit-approver:dev`. It is reached by ext-proc-delegation over HTTP on port 8080 (cluster-internal only).

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11)
- Namespace: `mcp-gateway`
- Internal service: `jit-approver.mcp-gateway.svc.cluster.local:8080` (HTTP, no Route — internal only)
- Gitea integration: `https://git.arsalan.io` repo `anaeem/nvidia-ida` — PRs created in a dedicated branch namespace (e.g., `jit/<request-id>`)
- No external hostname; Gitea webhook fires back to jit-approver via an OCP Route exposed only for that inbound webhook path

## Security posture

- SPIFFE ID: `spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/jit-approver`
- Gitea API token stored in Vault (`kv-v2/gitea/jit-approver-token`); injected via Vault Agent Injector (tmpfs); never in etcd or a Kubernetes Secret
- Gitea webhook signature (HMAC-SHA256) validated on all inbound webhook calls to prevent spoofed approvals
- Approval state is held in-memory with a configurable timeout (default 15 minutes); if no approval arrives within the timeout, jit-approver returns DENY to ext-proc-delegation — fail-closed
- NetworkPolicy: ingress on 8080 from `ext-proc-delegation` pod only; ingress on 9443 from OCP router (webhook endpoint); egress to Gitea (`git.arsalan.io:443`); deny all other
- Fail-mode: if jit-approver is unreachable, ext-proc-delegation treats the JIT check as DENY — the tool call is blocked (fail-closed); an alert fires to Alertmanager

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| ext-proc-delegation | inbound | 8080 HTTP | Hold/release decisions for tool calls |
| Gitea (`git.arsalan.io`) | outbound | 443 HTTPS | PR creation for JIT approval requests |
| Gitea webhook | inbound | 9443 HTTPS (Route) | Merge event callback — release held tool call |
| Vault Agent sidecar | inbound (localhost) | 8200 HTTPS | Gitea token injection |
| Alertmanager | outbound | 9093 HTTP | Timeout/failure alerting |

## Maturity flags

- jit-approver is a custom component (`oci.arsalan.io/nvidia-ida/jit-approver:dev`) — no upstream project or Red Hat support; the Gitea PR-merge-as-approval pattern is bespoke
- In-memory approval state means a jit-approver pod restart loses pending approvals; a future revision should use a persistent queue (Redis or CNPG) for production
- Gitea webhook reliability depends on network reachability from `git.arsalan.io` to the OCP Route on `anaeem`; confirm firewall rules allow inbound webhook from Gitea's origin IP

## Verify

```bash
# 1. Check jit-approver pod is Running
oc get pods -n mcp-gateway -l app=jit-approver

# 2. Confirm the Gitea token is Vault-injected (tmpfs, not a Secret)
oc exec -n mcp-gateway deploy/jit-approver -- mount | grep tmpfs

# 3. Trigger a synthetic JIT approval flow and verify a PR appears in Gitea
curl -s -X POST http://jit-approver.mcp-gateway.svc.cluster.local:8080/hold \
  -H "Content-Type: application/json" \
  -d '{"request_id":"test-001","tool":"pfsense.block_ip","caller":"spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/agent1"}' \
  | jq .pr_url
```
