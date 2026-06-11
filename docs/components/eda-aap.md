## Purpose

Event-Driven Ansible (EDA) with Ansible Automation Platform (AAP) 2.6 provides the automated remediation backbone. EDA Rulebooks listen to alert events from the observability stack, match conditions (e.g., GPU health degradation, policy violation, anomalous agent behavior), and trigger AAP Job Templates that execute remediation playbooks — creating a closed-loop, human-in-the-loop-optional response pipeline.

## Exists or create

**AAP EXISTS** — version 2.6 (gateway API confirmed) at `https://aap-aap.apps.hammer.na-launch.com` on the `hammer` cluster. This is **config-only integration** — no new AAP operator or controller is deployed. Work consists entirely of:

- Creating Event Streams, Rulebook Activations, and Credential objects in the existing AAP via the AAP API or UI
- Creating Job Templates in the existing Automation Controller (4.7.12)
- No Kubernetes manifests on the `anaeem` cluster for AAP itself

The MCP servers on the `virt` hub (`aap-mcp-server` namespace: `aap-mcp-ansible:8000`, `aap-mcp-eda:8001`, `aap-mcp-lint:8002`, `aap-mcp-redhat-docs:8003`) are future upstream MCP server candidates for routing via agentgateway — referenced as commented examples in the agentgateway config, not yet wired.

## Placement

- AAP Controller: `https://aap-aap.apps.hammer.na-launch.com` (hammer cluster, config-only)
- EDA Controller: co-located with AAP on hammer (same gateway URL)
- anaeem cluster: no AAP pods; EDA receives events via webhook/Event Stream from `agentic-observability` Alertmanager
- Alertmanager webhook endpoint on EDA: configured in AAP UI (URL from EDA Event Stream setup)

## Security posture

- AAP API credentials stored in Vault (`kv-v2/aap/controller-token`) on the anaeem cluster; injected into the EDA webhook sender component via Vault Agent Injector
- EDA Rulebook Activations use Credentials of type `Red Hat Ansible Automation Platform` pointing at the Controller — no hardcoded passwords in rulebook YAML
- Gitea PR-merge is the JIT approval channel for remediation playbooks: the JIT approver component creates a Gitea PR; EDA watches for the merge event before proceeding with destructive remediations
- Audit: all AAP job launches are logged by AAP's built-in activity stream; additionally forwarded to Loki via an AAP notification webhook
- Fail-mode: if EDA cannot reach AAP Controller, Rulebook Activations enter `failed` state and alert — human operator is notified via Alertmanager; no silent failure

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| Alertmanager (agentic-observability) | outbound → EDA | 443 HTTPS | Alert events triggering Rulebook Activations |
| EDA Event Stream | outbound → AAP Controller | 443 HTTPS | Job Template launch requests |
| Gitea (git.arsalan.io) | outbound from EDA | 443 HTTPS | PR webhook for JIT approval |
| jit-approver (anaeem) | outbound | 443 HTTPS | Pre-flight approval check before remediation |
| virt hub MCP servers | future | 8000-8003 HTTP | Candidate upstream MCP tool calls (commented-out) |

## Maturity flags

- AAP 2.6 with gateway API is GA
- EDA Event Streams (replacing legacy webhook receivers) is GA in AAP 2.6
- The Gitea PR-merge-as-approval pattern is a custom integration — no upstream AAP feature; relies on Gitea webhook reliability
- AAP 2.6 controller 4.7.12 is the current minor — check Red Hat errata for any CVEs before connecting to the platform network

## Verify

```bash
# 1. Confirm AAP controller is reachable and authenticated
curl -sk -u admin:<token> https://aap-aap.apps.hammer.na-launch.com/api/v2/ping/ | jq .version

# 2. List active EDA Rulebook Activations via AAP EDA API
curl -sk -H "Authorization: Bearer <token>" \
  https://aap-aap.apps.hammer.na-launch.com/eda/api/v1/activations/ | jq '.[].name'

# 3. Confirm an Alertmanager alert reaches EDA (trigger a test alert from agentic-observability)
oc exec -n agentic-observability deploy/alertmanager -- \
  amtool alert add alertname=test severity=warning
```
