## Purpose

OpenShift Sandboxed Containers (OSC) with Kata Containers provides a hardware-virtualized execution boundary for untrusted AI agent workloads. Each agent pod runs inside a lightweight KVM micro-VM rather than a shared kernel namespace, limiting the blast radius of a compromised or malicious agent to its own VM. This is the isolation tier applied in the PoC.

## Exists or create

CREATE on anaeem. The OSC operator is not yet installed. Nested virtualization is confirmed (`vmx` in `/proc/cpuinfo`, `/dev/kvm` present on node `anaeem-sno`) — Kata is feasible. Deploy the `sandboxed-containers-operator` from OperatorHub channel `stable`, create a `KataConfig` CR to install the Kata runtime on all worker nodes, and set `runtimeClassName: kata` on agent pods in namespace `agent-sandbox`. No confidential computing (peer-pods / Trustee) is applied in the PoC — see `confidential-containers.md` for the production TEE target.

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11, nested virt confirmed)
- Operator namespace: `openshift-sandboxed-containers-operator`
- Agent workload namespace: `agent-sandbox`
- `KataConfig` CR: cluster-scoped, installs Kata runtime on all schedulable nodes
- No external hostname

## Security posture

- SPIFFE ID: `spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/<agent-sa>` — each agent gets its own ServiceAccount and therefore its own SVID
- Isolation level: KVM micro-VM per pod (Kata `kata-qemu` runtime class on SNO nested virt); kernel is not shared with the host or other pods
- No privileged containers, no `hostPID`, no `hostNetwork` in `agent-sandbox` namespace — enforced by Kyverno ClusterPolicy
- Vault credentials for tool use (e.g., pfsense API key) are injected as ephemeral tmpfs mounts by Vault Agent Injector; never written to the VM disk
- NetworkPolicy: default-deny in `agent-sandbox`; explicit egress allow to `mcp-gateway.apps.anaeem.na-launch.com:443` only; no direct egress to the internet or other namespaces
- Fail-mode: if Kata runtime is not installed or the VM fails to start, the pod enters `OOMKilled` / `Error` — it does not fall back to `runc`; the `runtimeClassName` field is immutable post-creation

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| agentgateway | outbound from agent | 443 HTTPS | MCP tool calls via gateway |
| SPIRE Agent (CSI) | inbound (node-level) | Unix socket | SVID delivery to agent VM |
| Vault Agent Injector | inbound (init container) | 8200 HTTPS | Credential injection |

## Maturity flags

- OSC / Kata Containers `stable` channel is GA on OCP 4.20; nested-virt Kata is supported but carries a performance overhead vs. bare-metal Kata
- `kata-qemu` is the correct runtime class for nested virt (not `kata-remote` which requires peer-pods infrastructure)
- SNO single-node topology means a Kata VM startup failure during a `KataConfig` daemon rollout would render the single node unschedulable — apply during a maintenance window

## Verify

```bash
# 1. Confirm KataConfig is reconciled and Kata runtime is installed
oc get kataconfig -o jsonpath='{.items[0].status.installationStatus}'

# 2. Check a test pod in agent-sandbox uses the kata runtime class
oc get pod -n agent-sandbox -o jsonpath='{.items[*].spec.runtimeClassName}'

# 3. Exec into the agent pod and confirm a different kernel version (Kata VM kernel vs host)
oc exec -n agent-sandbox <agent-pod> -- uname -r
```
