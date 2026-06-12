# Agent Sandbox — Kata Containers Isolation

## Purpose

The `agent-sandbox` namespace is the isolated execution environment for all AI agent workloads. Every agent pod runs under the **Kata Containers** runtime (`kata-qemu`), which places the pod inside a lightweight KVM micro-VM rather than sharing the host kernel with other workloads.

This isolation limits the blast radius of a compromised or malicious agent: the worst-case escape is from the VM, not from a shared kernel namespace. Combined with no SA-token automount, Kyverno guardrails, and a default-deny NetworkPolicy that permits egress only to the MCP gateway, the agent pod has no path to the host, to other namespaces, or to credential stores.

---

## Placement

| Property | Value |
|---|---|
| Cluster | `anaeem` (SNO, OCP 4.20.11, nested virt confirmed) |
| Agent namespace | `agent-sandbox` |
| Operator namespace | `openshift-sandboxed-containers-operator` |
| Runtime class | `kata-qemu` (nested virt; not `kata-remote` which requires peer-pods infrastructure) |
| OSC operator channel | `stable` |
| Nested virt status | Confirmed — `vmx` flag in `/proc/cpuinfo`, `/dev/kvm` present on `anaeem-sno` |

---

## Isolation properties

| Property | Value |
|---|---|
| Kernel isolation | Separate KVM micro-VM per pod; host kernel not shared |
| Privileged containers | Not allowed — enforced by Kyverno ClusterPolicy |
| `hostPID` / `hostNetwork` | Not allowed — enforced by Kyverno ClusterPolicy |
| SA-token automount | `automountServiceAccountToken: false` on all agent pods |
| Credential delivery | SPIFFE CSI Driver tmpfs only; no Vault Secret volumes |
| NetworkPolicy egress | `mcp-gateway.apps.anaeem.na-launch.com:443` only |

---

## Security posture

- **SPIFFE ID per agent:** each agent gets its own ServiceAccount and therefore its own SVID (`spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/<agent-sa>`)
- **No standing credentials:** agents hold only their JWT-SVID; no API keys, no SA tokens, no pfSense credentials
- **Fail-mode:** if Kata runtime is not installed or the VM fails to start, the pod enters an error state — it does not fall back to `runc`; the `runtimeClassName` field is immutable post-creation

**NetworkPolicy:** default-deny in `agent-sandbox`; explicit egress allow to `mcp-gateway.apps.anaeem.na-launch.com:443` only; no direct egress to the internet or to other namespaces.

---

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|---|---|---|---|
| agentgateway | outbound from agent | 443 HTTPS | MCP tool calls via gateway |
| SPIRE Agent (CSI) | inbound (node-level) | Unix socket | SVID delivery to agent VM |

---

## Verify

```bash
# 1. Confirm KataConfig is reconciled and Kata runtime is installed
oc get kataconfig -o jsonpath='{.items[0].status.installationStatus}'

# 2. Check agent pods use the kata runtime class
oc get pod -n agent-sandbox -o jsonpath='{.items[*].spec.runtimeClassName}'
# Expected: kata-qemu (or kata)

# 3. Confirm a different kernel version in the agent pod (Kata VM kernel vs host)
oc exec -n agent-sandbox <agent-pod> -- uname -r

# 4. Confirm no SA-token volume is mounted on an agent pod
oc get pod -n agent-sandbox <pod> -o json \
  | jq '.spec.automountServiceAccountToken'
# Expected: false
```

---

## Production path — Confidential Containers

In production, the isolation target is **Confidential Containers** (CoCo) with peer-pods and hardware TEE attestation (Intel TDX or AMD SEV-SNP). This provides hardware-rooted attestation in addition to VM isolation — even the hypervisor operator cannot inspect agent memory.

CoCo requires hardware TEE support that is not available on the `anaeem` SNO node (a nested VM). It is documented separately in [Confidential Containers](confidential-containers.md) as a future production target.

---

## Maturity flags

- OSC / Kata Containers `stable` channel is GA on OCP 4.20
- Nested-virt Kata is supported but carries a performance overhead vs. bare-metal Kata
- `kata-qemu` is the correct runtime class for nested virt — not `kata-remote`
- SNO single-node topology means a `KataConfig` daemon rollout that fails to drain the node would render the only node unschedulable — apply during a maintenance window
