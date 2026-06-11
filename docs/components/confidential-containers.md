## Purpose

Confidential Containers (CoCo) with Kata peer-pods and the Trustee attestation service represents the production-grade hardware-TEE isolation target for agent workloads. It extends Kata's VM isolation with hardware-rooted attestation (Intel TDX / AMD SEV-SNP), encrypted VM memory, and remote attestation via the Trustee (Key Broker Service) — ensuring that even the hypervisor operator cannot inspect agent memory or inject secrets without hardware attestation evidence.

## Exists or create

**NOT APPLIED IN THE POC.** This document describes the production target only.

In the PoC, Kata Containers with `runtimeClassName: kata-qemu` (nested virt, no TEE) is the active isolation tier — see `sandboxed-containers.md`. Confidential Containers requires:

1. Hardware TEE support (Intel TDX or AMD SEV-SNP) — the `anaeem` SNO node is a nested VM on the `virt` hub; it does NOT expose TDX/SEV-SNP to the guest. A future bare-metal SNO or dedicated AMD SEV-SNP host is required.
2. The `peer-pods` runtime class — this routes pod VMs to a separate hypervisor node (or cloud instance) where TEE hardware is present.
3. A Trustee (KBS — Key Broker Service) deployment to perform remote attestation and conditionally release secrets to attested VMs.

When this tier is activated, it replaces `kata-qemu` with `kata-remote` (peer-pods) in `agent-sandbox`. Vault Agent Injector is replaced by Trustee-gated secret delivery — secrets are only unsealed inside the TEE after hardware attestation.

## Placement (production target, not applied)

- Cluster: future bare-metal or TEE-capable node
- Operator namespace: `openshift-sandboxed-containers-operator` (same operator, additional `PeerPodsConfig` CR)
- Trustee namespace: `trustee` (Key Broker Service + Attestation Service)
- Trustee Route (production): `https://trustee.apps.<future-cluster>.na-launch.com`
- Agent workload namespace: `agent-sandbox` (same namespace, `runtimeClassName: kata-remote`)

## Security posture

- Hardware TEE: TDX/SEV-SNP encrypted VM memory; attestation report signed by CPU hardware
- Trustee performs remote attestation before releasing any key material into the TEE; policy is defined as OPA rules in the KBS
- SPIFFE SVIDs are still issued inside the TEE (SPIRE agent runs inside the attested VM)
- Vault is replaced or complemented by Trustee as the root secret authority — Vault policies reference Trustee attestation claims
- NetworkPolicy: same default-deny posture as PoC; Trustee egress replaces Vault Agent Injector

## Interfaces (production target)

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| Trustee / KBS | outbound from TEE VM | 443 HTTPS | Remote attestation + secret release |
| SPIRE Agent | inbound (inside VM) | Unix socket | SVID delivery post-attestation |
| agentgateway | outbound from TEE VM | 443 HTTPS | MCP tool calls |

## Maturity flags

- CoCo with peer-pods on OCP is **Technology Preview** as of OCP 4.20 — not production-supported without explicit Red Hat engagement
- Trustee (KBS) is upstream Confidential Containers project code, not yet a Red Hat supported product
- TDX support in the Linux kernel (6.8+) and QEMU (8.2+) is stabilizing; AMD SEV-SNP is further along in the Red Hat stack

## Verify (when activated on a TEE-capable cluster)

```bash
# 1. Confirm peer-pods runtime class is registered
oc get runtimeclass kata-remote

# 2. Check Trustee KBS is healthy
curl -s https://trustee.apps.<cluster>.na-launch.com/kbs/v0/resource/default/test/key | jq .

# 3. Validate attestation evidence in a TEE agent pod log
oc logs -n agent-sandbox <kata-remote-pod> | grep "attestation"
```
