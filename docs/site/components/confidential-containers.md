# Confidential Containers — Production TEE Target

!!! warning "Not applied in the PoC"
    Confidential Containers (CoCo) is the **production-grade isolation target** described here for planning purposes. In the PoC, Kata Containers with `runtimeClassName: kata-qemu` (nested virt, no TEE) is the active isolation tier — see [Agent Sandbox](agent-sandbox.md). CoCo requires hardware TEE support that is not available on the `anaeem` SNO node (a nested VM on the `virt` hub).

---

## Purpose

Confidential Containers with Kata peer-pods and the Trustee attestation service extends Kata's VM isolation with **hardware-rooted attestation** (Intel TDX or AMD SEV-SNP):

- VM memory is encrypted at rest and in use — even the hypervisor operator cannot inspect agent memory
- Secrets are only released into the TEE after remote attestation by the Trustee Key Broker Service (KBS)
- SPIFFE SVIDs are still issued inside the TEE (SPIRE Agent runs inside the attested VM)

This is a **hardware-attestation upgrade path with no identity or policy redesign** — the same SPIRE trust domain, Keycloak realm, Vault policies, and Kyverno rules apply; only the isolation tier changes.

---

## Requirements for activation

1. **Hardware TEE support** — Intel TDX or AMD SEV-SNP on the physical host. The `anaeem` SNO node is a nested VM; it does not expose TDX/SEV-SNP to the guest.
2. **Peer-pods runtime class** (`kata-remote`) — routes pod VMs to a separate hypervisor node or cloud instance where TEE hardware is present.
3. **Trustee (KBS) deployment** — performs remote attestation and conditionally releases secrets to attested VMs.

---

## Placement (production target, not applied)

| Property | Value |
|---|---|
| Cluster | Future bare-metal or TEE-capable node |
| Operator namespace | `openshift-sandboxed-containers-operator` (same operator, additional `PeerPodsConfig` CR) |
| Trustee namespace | `trustee` (Key Broker Service + Attestation Service) |
| Trustee Route | `https://trustee.apps.<future-cluster>.na-launch.com` |
| Agent namespace | `agent-sandbox` (same, `runtimeClassName: kata-remote`) |

---

## Security posture

- Hardware TEE: TDX/SEV-SNP encrypted VM memory; attestation report signed by CPU hardware
- Trustee performs remote attestation before releasing any key material into the TEE; policy is OPA rules in the KBS
- Vault Agent Injector is replaced or complemented by Trustee-gated secret delivery
- NetworkPolicy: same default-deny posture as PoC; Trustee egress replaces Vault Agent Injector

---

## Verify (when activated on a TEE-capable cluster)

```bash
# 1. Confirm peer-pods runtime class is registered
oc get runtimeclass kata-remote

# 2. Check Trustee KBS is healthy
curl -s https://trustee.apps.<cluster>.na-launch.com/kbs/v0/resource/default/test/key | jq .

# 3. Validate attestation evidence in a TEE agent pod log
oc logs -n agent-sandbox <kata-remote-pod> | grep "attestation"
```

---

## Maturity flags

- CoCo with peer-pods on OCP is **Technology Preview** as of OCP 4.20 — not production-supported without explicit Red Hat engagement
- Trustee (KBS) is upstream Confidential Containers project code, not yet a Red Hat supported product
- TDX support (Linux kernel 6.8+, QEMU 8.2+) and AMD SEV-SNP are both stabilizing in the Red Hat stack
