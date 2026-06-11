# coco-stubs — Confidential Containers production target

**PRODUCTION TARGET — NOT APPLIED IN POC (no TEE hardware on SNO VM)**

All files in this directory are stubs for the production Confidential Containers
(CoCo) deployment.  They document the intended architecture and serve as the
starting point when bare-metal TEE nodes (AMD SEV-SNP or Intel TDX) are available.

## Why these are not applied

The `anaeem` platform target is a Single-Node OpenShift (SNO) VM running on the
`virt` hub via KubeVirt/CNV.  While nested virtualisation is confirmed (vmx +
/dev/kvm — enabling standard Kata via QEMU), hardware TEE features (AMD SEV-SNP
memory encryption, AMD attestation co-processor, Intel TDX module) are **not
available** in a nested VM.  Attempting to apply CoCo manifests on this cluster
would result in:

- `KataConfig` peer-pods controller failing to find a KVM/TEE-capable hypervisor.
- `confidential-containers-operator` reporting no eligible nodes.
- Peer-pod VMs unable to produce valid attestation reports (no hardware root of trust).

## Files

| File | Purpose |
|---|---|
| `kataconfig-coco.yaml` | KataConfig with `enablePeerPods: true`, targets `coco-worker` MCP |
| `trustee-stub.yaml` | KbsConfig CR + Trustee Deployment stub (Key Broker Service) |
| `README.md` (this file) | Attestation flow, production apply order, hardware requirements |

## Attestation flow (production)

```
┌─────────────────────────────────────────────────────────┐
│  Agent Pod (peer-pod VM, AMD SEV-SNP encrypted memory)  │
│                                                         │
│  1. Kata Agent boots, reads AA_KBC_PARAMS               │
│  2. Contacts Trustee (KBS) at kbs.trustee-operator-system│
│  3. KBS challenges: produce SEV-SNP attestation report  │
│  4. KBS verifies report via AMD KDS (external HTTPS)    │
│     OR Intel PCCS for TDX                               │
│  5. KBS releases Vault-wrapped key / Vault token        │
│  6. Vault Agent inside VM uses token to fetch secrets   │
│     → secrets written to tmpfs, NEVER leave the VM      │
└─────────────────────────────────────────────────────────┘
           │  attests to
           ▼
┌────────────────────────────────────┐
│  Trustee (KBS + AS + RVPS)         │
│  ns: trustee-operator-system       │
│  - Attestation Service (AS)        │
│    verifies SEV-SNP/TDX quotes     │
│  - Reference Value Provider (RVPS) │
│    holds expected firmware hashes  │
│  - Key Broker Service (KBS)        │
│    releases secrets on pass        │
└────────────────────────────────────┘
           │  token release
           ▼
┌──────────────────────────────────┐
│  Vault (ns vault)                │
│  Dynamic secrets via KV or DB    │
│  engine — same as PoC but gated  │
│  on hardware attestation         │
└──────────────────────────────────┘
```

## Hardware requirements

| Requirement | Detail |
|---|---|
| CPU | AMD EPYC (Milan/Genoa/Bergamo) with SEV-SNP, OR Intel Xeon (Sapphire Rapids+) with TDX |
| BIOS | SEV-SNP or TDX enabled in firmware |
| OS | RHCOS with CoCo kernel (kata-containers-kernel-confidential) |
| Operator | confidential-containers-operator (separate from OSC) |
| Network | Trustee must reach AMD KDS (https://kdsintf.amd.com) or Intel PCCS for quote verification |

## Production apply order

1. Add bare-metal TEE nodes to the cluster and label them:
   ```
   oc label node <tee-node-name> node-role.kubernetes.io/coco-worker=""
   ```

2. Install the `confidential-containers-operator` via Subscription.

3. Apply the KbsConfig CR and Trustee Deployment:
   ```
   # NOT on anaeem-sno — apply only on TEE-capable cluster
   kustomize build platform/isolation/coco-stubs | oc apply -f -
   ```

4. Apply the CoCo KataConfig:
   ```
   oc apply -f platform/isolation/coco-stubs/kataconfig-coco.yaml
   ```

5. Wait for the `coco-worker` MachineConfigPool to finish updating
   (node reboot required — schedule maintenance window).

6. Verify:
   ```
   oc get kataconfig cluster-kataconfig-coco -o jsonpath='{.status.installationStatus}'
   oc get runtimeclass kata-remote
   oc -n trustee-operator-system get pods -l app=trustee
   ```

7. Deploy an agent pod in `agent-sandbox` with `runtimeClassName: kata-remote`
   and verify attestation succeeds (Trustee logs will show "attestation passed").

## Relationship to PoC

The PoC (`platform/isolation/kata-runtimeclass/kataconfig.yaml`) and the CoCo
production target are mutually exclusive at the KataConfig level — only one
`KataConfig` per cluster is supported by the OSC operator.  The PoC KataConfig
must be deleted before the CoCo KataConfig is applied.

The NetworkPolicies in `platform/networkpolicies/` do not need to change between
PoC and production — the `agent-sandbox` egress rules already enforce no direct
access to Vault/Keycloak from agent pods (secrets arrive via Trustee + Vault Agent
inside the TEE VM in the production case).
