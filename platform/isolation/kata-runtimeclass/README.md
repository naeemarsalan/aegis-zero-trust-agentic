# kata-runtimeclass

Kata Containers runtime configuration for the nvidia-ida agentic platform.
Agent pods in the `agent-sandbox` namespace run inside lightweight QEMU VMs
(Kata shim) for kernel-level isolation between workloads and the SNO host.

## What is deployed

| Resource | Kind | Notes |
|---|---|---|
| cluster-kataconfig | KataConfig (kataconfiguration.openshift.io/v1) | enablePeerPods: false, targets master MCP |
| agent-pod-example.yaml | Reference snippet | Annotated Deployment showing runtimeClassName: kata |

## Why nested virtualisation is confirmed on anaeem-sno

- `vmx` flag present in `/proc/cpuinfo` on the SNO VM.
- `/dev/kvm` device is present and accessible.
- OpenShift Sandboxed Containers (OSC) operator detected KVM support during
  `checkNodeEligibility` verification.

This means Kata uses the standard `kata-qemu` shim without requiring bare-metal
TEE extensions (AMD SEV / Intel TDX).  Each agent pod runs in its own micro-VM
with a dedicated kernel, providing L3/4 network isolation enforced at the
hypervisor level in addition to the Kubernetes NetworkPolicies in
`platform/networkpolicies/`.

## Apply order

1. **`platform/00-operators`** — the OpenShift Sandboxed Containers (OSC) operator
   Subscription must be installed first.  The KataConfig CR below will be
   rejected if the CRD is not present.

   ```
   kustomize build platform/00-operators/osc | oc apply -f -
   oc -n openshift-sandboxed-containers-operator wait \
     --for=condition=Available deployment/sandboxed-containers-operator-controller-manager \
     --timeout=180s
   ```

2. **`platform/isolation/kata-runtimeclass`** — apply the KataConfig.

   ```
   kustomize build platform/isolation/kata-runtimeclass | oc apply -f -
   ```

3. **Wait for node reboot.**

   ```
   # Watch MachineConfigPool; status will go Degraded -> Updating -> Updated.
   # On SNO this triggers a FULL NODE REBOOT — the cluster will be
   # unreachable for 5-10 minutes.  PERFORM DURING A MAINTENANCE WINDOW.
   oc get mcp master -w
   ```

4. **Verify** the RuntimeClass exists and a test pod starts successfully:

   ```
   oc get runtimeclass kata
   oc get kataconfig cluster-kataconfig -o jsonpath='{.status.installationStatus}'

   # Smoke test — run a pod with runtimeClassName: kata
   oc run kata-test --image=registry.access.redhat.com/ubi9/ubi-minimal \
     --overrides='{"spec":{"runtimeClassName":"kata"}}' \
     -n agent-sandbox --restart=Never --command -- sleep 30
   oc -n agent-sandbox get pod kata-test -w
   oc -n agent-sandbox delete pod kata-test
   ```

## SNO maintenance-window warning

**CRITICAL — SNO = single-node cluster.  The KataConfig CR causes the OSC
operator to push a MachineConfig to the `master` pool.  OpenShift will drain
and reboot the node to apply the new kernel modules (kata-kernel-modules MC).**

- The cluster API is unavailable during the reboot (~5-10 min typical).
- ArgoCD sync will show the cluster as Offline during this window.
- Schedule this step outside business hours.
- After the reboot, verify all platform pods recover:
  ```
  oc get pods -A | grep -v Running | grep -v Completed
  ```

## Confidential Containers (production path)

See `platform/isolation/coco-stubs/` for NOT-APPLIED production manifests
targeting AMD SEV-SNP or Intel TDX.  These are stubs only — no TEE hardware
is present on the SNO VM.
