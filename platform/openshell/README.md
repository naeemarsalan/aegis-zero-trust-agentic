# NVIDIA OpenShell — the agent runtime (Phase 5b)

**Status: DEPLOYED + gateway healthy; a Sandbox agent proven consuming the
platform gateway (2026-06-13).** NVIDIA OpenShell is the namesake agent-runtime
("runtime environment for autonomous agents"). It was deployed from its OCI Helm
chart, its control-plane gateway is running, and an agent running in an OpenShell
**Sandbox** completed the full delegated chain: device-flow login → MCP tool call
through the platform gateway → downstream saw the **user** (`arsalan`,
`aud: mcp-downstream`, the RFC 8693-exchanged token).

## What runs

- **OpenShell gateway** (`openshell-0`, ns `openshell`) — Rust control-plane,
  TLS + mTLS, gateway-minted sandbox JWTs, K8s SA bootstrap authenticator,
  watching `Sandbox` resources. `1/1 Running`.
- **kubernetes-sigs/agent-sandbox** controller + `sandboxes.agents.x-k8s.io` CRD
  — the substrate OpenShell orchestrates (a Sandbox wraps a `podTemplate`).
- **capstone-agent Sandbox** — runs `oci.arsalan.io/nvidia-ida/sandbox-agent:dev`,
  which does the Keycloak device-flow login and the delegated gateway tool call.

## Install (what it actually took on OpenShift)

```bash
# 1. Prerequisite: the Agent Sandbox CRDs + controller (provides the Sandbox CRD
#    OpenShell's compute driver watches — without it the gateway logs a 404).
oc apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/latest/download/manifest.yaml

# 2. Namespace + SCCs. Sandboxes supervise containers, so the sandbox SA needs
#    privileged; the gateway needs to NOT pin uid/fsGroup to 1000 (out of the
#    OpenShift namespace range).
oc create ns openshell
oc adm policy add-scc-to-user privileged -z openshell-sandbox -n openshell

# 3. Install the gateway (relax the hardcoded uid/fsGroup; see values-openshift.yaml).
helm install openshell oci://ghcr.io/nvidia/openshell/helm-chart -n openshell \
  --set podSecurityContext.fsGroup=1000990000 \
  --set securityContext.runAsUser=1000990000 \
  --set sandbox.sandboxNamespace=openshell --set sandbox.runtimeClassName=kata

# 4. The gateway's SQLite data PVC must be created AFTER fsGroup is set, else the
#    DB file is unwritable (SQLITE_CANTOPEN). If you changed fsGroup post-install:
#    scale to 0, delete pvc openshell-data-openshell-0, scale back to 1.
```

Then apply `sandbox-capstone.yaml` to run the capstone agent through the substrate.

## Honest scope

The gateway is fully healthy and the Sandbox substrate runs our agent end-to-end
against the platform gateway. What is **not** wired here: OpenShell's *own*
provider/policy orchestration of a packaged agent (Claude Code/Codex) and running
the sandbox itself as a **Kata** micro-VM with the nested-SPIRE SVID flow — those
are the alpha frontier (OpenShell's container-supervision nested in Kata is
unconfirmed upstream). The zero-trust mechanics they would exercise are already
proven independently: see `../agent-sandbox/kata-svid/` (Kata + nested-SPIRE SVID)
and the `sandbox-agent` (device-flow + delegated gateway call). This deployment
joins them to the real OpenShell runtime.
