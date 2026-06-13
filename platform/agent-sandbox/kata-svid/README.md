# Kata + SVID: nested SPIRE agent inside the micro-VM

**Status: PROVEN end-to-end (2026-06-13).** An agent in a Kata micro-VM obtained
its own SPIFFE SVID from a SPIRE agent running *inside the VM*, used it to
authenticate to Vault, and pulled its inference credential — with no Kubernetes
SA token and no Vault token anywhere on disk, and a guest kernel (5.14) distinct
from the host (6.19), i.e. real hardware isolation.

```
svid-vault-fetch (inside Kata):
  got JWT-SVID  spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/openshell-agent
  vault login ok (token held in memory only, never written)
  inference credential materialized to tmpfs
```

## Why this is non-trivial

The SPIFFE CSI driver delivers SVIDs over a host **unix socket**, which cannot
cross the Kata VM boundary (virtio-fs can't proxy a live socket). The clean fix
is to run a **nested SPIRE agent inside the VM**: it reaches the SPIRE *server*
over plain TCP (pod network) and serves the workload API on a local in-VM socket
that the workload connects to. No host-socket forwarding is needed — so Kata PR
[#13162](https://github.com/kata-containers/kata-containers/pull/13162)
(UNIX-socket→vsock forwarding), while the right tool for forwarding a host socket,
is **not required** for this nested-agent design.

## Architecture (per pod)

```
Kata micro-VM (runtimeClassName: kata, shareProcessNamespace: true)
├── nested-spire-agent  (native sidecar)
│     join_token node attestation → SPIRE server (spire-server.svc:8081, TCP)
│     WorkloadAttestor: unix (uid)   serves /run/spire/sockets/agent.sock
├── svid-vault-fetch    (init, runAsUser 1001020000)
│     connects to the local agent socket → JWT-SVID(aud=vault)
│     → Vault auth/jwt role=openshell-agent → reads secret/agent-sandbox/inference
│     → writes /vault/secrets/inference.* (memory tmpfs); Vault token never written
└── agent               (main; reads the inference cred from tmpfs)
```

Key requirements discovered:
- **`shareProcessNamespace: true`** — the `unix` WorkloadAttestor reads the
  caller's `/proc`; without a shared PID namespace it fails "could not resolve
  caller information".
- **NetworkPolicy egress to the SPIRE server on the POD port `8081`** (the svc
  port 443 DNATs to containerPort 8081 — netpols match post-DNAT).
- **`unix:uid:<pinned>` registration entry** parented to the nested agent's
  SPIFFE ID; pin the workload's `runAsUser` to match (1001020000, in the
  agent-sandbox SCC range).
- The `spire-bundle` ConfigMap must be copied into `agent-sandbox` (it's
  namespaced); the agent verifies the server against `bundle.crt`.

## The blocker this works around (and what durable support needs)

The ZTWIM operator hardcodes the SPIRE server's `k8s_psat`
`service_account_allow_list` to its own `spire-agent` SA and reverts any
ConfigMap edit within ~25s; `join_token` isn't enabled by default; the
`SpireServer` CR exposes no field for either. So a nested agent can't node-attest
on the managed config as-is.

This demo therefore **temporarily reconfigures SPIRE out-of-band**. To reproduce:

```bash
NS=zero-trust-workload-identity-manager
KC=$HOME/.kube/anaeem-kubeconfig

# 1. Stop the operator reverting our changes
oc --kubeconfig=$KC -n $NS scale deploy zero-trust-workload-identity-manager-controller-manager --replicas=0

# 2. Add the join_token NodeAttestor to the server config + restart
#    (insert {"join_token":{"plugin_data":null}} into NodeAttestor[] in cm/spire-server)
oc --kubeconfig=$KC -n $NS edit cm spire-server         # add join_token attestor
oc --kubeconfig=$KC -n $NS delete pod spire-server-0    # reload

# 3. Generate a join token bound to the nested agent ID + register the workload entry
oc --kubeconfig=$KC -n $NS exec spire-server-0 -c spire-server -- \
  /spire-server token generate -spiffeID spiffe://anaeem.na-launch.com/nested-agent/openshell-kata -ttl 7200
oc --kubeconfig=$KC -n $NS exec spire-server-0 -c spire-server -- \
  /spire-server entry create \
    -parentID spiffe://anaeem.na-launch.com/nested-agent/openshell-kata \
    -spiffeID spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/openshell-agent \
    -selector unix:uid:1001020000 -x509SVIDTTL 3600

# 4. Copy the trust bundle into agent-sandbox, apply config/netpol, and the pod
oc --kubeconfig=$KC -n $NS get cm spire-bundle -o json \
  | jq '{apiVersion,kind,data,metadata:{name:.metadata.name,namespace:"agent-sandbox"}}' \
  | oc --kubeconfig=$KC apply -f -
oc --kubeconfig=$KC apply -f config-netpol.yaml
sed "s/__JOIN_TOKEN__/<token from step 3>/" pod.template.yaml | oc --kubeconfig=$KC apply -f -

# 5. Restore the operator when done (the running pod keeps renewing via its
#    cached SVID + datastore node record; a pod RESTART would need re-attestation,
#    which fails once join_token is reverted).
oc --kubeconfig=$KC -n $NS scale deploy zero-trust-workload-identity-manager-controller-manager --replicas=1
```

**Durable support** needs one of: an operator/CR field exposing the psat
`service_account_allow_list` or an additional node attestor (`join_token`); or
un-managing SPIRE and owning the server config. Until then this is a demonstrated
capability, not a GitOps-reconciled one.
