# UC1 — Pod Inspection: Proving No Credentials in the Agent Pod

This document shows the `oc exec` commands that prove the demo-agent pod contains
**no secrets, tokens, or credentials** in its environment or mounted volumes at
startup. All sensitive material arrives via Vault Agent tmpfs injection and exists
only for the lifetime of a single request exchange.

## Prerequisites

```bash
export KUBECONFIG=~/.kube/anaeem-kubeconfig
oc get pod -n agent-sandbox -l app=demo-agent
# Copy the pod name into POD_NAME below
POD_NAME=$(oc get pod -n agent-sandbox -l app=demo-agent -o jsonpath='{.items[0].metadata.name}')
```

## 1. No credentials in environment variables

```bash
oc exec -n agent-sandbox "${POD_NAME}" -- env | sort
```

Expected output: Only operational env vars (`MCP_GATEWAY_URL`, `LOKI_PUSH_URL`,
`HOME`, `PATH`, etc.). No `TOKEN`, `SECRET`, `PASSWORD`, `KEY`, or `KUBECONFIG`
variables.

## 2. No credentials in mounted volumes (vault-secrets is empty at start)

```bash
# At pod start, before any JIT grant, /vault/secrets/ should contain only
# the .vault-token (Vault Agent auth token) — no user credentials, no kubeconfig.
oc exec -n agent-sandbox "${POD_NAME}" -- ls -la /vault/secrets/
```

Expected output:
```
total 8
drwxrwxrwt  2 root root   60 <timestamp> .
drwxr-xr-x 11 root root 4096 <timestamp> ..
-rw-------  1 1000 1000   26 <timestamp> .vault-token
```

Only `.vault-token` (the Vault Agent token used for renewals) is present.
No user credentials. No kubeconfig. No API keys.

## 3. No default ServiceAccount token automounted

```bash
# The default SA token mount is disabled (automountServiceAccountToken: false)
oc exec -n agent-sandbox "${POD_NAME}" -- ls /var/run/secrets/kubernetes.io/ 2>&1
```

Expected output:
```
ls: /var/run/secrets/kubernetes.io/: No such file or directory
```

## 4. SPIRE SVID socket is present (agent identity) but contains no long-lived secret

```bash
# The SPIRE CSI volume mounts an abstract domain socket.
# There is no private key file on disk — SPIRE delivers SVIDs via the socket protocol.
oc exec -n agent-sandbox "${POD_NAME}" -- ls -la /spiffe-workload-api/
```

Expected output: A `tee` socket file. No `.key`, `.pem`, or `.crt` files.
The key material is ephemeral and delivered only when the workload requests it.

## 5. Verify Kata VM isolation (the pod runs inside a micro-VM)

```bash
# From the host node, verify the pod is using the kata-qemu shim (not runc)
oc debug node/anaeem-sno -- \
  chroot /host crictl inspect $(crictl pods --name demo-agent -q) 2>/dev/null \
  | python3 -m json.tool | grep -E 'runtime|kata'
```

Expected: `runtimeHandler: kata` in the pod spec.

Alternatively, inside the pod the kernel version will differ from the host:
```bash
# Host kernel
oc debug node/anaeem-sno -- chroot /host uname -r

# Pod kernel (Kata guest kernel — different version)
oc exec -n agent-sandbox "${POD_NAME}" -- uname -r
```

These should be **different** — confirming the pod runs in an isolated VM kernel.

## 6. No credentials in /tmp

```bash
oc exec -n agent-sandbox "${POD_NAME}" -- ls -la /tmp/
```

Expected: Empty or only ephemeral working files. No credentials.

## Summary of proof

| Check | Expected result | Why it matters |
|-------|----------------|----------------|
| `env` output | No TOKEN/SECRET/KEY/PASSWORD vars | Credentials not leaked via environment |
| `/vault/secrets/` | Only `.vault-token` at start | No user creds pre-loaded; JIT flow required |
| `/var/run/secrets/kubernetes.io/` | Does not exist | SA token not automounted → no Kube API access |
| `/spiffe-workload-api/` | Socket only, no key files | SVID material is ephemeral, delivered on-demand |
| `uname -r` vs host | Different kernel versions | Pod runs in Kata VM, not on host kernel |
| `/tmp/` | No credentials | tmpfs is clean |

The user's OAuth token is **never stored** in the pod. It is forwarded per-request
by the end-user's client through the MCP gateway, validated by Keycloak and Kyverno,
and forwarded by ext-proc-delegation to the downstream MCP server as a request header.
The agent pod itself never sees or stores the user's token.
