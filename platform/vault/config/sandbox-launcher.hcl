# Policy: sandbox-launcher
# Identity: ServiceAccount sandbox-launcher in namespace mcp-gateway
#           (Kubernetes auth role sandbox-launcher).
# Purpose: Lets the sandbox-launcher write the per-sandbox CONSENT GRANT on
#          CreateSandbox — and nothing else. This is the asymmetric WRITE
#          counterpart to ext-proc.hcl's READ grant on the same path: the
#          launcher writes the grant, ext-proc reads it, neither does the other.
#
# Principle: least privilege. The sandbox-launcher SA's k8s-auth role serves TWO
# clients that share this one policy: (1) the Vault Agent INJECTOR sidecar, which
# READS the OIDC client secret it mounts at /vault/secrets/launcher-oidc-secret
# (deployment annotation vault.hashicorp.com/role: sandbox-launcher); and (2) the
# app itself (vault.py, VAULT_K8S_AUTH_ROLE=sandbox-launcher), which WRITES the
# per-sandbox consent grant. So this policy MUST keep the OIDC read (or the pod
# fails to start) AND add the grant write — nothing else.
#
# The grant is a consent RECORD (user + scope + ttl + nonce), NOT a credential:
# the launcher verifies then DISCARDS the caller's token and writes only the
# verified identity string. vault.write_sandbox_grant additionally rejects any
# document carrying access_token/bearer/svid/private_key/etc., so a credential
# can never be persisted here even by mistake.

# (1) OIDC client secret injected by the Vault Agent sidecar — READ only.
# Preserves the launcher's existing, working start-up secret injection.
path "secret/data/sandbox-launcher/*" {
  capabilities = ["read"]
}

# (2) Per-sandbox consent grants — CREATE/UPDATE only (ext-proc holds the
# matching read in ext-proc.hcl; the two halves never overlap).
path "secret/data/sandbox-grants/*" {
  capabilities = ["create", "update"]
}

# Deny everything else explicitly to guard against policy-inheritance surprises.
path "*" {
  capabilities = ["deny"]
}
