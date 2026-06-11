# Policy: jit-approver
# Identity: spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/jit-approver
# Purpose: The JIT approver creates per-session ephemeral Vault Kubernetes roles
#          (jit-<session-id>) scoped to the reviewed and approved grant, mints a
#          short-lived Kubernetes SA token from that role, AND writes the tracking +
#          session-JWT record to the KV store for downstream consumers.
#
# H3 fix: per-session roles replace the static "jit-scoped" role.
#   The kubernetes/creds/<role> endpoint does not honour per-call
#   generated_role_rules overrides — only the rules set at role creation time
#   are applied.  Creating one role per approved session (with the exact
#   approved namespace/verbs/resources from the reviewed grants/<session>.yaml)
#   ensures the issued credential scope matches what the human reviewer approved.
#   See platform/vault/README.md §Kubernetes secrets engine for the full flow.
#
# N2 fix: jit-approver WRITES the tracking + session-JWT record to
#   secret/data/jit/<session-id> during the issuance step (vault.py:197-221).
#   This requires create + update (KV v2 write) as well as read (to confirm the
#   write) and delete (reaper deletes the record on expiry).
#   The previous "read-only" grant and its "written by ext-proc-delegation" comment
#   were both wrong — ext-proc-delegation never writes this path; jit-approver owns
#   the full lifecycle of secret/data/jit/*.
#
# Constraints:
#   - Kubernetes roles: create + update + read + delete on jit-* prefix ONLY.
#     "create" is needed to write kubernetes/roles/jit-<session-id>.
#     "update" is needed for idempotent re-apply if the bootstrap re-runs.
#     "read"   is needed to confirm the role was written correctly.
#     "delete" is needed so the reaper can clean up after session expiry.
#     Deny the old static "jit-scoped" role/creds explicitly (belt-and-suspenders).
#   - Kubernetes creds: read on jit-* prefix ONLY (to mint the SA token).
#   - JIT tracking + session-JWT KV records: full lifecycle (create/update/read/delete
#     on data path; delete on metadata path for hard-delete support in the reaper).
#   - No other paths accessible.

# Create/update/read/delete ephemeral per-session Kubernetes roles (jit-<session-id>).
# Scoped to the "jit-" prefix — approver cannot touch any other Vault k8s role.
path "kubernetes/roles/jit-*" {
  capabilities = ["create", "update", "read", "delete"]
}

# Explicit deny for the former static catch-all role name.
# This prevents any accidental fallback to a static over-privileged role
# if vault-bootstrap.sh were to re-add it.
path "kubernetes/roles/jit-scoped" {
  capabilities = ["deny"]
}

# Mint short-lived Kubernetes SA tokens from a per-session role.
# "read" maps to the vault read kubernetes/creds/jit-<session-id> call.
path "kubernetes/creds/jit-*" {
  capabilities = ["read"]
}

# Explicit deny for the former static credential endpoint.
path "kubernetes/creds/jit-scoped" {
  capabilities = ["deny"]
}

# JIT tracking + session-JWT KV records — written and managed by jit-approver.
#
# Lifecycle:
#   1. On issuance:  jit-approver POSTs to v1/secret/data/jit/<session-id>
#                   (KV v2 write = create or update).
#      Record contains: sa_token (Vault-minted k8s SA token),
#                       session_jwt (RS256 signed session-capability JWT),
#                       expires_at, namespace, tool_scope.
#   2. On status GET: jit-approver READs secret/data/jit/<session-id> to serve
#                   the sa_token + session_jwt to the agent over SVID-mTLS.
#   3. On reap:     jit-approver DELETEs secret/data/jit/<session-id> (soft delete)
#                   and secret/metadata/jit/<session-id> (hard-delete) so the
#                   secret is not recoverable after the window expires.
#
# N2 fix: capabilities include "create" and "update" (previously missing — only
#         "read" was granted, causing issuance KV writes to 403-fail and roll back).
path "secret/data/jit/*" {
  capabilities = ["create", "update", "read", "delete"]
}

# Static service credentials injected at pod start (gitea token, webhook
# secret, signing key) — read-only.
path "secret/data/jit-approver/*" {
  capabilities = ["read"]
}

# Delete-only on the metadata path: used by the reaper for hard-deletes.
# Granting create/update/read on the metadata path is NOT needed and would be
# over-privileged (it would allow listing all KV versions — principle of least privilege).
path "secret/metadata/jit/*" {
  capabilities = ["delete"]
}

# Deny all other paths.
path "*" {
  capabilities = ["deny"]
}
