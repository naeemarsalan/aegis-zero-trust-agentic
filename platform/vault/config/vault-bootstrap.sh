#!/usr/bin/env bash
# vault-bootstrap.sh — Declarative Vault configuration for nvidia-ida PoC.
#
# PREREQUISITES (run after `vault operator init` + `vault operator unseal`):
#   - VAULT_ADDR exported (e.g. https://vault.apps.anaeem.na-launch.com)
#   - VAULT_TOKEN exported (initial root token — rotate after bootstrap)
#   - environment/.env sourced for PFSENSE_API_URL and PFSENSE_API_KEY
#
# USAGE:
#   source environment/.env          # provides PFSENSE_API_URL, PFSENSE_API_KEY
#   export VAULT_ADDR=https://vault.apps.anaeem.na-launch.com
#   export VAULT_TOKEN=<root-token>  # from `vault operator init` output
#   bash platform/vault/config/vault-bootstrap.sh
#
# IDEMPOTENCY: Most `vault write` calls are idempotent (PUT semantics).
#              `vault auth enable` and `vault secrets enable` will error if the
#              engine already exists; the script ignores those specific errors.
#
# SECURITY NOTES:
#   - The root token MUST be revoked after bootstrap: vault token revoke "$VAULT_TOKEN"
#   - Unseal keys and root token go into environment/.env (git-ignored), NEVER git.
#   - This script writes NO secrets to stdout; set -x is intentionally omitted.

set -euo pipefail

# ── helpers ──────────────────────────────────────────────────────────────────
log()  { echo "[bootstrap] $*"; }
warn() { echo "[bootstrap] WARN: $*" >&2; }

enable_or_skip() {
  # $1 = type (auth|secrets), $2 = mount path, $3 = engine type, rest = options
  # (vault ... enable takes options BEFORE the positional engine type)
  local type="$1" path="$2" engine="$3"; shift 3
  if vault "$type" list 2>/dev/null | grep -q "^${path%/}/"; then
    warn "${type} engine at '${path}' already enabled — skipping enable"
  else
    vault "$type" enable -path="$path" "$@" "$engine"
    log "Enabled ${type} engine at '${path}'"
  fi
}

# ── pre-flight ────────────────────────────────────────────────────────────────
: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
: "${PFSENSE_API_URL:?source environment/.env first — PFSENSE_API_URL missing}"
: "${PFSENSE_API_KEY:?source environment/.env first — PFSENSE_API_KEY missing}"

log "Targeting Vault at ${VAULT_ADDR}"
vault status || { warn "Vault not unsealed — abort"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 1. Audit device ───────────────────────────────────────────────────────────
log "Enabling file audit device..."
vault audit enable file \
  file_path=/vault/audit/vault_audit.log \
  || warn "audit device may already exist (ignored)"

# ── 2. KV v2 secrets engine ───────────────────────────────────────────────────
log "Enabling KV-v2 at 'secret/'..."
enable_or_skip secrets secret kv -version=2

# ── 3. Policies ───────────────────────────────────────────────────────────────
log "Writing policies..."

vault policy write ext-proc       "${SCRIPT_DIR}/ext-proc.hcl"
vault policy write jit-approver   "${SCRIPT_DIR}/jit-approver.hcl"
vault policy write agent-deny     "${SCRIPT_DIR}/agent-deny.hcl"

log "Policies written: ext-proc, jit-approver, agent-deny"

# ── 4. JWT/OIDC auth (SPIRE OIDC issuer) ─────────────────────────────────────
log "Enabling JWT auth engine..."
enable_or_skip auth jwt jwt

# IMPORTANT: The SPIRE OIDC discovery endpoint uses a cert signed by the cluster
# CA.  In production, configure VAULT_CACERT or add the CA to the Vault container
# trust store.  For PoC, if the CA is not imported, pass
#   oidc_discovery_ca_pem=<PEM>
# as an additional parameter below.
log "Configuring JWT auth (SPIRE OIDC issuer)..."
# H2 fix: do NOT set default_role — every Vault JWT login must explicitly name a
# role.  A default_role is a latent footgun: any future role whose name collides
# with the default string (e.g. "ext-proc") would be reachable by any
# SPIRE-SVID-bearing workload that omits the role parameter.  Force-explicit role
# selection means a misconfigured caller fails closed rather than silently
# inheriting a privileged policy.
vault write auth/jwt/config \
  oidc_discovery_url="https://spire-oidc.apps.anaeem.na-launch.com"

# Role: ext-proc-delegation
log "Writing JWT role ext-proc-delegation..."
vault write auth/jwt/role/ext-proc-delegation \
  role_type="jwt" \
  bound_subject="spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/ext-proc-delegation" \
  user_claim="sub" \
  token_ttl="15m" \
  token_max_ttl="15m" \
  token_policies="ext-proc" \
  bound_audiences="vault"

# Role: jit-approver
log "Writing JWT role jit-approver..."
vault write auth/jwt/role/jit-approver \
  role_type="jwt" \
  bound_subject="spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/jit-approver" \
  user_claim="sub" \
  token_ttl="15m" \
  token_max_ttl="15m" \
  token_policies="jit-approver" \
  bound_audiences="vault"

log "JWT roles created"

# ── 5. Kubernetes secrets engine ─────────────────────────────────────────────
log "Enabling Kubernetes secrets engine..."
enable_or_skip secrets kubernetes kubernetes

# Configure against the anaeem cluster API.
# When run inside the Vault pod the SA token/CA come from the standard mount;
# when run from a workstation, export VAULT_K8S_SA_JWT and VAULT_K8S_CA_CERT
# (fetch them from the vault-0 pod with oc exec).
log "Configuring Kubernetes secrets engine..."
SA_JWT="${VAULT_K8S_SA_JWT:-$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)}"
SA_CA="${VAULT_K8S_CA_CERT:-$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)}"
vault write kubernetes/config \
  kubernetes_host="https://api.anaeem.na-launch.com:6443" \
  service_account_jwt="${SA_JWT}" \
  kubernetes_ca_cert="${SA_CA}"

# H3 fix: Per-session ephemeral Vault roles (jit-<session-id>) replace the
# static jit-scoped role.
#
# DESIGN:
#   1. jit-approver reads the reviewed grants/<session>.yaml from the merged
#      branch (C2 fix), extracts the approved namespace, verbs, and resources.
#   2. jit-approver calls:
#        vault write kubernetes/roles/jit-<session-id>
#          allowed_kubernetes_namespaces='["<approved-namespace>"]'
#          kubernetes_role_type="Role"
#          generated_role_rules='<approved rules from reviewed YAML>'
#          token_default_ttl="<approved_duration>"
#          token_max_ttl="1h"         # hard ceiling regardless of YAML
#   3. jit-approver calls:
#        vault write kubernetes/creds/jit-<session-id>
#      to mint the short-lived SA token.
#   4. Cleanup backstop (kyverno cleanup cronjob) deletes BOTH:
#        - The K8s SA + RoleBinding (lease cleanup)
#        - The ephemeral Vault role:  vault delete kubernetes/roles/jit-<session-id>
#      so no orphaned role accumulates after session expiry.
#
# WHY NOT A SINGLE STATIC ROLE:
#   The kubernetes/creds/<role> endpoint does NOT accept per-call generated_role_rules
#   overrides — that parameter is only honoured at role creation time.  Issuing from
#   a static role always produces the static rules regardless of what was reviewed
#   and approved.  Per-session ephemeral roles make the issued scope match the
#   reviewed scope exactly.
#
# SCOPE CEILING (enforced by Vault regardless of what jit-approver writes):
#   - allowed_kubernetes_namespaces: approver MUST supply the approved namespace;
#     the jit-approver policy (jit-approver.hcl) allows create/update on
#     kubernetes/roles/jit-* — the approver is the scope-enforcement point.
#   - token_max_ttl: 1h hard cap (set at Vault config time, not overridable by
#     the approver).
#
# BOOTSTRAP NOTE: No static "jit-scoped" role is pre-created here.  All roles
# are created at issuance time with the prefix "jit-" and cleaned up after use.
# The jit-approver.hcl policy is scoped to "jit-*" prefix only.

log "Kubernetes secrets engine configured (per-session jit-* roles; no static jit-scoped role)"

# ── 5b. Kubernetes AUTH method (Vault Agent Injector) ───────────────────────
# The pfsense-mcp Deployment uses injector annotations with role "pfsense-mcp"
# (default auth mount auth/kubernetes). Vault validates pod SA tokens via
# TokenReview using its own in-cluster identity (auth-delegator binding is
# created by the Helm chart).
log "Enabling Kubernetes auth method..."
enable_or_skip auth kubernetes kubernetes
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443"

log "Writing pfsense-mcp policy and Kubernetes auth role..."
vault policy write pfsense-mcp "${SCRIPT_DIR}/pfsense-mcp.hcl"
vault write auth/kubernetes/role/pfsense-mcp \
  bound_service_account_names="pfsense-mcp" \
  bound_service_account_namespaces="agentic-mcp" \
  token_policies="pfsense-mcp" \
  token_ttl="15m" \
  token_max_ttl="1h"

# ── 6. KV secrets — MCP tool credentials ─────────────────────────────────────
# Values come from environment/.env — NEVER committed to git.
log "Writing pfsense MCP tool credentials to KV..."
vault kv put secret/mcp-tools/pfsense \
  api_url="${PFSENSE_API_URL}" \
  api_key="${PFSENSE_API_KEY}"

# Paths the pfsense-mcp injector templates actually read
# (platform/rhoai/base/pfsense-mcp-deployment.yaml):
: "${PFSENSE_USERNAME:?source environment/.env first — PFSENSE_USERNAME missing}"
: "${PFSENSE_PASSWORD:?source environment/.env first — PFSENSE_PASSWORD missing}"
: "${MCP_API_TOKENS:?source environment/.env first — MCP_API_TOKENS missing}"
vault kv put secret/pfsense/credentials \
  username="${PFSENSE_USERNAME}" \
  password="${PFSENSE_PASSWORD}"
vault kv put secret/mcp-tools/mcp-tokens \
  tokens="${MCP_API_TOKENS}"

log "Secrets written: secret/mcp-tools/pfsense, secret/pfsense/credentials, secret/mcp-tools/mcp-tokens"

# ── 7. Completion ─────────────────────────────────────────────────────────────
log ""
log "Bootstrap complete."
log ""
log "NEXT STEPS (PoC):"
log "  1. Revoke the root token: vault token revoke \${VAULT_TOKEN}"
log "  2. Store unseal keys in environment/.env (git-ignored) or a secrets manager."
log "  3. Verify: vault auth list, vault secrets list, vault policy list"
log "  4. Test JWT login:"
log "     vault write auth/jwt/login role=ext-proc-delegation jwt=<spire-svid-jwt>"
log ""
log "PRODUCTION NOTES:"
log "  - Enable auto-unseal (AWS KMS / Azure Key Vault / OCP Secrets Manager)."
log "  - Rotate the CA PEM in auth/jwt/config if the SPIRE CA is renewed."
log "  - Move unseal keys from .env into a hardware security module."
