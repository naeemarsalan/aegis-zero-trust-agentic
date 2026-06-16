# Policy: ext-proc
# Identity: spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/ext-proc-delegation
# Purpose: Allows the ext-proc-delegation sidecar to read MCP tool secrets only.
#          It MUST NOT have write access to any path.
#
# Principle: least privilege — read-only on a single secret sub-tree.
# Agents NEVER talk to Vault directly; this policy is for a trusted platform
# component (see agent-deny.hcl for the explicit agent denial).

path "secret/data/mcp-tools/*" {
  capabilities = ["read"]
}

# Keycloak client secret for the token-exchange call (injected by the Vault
# Agent at pod start — see deploy/base/deployment.yaml annotations).
path "secret/data/mcp-gateway/*" {
  capabilities = ["read"]
}

# Sandbox consent grants (Option D delegated identity). ext-proc reads the
# grant at secret/data/sandbox-grants/<sandbox-uid> to learn the authorised
# user for an SVID-bearing in-sandbox agent, then runs RFC 8693 on-behalf
# impersonation. Read-only — ext-proc never writes grants.
path "secret/data/sandbox-grants/*" {
  capabilities = ["read"]
}

# Deny all other paths explicitly to guard against policy inheritance surprises.
path "*" {
  capabilities = ["deny"]
}
