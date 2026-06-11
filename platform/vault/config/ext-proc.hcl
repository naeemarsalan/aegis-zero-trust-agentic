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

# Deny all other paths explicitly to guard against policy inheritance surprises.
path "*" {
  capabilities = ["deny"]
}
