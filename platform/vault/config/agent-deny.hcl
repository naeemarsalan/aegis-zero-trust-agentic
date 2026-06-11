# Policy: agent-deny
# Purpose: Explicit deny-all policy for agent identities.
#
# SECURITY INVARIANT: Agents (running in agent-sandbox or agentic-mcp namespaces)
# MUST NEVER talk to Vault directly.  All secret access is mediated by the
# ext-proc-delegation component, which validates the SPIFFE SVID, checks Kyverno
# policy, and proxies only permitted tool calls.
#
# This policy exists as a defence-in-depth measure: even if an agent somehow
# obtained a Vault token, it would have zero capabilities.
#
# If you find yourself trying to grant an agent identity access to any Vault path,
# STOP — redesign the flow so that a trusted platform component mediates access.

path "*" {
  capabilities = ["deny"]
}
