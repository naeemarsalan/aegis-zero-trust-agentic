# Vault policy for the sandboxed agent (Phase 5 capstone — OpenShell-in-Kata).
#
# The agent runs inside a Kata micro-VM in agent-sandbox with
# automountServiceAccountToken: false — it has NO Kubernetes SA token. Its only
# identity is its SPIRE JWT-SVID (spiffe://anaeem.na-launch.com/ns/agent-sandbox/
# sa/openshell-agent), which it presents to Vault auth/jwt to obtain a token and
# read its own secrets. This enforces the design invariant: the agent pulls its
# inference credential FROM Vault USING its identity — it is never handed a token.
#
# Least privilege: read-only, single path. No list, no write, nothing else.
path "secret/data/agent-sandbox/inference" {
  capabilities = ["read"]
}
