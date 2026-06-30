# Policy: llm-proxy
# Identity: serviceaccount maas/llm-proxy (Kubernetes auth role "llm-proxy")
# Purpose: MaaS model-plane server-side OpenRouter-key read path. The llm-proxy
#          injects the OpenRouter API key into the upstream completion call
#          server-side — the agent SVID is the model credential and never holds
#          the key. Read-only on exactly the one path the proxy reads.
#
# Least privilege: read-only, single path. No list, no write, nothing else.
path "secret/data/mcp-tools/openrouter" {
  capabilities = ["read"]
}
