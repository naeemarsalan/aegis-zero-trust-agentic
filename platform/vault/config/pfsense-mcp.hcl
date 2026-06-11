# Policy for the pfsense-mcp Vault Agent sidecar (Kubernetes auth role
# "pfsense-mcp"). Read-only on exactly the two paths the injector templates
# reference in platform/rhoai/base/pfsense-mcp-deployment.yaml.

path "secret/data/pfsense/credentials" {
  capabilities = ["read"]
}

path "secret/data/mcp-tools/mcp-tokens" {
  capabilities = ["read"]
}
