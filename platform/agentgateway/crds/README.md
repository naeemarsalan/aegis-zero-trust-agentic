# CRD Vendoring

Vendor agentgateway CRD YAMLs here for offline `kubeconform` validation.

## Fetch

```bash
VERSION=v1.3.0-alpha.1
REPO=https://raw.githubusercontent.com/agentgateway/agentgateway/${VERSION}

# Check release assets for the bundled CRD file (exact name may vary):
gh release view ${VERSION} --repo agentgateway/agentgateway --json assets --jq '.[].name'

# Typical pattern — adjust filename as needed:
curl -sL "${REPO}/controller/install/helm/agentgateway/files/crds.yaml" \
  -o agentgateway-crds.yaml
```

## Validate

```bash
kustomize build platform/agentgateway/overlays/anaeem | \
  kubeconform \
    -schema-location default \
    -schema-location "crds/{{ .ResourceKind }}_{{ .ResourceAPIVersion }}.json" \
    -ignore-missing-schemas \
    -summary
```
