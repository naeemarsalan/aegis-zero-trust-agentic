# platform/kyverno/tests

## What

Policy test cases for the four authz `ValidatingPolicy` resources and a Chainsaw test skeleton for the four admission `ClusterPolicy` guardrails.

## Structure

```
tests/
├── authz/
│   ├── test.yaml               # kyverno-json test suite (14 cases covering all policy x group x tool combinations)
│   └── resources/              # Envoy CheckRequest stubs (one file per scenario)
│       ├── no-auth-request.yaml
│       ├── options-preflight.yaml
│       ├── well-known-request.yaml
│       ├── mcp-users-get-firewall-rules.yaml
│       ├── mcp-users-add-firewall-rule.yaml
│       ├── mcp-admins-add-firewall-rule-with-jit.yaml
│       ├── mcp-admins-add-firewall-rule-no-jit.yaml
│       ├── mcp-admins-get-firewall-rules.yaml
│       ├── restricted-group-get-rules.yaml
│       └── no-group-get-rules.yaml
└── guardrails/
    └── chainsaw-test.yaml      # Chainsaw test skeleton for ClusterPolicy guardrails
```

## Running authz policy tests (kyverno-json)

`kyverno-json test` evaluates CEL policies offline without a cluster.

```bash
# Install kyverno-json (if not present)
go install github.com/kyverno/kyverno-json/cmd/kyverno-json@latest
# or download from https://github.com/kyverno/kyverno-json/releases

# Run from repo root
kyverno-json test platform/kyverno/tests/authz/
```

Expected output: 14 tests, 0 failures.

### JWT test tokens

Test resource files contain pre-encoded fake JWT tokens with the following payloads.
Signatures are intentionally invalid (`FAKESIG_FOR_POLICY_TESTS_ONLY`) — `kyverno-json`
mocks `jwks.Fetch()` and `jwt.Decode()` for offline evaluation.

| Token group | Groups claim | Used in |
|---|---|---|
| `mcp-users` | `["mcp-users"]` | `mcp-users-*.yaml` |
| `mcp-admins` | `["mcp-admins"]` | `mcp-admins-*.yaml` |
| `restricted` | `["restricted"]` | `restricted-group-*.yaml` |
| `no-group` | `[]` | `no-group-*.yaml` |

For integration tests (real cluster), obtain tokens from Keycloak:
```bash
# mcp-users token
curl -s -X POST \
  https://keycloak.apps.ocp-dev.na-launch.com/realms/agentic/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=mcp-gateway&username=<user>&password=<pw>' \
  | jq -r .access_token
```

## Running guardrail tests (Chainsaw)

Chainsaw tests require a running cluster with Kyverno and the guardrail policies installed.

```bash
# Install chainsaw
go install github.com/kyverno/chainsaw@latest
# or https://kyverno.github.io/chainsaw/latest/quick-start/

# Point kubeconfig at anaeem cluster
export KUBECONFIG=~/.kube/anaeem-kubeconfig

# Apply guardrails first
kustomize build platform/kyverno/guardrails/overlays/anaeem | oc apply -f -

# Run chainsaw tests
chainsaw test platform/kyverno/tests/guardrails/
```

The chainsaw tests exercise each guardrail ClusterPolicy in Audit mode.  When policies are flipped to Enforce, update the test `expect` blocks to assert admission rejection instead of successful apply.
