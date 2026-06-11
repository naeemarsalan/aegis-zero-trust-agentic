# platform/kyverno

## What

Kyverno policy enforcement for the nvidia-ida agentic platform on the anaeem SNO cluster.  Three sub-components:

| Component | Namespace | Purpose |
|---|---|---|
| `authz/` | `kyverno` | Envoy authz server + 4 ValidatingPolicies for MCP tool authorization |
| `guardrails/` | cluster-scoped | 4 admission ClusterPolicies for platform security invariants |
| `cleanup/` | cluster-scoped | ClusterCleanupPolicy backstop for expired JIT resources |

## Directory layout

```
platform/kyverno/
├── authz/
│   ├── base/               # Deployment, Service, RBAC, NetworkPolicy, 4x ValidatingPolicy
│   ├── overlays/anaeem/
│   └── README.md
├── guardrails/
│   ├── base/               # 4x ClusterPolicy (Audit mode for PoC)
│   ├── overlays/anaeem/
│   └── README.md
├── cleanup/
│   ├── base/               # ClusterCleanupPolicy + commented CronJob fallback
│   ├── overlays/anaeem/
│   └── README.md
├── tests/
│   ├── authz/              # kyverno-json test cases (14 scenarios)
│   ├── guardrails/         # Chainsaw test skeleton
│   └── README.md           # How to run all tests
├── overlays/
│   └── anaeem/
│       └── kustomization.yaml   # Aggregating overlay for all sub-components
└── README.md               # This file
```

## Apply order

Pre-requisites: Kyverno operator installed (via `platform/00-operators`), `keycloak` namespace running with realm `agentic`.

Apply individual sub-components in order, or all at once via the aggregating overlay:

```bash
# All components at once (recommended)
kustomize build platform/kyverno/overlays/anaeem | oc apply -f -

# Or individually
kustomize build platform/kyverno/authz/overlays/anaeem | oc apply -f -
kustomize build platform/kyverno/guardrails/overlays/anaeem | oc apply -f -
kustomize build platform/kyverno/cleanup/overlays/anaeem | oc apply -f -
```

## Verify

```bash
# Authz server
oc get pods -n kyverno -l app.kubernetes.io/name=kyverno-authz-server
oc get svc kyverno-authz-server -n kyverno
oc get validatingpolicies -n kyverno

# Guardrails
oc get clusterpolicies

# Cleanup
oc get clustercleanuppolicies

# Offline policy tests
kyverno-json test platform/kyverno/tests/authz/

# Integration tests (requires cluster)
chainsaw test platform/kyverno/tests/guardrails/
```

## Security invariants enforced here

- No unauthenticated MCP calls (401 without valid Keycloak JWT)
- `mcp-users` group: read-only pfSense tools only (`get_firewall_rules`, `get_interfaces`, `get_dhcp_leases`)
- `mcp-admins` + write tools: JIT session header required (Gitea PR-merge approval gate)
- `restricted` group: unconditionally blocked
- Agent pods in `agent-sandbox`: must use Kata runtime class
- Platform pods: no default SA token automount
- Platform namespaces: default-deny NetworkPolicy auto-generated and validated
- Container images: must come from `oci.arsalan.io`, `registry.redhat.io`, or `quay.io` (Audit — see guardrails/README.md for Enforce pre-conditions)
