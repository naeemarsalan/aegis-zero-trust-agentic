# networkpolicies

Kubernetes NetworkPolicies for all nvidia-ida platform namespaces.
Implements a default-deny-all (ingress + egress) posture with explicit
allow rules — zero-trust L3/4 enforcement to complement SPIRE (SVID),
Keycloak (OIDC), Kyverno (authz policy), and Vault (secrets) controls.

## What is deployed

Per-namespace NetworkPolicy sets (one file per namespace):

| File | Namespace | Policies |
|---|---|---|
| `np-keycloak.yaml` | keycloak | default-deny, router ingress, mcp-gateway ingress, dns egress, db egress |
| `np-vault.yaml` | vault | default-deny, injector-consumer ingress (keycloak+mcp-gateway+agentic-observability ONLY), mcp-gateway ingress, dns+kube-api egress |
| `np-mcp-gateway.yaml` | mcp-gateway | default-deny, router ingress, keycloak/vault/kyverno/agentic-mcp/dns/kube-api egress |
| `np-kyverno.yaml` | kyverno | default-deny, mcp-gateway ingress, webhook ingress, kube-api+keycloak-jwks+dns egress |
| `np-agentic-mcp.yaml` | agentic-mcp | default-deny, mcp-gateway-only ingress, dns+pfSense-API (172.99.0.0/16:443) egress |
| `np-agent-sandbox.yaml` | agent-sandbox | default-deny, mcp-gateway+jit-approver+kube-api+dns egress ONLY |
| `np-agentic-observability.yaml` | agentic-observability | default-deny, openshift-monitoring ingress, loki/grafana+dns egress |

## Traffic matrix

The table below maps allowed traffic flows.  ✓ = explicitly allowed by NetworkPolicy.
Blank = blocked by default-deny.  "dns" = openshift-dns ns UDP/TCP 53/5353.

| Source \ Destination | keycloak | vault | mcp-gateway | kyverno | agentic-mcp | agent-sandbox | agentic-observability | Loki/Grafana (ext) | pfSense API 172.99.0.0/16 (ext) | kube-api | dns |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **openshift-ingress** (router) | ✓ 8080/8443 | | ✓ 8080/8443 | | | | | | | | |
| **mcp-gateway** | ✓ 8080/8443 | ✓ 8200 | | ✓ 9081 | ✓ 8000 | | | | | ✓ (jit-approver, agentgateway only) | ✓ |
| **kyverno** | ✓ 8080/8443 (JWKS) | | | | | | | | | ✓ | ✓ |
| **vault** | | | | | | | | | | ✓ | ✓ |
| **keycloak** | | ✓ 5432 (db, same ns) | | | | | | | | | ✓ |
| **agent-sandbox** | | | ✓ 8080/8443 | | | | | | | ✓ | ✓ |
| **agentic-mcp** (pfsense-mcp pod only) | | | | | | | | | ✓ 443 | | ✓ |
| **agentic-observability** | | | | | | | | ✓ 3100/3000 | | | ✓ |
| **openshift-monitoring** | | | | | | | ✓ 9090/8888 | | | | |

### Key security invariants enforced at L3/4

1. **agent-sandbox has NO direct path to vault, keycloak, or agentic-mcp.**
   Agents receive secrets via Vault Agent tmpfs injection (init container, not
   direct API call) and must contact MCP servers exclusively via mcp-gateway.

2. **agentic-mcp is only reachable from mcp-gateway.**
   No other namespace can contact MCP servers directly.  The gateway enforces
   authentication (OIDC), authorization (Kyverno), identity forwarding, and
   audit logging before any MCP tool call is proxied.

3. **Vault ingress is restricted to keycloak, mcp-gateway, and agentic-observability ONLY.**
   agent-sandbox and agentic-mcp are explicitly removed from the Vault ingress allowlist (M3
   fix).  Previously they appeared in the injector-consumers list as a latent hole — inert
   because agent-sandbox has no matching egress to vault, but a future accidental egress rule
   addition would have opened a direct credential-store path.  Now vault's ingress is fully
   belt-and-suspenders: even if an egress rule were accidentally added to agent-sandbox or
   agentic-mcp pointing at vault, the vault-side ingress policy drops it.  Only
   mcp-gateway (ext-proc-delegation :9000 and jit-approver :8080) and keycloak (CNPG DB
   connection, Vault Agent sidecar) hold a vault ingress path.  agentic-observability is
   allowed for metrics scrape only.

4. **DNS egress uses openshift-dns (port 5353/53), not arbitrary resolvers.**
   All namespaces are restricted to the cluster-internal DNS service.

5. **agentic-mcp egress to pfSense REST API is scoped to pod label app=pfsense-mcp only.**
   The `allow-egress-pfsense-api` policy targets `app: pfsense-mcp` pods and allows egress to
   `172.99.0.0/16:443`.  The pfSense firewall REST API endpoint is `https://172.99.0.1`
   (API key stored in Vault — never in git or the pod environment).  No other pod in
   agentic-mcp has egress to this range.  agentic-mcp INGRESS remains restricted to
   mcp-gateway only — pfsense-mcp is unreachable except via the authenticated gateway path.

## Apply order

NetworkPolicies are namespace-scoped.  The namespaces must exist before applying.
Apply this component AFTER all namespace-creating components:

```
# 1. Create namespaces (done by individual components)
kustomize build platform/keycloak/overlays/anaeem | oc apply -f -
kustomize build platform/vault/overlays/anaeem    | oc apply -f -
# ... (mcp-gateway, kyverno, agentic-mcp, agent-sandbox, agentic-observability)

# 2. Apply NetworkPolicies
kustomize build platform/networkpolicies/overlays/anaeem | oc apply -f -
```

## Verify

```
# Check all policies are created
oc get networkpolicy -A | grep -v openshift

# Verify default-deny exists in each namespace
for ns in keycloak vault mcp-gateway kyverno agentic-mcp agent-sandbox agentic-observability; do
  echo "=== $ns ==="
  oc -n $ns get networkpolicy default-deny-all
done

# Test connectivity is blocked (should FAIL — confirms deny-all is active)
# From agent-sandbox, attempting to reach vault must be dropped:
oc -n agent-sandbox run connectivity-test --image=registry.access.redhat.com/ubi9/ubi-minimal \
  --restart=Never --rm -i -- \
  curl -m 3 http://vault.vault.svc.cluster.local:8200/v1/sys/health
# Expected: curl: (28) Connection timed out

# Test connectivity is allowed (should SUCCEED)
# mcp-gateway -> keycloak OIDC discovery:
oc -n mcp-gateway exec deploy/agentgateway -- \
  curl -sk https://keycloak.keycloak.svc.cluster.local:8443/realms/agentic/.well-known/openid-configuration | head -1
```

## OpenShift-specific notes

- OpenShift uses `kubernetes.io/metadata.name` labels on namespaces for
  `namespaceSelector.matchLabels` — these are set automatically by OCP since k8s 1.21.
- The openshift-ingress namespace has label `kubernetes.io/metadata.name: openshift-ingress`
  by default; verify with `oc get ns openshift-ingress --show-labels`.
- The `172.30.0.1/32` ipBlock for kube-api is the standard OCP cluster IP for
  the kubernetes.default.svc Service.  Verify with `oc get svc kubernetes -n default`.

## Deploy-time selector verification (REQUIRED before relying on these policies)

NetworkPolicy `allow` rules are fail-closed: a podSelector that matches no pods
silently blocks that traffic. Workload label conventions differ across the repo
(`app: <name>` for jit-approver/ext-proc/otel; `app.kubernetes.io/name: ...` for
kyverno-authz-server, vault, the RHOAI MCP servers), and some data-plane pods are
generated by operators (agentgateway) so their labels are only knowable on-cluster.
After deploy, verify every selector against live labels:

```
oc get pods -A --show-labels | grep -E 'jit-approver|ext-proc|kyverno-authz|agentgateway|vault|keycloak|pfsense-mcp'
```

Known items to confirm/resolve on the live cluster:

- **agentgateway data-plane label** — `np-mcp-gateway.yaml` `allow-egress-kube-api`
  uses `matchExpressions{key: app.kubernetes.io/component, In: [jit-approver, agentgateway]}`.
  The agentgateway *data-plane* Deployment is created by the agentgateway controller;
  confirm its actual pod label and update this selector. (jit-approver is webhook-driven
  and likely does **not** need kube-api egress — drop it from this rule if confirmed.)
- **Duplicate netpol source** — `platform/agentgateway/base/networkpolicies.yaml` also
  defines policies for the `mcp-gateway` namespace (selecting `app.kubernetes.io/name:
  mcp-gateway`). NetworkPolicies are additive (allows union), so this is redundant, not
  harmful — but decide one owner (prefer this `platform/networkpolicies/` component) and
  remove the duplicate to avoid drift.
- **Helm-chart pod labels** (vault server, keycloak) — `np-vault.yaml` selects
  `app.kubernetes.io/name: vault` and `np-keycloak.yaml` selects `app: keycloak`;
  confirm against the rendered chart/operator output.
