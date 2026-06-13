#!/usr/bin/env bash
# Populate the openshell-oidc-ca ConfigMap with the CA the OpenShell gateway must
# trust to validate Keycloak's OIDC issuer over TLS.
#
# The Keycloak public route (keycloak.apps.<domain>) is EDGE-terminated, so the
# OpenShift router presents the ingress wildcard cert (*.apps.<domain>) signed by
# the ingress-operator router-CA. That router-CA lives, cluster-wide, in
# openshift-config-managed/default-ingress-cert (key ca-bundle.crt). The gateway
# reads this ConfigMap via server.oidc.caConfigMapName (chart sets
# SSL_CERT_FILE=/etc/openshell-tls/oidc-ca/ca.crt). See
# platform/openshell/values-openshift.yaml.
#
# Idempotent: re-run after a cluster ingress-CA rotation to refresh the bundle.
set -euo pipefail
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/anaeem-kubeconfig}"
NS="${OPENSHELL_NS:-openshell}"

ca="$(mktemp)"; trap 'rm -f "$ca"' EXIT
oc --kubeconfig="$KUBECONFIG" -n openshift-config-managed \
   get configmap default-ingress-cert -o jsonpath='{.data.ca-bundle\.crt}' > "$ca"
test -s "$ca" || { echo "ERROR: empty ingress CA bundle" >&2; exit 1; }

oc --kubeconfig="$KUBECONFIG" -n "$NS" create configmap openshell-oidc-ca \
   --from-file=ca.crt="$ca" --dry-run=client -o yaml \
 | oc --kubeconfig="$KUBECONFIG" -n "$NS" apply -f -

echo "openshell-oidc-ca updated with the ingress router-CA:"
oc --kubeconfig="$KUBECONFIG" -n "$NS" get configmap openshell-oidc-ca \
   -o jsonpath='{.data.ca\.crt}' | openssl x509 -noout -subject -issuer 2>/dev/null || true
