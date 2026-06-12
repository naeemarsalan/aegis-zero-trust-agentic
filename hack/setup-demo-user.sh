#!/usr/bin/env bash
# setup-demo-user.sh — idempotently set the UC1 demo user's password.
#
# The realm-import (platform/keycloak/base/realm-import.yaml) creates the
# `arsalan` user with a complete profile but NO password (passwords are not
# stored in git). This script sets it from DEMO_PASSWORD in environment/.env so
# a fresh deploy is reproducible without manual UI steps.
#
# Usage:
#   source environment/.env   # provides DEMO_PASSWORD, and KEYCLOAK admin creds
#   bash hack/setup-demo-user.sh
#
# Requires: the keycloak-initial-admin Secret (temp-admin) and the public route.
set -euo pipefail

KC="${KEYCLOAK_URL:-https://keycloak.apps.anaeem.na-launch.com}"
REALM="${DEMO_REALM:-agentic}"
USER="${DEMO_USER:-arsalan}"
: "${DEMO_PASSWORD:?set DEMO_PASSWORD in environment/.env}"

OC="${OC:-oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify}"
ADMIN_USER="$($OC get secret keycloak-initial-admin -n keycloak -o jsonpath='{.data.username}' | base64 -d)"
ADMIN_PW="$($OC get secret keycloak-initial-admin -n keycloak -o jsonpath='{.data.password}' | base64 -d)"

TOK="$(curl -sk -d client_id=admin-cli -d "username=${ADMIN_USER}" --data-urlencode "password=${ADMIN_PW}" \
  -d grant_type=password "${KC}/realms/master/protocol/openid-connect/token" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"

UID_="$(curl -sk -H "Authorization: Bearer ${TOK}" "${KC}/admin/realms/${REALM}/users?username=${USER}" \
  | python3 -c 'import json,sys; u=json.load(sys.stdin); print(u[0]["id"] if u else "")')"
[ -n "${UID_}" ] || { echo "user ${USER} not found in realm ${REALM}"; exit 1; }

curl -sk -X PUT -H "Authorization: Bearer ${TOK}" -H "Content-Type: application/json" \
  -d "{\"type\":\"password\",\"value\":\"${DEMO_PASSWORD}\",\"temporary\":false}" \
  "${KC}/admin/realms/${REALM}/users/${UID_}/reset-password"

echo "demo user ${USER} password set"
