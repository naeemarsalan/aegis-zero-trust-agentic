#!/usr/bin/env bash
# Publish the MCP capability catalog to the PUBLIC mirror repo that RHDH reads.
#
# Why a separate public repo: RHDH's (Backstage) Gitea URL reader reliably ingests
# only PUBLIC, root-level catalog files — it 404s ("no matching files found") on a
# PRIVATE repo even when the token is valid and the file is curl-able. nvidia-ida is
# private, so the registered catalog location points at anaeem/nvidia-ida-catalog
# (public, root all.yaml). This script regenerates that all.yaml from the authoring
# sources in THIS directory and pushes it, so the mirror never drifts.
#
# Auth: a Forgejo PAT with write to anaeem/nvidia-ida-catalog. Pass via GITEA_PAT.
# Usage:  GITEA_PAT=<pat> ./publish-public-catalog.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
PAT="${GITEA_PAT:?set GITEA_PAT to a Forgejo PAT with write on anaeem/nvidia-ida-catalog}"
API="https://git.arsalan.io/api/v1"
REPO="anaeem/nvidia-ida-catalog"
PATH_IN_REPO="all.yaml"
PUBLIC_RAW="https://git.arsalan.io/${REPO}/raw/branch/main/${PATH_IN_REPO}"

# Concatenate the per-entity authoring files (NOT the legacy ./all.yaml aggregator)
# and repoint each entity's source-location annotation at the published mirror.
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
{
  cat "$here/groups.yaml"; echo "---"
  cat "$here/system-agentic-platform.yaml"; echo "---"
  cat "$here/pfsense.yaml"; echo "---"
  cat "$here/echo.yaml"
} | sed -E "s#url:https://git.arsalan.io/anaeem/nvidia-ida/raw/branch/main/platform/devhub/catalog/[A-Za-z0-9_-]+\.yaml#url:${PUBLIC_RAW}#g" > "$tmp"

echo "Built $(grep -c '^kind:' "$tmp") entities -> ${REPO}/${PATH_IN_REPO}"
content="$(base64 -w0 "$tmp")"

# Create or update (Forgejo contents API needs the current blob sha to update).
sha="$(curl -s -H "Authorization: token $PAT" "${API}/repos/${REPO}/contents/${PATH_IN_REPO}?ref=main" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("sha",""))' 2>/dev/null || true)"
if [ -n "$sha" ]; then
  body="$(python3 -c "import json,sys;print(json.dumps({'message':'Update MCP capability catalog','content':sys.argv[1],'sha':sys.argv[2],'branch':'main'}))" "$content" "$sha")"
  method=PUT
else
  body="$(python3 -c "import json,sys;print(json.dumps({'message':'Add MCP capability catalog','content':sys.argv[1],'branch':'main'}))" "$content")"
  method=POST
fi
code="$(curl -s -o /dev/null -w '%{http_code}' -X "$method" -H "Authorization: token $PAT" \
  -H 'Content-Type: application/json' "${API}/repos/${REPO}/contents/${PATH_IN_REPO}" -d "$body")"
echo "  ${method} -> HTTP ${code}"
[ "$code" = 200 ] || [ "$code" = 201 ] || { echo "publish failed"; exit 1; }
echo "  published: ${PUBLIC_RAW}"
