#!/usr/bin/env bash
# build-and-push.sh — Build the upstream pfsense-mcp-server and push to our registry.
#
# Source: /home/anaeem/pfsense-mcp-server (gensecaihq/pfsense-mcp-server)
# Upstream is NOT rewritten; this script just builds its Dockerfile and re-tags.
#
# Usage:
#   bash services/pfsense-mcp-server/build-and-push.sh [--no-push]
#
# Tags produced:
#   oci.arsalan.io/nvidia-ida/pfsense-mcp:1.0.0   (stable release tag)
#   oci.arsalan.io/nvidia-ida/pfsense-mcp:dev      (latest dev tag)

set -euo pipefail

UPSTREAM_DIR="/home/anaeem/pfsense-mcp-server"
REGISTRY="oci.arsalan.io"
IMAGE_BASE="${REGISTRY}/nvidia-ida/pfsense-mcp"
VERSION="1.0.0"
PUSH=true

# ── argument parsing ──────────────────────────────────────────────────────────
for arg in "$@"; do
  case "${arg}" in
    --no-push) PUSH=false ;;
    *) echo "Unknown argument: ${arg}"; exit 1 ;;
  esac
done

# ── sanity checks ─────────────────────────────────────────────────────────────
if [[ ! -d "${UPSTREAM_DIR}" ]]; then
  echo "ERROR: upstream directory not found: ${UPSTREAM_DIR}"
  echo "       Clone gensecaihq/pfsense-mcp-server to that path first."
  exit 1
fi

if [[ ! -f "${UPSTREAM_DIR}/Dockerfile" ]]; then
  echo "ERROR: Dockerfile not found in ${UPSTREAM_DIR}"
  exit 1
fi

if ! command -v docker &>/dev/null && ! command -v podman &>/dev/null; then
  echo "ERROR: neither docker nor podman found in PATH"
  exit 1
fi

# Use podman if available (OpenShift CI), fall back to docker
CONTAINER_CLI="docker"
if command -v podman &>/dev/null; then
  CONTAINER_CLI="podman"
fi

echo "==> Building from ${UPSTREAM_DIR}"
echo "    CLI:     ${CONTAINER_CLI}"
echo "    Tags:    ${IMAGE_BASE}:${VERSION}  ${IMAGE_BASE}:dev"
echo "    Push:    ${PUSH}"
echo ""

# ── build ─────────────────────────────────────────────────────────────────────
"${CONTAINER_CLI}" build \
  --build-arg VERSION="${VERSION}" \
  -t "${IMAGE_BASE}:${VERSION}" \
  -t "${IMAGE_BASE}:dev" \
  "${UPSTREAM_DIR}"

echo ""
echo "==> Build complete"

# ── push ──────────────────────────────────────────────────────────────────────
if [[ "${PUSH}" == true ]]; then
  echo "==> Pushing ${IMAGE_BASE}:${VERSION}"
  "${CONTAINER_CLI}" push "${IMAGE_BASE}:${VERSION}"

  echo "==> Pushing ${IMAGE_BASE}:dev"
  "${CONTAINER_CLI}" push "${IMAGE_BASE}:dev"

  echo ""
  echo "==> Done.  Images available at:"
  echo "    ${IMAGE_BASE}:${VERSION}"
  echo "    ${IMAGE_BASE}:dev"
else
  echo "==> Skipping push (--no-push)"
  echo "    Local tags:"
  echo "    ${IMAGE_BASE}:${VERSION}"
  echo "    ${IMAGE_BASE}:dev"
fi
