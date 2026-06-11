#!/usr/bin/env bash
# hack/render.sh — render every kustomize overlay to rendered/<component>.yaml
#
# Output directory rendered/ is gitignored.
# Each overlay is written as:
#   rendered/<component>/<overlay-relative-path>.yaml
# where <component> is the path relative to the repo root with "/" replaced by "__".
#
# Usage:
#   bash hack/render.sh
#   make render

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RENDER_DIR="${REPO_ROOT}/rendered"

# ── colour helpers ─────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
RESET=$'\033[0m'

pass() { echo "${GREEN}RENDER${RESET}  $*"; }
fail() { echo "${RED}FAIL  ${RESET}  $*"; }
warn() { echo "${YELLOW}WARN  ${RESET}  $*"; }

if ! command -v kustomize &>/dev/null; then
  echo "${RED}ERROR${RESET}: kustomize not found. Install from https://kubectl.docs.kubernetes.io/installation/kustomize/"
  exit 1
fi

# Prepare rendered/ directory
mkdir -p "${RENDER_DIR}"

declare -a FAILURES=()

# Find all kustomization files under platform/ and gitops/
while IFS= read -r kfile; do
  dir="$(dirname "${kfile}")"
  # Compute a safe output filename: strip repo root prefix, replace / with __
  rel="${dir#"${REPO_ROOT}/"}"
  safe="${rel//\//__}"
  out="${RENDER_DIR}/${safe}.yaml"

  # Ensure parent dir of output exists (it's all flat under rendered/)
  mkdir -p "${RENDER_DIR}"

  if kustomize build "${dir}" > "${out}" 2>&1; then
    line_count=$(wc -l < "${out}")
    pass "${rel}  →  rendered/${safe}.yaml  (${line_count} lines)"
  else
    fail "${rel}  (kustomize build failed)"
    # Write the error into the output file for inspection
    {
      echo "# kustomize build FAILED for ${rel}"
      echo "# Error output:"
      kustomize build "${dir}" 2>&1 | sed 's/^/# /' || true
    } > "${out}"
    FAILURES+=("${rel}")
  fi
done < <(find \
    "${REPO_ROOT}/platform" \
    "${REPO_ROOT}/gitops" \
    -maxdepth 5 \
    \( -name "kustomization.yaml" -o -name "kustomization.yml" \) \
    2>/dev/null | sort)

found_count=$(find \
    "${REPO_ROOT}/platform" \
    "${REPO_ROOT}/gitops" \
    -maxdepth 5 \
    \( -name "kustomization.yaml" -o -name "kustomization.yml" \) \
    2>/dev/null | wc -l)

if [[ "${found_count}" -eq 0 ]]; then
  warn "No kustomization.yaml files found under platform/ or gitops/ — nothing rendered."
fi

echo ""
if [[ ${#FAILURES[@]} -eq 0 ]]; then
  echo "${GREEN}Render complete. Output in rendered/${RESET}"
  exit 0
else
  echo "${RED}${#FAILURES[@]} render(s) failed:${RESET}"
  for f in "${FAILURES[@]}"; do
    echo "  ${RED}✗${RESET}  ${f}"
  done
  exit 1
fi
