#!/usr/bin/env bash
# hack/validate.sh — offline validation gate for nvidia-ida
#
# Checks:
#   1. kustomize build on every kustomization.yaml under platform/ and gitops/
#   2. kubeconform (auto-installed if missing) piped over each build output
#   3. go vet + go build in services/ext-proc-delegation (if go present)
#   4. python -m py_compile over services/*/*.py files (if python3 present)
#
# Exit code: non-zero if any check failed; prints a summary table at the end.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBECONFORM_VERSION="0.7.0"
KUBECONFORM_BIN="${HOME}/.local/bin/kubeconform"
KUBECONFORM_SKIP_MISSING="-ignore-missing-schemas"

# ── colour helpers ─────────────────────────────────────────────────────────────
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
RESET=$'\033[0m'

pass() { echo "${GREEN}PASS${RESET}  $*"; }
fail() { echo "${RED}FAIL${RESET}  $*"; }
warn() { echo "${YELLOW}WARN${RESET}  $*"; }
info() { echo "      $*"; }

# ── result accumulator ─────────────────────────────────────────────────────────
declare -a FAILURES=()
record_fail() { FAILURES+=("$1"); }

# ── install kubeconform if missing ─────────────────────────────────────────────
install_kubeconform() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)  arch="amd64" ;;
    aarch64) arch="arm64" ;;
    *)       warn "Unknown arch ${arch}, skipping kubeconform install"; return 1 ;;
  esac
  local os
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  local url="https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/kubeconform-${os}-${arch}.tar.gz"
  info "Downloading kubeconform ${KUBECONFORM_VERSION} from ${url}"
  mkdir -p "${HOME}/.local/bin"
  local tmp
  tmp="$(mktemp -d)"
  if curl -fsSL "${url}" | tar -xz -C "${tmp}"; then
    install -m 0755 "${tmp}/kubeconform" "${KUBECONFORM_BIN}"
    rm -rf "${tmp}"
    info "Installed kubeconform to ${KUBECONFORM_BIN}"
  else
    warn "Failed to download kubeconform — schema validation will be skipped"
    rm -rf "${tmp}"
    return 1
  fi
}

ensure_kubeconform() {
  if command -v kubeconform &>/dev/null; then
    KUBECONFORM_BIN="$(command -v kubeconform)"
    return 0
  fi
  if [[ -x "${KUBECONFORM_BIN}" ]]; then
    return 0
  fi
  install_kubeconform || return 1
}

KUBECONFORM_OK=false
if ensure_kubeconform; then
  KUBECONFORM_OK=true
fi

# ── 1. kustomize build + kubeconform ──────────────────────────────────────────
echo ""
echo "=== 1/4  kustomize build + kubeconform ==================================="

if ! command -v kustomize &>/dev/null; then
  warn "kustomize not found — skipping manifest validation"
  record_fail "kustomize not installed"
else
  # Find every kustomization.yaml (or kustomization.yml) under platform/ and gitops/
  while IFS= read -r kfile; do
    dir="$(dirname "${kfile}")"
    rel="${dir#"${REPO_ROOT}/"}"
    output_file="$(mktemp)"
    build_ok=false
    conform_ok=false

    # Components that use the helmCharts generator require --enable-helm.
    # Search both the current kustomization.yaml AND any kustomization.yaml files
    # reachable via relative "../" references (e.g. overlays that extend a helm base).
    # We do this by scanning the component subtree rooted two levels up from the
    # kustomization file — conservative but avoids false negatives.
    HELM_FLAG=""
    component_root="$(dirname "$(dirname "${dir}")")"
    if grep -rq "helmCharts:" "${component_root}" 2>/dev/null; then
      HELM_FLAG="--enable-helm"
    fi

    if kustomize build ${HELM_FLAG} "${dir}" > "${output_file}" 2>&1; then
      build_ok=true
    fi

    if [[ "${build_ok}" == true ]]; then
      if [[ "${KUBECONFORM_OK}" == true ]]; then
        # Re-run build piped to kubeconform; capture errors
        if kustomize build ${HELM_FLAG} "${dir}" 2>/dev/null \
            | "${KUBECONFORM_BIN}" \
                ${KUBECONFORM_SKIP_MISSING} \
                -kubernetes-version "1.33.0" \
                -summary \
                -output pretty 2>&1; then
          conform_ok=true
          pass "${rel}"
        else
          fail "${rel} (kubeconform)"
          record_fail "${rel}: kubeconform errors"
        fi
      else
        conform_ok=true
        pass "${rel}  (kubeconform skipped)"
      fi
    else
      fail "${rel} (kustomize build)"
      # Show first 20 lines of error
      head -20 "${output_file}" | while IFS= read -r line; do info "  ${line}"; done
      record_fail "${rel}: kustomize build failed"
    fi
    rm -f "${output_file}"
  done < <(find \
      "${REPO_ROOT}/platform" \
      "${REPO_ROOT}/gitops" \
      -maxdepth 5 \
      \( -name "kustomization.yaml" -o -name "kustomization.yml" \) \
      2>/dev/null | sort)

  # Report if no kustomizations found yet (dirs may not exist yet)
  found_count=$(find \
      "${REPO_ROOT}/platform" \
      "${REPO_ROOT}/gitops" \
      -maxdepth 5 \
      \( -name "kustomization.yaml" -o -name "kustomization.yml" \) \
      2>/dev/null | wc -l)
  if [[ "${found_count}" -eq 0 ]]; then
    warn "No kustomization.yaml files found under platform/ or gitops/ (dirs may not exist yet)"
  fi
fi

# ── 2. Go: vet + build in services/ext-proc-delegation ───────────────────────
echo ""
echo "=== 2/4  Go vet + build (services/ext-proc-delegation) ==================="

GO_DIR="${REPO_ROOT}/services/ext-proc-delegation"

if ! command -v go &>/dev/null; then
  warn "go not found — skipping Go validation"
elif [[ ! -d "${GO_DIR}" ]]; then
  warn "services/ext-proc-delegation not found — skipping Go validation"
else
  echo "      go vet ./..."
  if (cd "${GO_DIR}" && go vet ./... 2>&1); then
    pass "go vet"
  else
    fail "go vet"
    record_fail "services/ext-proc-delegation: go vet failed"
  fi

  echo "      go build ./..."
  if (cd "${GO_DIR}" && go build ./... 2>&1); then
    pass "go build"
  else
    fail "go build"
    record_fail "services/ext-proc-delegation: go build failed"
  fi
fi

# ── 3. Python syntax check ────────────────────────────────────────────────────
echo ""
echo "=== 3/4  Python syntax (services/*/*.py) ================================="

if ! command -v python3 &>/dev/null; then
  warn "python3 not found — skipping Python syntax check"
else
  py_files=()
  while IFS= read -r f; do
    py_files+=("${f}")
  done < <(find "${REPO_ROOT}/services" -maxdepth 5 -name "*.py" 2>/dev/null | sort)

  if [[ ${#py_files[@]} -eq 0 ]]; then
    warn "No .py files found under services/ yet"
  else
    for pyf in "${py_files[@]}"; do
      rel="${pyf#"${REPO_ROOT}/"}"
      if python3 -m py_compile "${pyf}" 2>&1; then
        pass "${rel}"
      else
        fail "${rel}"
        record_fail "${rel}: python syntax error"
      fi
    done
  fi
fi

# ── 4. Summary ────────────────────────────────────────────────────────────────
echo ""
echo "=== 4/4  Summary ========================================================="

if [[ ${#FAILURES[@]} -eq 0 ]]; then
  echo "${GREEN}All checks passed.${RESET}"
  exit 0
else
  echo "${RED}${#FAILURES[@]} check(s) failed:${RESET}"
  for f in "${FAILURES[@]}"; do
    echo "  ${RED}✗${RESET}  ${f}"
  done
  exit 1
fi
