# nvidia-ida — developer targets
# Usage: make help  (default)
#
# Prerequisites: kustomize, kubeconform (auto-installed to ~/.local/bin if missing),
#                go 1.22+, python3, podman.

SHELL        := /bin/bash
.DEFAULT_GOAL := help

REGISTRY     := oci.arsalan.io/nvidia-ida
TAG          := dev
SERVICES     := ext-proc-delegation jit-approver pfsense-mcp

# ─── primary targets ──────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help message (default target)
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
	     /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: validate
validate: ## Validate all kustomize overlays, service code, and Python syntax
	@bash hack/validate.sh

.PHONY: render
render: ## Render all kustomize overlays into rendered/<component>.yaml
	@bash hack/render.sh

.PHONY: test-extproc
test-extproc: ## Run Go unit tests for services/ext-proc-delegation
	@if [ ! -d services/ext-proc-delegation ]; then \
	  echo "services/ext-proc-delegation does not exist — skipping"; exit 0; \
	fi
	cd services/ext-proc-delegation && go test ./...

.PHONY: test-policies
test-policies: ## Run Kyverno CLI tests for platform/kyverno policies (if kyverno CLI present)
	@if ! command -v kyverno &>/dev/null; then \
	  echo "kyverno CLI not found — skipping policy tests (install from https://kyverno.io/docs/kyverno-cli/)"; exit 0; \
	fi
	@if [ ! -d platform/kyverno ]; then \
	  echo "platform/kyverno does not exist — skipping"; exit 0; \
	fi
	@echo "Running kyverno test..."
	kyverno test platform/kyverno/

.PHONY: build-images
build-images: ## Build all service container images tagged $(REGISTRY)/<name>:dev
	@for svc in $(SERVICES); do \
	  dir="services/$${svc}"; \
	  if [ ! -d "$${dir}" ]; then \
	    echo "SKIP  $${svc} — directory $${dir} not found"; \
	    continue; \
	  fi; \
	  if [ ! -f "$${dir}/Containerfile" ] && [ ! -f "$${dir}/Dockerfile" ]; then \
	    echo "SKIP  $${svc} — no Containerfile or Dockerfile in $${dir}"; \
	    continue; \
	  fi; \
	  image="$(REGISTRY)/$${svc}:$(TAG)"; \
	  echo "BUILD $${image}"; \
	  podman build -t "$${image}" "$${dir}"; \
	done
	@echo "Done building images."

# ─── convenience aliases ──────────────────────────────────────────────────────

.PHONY: all
all: validate render ## Run validate then render
