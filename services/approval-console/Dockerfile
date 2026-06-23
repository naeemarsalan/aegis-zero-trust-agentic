FROM python:3.12-slim

# Non-root user — matches jit-approver convention
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

# --------------------------------------------------------------------------
# webshell dependency: the webshell bridge (webshell/bridge.py) shells out to
# the `oc` CLI to open an interactive `oc exec -it ... -- /bin/bash` PTY on the
# sandbox pod. python:3.12-slim ships no `oc`, so `create_subprocess_exec`
# raised [Errno 2] No such file or directory and the popup stayed black.
# Bundle a matching OpenShift client at /usr/local/bin/oc. In-cluster, `oc`
# auto-authenticates via the mounted SA token + KUBERNETES_SERVICE_HOST (no
# kubeconfig). The console SA has get/create on pods/exec in ns openshell.
# OCP server is 4.20; the 4.19 stable client is wire-compatible (±1 minor).
# --------------------------------------------------------------------------
ARG OC_VERSION=4.19.0
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    curl -fsSL -o /tmp/oc.tar.gz \
      "https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/${OC_VERSION}/openshift-client-linux-${OC_VERSION}.tar.gz"; \
    tar -xzf /tmp/oc.tar.gz -C /usr/local/bin oc; \
    chmod 0755 /usr/local/bin/oc; \
    rm -f /tmp/oc.tar.gz; \
    apt-get purge -y curl; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*; \
    /usr/local/bin/oc version --client

WORKDIR /app

# Runtime deps only (no build tools in final image)
RUN pip install --no-cache-dir \
    "fastapi==0.115.12" \
    "uvicorn[standard]==0.34.3" \
    "httpx==0.28.1" \
    "pydantic==2.12.5" \
    "kubernetes==31.0.0"

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir --no-deps -e .

USER 1001

# approval-console listens on 8090 to avoid clashing with jit-approver (8080)
# when running both in the same namespace or host.
EXPOSE 8090

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Required env at runtime:
#   JIT_APPROVER_URL  — e.g. http://jit-approver.mcp-gateway.svc.cluster.local:8080
#   GITEA_URL         — e.g. https://git.arsalan.io
#   GITEA_TOKEN       — Gitea API token (or /vault/secrets/gitea-token)
#   GITEA_REPO        — e.g. anaeem/nvidia-ida  (owner/repo)
CMD ["python", "-m", "approval_console.app"]
