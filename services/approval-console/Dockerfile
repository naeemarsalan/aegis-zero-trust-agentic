FROM python:3.12-slim

# Non-root user — matches jit-approver convention
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Runtime deps only (no build tools in final image)
RUN pip install --no-cache-dir \
    "fastapi==0.115.12" \
    "uvicorn[standard]==0.34.3" \
    "httpx==0.28.1" \
    "pydantic==2.12.5"

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
