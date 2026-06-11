FROM python:3.12-slim

# Non-root user
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Install runtime dependencies first (better layer caching)
RUN pip install --no-cache-dir \
    "fastapi==0.115.12" \
    "uvicorn[standard]==0.34.3" \
    "httpx==0.28.1" \
    "pydantic==2.12.5" \
    "pydantic-settings==2.9.1" \
    "PyYAML==6.0.2" \
    "prometheus-client==0.21.0"

# Copy project files
COPY pyproject.toml ./
COPY src/ ./src/

# Install the package itself (no dev extras)
RUN pip install --no-cache-dir --no-deps -e .

# Drop to non-root
USER 1001

# jit-approver listens on 8080
EXPOSE 8080

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Vault injector writes:
#   /vault/secrets/gitea-token
#   /vault/secrets/webhook-secret
# SPIFFE workload API writes SVID JWT at SVID_JWT_PATH (default /var/run/secrets/svid.jwt)
CMD ["python", "-m", "jit_approver.api"]
