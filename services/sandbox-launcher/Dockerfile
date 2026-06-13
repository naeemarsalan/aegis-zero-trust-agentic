FROM python:3.12-slim

# Non-root user — mirrors jit-approver pattern
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
    "prometheus-client==0.21.0" \
    "PyJWT==2.10.1" \
    "cryptography>=43.0.0" \
    "grpcio==1.81.1" \
    "protobuf>=6.31,<7"

# Copy project files
COPY pyproject.toml ./
COPY src/ ./src/

# Install the package itself (no dev extras)
RUN pip install --no-cache-dir --no-deps -e .

# Drop to non-root
USER 1001

# sandbox-launcher listens on 8080
EXPOSE 8080

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Vault injector writes:
#   /vault/secrets/launcher-oidc-secret (OIDC client secret for gateway calls)
# RHDH JWKS URL + token issuer come from env vars (no secrets stored)
# mTLS certs for OpenShell gRPC: /etc/openshell-client-tls/{ca,tls}.{crt,key}
# Baseline policy ConfigMap: /etc/openshell-baseline/baseline.yaml
CMD ["python", "-m", "sandbox_launcher.api"]
