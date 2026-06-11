# echo-mcp — minimal MCP identity-echo server (UC1 golden test upstream)
FROM python:3.12-slim AS builder
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --target=/install .

FROM python:3.12-slim
# OpenShift runs containers with an arbitrary high UID in the root (0) group.
RUN useradd -u 1001 -r -g 0 -s /sbin/nologin echo || true
WORKDIR /app
COPY --from=builder /install /usr/local/lib/python3.12/site-packages
COPY src ./src
ENV PYTHONPATH=/app/src \
    MCP_PORT=8000 \
    LOG_LEVEL=INFO
USER 1001
EXPOSE 8000
ENTRYPOINT ["python", "-m", "echo_mcp.server"]
