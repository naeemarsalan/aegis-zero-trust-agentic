# Agent harness — in-sandbox runner for the nvidia-ida PoC.
#
# Base: UBI 9 + Python 3.11 (Red Hat universal base image, FIPS-compatible
# for OpenShift/Kata environments). Runs as a non-root, OCP arbitrary-UID-safe
# process (HOME=/tmp so the spawned claude CLI has a writable config dir).
#
# Security notes:
#   - No credentials in this image. The agent SVID arrives at runtime via
#     the SPIFFE Workload API socket. The inference credential (OpenRouter
#     ANTHROPIC_AUTH_TOKEN) arrives purely via the pod environment — never baked.
#   - The .claude/skills/ directory is COPIED into the image at a fixed path
#     (/app/.claude/skills) so the SDK loads on-disk skills without a network fetch.
#
# Build:
#   docker build -t oci.arsalan.io/nvidia-ida/agent-harness:dev .
#
# Run (example — actual deployment is via the sandbox pod spec):
#   docker run --rm \
#     -e MCP_GATEWAY_URL=https://mcp-gateway.apps.anaeem.na-launch.com \
#     -e AGENT_GOAL="list all firewall rules" \
#     --env-file inference.env \
#     -v /run/spiffe/:/spiffe-workload-api/:ro \
#     oci.arsalan.io/nvidia-ida/agent-harness:dev

# Single stage: the UBI9 python-311 image keeps site-packages under
# /opt/app-root (SCL app-root) which IS on sys.path. A multi-stage
# `pip install --prefix=/install` + `COPY /install /usr/local` lands packages
# OFF sys.path on this base, so we install directly into the runtime image.
FROM registry.access.redhat.com/ubi9/python-311:latest

# Root for installation; the process runs non-root (OCP assigns the UID).
USER 0

WORKDIR /app

# Install Python deps into the image's app-root site-packages (on sys.path).
# Copy requirements first so this layer caches unless the spec changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt \
 && python3 -c "import claude_agent_sdk, httpx; print('deps import OK')"

# Harness source + on-disk skills (SDK resolves skills relative to cwd /app).
COPY src/ ./src/
COPY .claude/ ./.claude/

# System Claude Code CLI via the native standalone installer (NOT npm/Node: this
# UBI image's dnf repos point at an unreachable Satellite, and we don't need
# Node anyway). The SDK's BUNDLED binary IGNORES ANTHROPIC_BASE_URL (upstream
# bug), which breaks routing through OpenRouter's Anthropic-compatible endpoint;
# pointing CLAUDE_CLI_PATH at this self-contained binary makes the SDK spawn it
# instead, honouring ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN. No credential is
# baked in — auth arrives purely via the pod environment at runtime.
RUN export HOME=/root \
 && curl -fsSL https://claude.ai/install.sh | bash \
 && real="$(readlink -f /root/.local/bin/claude 2>/dev/null || true)"; \
    { [ -n "$real" ] && [ -f "$real" ]; } || real="$(find / -type f -name claude -executable 2>/dev/null | head -1)"; \
    echo "resolved claude binary: $real"; [ -n "$real" ] && [ -f "$real" ] \
 && cp "$real" /usr/local/bin/claude \
 && chmod 0755 /usr/local/bin/claude \
 && /usr/local/bin/claude --version

# Drop to non-root (OCP overrides with an arbitrary UID under restricted-v2).
USER 1001

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Default gateway URL — overridden by the pod spec environment.
    MCP_GATEWAY_URL=https://mcp-gateway.apps.anaeem.na-launch.com \
    # SPIFFE Workload API socket path (mounted by SPIRE CSI driver).
    SPIFFE_ENDPOINT_SOCKET=unix:///spiffe-workload-api/spire-agent.sock \
    # Sidecar-written SVID JWT path (alternative to Workload API).
    SVID_JWT_PATH=/var/run/secrets/svid-gateway.jwt \
    # Add the harness src to PYTHONPATH.
    PYTHONPATH=/app/src \
    # Force the SDK to spawn the system CLI (honours ANTHROPIC_BASE_URL).
    CLAUDE_CLI_PATH=/usr/local/bin/claude \
    # HOME must be writable under OpenShift's arbitrary-UID SCC; /tmp always is.
    # The system claude CLI writes its config/state under $HOME; skills still
    # load from the cwd (/app/.claude/skills), independent of HOME.
    HOME=/tmp

# The agent goal arrives via argv[1] or AGENT_GOAL env var.
ENTRYPOINT ["python", "-m", "agent_harness.agent_runner"]
