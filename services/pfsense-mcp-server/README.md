# pfsense-mcp-server — vendor integration layer

This directory is the **thin vendor-integration wrapper** around the upstream
[gensecaihq/pfsense-mcp-server](https://github.com/gensecaihq/pfsense-mcp-server).

The complete, battle-tested pfSense MCP server (327 tools, MCP 2025-11-25 spec,
streamable-http transport on port 3000 at path `/mcp`, bearer-token auth, read-only mode,
risk classification, per-tool allowlist) already exists at:

```
/home/anaeem/pfsense-mcp-server
```

We do **NOT** rewrite that server.  This directory provides only:

| File | Purpose |
|---|---|
| `build-and-push.sh` | Build the upstream Dockerfile and push `oci.arsalan.io/nvidia-ida/pfsense-mcp:1.0.0` + `:dev` |
| `.env.example` | Documents the env-var contract for our deployment |
| `tests/test_smoke.py` | Integration smoke test: health + MCP initialize handshake |
| `README.md` | This file |

---

## Upstream server details

Source: `/home/anaeem/pfsense-mcp-server` (gensecaihq/pfsense-mcp-server)

- **MCP spec:** 2025-11-25
- **Transport:** streamable-http
- **Internal port:** 3000
- **MCP path:** `/mcp`
- **Health:** `curl http://127.0.0.1:3000/mcp` (healthcheck in Dockerfile)
- **Auth:** `MCP_API_KEY` bearer token (comma-separated for per-user tokens)
- **Guardrails:** `MCP_READ_ONLY`, `MCP_ALLOWED_TOOLS`, risk classification, rate limiting
- **pfSense version:** CE_2_8_1 (requires pfSense-pkg-RESTAPI v2)
- **pfSense backend:** https://172.99.0.1 (basic auth: admin)

---

## Build and push

```bash
cd services/pfsense-mcp-server
bash build-and-push.sh
```

The script builds `/home/anaeem/pfsense-mcp-server/Dockerfile` and tags:

- `oci.arsalan.io/nvidia-ida/pfsense-mcp:1.0.0`
- `oci.arsalan.io/nvidia-ida/pfsense-mcp:dev`

---

## Credential delivery — IMPORTANT

**PFSENSE credentials and MCP_API_KEY (per-user tokens) are NEVER baked into the image
or stored in git.  They are delivered exclusively via the Vault Agent Injector to
a tmpfs mount at `/vault/secrets/` inside the pod.**

| Vault secret path | Rendered file | Read by |
|---|---|---|
| `secret/data/pfsense/credentials` | `/vault/secrets/pfsense` | server startup (PFSENSE_USERNAME / PFSENSE_PASSWORD) |
| `secret/data/mcp-tools/mcp-tokens` | `/vault/secrets/mcp-tokens` | ext-proc-delegation injects per-user Bearer |

The platform/rhoai Vault Agent Injector annotations render these files.
The upstream server reads `PFSENSE_USERNAME` and `PFSENSE_PASSWORD` from env (sourced from
`/vault/secrets/pfsense`) and validates `MCP_API_KEY` bearer tokens from
`/vault/secrets/mcp-tokens`.

---

## UC2 demo allowlist

For the UC2 demo the `MCP_ALLOWED_TOOLS` env is set to:

```
get_firewall_rules,get_interfaces,get_dhcp_leases,get_system_info,
search_firewall_rules,search_aliases,create_firewall_rule_advanced
```

Read tools (`get_*`, `search_*`) are always allowed regardless of the allowlist.
`create_firewall_rule_advanced` is the single MEDIUM-risk write operation permitted in the
demo, gated by the upstream guardrails (rate limit + audit log) and the platform JIT
approval flow at the Kyverno authz layer.

---

## Identity delegation (UC1 proof)

The ext-proc-delegation service fetches the **requesting USER's** pfSense MCP token from
Vault and injects it as the `Authorization: Bearer <user-token>` header before forwarding
to this server.  The upstream BearerAuthMiddleware validates the token against
`MCP_API_KEY` — which is a comma-separated list of per-user tokens loaded from
`/vault/secrets/mcp-tokens`.

Because each user gets their own token in that list, the pfSense MCP server's audit log
attributes every tool call to the specific user whose token was injected by ext-proc.
The agent's own service-account identity is never seen by this server.

This is the **UC1 proof**: downstream MCP sees USER identity, never the agent's.

---

## Integration smoke test

`tests/test_smoke.py` performs two checks against a running instance (requires the server
to be accessible at `MCP_SMOKE_URL`, default `http://localhost:3000`):

1. `GET /mcp` health probe — expects HTTP 200 or 405 (MCP endpoint alive)
2. MCP `initialize` JSON-RPC handshake — expects `serverInfo.name` in response

Run:

```bash
MCP_SMOKE_URL=http://localhost:3000 \
MCP_SMOKE_API_KEY=your-token \
pytest services/pfsense-mcp-server/tests/test_smoke.py -v
```
