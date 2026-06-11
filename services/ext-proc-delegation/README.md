# ext-proc-delegation

## What

A gRPC Envoy ext_proc server that performs **credential delegation** for MCP tool calls passing through agentgateway. It intercepts HTTP requests, **independently verifies** caller identity, exchanges the caller's token for a downstream token via Keycloak (RFC 8693), fetches per-tool secrets from Vault, injects the downstream token into the upstream request, and strips credential headers from the upstream response.

This is the trust enforcement boundary: downstream MCP servers see the **user's** identity, never the agent pod's identity. All errors fail closed (HTTP 401/403/413).

### Identity verification (defense in depth)

ext-proc does **not** trust that the gateway already validated the token. It cryptographically re-verifies the inbound `Authorization: Bearer` JWT against the Keycloak realm JWKS on every request:

- RS256 signature against keys fetched from `KEYCLOAK_JWKS_URL` (cached ~10m, force-refreshed on an unknown `kid` for rotation), `alg=none` and non-RS256 are rejected at parse;
- `iss == KEYCLOAK_ISSUER`, the token audience contains `EXPECTED_AUDIENCE`, and `exp`/`nbf` within leeway.

The **verified** token (never a header-copied or metadata-derived one) becomes the `subject_token` for exchange. When the gateway forwards `dev.agentgateway.jwt` metadata it is treated only as a cross-check: if those claims disagree with the verified token (e.g. a different `sub`/`iss`), the request **fails closed**. No verifiable token ⇒ `401`.

ext-proc also fails closed on body-less / empty-body / headers-only flows: a downstream credential is minted only in the RequestBody leg, so a stream that reaches ResponseHeaders without a completed exchange is denied (`403`) rather than allowed with an empty downstream token.

## Why

Zero-trust requirement: no static credentials in etcd or agent pods. Short-lived delegated tokens scoped to the downstream audience per MCP tool call. Full audit trail hashed to Loki (args SHA-256, never raw).

## Apply order

1. Vault JWT auth role `ext-proc-delegation` and policy for `secret/data/mcp-tools/*` and `secret/data/mcp-gateway/keycloak-client-secret` must exist before deployment.
2. SPIRE `ClusterSPIFFEID` for `ns/mcp-gateway/sa/ext-proc-delegation` must be registered.
3. Keycloak client `ext-proc-delegation` with token-exchange permissions for `mcp-downstream` audience must exist in realm `agentic`.
4. Apply: `kustomize build deploy/overlays/anaeem | kubectl apply -f -`

## Verify

```bash
# gRPC health check
grpc-health-probe -addr=ext-proc-delegation.mcp-gateway.svc.cluster.local:9000

# Prometheus metrics
curl http://ext-proc-delegation.mcp-gateway.svc.cluster.local:9090/metrics | grep agent_mcp_calls_total

# Audit logs (Loki)
logcli query '{namespace="mcp-gateway"} |= "credential_delegation"' --limit=5
```

## Security invariants

- `FAIL_MODE=closed` (compile-time grep target) — no partial success forwarding.
- Inbound JWT independently verified against Keycloak JWKS (signature/iss/aud/exp); gateway claims are not trusted, only cross-checked.
- No allow/inject is ever emitted with an empty downstream token (fail closed on body-less / no-body requests).
- Tool args logged as SHA-256 only (`mcp_args_hash`), never raw.
- Client secret read from Vault-injected tmpfs file at runtime; never an env var value.
- SPIFFE SVID (not a static token) authenticates to Vault, with the role named **explicitly** (no `default_role` reliance).
- All network egress except DNS, Keycloak, and Vault is default-deny via NetworkPolicy.

## Verification config (required env)

| Env | Default | Meaning |
|-----|---------|---------|
| `KEYCLOAK_JWKS_URL` | `https://keycloak.apps.anaeem.na-launch.com/realms/agentic/protocol/openid-connect/certs` | Realm JWKS endpoint for inbound token verification |
| `KEYCLOAK_ISSUER` | `https://keycloak.apps.anaeem.na-launch.com/realms/agentic` | Expected `iss` of the caller token |
| `EXPECTED_AUDIENCE` | `mcp-gateway` | Audience the caller token must contain |
