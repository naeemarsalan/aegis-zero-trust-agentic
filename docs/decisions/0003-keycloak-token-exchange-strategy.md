# ADR 0003 — Keycloak token-exchange strategy

## Status

Accepted.

## Context

UC1 requires the delegation service to turn the agent's SPIFFE JWT-SVID into the **user's**
federated access token scoped to the downstream MCP audience, so `pfsense-mcp` sees the user,
not the agent. Two standards are in play:

- **RFC 7523 (JWT bearer grant)** — exchange an externally-issued JWT (the SPIRE JWT-SVID,
  an *external* assertion) for a Keycloak token. In RHBK this leg rides a **preview feature**.
- **RFC 8693 (OAuth 2.0 Token Exchange)** — exchange an existing token for one scoped to a
  different audience/subject. Keycloak's RFC 8693 support is strongest for
  **internal-to-internal** exchange (a token Keycloak itself issued, re-scoped to another
  client/audience); external-token and impersonation cases are more constrained and version-
  dependent.

The delegation chain is therefore: **leg 0/1** RFC 7523 jwt-bearer (SVID → Keycloak token,
preview) then **leg 2** RFC 8693 exchange (→ downstream audience). Both legs touch features
whose stability varies by RHBK version (SWOT Threats: "Keycloak preview-feature instability on
the impersonation leg").

## Decision

Implement the two-leg exchange (RFC 7523 jwt-bearer → RFC 8693 audience exchange) and gate it
behind a **service-level `mode` flag** with two values:

- **`standard`** — the full RFC 7523 (preview) + RFC 8693 path described above. Default when
  the target RHBK version supports the preview feature.
- **`legacy`** — a fallback path that avoids the fragile preview leg (e.g., a pre-provisioned
  federated-identity / direct-grant arrangement, or a constrained internal-internal-only
  exchange) for RHBK versions where the preview feature is unavailable or unstable.

The flag is configuration (`internal/keycloak` + `internal/config`), selected per environment,
so the same binary runs against either RHBK posture without a code change.

## Consequences

- The PoC is **not blocked** by RHBK preview-feature instability — `legacy` is the documented
  escape hatch (mitigates the SWOT Threat directly).
- Acknowledged limits: RFC 8693 in Keycloak is most reliable **internal-to-internal**;
  external-token (RFC 7523) and impersonation cases carry preview/version risk and must be
  re-validated against the **actual RHBK version on anaeem** before the demo (open risk #1 in
  the plan).
- `internal/keycloak` must implement both legs behind one interface and select by `mode`;
  tests (testcontainer Keycloak double) must cover both paths and the failure-to-fail-closed
  behavior when an exchange leg errors.
- Audit/OTel must record which `mode` produced a given token so the exchange posture is
  observable per request.
- Downstream audience is an **allowlist** mapped per tool — the exchange may only target an
  approved audience (threat-model TB-C, Elevation).
