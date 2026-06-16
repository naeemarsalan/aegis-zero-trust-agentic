// Package spire verifies SPIRE-issued JWT-SVIDs for the agent-sandbox workload.
//
// The SPIRE OIDC discovery provider issues RS256 or ES256 JWTs whose issuer is
// https://spire-oidc.apps.anaeem.na-launch.com (SpireOIDCDiscoveryProvider
// jwtIssuer). These are a SEPARATE token class from the Keycloak user JWTs;
// the only workload identity carried is in the standard JWT sub claim:
//
//	sub = spiffe://anaeem.na-launch.com/ns/openshell/sandbox/<sandbox-uuid>
//
// Real SPIRE JWT-SVIDs do NOT carry arbitrary custom claims. The sandbox UUID
// (== the k8s Sandbox CR uid, the Vault grant key) is parsed from the SPIFFE
// URI path segment that follows "/sandbox/".
//
// SECURITY INVARIANT: the SVID verifier enforces the trust domain
// anaeem.na-launch.com (no other trust domain is accepted). The sub claim in
// a SPIRE JWT-SVID is the SPIFFE URI, not a human username; do NOT use it as
// the downstream requested_subject — use grant.User instead.
//
// Fail-closed: if the sub does not contain a "/sandbox/<uuid>" segment, or the
// uuid is empty, VerifySVID returns an error. A generic ns/sa SVID that has no
// sandbox binding is rejected immediately.
package spire

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"git.arsalan.io/anaeem/nvidia-ida/services/ext-proc-delegation/internal/jwks"
)

const (
	// TrustDomain is the only SPIFFE trust domain we accept. SVIDs from any
	// other trust domain are rejected regardless of signature validity.
	TrustDomain = "spiffe://anaeem.na-launch.com/"
)

// SVIDClaims holds the trusted claims extracted from a verified SPIRE JWT-SVID.
// These are derived ONLY from the cryptographically verified payload — never
// from HTTP headers.
type SVIDClaims struct {
	// SpiffeID is the full SPIFFE URI (the JWT sub claim), e.g.
	// spiffe://anaeem.na-launch.com/ns/openshell/sandbox/<uuid>
	SpiffeID string

	// SandboxUID is the sandbox UUID parsed from the SPIFFE URI path segment
	// following "/sandbox/". It equals the k8s Sandbox CR uid and the Vault
	// grant key (secret/data/sandbox-grants/<SandboxUID>). Always non-empty on
	// a successful VerifySVID call; VerifySVID fails closed if the sub has no
	// "/sandbox/<uuid>" segment.
	SandboxUID string

	// SandboxNonce is vestigial and always empty. Real SPIRE JWT-SVIDs cannot
	// carry arbitrary custom claims; binding is the cryptographic, unique
	// sub-path UUID. This field is retained for struct compatibility only and
	// must not be used for any security decision.
	SandboxNonce string
}

// Verifier wraps a jwks.Verifier configured for the SPIRE OIDC JWKS endpoint
// and enforces the SPIFFE trust domain.
type Verifier struct {
	inner *jwks.Verifier
}

// New constructs a SPIRE SVID verifier.
// cfg.JWKSURL is the SPIRE OIDC discovery JWKS endpoint
// (e.g. https://spire-oidc.apps.anaeem.na-launch.com/keys).
// cfg.Issuer must match the spire-oidc jwtIssuer config field.
// cfg.ExpectedAudience must be "mcp-gateway".
// AllowEC is forced to true (SPIRE may issue ES256).
func New(cfg jwks.Config) (*Verifier, error) {
	// SPIRE OIDC providers may issue ES256 or RS256; always allow both.
	cfg.AllowEC = true
	v, err := jwks.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("spire verifier: %w", err)
	}
	return &Verifier{inner: v}, nil
}

// VerifySVID verifies the raw JWT-SVID string and returns its trusted claims.
// Fails closed if:
//   - the signature is invalid or the token is expired
//   - the issuer does not match the configured SPIRE OIDC issuer
//   - the audience claim does not contain the expected audience
//   - the sub claim is not a SPIFFE URI within the expected trust domain
//   - the sub path does not contain a "/sandbox/<uuid>" segment
//   - the parsed sandbox UUID is empty
//
// The sandbox UUID is parsed from the SPIFFE URI path:
//
//	spiffe://anaeem.na-launch.com/ns/<ns>/sandbox/<uuid>
//
// A generic SPIRE workload SVID (e.g. ns/sa/agent) that has no "/sandbox/"
// segment is rejected — it is not bound to any consent grant.
func (v *Verifier) VerifySVID(ctx context.Context, raw string) (*SVIDClaims, error) {
	vt, err := v.inner.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("spire svid: %w", err)
	}

	// Enforce SPIFFE trust domain. The sub of a SPIRE JWT-SVID is the SPIFFE URI.
	if !strings.HasPrefix(vt.Sub, TrustDomain) {
		return nil, fmt.Errorf("spire svid: sub %q is not in trust domain %s",
			vt.Sub, TrustDomain)
	}

	// Parse the sandbox UUID from the SPIFFE URI path.
	// Expected form: spiffe://anaeem.na-launch.com/ns/<ns>/sandbox/<uuid>
	// The path portion after the trust domain prefix is: ns/<ns>/sandbox/<uuid>
	uid, err := sandboxUIDFromSub(vt.Sub)
	if err != nil {
		return nil, fmt.Errorf("spire svid: %w", err)
	}

	return &SVIDClaims{
		SpiffeID:   vt.Sub,
		SandboxUID: uid,
		// SandboxNonce is intentionally empty: real SPIRE JWT-SVIDs cannot carry
		// custom claims. Binding is the cryptographic sub-path UUID above.
	}, nil
}

// sandboxUIDFromSub parses the sandbox UUID from a SPIFFE URI sub claim.
//
// The URI must contain a "/sandbox/" path segment with a non-empty final
// component. Examples:
//
//	spiffe://anaeem.na-launch.com/ns/openshell/sandbox/550e8400-e29b-41d4-a716-446655440000
//	  -> "550e8400-e29b-41d4-a716-446655440000"
//
// Fails closed (returns error) when:
//   - the URI contains no "/sandbox/" segment
//   - the segment after "/sandbox/" is empty
func sandboxUIDFromSub(sub string) (string, error) {
	const marker = "/sandbox/"
	idx := strings.Index(sub, marker)
	if idx == -1 {
		return "", fmt.Errorf("sub %q has no /sandbox/ segment — not a sandbox SVID", sub)
	}
	uid := sub[idx+len(marker):]
	// Reject empty uuid and any path that continues beyond the UUID (e.g. /sandbox//extra).
	uid = strings.TrimRight(uid, "/")
	if uid == "" {
		return "", fmt.Errorf("sub %q has empty sandbox UUID after /sandbox/", sub)
	}
	// Reject embedded slashes: the UUID must be the final, single path component.
	if strings.Contains(uid, "/") {
		return "", fmt.Errorf("sub %q has multiple path components after /sandbox/", sub)
	}
	return uid, nil
}

// IsSPIRESVID heuristically detects whether the bearer token is likely a
// SPIRE JWT-SVID vs a Keycloak token, to decide which verification path to
// take. It does NOT perform any cryptographic check.
//
// Detection rule: the "iss" claim in the UNVERIFIED (peeked) payload contains
// the spireIssuer string. We peek the payload without verifying it — this is
// safe because the actual VerifySVID call that follows enforces all
// cryptographic guarantees. The peek result alone never unlocks any privilege.
//
// Returns true if the raw token appears to be a SPIRE SVID.
// Returns false for any other token or parse failure — callers should then
// attempt Keycloak verification.
func IsSPIRESVID(raw, spireIssuer string) bool {
	if raw == "" || spireIssuer == "" {
		return false
	}
	// JWT has 3 dot-separated parts. Peek the payload (part[1]).
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return false
	}
	// Base64url-decode the payload to read the "iss" claim without parsing JSON.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	// Simple string-search is safe here because we only use this result to
	// route to the right verifier; the actual cryptographic check is in
	// VerifySVID. A forged "iss" in an unverified payload would route to
	// VerifySVID, which then rejects the bad signature and sub trust-domain.
	return strings.Contains(string(payload), `"`+spireIssuer+`"`)
}
